# 设计说明：本地安全事件检测与告警关联引擎

## 1. 事件时间模型（Event Time）

引擎中**所有检测判定只使用事件时间 `EventTime`**（日志自身携带的发生时间）；
接收时间 `ReceivedAt`（墙钟）仅用于审计记录，不参与任何窗口/阈值/迟到计算。
这保证同一批事件在任何到达顺序、任何墙钟时刻重放，结论一致。

### 1.1 归一化事件

| 字段 | 含义 |
| --- | --- |
| `ID` | 事件唯一标识，重复投递判定的键 |
| `TenantID` | 租户，规则匹配与告警隔离的边界 |
| `Type` / `Entity` | 事件类型（路由规则）/ 关联实体（窗口归属） |
| `EventTime` | 事件时间，检测的唯一时间语义，内部统一为 UTC |
| `ReceivedAt` | 接收时间，仅审计用 |
| `Attrs` / `Raw` | 归一化属性 / 原始报文，便于追溯 |

支持三种来源解析（`internal/event/parser.go`）：

- **syslog**：`<pri>RFC3339 host app: k=v k=v ...`
- **JSON**：`{"id","type","entity","ts","attrs"}`，`ts` 接受 RFC3339 或 Unix 秒/毫秒
- **CEF**：`CEF:0|vendor|product|ver|sig|name|sev|externalId=.. act=.. suser=.. rt=..`

### 1.2 不静默丢弃：四种互斥去向

| 去向 | 判定条件 | 可区分原因 |
| --- | --- | --- |
| `accepted` | 解析、必填字段、时间戳均合法，且未重复、未迟到 | — |
| `duplicate` | 同一 `ID` 再次到达（**去重优先于迟到**：迟到事件的重投仍是重复） | `duplicate_event` |
| `late` | 到达时事件时间 `<= 已断言水位 W` | `late_event`（隔离记录含事件时间与水位） |
| `rejected` | 无法进入检测 | `parse_error` / `missing_field` / `bad_timestamp` / `timestamp_in_future` / `timestamp_too_old` |

拒绝与迟到记录都写入**隔离区**（`Engine.Quarantine()`），含原始报文、原因与明细，绝不静默丢弃。
时间戳合法性（未来偏移、最大年龄）以可注入的接收时间基准校验，测试中使用固定基准。

### 1.3 水位（Watermark）与迟到

水位必须由生产者**显式断言**：

- `AdvanceWatermark(W)` 断言「事件时间 `<= W` 的事件均已到达」。
  断言后才到达且 `EventTime <= W` 的事件判为**迟到**，隔离、不参与检测。
- 在任何水位断言之前到达的事件不可能迟到。因此：
  **把同一批事件以任意顺序（含重复）喂入，最后统一 `Advance(批尾)` ，得到的结论与到达顺序完全无关。**
- `Tick()` 是在线模式便利方法，断言 `W = 已观测最大事件时间 - AllowedLateness`。
  交错接收/`Tick` 时产生的迟到反映真实流式到达语义；需要可复现的批处理结论时用显式 `Advance`。
- 断言水位时，所有 `EventTime <= W` 的缓冲事件按 `(事件时间, 实体, ID)` 全局排序后
  一次性释放给关联器；跨多次断言的释放序列整体有序。

**未完成窗口的处理语义**：窗口右端为 `t` 的判定在水位到达 `t` 时定论。
流结束时调用 `Advance(t)` 把水位推进到所有窗口右端之后，未完成窗口即获得确定性结论；
重复推进或回退均安全（回退忽略、重复推进无产出，幂等）。

## 2. 关联检测语义（Correlation）

实现见 `internal/detect/correlator.go`。规则：

```
EventType 匹配 + Window(滑动窗口) + Threshold(阈值) + SuppressFor(抑制间隔)
```

### 2.1 滑动窗口累计（确定性算法）

- 按 `(规则版本, 实体)` 维护**有序的未消费事件**序列（事件由入口保证全局有序）。
- 以每个候选事件的事件时间 `t` 作为窗口右端，考察闭区间 `[t-Window, t]`：
  窗口内未消费事件数 `>= Threshold` 时在 `t` 处**穿越阈值**。
- 穿越成立即**消费窗口内全部事件**，窗口从下一个未消费事件继续滑动
  （consume-on-fire：每个事件最多被一条告警合并，杜绝同一事件被重复计数）。
- 只有早于 `watermark-Window` 的事件才会被裁剪（它们不可能再进入任何剩余窗口）；
  尚未定论但仍在窗口内的事件保留，保证乱序安全。
- 判定在水位到达穿越点 `t` 时即为最终；之后迟到事件已被入口隔离，结论不会被改写。

### 2.2 抑制（Suppression）与可追溯合并

- 抑制键 `AlertKey = 规则ID | 实体`。阈值穿越时若处于抑制期
  （`t <= 抑制截止时间`），不再产生新告警，而是输出一条**抑制命中**：
  - 复用主告警的确定性 `FireID`（`SuppressedBy = FireID`）；
  - 携带本次命中合并的事件 ID 列表；
  - 抑制期**滚动顺延**到 `t + SuppressFor`。
- 抑制期结束后的再次穿越产生新告警（新 `FireID`）。
- 物化到告警存储时：抑制命中通过 `MergeSuppressed` 把事件 ID 幂等追加到主告警，
  `EventIDs` 记录该告警合并的**全部**事件，`SuppressedCount` 记录追加次数——
  「一条告警合并了哪些事件」完全可追溯；合并动作自身也产生审计记录。
- 抑制是规则时间窗口的相关概念（事件时间），与值班人员手动关闭告警相互独立：
  手动关闭不改变规则抑制状态，后续抑制命中仍会合并到原告警（留下审计），这是有意的、可解释的行为。

### 2.3 规则版本化（运行中更新不改写历史）

- 规则以 `(TenantID, RuleID, Version)` 版本化保存，`Version` 必须递增，
  `EffectiveAt` 必须随版本单调不减。
- 事件时间 `t` 的事件只受 **`EffectiveAt <= t` 的最新版本**约束
  （`RuleSet.EffectiveAt`）。因此规则在墙钟意义上的「运行中更新」不会改变
  历史事件的适用版本；规则更新可以补录/回放（`EffectiveAt` 允许早于当前墙钟），
  使整套结论对「更新发生的时刻」不敏感、可复现。
- 累计器按 `(规则ID, 版本, 实体)` 独立，窗口**绝不跨版本混合计数**；
  新版本从其 `EffectiveAt` 起对新到事件起算新窗口。
- 已输出的判定不可变；抑制状态跨版本连续存续。
- `FireID` 为确定性标识 `fire:<规则>:<实体>:<首次事件时间UnixNano>:<该键第几次新发>`，
  不含墙钟/随机数/map 遍历序，跨运行可复现。

## 3. 告警生命周期与租户隔离

实现见 `internal/alert/store.go`。单互斥锁串行化所有变更，并发提交下最终状态唯一。

### 3.1 状态机（转换均幂等）

```
open   --Ack-->     acked      （acked 上重复 Ack => 幂等命中，留痕 already_acked）
open/acked --Close--> closed   （closed 上重复 Close => 幂等命中，留痕 already_closed）
closed --Reopen-->  open       （open/acked 上重复 Reopen => 幂等命中，留痕 already_open）
closed --Ack-->     错误 ErrInvalidTransition（须先 Reopen）
```

幂等含义：相同操作重复提交不产生额外状态变化、不报错；但**每次调用都写一条审计**，
可区分「真实转换」与「幂等命中」（`Reason` 与 `FromState/ToState` 相同与否）。

### 3.2 权限规则

| 角色 | Get/List/AuditLog | Ack / Close / Reopen |
| --- | --- | --- |
| `viewer` | 允许（限本租户） | 拒绝 `ErrPermissionDenied` |
| `operator` / `admin` | 允许（限本租户） | 允许（限本租户） |

- 任何对**其他租户**告警的访问（含读取、合并）一律拒绝 `ErrCrossTenant`，
  与权限错误类型可区分；告警不存在返回 `ErrAlertNotFound`。
- 失败原因三分类互不重叠：`ErrAlertNotFound` / `ErrCrossTenant` / `ErrPermissionDenied` /
  `ErrInvalidTransition`，调用方与测试可精确断言。

### 3.3 审计

- 每条告警有按序号严格递增的审计视图：`create`、每次 `ack/close/reopen`（含幂等命中）、
  每次 `suppress_merge`。
- 存储还维护**全量有序审计链** `AuditTrail()`（含被拒绝的越权/跨租户/非法尝试），
  全局序号连续无缺口；`DeniedAttempts()` 提供拒绝视图。
- 记录含操作者、租户、起止状态、墙钟时间与原因（「谁在什么时候因为什么改了什么」）。

## 4. 受控历史回补（Backfill）与结论更正

上游日志源头偶尔补发、或延迟很久才把某段数据送来。这些记录按在线语义会判迟到隔离。
回补提供一个**受控入口**：运维确认上游补齐后，主动发起一次回补，把指定范围内之前
隔离的记录重新纳入检测。实现见 `internal/engine/backfill.go`、`internal/backfill/`。

### 4.1 适用范围与边界

- **按 `(租户, 时间段)` 圈定**：请求只携带 `TenantID + [From,To]`，只处理该租户、
  事件时间落在闭区间内、且此前因**迟到**被隔离的记录。解析失败（rejected）不属于
  回补对象——它们不是"晚到"，而是报文本身不合法。
- **只重算、不改在线状态**：回补在**隔离的临时关联器**上对事件日志做 shadow 重放，
  不触碰在线水位、在线累计器、在线抑制状态。因此回补进行时新事件照常写入/查询，
  其他租户、其他时间段已定的结论不会跟着变。
- **`To` 不得越过当前已断言水位**：那段结论尚未定论，回补它没有意义（返回
  `ErrRangeNotFinalized`）。`From` 不得早于 `now - MaxBackfillAge`
  （配置项；零值表示不限年龄），返回 `ErrBeyondHorizon`。
- **按事件时间选规则版本**：补进来的历史记录按它**自己的事件时间**匹配当时生效的
  规则版本（复用 `RuleSet.EffectiveAt`），不会因为规则现在已改成新版就套用新版。
- 回补是一次性受控操作，不是放开迟到限制：在线 `Ingest` 的迟到/去重语义不变。

### 4.2 不双算、不重复告警

- **事件级去重**：引擎维护全量事件日志（正常释放 + 历次回补补入）与去重索引。
  回补候选若已在日志中（正常事件重投、或已被更早的回补纳入），一律跳过并在
  `Result.SkippedDup` 交代，绝不二次计数。
- **请求级幂等**：`RequestID` 是调用方提供的幂等键。同一请求重复发起（或并发
  同时提交）只真正执行一次，其余返回 `Replayed=true` 的同一结果，不重复产出。
- **重叠回补**：不同 `RequestID` 但范围重叠时，后执行的重算其基线已包含先前补入
  的事件，结论一致即返回 `accepted_unchanged`，不会再产生一条矛盾告警。
- 回补与在线写入共用引擎同一把全局锁串行化，配合上述去重，并发跑完终态唯一。

### 4.3 更正语义：原结论保留，可见结论唯一

回补**绝不悄悄改写或删除原结论**。重算后在同一 `(租户,规则,实体,时间窗)` 上：

- 原告警被标记为 `superseded`（新增的生命周期状态）：记录保留、可 `Get`、可查
  审计，并通过 `SupersededBy` 指向当前生效结论；但不再是"可见最终版"。
- 更正产生一条新告警，与原结论共享同一 `RootID`（更正链），状态从 `open` 起，
  其 `EventIDs` 是补数后该窗口合并的**全部**事件，`SuppressedCount` 记抑制合并数。
- `Store.List` 只返回当前可见结论（排除 superseded），因此同一时间窗上**可见结论
  唯一**；`Store.ListAll` 返回含历史版本的完整结论链供追溯。
- 被替代的历史结论不再接受 Ack/Close/Reopen（返回 `ErrInvalidTransition`）；
  运维应对当前生效的替代告警操作。

更正有三种类型（`Correction.Kind`），都记录原结论、补入事件、窗口起止与依据：

| Kind | 含义 |
| --- | --- |
| `added` | 原时间窗上没有结论，补入事件后新窗口首次成立，新增一条更正告警 |
| `revised` | 原时间窗上已有告警，补入事件后窗口/合并事件/规则版本变化，原结论被同 RootID 的替代告警取代 |
| `revoked` | 原结论在重算后不再成立（防御性；纯补数只会新增事件，理论上不出现） |

shadow 重算按"结论组"对齐（一次新发告警 + 其后到下一次新发之间的全部抑制命中
构成一个结论组），组身份锚点是首发窗口的第一个事件 ID——它跨重算稳定。规划器
`backfill.PlanChanges` 是纯函数（不碰存储/水位/墙钟），只依赖两组 Decision、事件
集合与区间，因此更正结果可复现、可单测。

### 4.4 请求结果三态（调用方无需猜测）

| `Result.Status` | 含义 |
| --- | --- |
| `accepted_changed` | 被接受且**真的改变**了可见结论（`Corrections` 非空） |
| `accepted_unchanged` | 被接受但重算结论与现状一致（无新事件/补了也不影响结论），**不产生任何告警或审计噪音** |
| `rejected` | 被拒绝，`Result.Err` 为可区分原因（见下） |

可区分的拒绝原因（`internal/backfill` 的 sentinel error）：

- `ErrInvalidRange`：区间非法（空、`From>To`、缺租户/RequestID）。
- `ErrRangeNotFinalized`：`To` 越过当前水位。
- `ErrBeyondHorizon`：早于可回补下限。
- `ErrCrossTenant`：操作者租户与目标租户不一致（复用 `alert.ErrCrossTenant`）。
- `ErrPermissionDenied`：仅 `operator`/`admin` 可发起（viewer 拒绝）。

`Result` 还交代：`Backfilled`（实际纳入的事件）、`SkippedDup`（重复跳过）、
`Advisories`（不改变结论但需说明的边界影响，如补入事件被区间外窗口吸收——此时
区间外结论保持不变，仅给提示）。

### 4.5 本地复现

```go
eng, rules, store := engine.New(engine.Config{AllowedLateness: 30*time.Second, MaxBackfillAge: 24*time.Hour, Parse: ...})
// ... 正常喂事件、Advance 推进水位；迟到事件进入隔离 ...

res := eng.Backfill(backfill.Request{
    RequestID: "bf-001", TenantID: "t1",
    From: base, To: base.Add(2*time.Minute),
    Operator: alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator},
    Reason:   "upstream re-delivered after recovery",
})
res.Status // accepted_changed / accepted_unchanged / rejected
res.Corrections // OldAlertIDs -> NewAlertID、AddedEventIDs、AllEventIDs、窗口、规则版本、依据
store.List("t1")     // 当前可见结论（唯一）
store.ListAll("t1")  // 含 superseded 历史版本的完整结论链
```

## 5. 并发模型

- `Engine` 以单一互斥锁串行化 `Ingest / Advance / Tick / Backfill`：解析、入口判定、
  检测提交、告警物化与回补的 shadow 重算/更生物化在临界区内顺序完成；`alert.Store`
  与 `backfill.Service` 亦自带锁。
- 因此无论多少 goroutine、以何种交错顺序写入或发起回补，只要喂入的**事件集合相同**
  且最终断言水位相同，规则选择、窗口累计、抑制与告警 ID、合并事件集合就完全一致
  （见 `TestEngineConcurrentWritersConsistent`、`TestBackfillConcurrent`，
  `go test -race` 验证无数据竞争）。
- 唯一的非确定项：多个**不同 `RequestID`** 的重叠回补并发时，谁先被串行调度谁生效；
  但无论谁先，最终同一时间窗上都只有一条可见结论。需要跨调度完全相同的更正 ID 时，
  让重复提交共享同一 `RequestID`（幂等）。

## 6. 验证方法

```bash
go test ./...                 # 全量单测
go test -race ./...           # 竞态检测
go test -v ./internal/...     # 查看含事件序列/时间基准/判定依据/更正依据的日志
go test ./internal/engine/ -run Backfill -v   # 只跑回补与更正用例
go run ./cmd/sedemo           # 端到端演示（乱序/重复/并发/回补更正/规则更新/权限/审计/隔离）
```

测试覆盖矩阵：

| 场景 | 测试 |
| --- | --- |
| 三来源解析、五类拒绝原因、时间戳校验 | `event/parser_test.go` |
| 乱序到达结论一致、重复投递、迟到、Tick、Flush 语义 | `event/ingest_test.go` |
| 规则版本化、EffectiveAt 选择、非法版本 | `detect/ruleset_test.go` |
| 阈值触发、窗口滑动、抑制合并、版本不混算、水位幂等、实体/租户 | `detect/correlator_test.go` |
| 生命周期幂等、角色、跨租户、非法转换、审计链、并发唯一终态、合并幂等、**superseded 更正** | `alert/store_test.go` |
| 乱序+重复+多来源可复现、拒绝/迟到可区分、并发写入一致、未完成窗口收尾 | `engine/engine_test.go` |
| **差异规划：新增/更正/不变**（纯函数对齐、锚点、抑制计数） | `backfill/planner_test.go` |
| **回补端到端**：迟到补入新增更正、原结论 revised 且唯一可见、结论不变无噪音、幂等、重叠不双算、拒绝五分类、跨租户隔离、并发回补、按事件时间选版本 | `engine/backfill_test.go` |

单测日志会打印：时间基准（`time_base`）、断言水位、事件释放/合并序列、
判定依据（`Decision.Reason`：阈值、窗口、右端时间、规则版本、FireID）、
重复/迟到计数与隔离原因、回补的补入事件/窗口变化/原结论→新结论的更正依据。
