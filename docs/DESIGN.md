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
open/acked/closed --回补更正--> superseded（终态：旧结论留痕，不再可处置、不在正常查询出现）
superseded --Ack/Close/Reopen--> 错误 ErrAlertSuperseded
```

`superseded` 是回补更正赋予**旧结论**的终态（见 §4A）：它保留可查但不再是活跃告警，
正常查询 `List` 不返回，任何生命周期操作都被明确拒绝。

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
  每次 `suppress_merge`；被回补取代时记录 `supersede`（旧终态）与更正告警的
  `create_correction`（撤回另记 `withdraw_correction`），抑制命中重定向记
  `suppress_merge_redirect`。
- 存储还维护**全量有序审计链** `AuditTrail()`（含被拒绝的越权/跨租户/非法尝试），
  全局序号连续无缺口；`DeniedAttempts()` 提供拒绝视图。
- 记录含操作者、租户、起止状态、墙钟时间与原因（「谁在什么时候因为什么改了什么」）。

## 4. 并发模型

- `Engine` 以单一互斥锁串行化 `Ingest / Advance / Tick / Backfill`：解析、入口判定、
  检测提交、告警物化、回补重算与更正在同一临界区内顺序完成；`alert.Store` 亦自带锁。
- 因此无论多少 goroutine、以何种交错顺序写入或回补，只要喂入的**事件集合相同**
  且最终断言水位相同，规则选择、窗口累计、抑制与告警 ID、合并事件集合就完全一致
  （见 `TestEngineConcurrentWritersConsistent`、`TestBackfillConcurrentOverlapStable`，
  `go test -race` 验证无数据竞争）。

## 4A. 受控回补与更正（Backfill & Correction）

实现见 `internal/engine/backfill.go`、`internal/alert/correction.go`。

### 4A.1 适用范围与边界

运维确认上游补齐某段数据后，可按**租户 + 事件时间闭区间 `[Start,End]`** 主动发起一次
受控回补，把此前因迟到被入口隔离的记录（或请求显式补投的记录）重新纳入检测。约束：

- 必须提供 `RequestID`（调用方幂等键）、本租户身份与 `operator/admin` 角色；
  `viewer` 拒绝（`ErrBackfillUnauthorized`），操作者租户与目标租户不一致拒绝
  （`ErrBackfillCrossTenant`），与普通权限错误可区分。
- 时间范围必须合法（零值/起止颠倒 → `ErrBackfillBadRange`），跨度不得超过
  `MaxBackfillAge`（默认 24h，→ `ErrBackfillTooWide`），且 `End` 不得越过已断言
  水位（只能回补已定论的历史，→ `ErrBackfillBeyondWatermark`）。
- 只重算**穿越点 `FireAt` 落在区间内**的窗口；区间外、其它租户的既有结论一律不动。
- 补入的历史事件按其**自身事件时间**匹配当时生效的规则版本（复用版本化规则集），
  不会因为"现在规则变了"而用新版本重判旧事件。
- 回补请求中无法解析、越出区间、与事件日志重复的补投记录不致命：按
  `out_of_backfill_range / duplicate_event / parse_error/...` 进入 `SkippedExtra`，
  其余记录照常处理；所有拒绝尝试写入全量审计链。

### 4A.2 怎么判定"结论变了"（为什么结论不变时零噪音）

回补用两个全新关联器分别重放：**基线**（事件日志，不含补入事件）与**重算**
（事件日志 + 补入事件），重放不触碰在线关联器状态。抑制命中会先折叠进其所属主告警，
因此比对单位是"一条完整结论 = 主告警合并的全部事件（含抑制追加）"。随后按
`(规则,实体)` 分组、只保留区间内的穿越，再做两阶段对齐：

1. 两侧某窗口的**合并事件集合完全相同** ⇒ 同一窗口、结论不变；
2. 剩余窗口按穿越点有序两两配对：成对的是结论**变更（changed）**，
   只在基线侧的是**撤回（withdrawn）**，只在重算侧的是**新增（added）**。

"第几次新发"的序号漂移本身不算变化；只有窗口事件集合真正不同才产生更正。
**结论不变时不产生任何告警、更正或状态变更**（`accepted_no_change`）。

### 4A.3 更正结果的语义：唯一当前结论 + 旧结论留痕

窗口身份是 `(租户, 规则, 实体, 时间窗)`，其中时间窗以**原结论穿越点**为锚
（补入事件可能让重算穿越点发生位移，但它仍是"同一个窗口的更正"）。

- 每个窗口**至多一条更正**（存储层维护窗口唯一索引）。更正生效时：
  - 原结论告警**不删除、不改写内容**，而是进入新的终态 `superseded`，
    并通过 `Alert.SupersededBy` 指向更正记录；
  - 更正结论是一条独立的新告警（`IsCorrection`、`CorrectionID`），
    `withdrawn` 时没有替代告警。
- **正常查询 `Store.List` 只返回当前有效结论**：被取代的旧告警（以及任何被更正
  记录引用为原结论的告警）不会出现，因此同一租户/规则/实体/时间窗在查询结果中
  至多一条。需要留痕时用：
  - `Store.Get(oldID)` 读旧告警本体（仍是 `superseded` 终态）；
  - `Store.ListHistory(tenant)` 列出含旧结论在内的全部告警；
  - `Store.GetCorrection(id)` / `ListCorrections(tenant)` 读不可变更正记录，
    其中含 `OriginalAlertIDs`（旧结论）、`CorrectedAlertID`（新结论）、
    `BaselineEventIDs / FinalEventIDs / AddedEventIDs`（原事件集、最终事件集、
    本次补入事件）——旧结论 → 更正记录 → 补入事件的追溯链完整闭合。
- **旧结论的状态不再自相矛盾**：`superseded` 是终态，`Ack/Close/Reopen` 一律返回
  可区分的 `ErrAlertSuperseded`；它既不会在正常列表里看着"还能处置"，也不会被
  真去处置时才拒绝。更正后的当前结论照常走 open/acked/closed 生命周期。
- **同一窗口不能被再更正一次**：范围内若已存在定案更正，整次回补在重算前即被
  拒绝（`ErrBackfillWindowCorrected`）；把更正告警当原结论再更正也同样拒绝
  （`alert.ErrWindowAlreadyCorrected`），从引擎到存储双层拦截。
- **原子性**：一次回补若涉及多个窗口，全部更正在存储的单个临界区内批量生效；
  任一窗口冲突则整批回滚（撤销新告警、更正记录、终态标记并恢复审计快照），
  绝不留下"部分窗口已更正"的中间状态。
- **与在线抑制的衔接**：更正生效后，在线关联器的抑制期会被同步——
  changed/add 时改挂到更正告警，withdrawn 时清除；若极端情况下在线抑制命中晚到
  并指向已被取代的旧告警，存储会把合并**重定向**到当前更正告警，旧结论保持终态、
  不被复活（撤回无替代告警时返回 `ErrAlertSuperseded`）。

### 4A.4 幂等、并发与可复现

- 同一 `RequestID` 重复或并发发起：首次结果登记在幂等台账，后续返回
  `idempotent_replay` 与首次的更正/告警，绝不重复产出。
- 不同 `RequestID` 但**互相重叠**的回补：引擎单锁串行化，先到者认领补入事件并
  更正窗口；其余请求因区间命中定案窗口而**整批拒绝**（`ErrBackfillWindowCorrected`），
  且不写入任何补入事件、不影响其它窗口与其它租户。因此无论多少个运维并发发起、
  与查询/在线写入如何交叉，同一窗口最终可见结论恒为一条；给定相同事件集合与调用集合，
  结果稳定可复现（测试以 1/8/16 并发度断言最终事件集合一致）。
- 回补与 `Ingest/Advance` 共享同一把引擎锁，查询过程中不可能同时看到同窗口的
  旧、新两条活跃结论。

## 5. 验证方法

```bash
go test ./...                 # 全量单测
go test -race ./...           # 竞态检测
go test -v ./internal/...     # 查看含事件序列/时间基准/判定依据的日志
go run ./cmd/sedemo           # 端到端演示（乱序/重复/并发/规则更新/权限/审计/隔离/回补更正）
```

测试覆盖矩阵：

| 场景 | 测试 |
| --- | --- |
| 三来源解析、五类拒绝原因、时间戳校验 | `event/parser_test.go` |
| 乱序到达结论一致、重复投递、迟到、Tick、Flush 语义 | `event/ingest_test.go` |
| 规则版本化、EffectiveAt 选择、非法版本 | `detect/ruleset_test.go` |
| 阈值触发、窗口滑动、抑制合并、版本不混算、水位幂等、实体/租户 | `detect/correlator_test.go` |
| 生命周期幂等、角色、跨租户、非法转换、审计链、并发唯一终态、合并幂等 | `alert/store_test.go` |
| 更正后唯一可见+旧结论可追溯、窗口不可二次更正、撤回终态、抑制重定向、跨租户、并发唯一、批量原子回滚 | `alert/correction_test.go` |
| 乱序+重复+多来源可复现、拒绝/迟到可区分、并发写入一致、未完成窗口收尾 | `engine/engine_test.go` |
| 回补改结论唯一可见/可追溯、乱序+重复补投、同 ID 幂等、重叠/并发回补、跨租户、结论不变零噪音、与在线写入/抑制交叉、added | `engine/backfill_test.go` |

### 5.1 在本地复现回补更正

最快的方式是运行端到端演示（输出含"---- 1.5) 受控回补 ----"小节）：

```bash
go run ./cmd/sedemo
```

也可以直接运行针对性用例观察过程日志：

```bash
go test -v ./internal/engine/ -run TestBackfillChangedUniqueVisibleTraceable
go test -v ./internal/engine/ -run TestBackfillConcurrentOverlapStable
go test -v ./internal/alert/  -run TestCorrection
go test -race -count=10 ./internal/engine/ -run TestBackfill   # 重压并发路径
```

手工复现"改结论"的最小序列（事件时间相对某个基准 `base`，窗口 1m、阈值 3）：

1. 先喂 `f1@0s f2@20s f3@40s`，再 `Advance(base+10m)` ⇒ 产生一条 open 告警（合并 f1,f2,f3）；
2. 补一条迟到记录 `f0@10s`（入口判 late 并隔离）；
3. `Backfill(RequestID, [base-1m, base+10m])` ⇒ 状态 `applied_changed`，
   窗口结论改为合并 `f0,f1,f2`；`List` 只剩更正后的一条，旧告警可经
   `Get/ListHistory/GetCorrection` 追溯到本次补入的 `f0`；
4. 用同一 `RequestID` 再发一次 ⇒ `idempotent_replay`；换一个 `RequestID` 再发
   ⇒ `rejected` / `ErrBackfillWindowCorrected`，且结论与告警数量不变。

单测日志会打印：时间基准（`time_base`）、断言水位、事件释放/合并序列、
判定依据（`Decision.Reason`：阈值、窗口、右端时间、规则版本、FireID）、
重复/迟到计数与隔离原因。
