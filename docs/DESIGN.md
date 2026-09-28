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

- 抑制键 `AlertKey = 租户 | 规则ID | 实体`（面向解释的字符串仍是 `规则ID|实体`，
  但内部累计、抑制期、新发计数一律带租户；不同租户下同名规则/实体绝不串窗口、
  串抑制或共享 FireID 序号）。阈值穿越时若处于抑制期
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
- 累计器按 `(租户, 规则ID, 版本, 实体)` 独立，窗口**绝不跨版本、跨租户混合计数**；
  新版本从其 `EffectiveAt` 起对新到事件起算新窗口。
- 已输出的判定不可变；抑制状态跨版本连续存续（但不跨租户）。
- `FireID` 为确定性、全局唯一的标识
  `fire:<租户>:<规则>:<实体>:<首次事件时间UnixNano>:<该租户内该键第几次新发>`，
  不含墙钟/随机数/map 遍历序，跨运行可复现，且不同租户即使规则 ID、实体名完全
  相同也不会撞 ID（避免告警存储按 ID 幂等去重时跨租户误并）。

## 3. 告警生命周期与租户隔离

实现见 `internal/alert/store.go`。单互斥锁串行化所有变更，并发提交下最终状态唯一。

### 3.1 状态机（转换均幂等）

```
open   --Ack-->     acked      （acked 上重复 Ack => 幂等命中，留痕 already_acked）
open/acked --Close--> closed   （closed 上重复 Close => 幂等命中，留痕 already_closed）
closed --Reopen-->  open       （open/acked 上重复 Reopen => 幂等命中，留痕 already_open）
closed --Ack-->     错误 ErrInvalidTransition（须先 Reopen）

open/acked/closed --回补更正--> superseded（终态，见第 4 节）
```

幂等含义：相同操作重复提交不产生额外状态变化、不报错；但**每次调用都写一条审计**，
可区分「真实转换」与「幂等命中」（`Reason` 与 `FromState/ToState` 相同与否）。

`superseded` 是终态：已被回补更正取代的旧结论停在该状态，Ack/Close/Reopen 与
抑制合并一律返回 `ErrAlertSuperseded`，不会出现「列表上看着能处置、处置时又被拒」。

### 3.2 查询视图：活跃结论 vs 留痕

| API | 内容 | 用途 |
| --- | --- | --- |
| `List(tenant)` | 仅**当前有效的最终结论**（`Superseded == false`） | 调用方日常查询、值班处置的唯一入口 |
| `EffectiveAlerts(tenant)` | 同上，按窗口穿越点 `FireAt` 排序 | 按时间窗对齐的有效结论视图 |
| `Get(id, op)` | 单条记录，**含已被取代的旧结论**（强制租户隔离） | 顺着旧 ID 留痕追溯 |
| `ListHistory(tenant)` | 全部记录，含 `superseded` 旧结论 | 审计/留痕浏览 |
| `AuditLog` / `GetCorrection` / `ListCorrections` | 审计链与更正记录 | 追溯「为什么变、补了什么、被谁取代」 |

不变量：**同一（租户, 规则, 实体, 时间窗 `FireAt`）在 `List` 视图中至多一条记录**。
存储在创建更正告警前做窗口冲突校验，尝试并列第二条有效结论时返回
`ErrCorrectionConflict` 且不产生任何半更新。

### 3.3 权限规则

| 角色 | Get/List/AuditLog | Ack / Close / Reopen |
| --- | --- | --- |
| `viewer` | 允许（限本租户） | 拒绝 `ErrPermissionDenied` |
| `operator` / `admin` | 允许（限本租户） | 允许（限本租户） |

- 任何对**其他租户**告警的访问（含读取、合并）一律拒绝 `ErrCrossTenant`，
  与权限错误类型可区分；告警不存在返回 `ErrAlertNotFound`。
- 失败原因三分类互不重叠：`ErrAlertNotFound` / `ErrCrossTenant` / `ErrPermissionDenied` /
  `ErrInvalidTransition`，调用方与测试可精确断言。

### 3.4 审计

- 每条告警有按序号严格递增的审计视图：`create`、每次 `ack/close/reopen`（含幂等命中）、
  每次 `suppress_merge`、以及更正时的 `supersede` / `create_correction` /
  `withdraw_correction`（`supersede` 记录真实前置状态，如 `acked -> superseded`）。
- 存储还维护**全量有序审计链** `AuditTrail()`（含被拒绝的越权/跨租户/非法尝试），
  全局序号连续无缺口；`DeniedAttempts()` 提供拒绝视图。
- 记录含操作者、租户、起止状态、墙钟时间与原因（「谁在什么时候因为什么改了什么」）。

## 4. 受控回补与更正结论（Backfill & Correction）

上游确认某段历史数据补齐后，运维按**租户 + 事件时间段**发起一次受控回补，
把此前被入口判迟到而隔离的事件（以及请求中显式补投的原始记录）重新纳入检测。
实现见 `internal/engine/backfill.go` 与 `internal/alert/correction.go`。

### 4.1 适用范围与边界

- **圈选范围**：只重算请求租户内、事件时间闭区间 `[Start, End]` 内的窗口；
  只有穿越点 `FireAt` 落在区间内的判定参与比对，区间外既有结论完全不动。
- **只回补已定论的历史**：`End` 不得越过当前已断言水位（`ErrBackfillBeyondWatermark`），
  避免与在线未决窗口竞争。
- **跨度上限**：`End-Start` 不得超过最大可回补跨度（默认 `DefaultMaxBackfillAge = 24h`，
  `Config.MaxBackfillAge` 可调），超限拒绝 `ErrBackfillTooWide`。
- **权限与租户**：仅 `operator/admin` 可发起，操作者租户必须等于目标租户；
  viewer 拒绝 `ErrBackfillUnauthorized`，跨租户拒绝 `ErrBackfillCrossTenant`；
  缺少 `RequestID`、零值/颠倒时间范围分别拒绝 `ErrBackfillNoRequestID` /
  `ErrBackfillBadRange`。所有拒绝都写审计且**不改动任何既有结论**。
- **历史按当时规则版本评估**：重放用全新关联器、版本化规则集，补入的历史事件
  自动匹配其事件时间当时生效的规则版本，与在线检测的版本选择语义一致。
- 请求里的补投原始记录重新解析：非法记录进 `SkippedExtra`（带可区分原因），
  区间外记录跳过，同 ID 重复（含跨来源、与事件日志重复）去重。

### 4.2 幂等与并发

- `RequestID` 是调用方提供的幂等键：同一 ID 重复或并发重叠发起直接返回首次结果
  （状态置为 `idempotent_replay`），绝不重复产出告警或更正。
- 回补与在线 `Ingest/Advance/Tick` 共用引擎单锁串行化；多个运维并发发起互相重叠的
  回补、或回补与查询/写入交叉时，最终结论只取决于已认领事件集合，与交错顺序无关。
- 迟到事件按「未认领」状态被某次回补认领一次后并入事件日志，之后其它回补不会再算它；
  consume-on-fire 保证同一事件不会在结论里被计数两遍。

### 4.3 更正结果的语义（旧结论怎么保留、唯一可见怎么保证）

每次回补对区间内每个 `(规则, 实体)` 做两阶段比对：

1. 基线（事件日志不含本次补入）与重放（叠加补入事件）中，**合并事件集合完全相同**
   的窗口配对为「结论不变」——不产出任何东西（零噪音）。
2. 剩余窗口按穿越点有序配对：基线有/重放有 => `changed`；仅基线有 => `withdrawn`；
   仅重放有 => `added`。仅当窗口事件集合真正不同时才登记更正。

结论变化时：

- 不可变的 `Correction` 记录承载全部追溯信息：`RequestID`、租户/规则/实体/版本、
  窗口端点、`OriginalAlertIDs`（被取代的旧结论）、`CorrectedAlertID`（新结论，
  withdrawn 为空）、`BaselineEventIDs` / `FinalEventIDs` / `AddedEventIDs`、原因与操作者。
- **旧结论不删除、不改写事件集合**：进入 `superseded` 终态并写入 `supersede` 审计，
  `SupersededBy` 指向更正记录；仍可用 `Get` / `ListHistory` / `AuditLog` 读取，
  顺着 `SupersededBy -> Correction -> CorrectedAlertID / AddedEventIDs` 完整追溯，
  但不再出现在 `List`，也不能再被 Ack/Close/Reopen 或抑制合并修改。
- **更正告警**（`IsCorrection`）从 `open` 开始正常生命周期，`Supersedes` 正向记录
  它取代了谁；它成为该窗口在 `List` 中唯一可见的最终结论。
- 同一窗口被后续回补再次更正时形成**单链**：上一代更正告警同样进入 `superseded`，
  最新一代唯一可见；已被取代的记录不能被另一条更正再次取代
  （`ErrAlertSuperseded`），窗口冲突校验拦截并列的第二条有效结论
  （`ErrCorrectionConflict`），因此同一窗口永远只有一条当前结论、且只有一条更正链。
- 结论不变（`accepted_no_change`）时不产生告警也不产生更正；补入事件仍只认领一次。

> 说明：在「仅补入事件、规则集不变」的前提下，consume-on-fire 算法对事件增加是
> 单调的（补事件只会让穿越提前或新增，不会减少穿越），因此 `withdrawn` 主要出现在
> 规则配置经版本化更正后重算历史的场景；存储层完整支持撤回语义并有独立单测。

## 5. 并发模型

- `Engine` 以单一互斥锁串行化 `Ingest / Advance / Tick / Backfill`：解析、入口判定、
  检测提交、告警物化、回补重放与更正在临界区内顺序完成；`alert.Store` 亦自带锁
  （引擎持引擎锁、存储操作再取存储锁，锁序单向，无死锁）。
- 因此无论多少 goroutine、以何种交错顺序写入或发起重叠回补，只要最终已认领的
  **事件集合相同**且最终断言水位相同，规则选择、窗口累计、抑制、告警 ID、
  合并事件集合与「哪条结论有效」就完全一致
  （见 `TestEngineConcurrentWritersConsistent`、
  `TestBackfillConcurrentOverlapsSingleEffective`、
  `TestBackfillConcurrentWithIngest`，`go test -race` 验证无数据竞争）。

## 6. 验证方法

```bash
go test ./...                                              # 全量单测
go test -race ./...                                        # 竞态检测
go test -v ./internal/...                                  # 查看含事件序列/时间基准/判定依据的日志
go test ./internal/engine/ -run TestBackfill -count=5      # 回补场景多轮稳定复现
go run ./cmd/sedemo                                        # 第 9 节演示回补更正：正常查询 vs 留痕
```

测试覆盖矩阵：

| 场景 | 测试 |
| --- | --- |
| 三来源解析、五类拒绝原因、时间戳校验 | `event/parser_test.go` |
| 乱序到达结论一致、重复投递、迟到、Tick、Flush 语义 | `event/ingest_test.go` |
| 规则版本化、EffectiveAt 选择、非法版本 | `detect/ruleset_test.go` |
| 阈值触发、窗口滑动、抑制合并、版本不混算、水位幂等、实体/**跨租户同名规则/实体隔离（含 FireID 不撞）** | `detect/correlator_test.go` |
| 生命周期幂等、角色、跨租户、非法转换、审计链、并发唯一终态、合并幂等 | `alert/store_test.go` |
| 撤回终态、窗口冲突守卫、重复取代拒绝、更正幂等、更正记录租户隔离 | `alert/correction_test.go` |
| 乱序+重复+多来源可复现、拒绝/迟到可区分、并发写入一致、未完成窗口收尾 | `engine/engine_test.go` |
| **回补改结论后唯一可见+旧结论可追溯、链式二次更正是单链、新增(added)** | `engine/backfill_test.go` |
| **回补乱序+跨来源重复投递、并发重叠回补、回补与写入/查询交叉、跨租户互不影响、结论不变零噪音、拒绝不影响其它窗口** | `engine/backfill_test.go` |

单测日志会打印：时间基准（`time_base`）、断言水位、事件释放/合并序列、
判定依据（`Decision.Reason`：阈值、窗口、右端时间、规则版本、FireID）、
重复/迟到计数与隔离原因。
