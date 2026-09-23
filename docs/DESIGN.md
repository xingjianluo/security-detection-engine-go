# 本地安全事件检测与告警关联引擎 — 设计与语义说明

本文档说明引擎的**事件时间模型、关联与抑制语义、规则更新语义、权限规则、审计**，
以及如何验证。引擎为纯本地实现，仅依赖 Go 标准库；所有时间语义均可通过注入时钟复现。

---

## 1. 总体结构

```
cmd/demo                可运行的端到端演示（假时钟，输出确定）
internal/clock          时间来源抽象：SystemClock / FakeClock
internal/event          归一化事件模型、多来源解析器、拒绝/隔离原因
internal/rule           规则与不可变版本、按(租户,规则ID)组织、按事件时间选择版本
internal/detect         水位线 + 滑动窗口有状态关联、去重、迟到/超期分类、阈值穿越
internal/alert          告警生命周期、抑制合并、租户隔离、CAS 幂等状态机
internal/audit          只追加审计日志
internal/engine         顶层编排（解析→隔离→检测→告警→审计），并发安全
```

数据在引擎中的路径：

```
原始记录
  └─ Parser 解析（语法/必填字段/时间戳）
       ├─ 不合法 → StatusRejected（带可区分 RejectReason），不参与计算
       └─ 归一化 Event
            ├─ 事件时间远超处理时间 → StatusQuarantined(timestamp_in_future)
            ├─ Detector.Observe
            │    ├─ 重复 ID → duplicate（只计一次）
            │    ├─ 早于 水位线-保留期 → StatusQuarantined(beyond_retention)
            │    └─ 否则计入窗口，标记 on_time/late
            └─ （提交边界 Advance/Drain）水位线推进 → Finding → Alert 生命周期 + 审计
```

---

## 2. 事件时间模型（event-time semantics）

引擎严格区分两类时间：

| 时间 | 来源 | 用途 |
|------|------|------|
| **事件时间 event time** | 记录负载中的 `ts` | 窗口计算、迟到判定、规则版本选择、触发与抑制锚点的唯一基准 |
| **处理时间 processing time** | 可注入 `Clock` | 审计时间戳、"未来事件"判定、规则版本"已发布"判定 |

### 2.1 时间戳解析

`ts` 只接受三种**无歧义**格式，其他一律拒绝（不猜测本地时区）：

- RFC3339 / RFC3339Nano（例 `2026-09-24T10:00:00Z`、带毫秒）；
- 纯数字 Unix **秒**（≤11 位）；
- 纯数字 Unix **毫秒**（≥12 位）。

像 `2026-09-24 10:00:00` 这种无时区串会被拒绝；浮点秒（易丢精度）也拒绝。

### 2.2 水位线（watermark）

对每个租户独立维护：

```
watermark = maxObservedEventTime − L      （L = AllowedLateness，乱序宽限）
```

- 事件时间 `≥ watermark`：**on_time（正常）**；
- 事件时间 `< watermark` 但 `≥ watermark − R`：**late（迟到，仍计入窗口）**；
- 事件时间 `< watermark − R`（R = Retention，保留期）：**expired（超期隔离）**。

### 2.3 触发只在窗口"冻结"时评估

事件按 `(事件时间, 事件ID)` 全序存入窗口。阈值穿越评估**只在水位线推进时**进行，
且每个候选位置有冻结光标（`evalPos`）：

- 一旦某事件时间点被水位线覆盖并评估，结论即**冻结**，永不重新评估；
- 迟到事件若插入到冻结位置之前：照常计入计数（影响之后的判定），但其自身**不再触发**；
- 因此在乱序宽限内，同一批事件无论物理到达顺序如何，触发集合（触发时间、触发事件、
  窗口内事件列表）完全一致——这是"可复现"的核心保证。

### 2.4 坏记录不静默丢弃，且原因可区分

解析拒绝（`Status=rejected`）原因：

| RejectReason | 含义 |
|---|---|
| `unknown_source` | 未注册的来源 |
| `syntax_invalid` | 负载无法按来源语法解析 |
| `missing_event_id` / `missing_tenant` / `missing_entity` / `missing_event_type` | 必填字段缺失 |
| `timestamp_unparseable` | 无 `ts`、`null`、或格式无法解析 |
| `timestamp_non_positive` | 时间戳为 0/负 |

隔离（`Status=quarantined`）原因：

| QuarantineReason | 含义 |
|---|---|
| `timestamp_in_future` | 事件时间领先处理时间超过 `FutureTolerance` |
| `beyond_retention` | 迟到超过保留期 R |

### 2.5 提交边界（为什么 Ingest 不立即出警）

`Ingest` 只把事件计入窗口状态；告警在显式提交边界统一落地：

- `Advance()`：把水位线推进到 `maxObserved − L`，只让**已稳定**的窗口触发
  （流式出警，不排空乱序宽限区）；
- `Drain()`：推进到 `maxObserved`，排空全部待评估窗口，得到最终结论。

这样设计是为了保证**并发写入的最终状态与 goroutine 交织顺序无关**：若每条事件都
立即推进水位线，交织顺序会改变抑制锚点；统一在提交边界落地则消除了该不确定性。

> 关于抑制锚点的补充：检测 finding 集合与到达顺序无关；但"告警抑制锚点"在流式
> 语义中是**最早的稳定阈值穿越时刻**。复现对照时应固定提交边界（见测试）。

---

## 3. 关联检测与抑制语义

### 3.1 规则

规则字段：`EventType`（为空匹配全部）、`EntityScope`（为空不过滤实体）、
`Threshold`（窗口内阈值，>0）、`Window`（滑动窗口，>0）、`Suppression`（抑制间隔，≥0）。
检测按 `(租户, 规则版本, 实体)` 维度独立累计。

### 3.2 滑动窗口阈值穿越

窗口为 `[t − Window, t]`；当事件 `t` 在窗口冻结时被评估、且窗口内累计事件数
`≥ Threshold`，产生一个 `Finding`（阈值穿越）。每个候选位置只穿越一次（冻结光标保证）。

### 3.3 抑制（suppression）与可追溯合并

同一 `(租户, 规则, 实体)`：

- 首次穿越创建一条告警，锚点为触发事件时间 `first`，抑制区间 `[first, first + Suppression]`；
- 抑制区间内的后续命中**不再另开告警**，而是合并进同一条；
- 合并会把该次命中窗口切片中尚未归并的事件全部追加到 `MergedEventIDs`，
  并把 `SuppressedCount +1`——因此**一条告警可完整追溯它合并了哪些事件、抑制了几次命中**；
- 抑制区间结束后的新命中另起一条告警（旧告警仍保留其生命周期，除非被关闭）；
- 已被**关闭**的同键告警不再抑制，新命中立即起新警。

批量应用 `Store.ApplyFindings` 在同一把锁内按事件时间全序确定锚点，
使一批 findings 的归属与逐条/批量的落地方式无关；告警 ID 由
`(租户, 规则, 首触发事件ID)` 确定性派生（双路 FNV-1a），相同输入重放出相同 ID。

---

## 4. 规则运行中更新的语义（不静默改写已判定结果）

- 规则身份是 `(租户, 规则ID)`；每次 `UpsertRule` 生成一个**不可变版本**，
  版本号在该身份内单调递增，`EffectiveFrom` 必须单调不减。
- **版本绑定发生在事件到达（处理时间）时刻**：事件只对"当时已发布
  （`EffectiveFrom ≤ 当前处理时间`）"的版本可见，并在这些版本中按其**事件时间**选择生效版本。
- 事件一旦绑定版本即冻结。之后再发布的新版本：
  - 不影响已进入系统的事件（它们已经按旧版本累计/触发）；
  - 只影响在新版本发布之后到达的新事件。
- 跨越版本切换、尚未完成的窗口**不会**把旧版本与新版本的计数静默合并；
  版本各自维护独立窗口状态。
- 首个版本 `EffectiveFrom` 为零值时对全部事件时间生效（自时间原点）。

---

## 5. 告警生命周期、租户隔离与并发

### 5.1 状态机（全部转移幂等）

```
Open ──acknowledge──▶ Acknowledged ──close──▶ Closed
 ▲                      │                      │
 └────── reopen ────────┘ (Closed→Open)        │
        (仅 Closed 可 reopen；Acked→reopen 非法) │
```

- 重复提交相同目标状态：返回 `Changed=false` 与原因（如 `already closed`），
  **版本号不变**，审计标记为 `idempotent no-op`；
- 非法转移（如 `Acknowledged → reopen`）返回 `ErrInvalidTransition`，状态不变。

### 5.2 乐观并发控制（CAS）

每次真实变更使告警 `Version +1`。操作可带 `expectVersion`：

- `expectVersion = -1`：不校验版本；
- 否则必须等于当前版本，不匹配返回 `ErrVersionConflict`，**本次提交无效**。

并发提交基于同一旧版本时，恰好一个成功，其余得到可区分的冲突错误；最终状态唯一。

### 5.3 租户隔离与权限

- 告警按租户存储；`Get/List/Acknowledge/Close/Reopen` 都校验租户归属。
- 跨租户访问返回 `ErrCrossTenant`；空租户访问返回 `ErrEmptyTenant`（防止跨租户扫描）；
  操作者为空返回 `ErrEmptyOperator`。
- 被拒绝的访问**不会改变任何状态**，但同样写入 `access.denied` 审计记录，
  落在操作者所声明的租户下，便于追溯越权尝试。
- 本地引擎不设跨租户超级管理员角色；租户之间完全隔离。

### 5.4 锁序与并发安全

引擎用单把互斥锁串行化 `Ingest / Advance / Drain / UpsertRule / 生命周期操作`；
告警存储有自己的锁。固定锁序 `engine.mu → alert.Store.mu`，避免死锁。
全部包通过 `go test -race`。

---

## 6. 审计

审计日志只追加（append-only），记录有全局单调序号 `Seq` 与处理时间戳。动作包括：

`alert.create`、`alert.merge`、`alert.acknowledge`、`alert.close`、`alert.reopen`、
`rule.update`、`access.denied`。

- create 记录阈值、触发时间、窗口内归并事件；merge 记录抑制锚点与被合并的触发；
- 生命周期变更记录 `from → to` 与变更后版本；幂等 no-op 也留痕；
- 越权拒绝记录原因。可按租户过滤查询（空租户仅用于测试/导出）。

---

## 7. 支持的事件来源

| Source | 格式 | 说明 |
|---|---|---|
| `syslog` | `k=v` 空白分隔，值可带双引号 | 例 `id=e1 tenant=t1 entity=h type=ssh.auth_failed ts=1700000000` |
| `json` | JSON 对象 | `ts` 为 RFC3339 字符串或整数秒/毫秒；额外字段进 metadata |
| `cef` | `CEF:0\|vendor\|prod\|ver\|sig\|name\|severity\|ext` | 归一化字段在扩展段 `key=value` |

注册表 `event.Registry` 可扩展更多来源；未知来源返回 `unknown_source`。

---

## 8. 如何验证

### 8.1 运行测试

```bash
go test ./...                 # 全部单测
go test -race ./...           # 带竞态检测（CI 推荐）
go test -v ./internal/engine  # 查看端到端：事件序列/时间基准/判定依据日志
```

### 8.2 测试覆盖与"失败原因可区分"

- **解析/归一化**：三来源正常解析；语法错误、各字段缺失、时间戳不可解析、
  零/负时间、歧义时间格式——每种都有独立断言。
- **乱序可复现**：同一批事件按正序/逆序/洗牌到达，告警 ID、状态、归并事件集合、
  抑制计数逐项相等（`TestReproducibleAcrossArrivalOrders`、检测器层
  `TestOutOfOrderReproducible`）。
- **迟到**：宽限内迟到事件计入并补全未来窗口；冻结位置不二次触发
  （`TestLateWithinLatenessAffectsFutureDecision`）。
- **超期隔离**：早于 `watermark − R` 隔离，边界内的迟到仍保留
  （`TestExpiredBeyondRetentionQuarantinedUpstream`）。
- **重复投递**：同 ID 只计一次，重复不产生多余告警
  （`TestDuplicateDeliveryEndToEnd`、`TestDuplicateDeliveryCountedOnce`）。
- **并发写入**：多 goroutine 混合重复+乱序，重复运行与固定提交边界基线一致
  （`TestConcurrentWritesFinalStateUnique`、`TestStressConcurrentMixedWriters`）。
- **生命周期/租户/CAS**：幂等、非法转移、版本冲突唯一胜者、跨租户拒绝
  （`internal/alert` 与 `TestAlertLifecycleAuditAndTenantIsolation`）。
- **规则热更新**：已进入事件不被追溯改写，切换后新事件绑定新版本
  （`TestRuleUpdateFreezesAndReapplies`、检测器 `TestRuleUpdateDoesNotRewriteFrozenResult`）。

单测日志会打印：**时间基准 t0、参数 L/R、物理到达顺序、每条事件的
status/timing/duplicate、水位线、触发与归并事件、最终审计轨迹**。

### 8.3 运行演示

```bash
go run ./cmd/demo
```

演示使用假时钟，输出完全确定、可重复运行复现，覆盖乱序、重复、迟到、
抑制合并、抑制过期另起、坏记录拒绝、确认/关闭/幂等、跨租户拒绝与审计。

---

## 9. 关键默认参数（可配置）

| 参数 | 默认 | 含义 |
|---|---|---|
| `AllowedLateness (L)` | 5s | 水位线滞后量/乱序宽限 |
| `Retention (R)` | 30s | 迟到保留期，超过则隔离 |
| `FutureTolerance` | 2s | 事件时间领先处理时间的容忍带，超过则隔离 |

生产中应以来源时钟偏差与 SLA 调整；测试中可按场景设置（如 L=10s、R=30s）。
