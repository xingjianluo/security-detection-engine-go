# 本地安全事件检测与告警关联引擎（Go）

用本地事件流模拟多来源安全日志采集，在**乱序到达、重复投递、并发写入**下给出
**一致且可解释**的检测结论：事件归一化 → 事件时间水位与迟到/去重判定 →
滑动窗口有状态关联与告警抑制 → 告警生命周期、租户隔离与审计。

## 架构

```
原始记录(syslog/json/cef)
        │  Parse            解析失败 → rejected（可区分原因）→ 隔离区
        ▼
   归一化 Event ── Ingestor ── 重复(duplicate) / 迟到(late) / 正常(accepted)
        │  显式水位 Advance(W) / 在线 Tick()
        ▼  按 (事件时间,实体,ID) 全局有序释放
  Correlator（规则版本化 · 滑动窗口阈值 · consume-on-fire · 抑制合并 · 租户隔离）
        │  Decision（新发告警 / 抑制命中，确定性 FireID，携带合并事件 ID）
        ▼
  alert.Store（幂等 Ack/Close/Reopen · 角色与租户隔离 · 全量审计链）
        ▲
        │ 受控回补 Backfill（按租户+时间段圈选 · 重放比对 · 幂等）
        │ 结论变化：旧结论 superseded 留痕，更正结论成为唯一可见最终结论
```

| 包 | 职责 |
| --- | --- |
| `internal/event` | 多来源解析与归一化；拒绝原因分类；去重、迟到、显式水位、确定性排序释放 |
| `internal/detect` | 版本化规则集；滑动窗口累计阈值；抑制与合并；按事件时间选择规则版本；累计/抑制/FireID 全部租户隔离 |
| `internal/alert` | 告警状态机（幂等）；租户隔离与角色权限；不可变审计（含拒绝尝试）；回补更正（superseded 留痕 + 唯一可见结论） |
| `internal/engine` | 并发安全编排（单锁串行化），物化检测结论为告警，维护隔离区；受控回补（重放、比对、幂等台账） |
| `cmd/sedemo` | 端到端演示程序（含回补更正：正常查询 vs 留痕查询） |

## 快速开始

```bash
go test ./...              # 单元测试（乱序/迟到/重复/并发）
go test -race ./...        # 竞态检测
go run ./cmd/sedemo        # 演示：乱序+重复+并发+规则更新+权限+审计+隔离
```

最小用法：

```go
eng, rules, store := engine.New(engine.Config{
    AllowedLateness: 30 * time.Second,
    Parse:           event.ParseConfig{Now: clock}, // 固定时间基准，便于复现
})
rules.Put(detect.Rule{ID: "brute", TenantID: "t1", Version: 1,
    EventType: "login_fail", Window: time.Minute, Threshold: 3,
    SuppressFor: 5 * time.Minute, EffectiveAt: base})

// 任意顺序、任意并发地喂入三来源原始记录
r := eng.Ingest("t1", event.SourceJSON, `{"id":"e1",...}`)
// r.Disposition: accepted / duplicate / late / rejected（原因可区分）

eng.Advance(base.Add(2 * time.Minute)) // 显式断言水位，窗口定论、物化告警
eng.Quarantine()                        // rejected + late 记录，不静默丢弃
store.Ack(alertID, alert.Operator{ID:"ops", TenantID:"t1", Role:alert.RoleOperator}, "处理中")
store.List("t1")                        // 当前有效的最终结论（不含已被更正取代的旧告警）
store.ListHistory("t1")                 // 留痕视图：含 superseded 旧结论，可追溯
store.AuditLog(alertID, op)             // 完整状态变更轨迹

// 上游补齐迟到数据后，按租户 + 事件时间段发起受控回补（同一 RequestID 幂等）
res := eng.Backfill(engine.BackfillRequest{
    RequestID: "bf-20260924-01", TenantID: "t1",
    Operator: alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator},
    Start: base, End: base.Add(2 * time.Minute),
    Extra: nil, // 也可在请求里直接补投刚补发的原始记录
})
// res.Status: applied_changed / accepted_no_change / idempotent_replay / rejected
// 结论变化时：旧告警进入 superseded 终态（Get/ListHistory/AuditLog 可查，不可再处置），
// 更正告警成为该（规则,实体,时间窗）唯一可见的最终结论；结论不变零噪音。
```

## 核心保证（一句话版）

- **时间语义**：检测只用事件时间；迟到由显式水位判定，整批乱序喂入后统一推进水位，结论与到达顺序无关。
- **不丢弃**：解析失败（5 类原因）与迟到事件均带原因进入隔离区；重复事件单独判定且去重优先。
- **可复现**：窗口算法 consume-on-fire、规则按事件时间选版本、FireID 确定性生成。
- **抑制可追溯**：抑制期内重复命中合并为一条告警，告警记录合并的全部事件 ID。
- **规则热更新安全**：新版本只影响 `EffectiveAt` 之后的事件，历史结论不被静默改写；窗口不跨版本混算。
- **生命周期**：Ack/Close/Reopen 幂等；跨租户与越权被明确拒绝；所有变更与拒绝均有审计。
- **并发唯一**：单锁串行化 + 状态存储自带锁，`-race` 下并发写入终态唯一。
- **回补安全**：只对请求的租户与事件时间段重算，其它租户/窗口不受影响；同 `RequestID` 重复或并发重叠发起只生效一次；结论不变零噪音。
- **更正语义**：回补改变结论后，旧告警进入 `superseded` 终态留痕（仍可 `Get`/`ListHistory`，顺着 `SupersededBy` 找到 `Correction` 与补入事件），但不再出现在正常查询 `List` 中、也不可再处置；同一（租户,规则,实体,时间窗）任何时刻只有一条未被取代的有效结论，多次回补形成单链，绝不并列。
- **越界拒绝**：越权（非 operator/admin）、跨租户、时间范围非法/超过最大跨度（默认 24h）/越过已断言水位的回补一律拒绝并记审计，拒绝不改动任何既有结论。

## 本地复现与验证

```bash
go test ./...                                   # 全量单元测试
go test -race ./...                             # 竞态检测（回补/写入/查询并发交叉）
go test ./internal/engine/ -run TestBackfill -count=5   # 回补场景多轮稳定性
go run ./cmd/sedemo                             # 第 9 节演示回补更正的可见性与留痕
```

回补相关用例覆盖：改变结论后**可见结论唯一、旧结论可追溯**；乱序加跨来源重复投递；并发重叠回补及与在线写入/查询交叉；跨租户互不影响；结论不变零噪音；越权/跨租户/超范围拒绝且不影响其它窗口；链式二次更正只有最新一条有效。原有乱序、去重、迟到、抑制、规则更新、告警生命周期用例继续全部通过。

详细语义、状态机、边界约定与验证矩阵见 [`docs/DESIGN.md`](docs/DESIGN.md)。
