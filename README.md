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
  Correlator（规则版本化 · 滑动窗口阈值 · consume-on-fire · 抑制合并）
        │  Decision（新发告警 / 抑制命中，确定性 FireID，携带合并事件 ID）
        ▼
  alert.Store（幂等 Ack/Close/Reopen · 角色与租户隔离 · 全量审计链）
```

| 包 | 职责 |
| --- | --- |
| `internal/event` | 多来源解析与归一化；拒绝原因分类；去重、迟到、显式水位、确定性排序释放 |
| `internal/detect` | 版本化规则集；滑动窗口累计阈值；抑制与合并；按事件时间选择规则版本 |
| `internal/alert` | 告警状态机（幂等）；租户隔离与角色权限；不可变审计（含拒绝尝试） |
| `internal/engine` | 并发安全编排（单锁串行化），物化检测结论为告警，维护隔离区 |
| `cmd/sedemo` | 端到端演示程序 |

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
store.AuditLog(alertID, op)             // 完整状态变更轨迹
```

## 核心保证（一句话版）

- **时间语义**：检测只用事件时间；迟到由显式水位判定，整批乱序喂入后统一推进水位，结论与到达顺序无关。
- **不丢弃**：解析失败（5 类原因）与迟到事件均带原因进入隔离区；重复事件单独判定且去重优先。
- **可复现**：窗口算法 consume-on-fire、规则按事件时间选版本、FireID 确定性生成。
- **抑制可追溯**：抑制期内重复命中合并为一条告警，告警记录合并的全部事件 ID。
- **规则热更新安全**：新版本只影响 `EffectiveAt` 之后的事件，历史结论不被静默改写；窗口不跨版本混算。
- **生命周期**：Ack/Close/Reopen 幂等；跨租户与越权被明确拒绝；所有变更与拒绝均有审计。
- **受控回补**：按租户+事件时间段把迟到/补投记录重算进历史窗口。结论变了才产出**更正**：
  旧结论进入 `superseded` 终态并留痕（可经 `Get/ListHistory/GetCorrection` 追溯到
  更正记录与补入事件），正常查询同一租户/规则/实体/时间窗只看到**唯一当前结论**；
  同一窗口不可二次更正，重叠/重复回补幂等或明确拒绝，结论不变零噪音，跨租户互不影响。
- **并发唯一**：单锁串行化 + 状态存储自带锁，`-race` 下并发写入/并发回补终态唯一。

详细语义、状态机、回补边界与验证矩阵见 [`docs/DESIGN.md`](docs/DESIGN.md)。
