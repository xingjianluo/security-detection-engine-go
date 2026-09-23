# 本地安全事件检测与告警关联引擎（Go）

用本地事件流模拟多来源安全日志，在**乱序到达、重复投递、并发写入**下产出
**一致且可解释**的检测结论；支持滑动窗口有状态关联、告警抑制与生命周期、
租户隔离、版本化规则热更新与全量审计。纯标准库实现，无外部依赖。

## 快速开始

```bash
go run ./cmd/demo        # 端到端演示（假时钟，输出确定、可重复复现）
go test ./...            # 全部单元/集成测试
go test -race ./...      # 带竞态检测
go test -v ./internal/engine   # 打印事件序列、时间基准、水位线与判定依据
```

## 能力一览

- **多来源解析与归一化**：syslog（`k=v`）、JSON、CEF；字段缺失/时间戳异常/
  格式不合法的记录**不静默丢弃**，按可区分原因拒绝（rejected）或隔离（quarantined）。
- **明确的事件时间语义**：基于水位线 `wm = maxObserved − L` 区分
  正常 / 迟到（宽限内仍计入）/ 超期（隔离）；事件时间与处理时间严格分离，处理时钟可注入。
- **有状态滑动窗口关联**：按 `(租户, 规则版本, 实体)` 累计阈值；短时间重复命中
  **抑制为一条告警**，并记录合并了哪些事件、抑制了几次。
- **规则热更新不改写历史**：规则为不可变版本；事件在到达时绑定当时已发布版本，
  已判定结果冻结，未完成窗口不跨版本静默合并。
- **告警生命周期与租户隔离**：Open/Acknowledged/Closed + Reopen，全部幂等；
  CAS 版本控制保证并发提交唯一胜者；跨租户/越权操作被拒绝并审计。
- **可追溯审计**：创建、合并、确认、关闭、重开、规则更新、越权拒绝全部留痕。
- **可复现测试**：乱序 / 迟到 / 重复 / 并发场景；告警 ID 由输入确定性派生；
  单测日志打印事件序列、时间基准与判定依据。

## 最小用法

```go
clk := clock.NewFakeClock(baseTime)
e := engine.New(engine.DefaultConfig(), clk)

e.UpsertRule("tenant-a", "secops", rule.Rule{
    ID: "brute-force", EventType: "ssh.auth_failed",
    Threshold: 3, Window: 90 * time.Second, Suppression: 60 * time.Second,
}, time.Time{}) // 首个版本零值生效点 = 自时间原点生效

for _, raw := range events {
    r := e.Ingest(event.SourceSyslog, raw) // 只计入窗口
    // r.Status / r.Timing / r.Duplicate / r.RejectReason / r.Quarantine
}
e.Advance() // 可选：让已稳定(越过乱序宽限)的窗口流式出警
e.Drain()   // 排空窗口，得到最终告警

alerts := e.ListAlerts("tenant-a")
tr, err := e.Acknowledge("tenant-a", alerts[0].ID, "alice", -1)
_ = e.AuditTrail("tenant-a")
```

## 文档

详细的事件时间模型、关联与抑制语义、规则更新语义、权限/锁规则与验证方法见
[`docs/DESIGN.md`](docs/DESIGN.md)。

## 代码结构

```
internal/clock    时间来源（系统/可注入假时钟）
internal/event    归一化模型、syslog/json/cef 解析器、拒绝与隔离原因
internal/rule     规则与不可变版本（按 租户+规则ID 组织、按事件时间选择版本）
internal/detect   水位线、滑动窗口阈值穿越、去重、迟到/超期、冻结光标
internal/alert    抑制合并、生命周期状态机、CAS、租户隔离、确定性告警 ID
internal/audit    只追加审计日志
internal/engine   顶层编排（并发安全）
cmd/demo          可运行演示
```
