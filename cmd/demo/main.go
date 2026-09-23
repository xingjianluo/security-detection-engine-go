// Command demo 用本地事件流演示乱序、重复、迟到与规则更新下的检测结论。
//
// 运行：go run ./cmd/demo
// 所有处理时间由内置假时钟驱动，因此输出完全确定、可重复运行复现。
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/clock"
	"github.com/xingjianluo/security-detection-engine-go/internal/engine"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
	"github.com/xingjianluo/security-detection-engine-go/internal/rule"
)

func main() {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFakeClock(base)
	e := engine.New(engine.Config{
		AllowedLateness: 10 * time.Second,
		Retention:       30 * time.Second,
		FutureTolerance: 2 * time.Second,
	}, clk)

	// 规则：90 秒内同实体 3 次登录失败即告警，60 秒内重复命中抑制为一条。
	_, _ = e.UpsertRule("tenant-a", "secops", rule.Rule{
		ID: "brute-force", EventType: "ssh.auth_failed",
		Threshold: 3, Window: 90 * time.Second, Suppression: 60 * time.Second,
	}, time.Time{})
	_, _ = e.UpsertRule("tenant-b", "secops", rule.Rule{
		ID: "brute-force", EventType: "ssh.auth_failed",
		Threshold: 3, Window: 90 * time.Second, Suppression: 60 * time.Second,
	}, time.Time{})

	fmt.Println("=== 本地安全事件检测引擎演示 ===")
	fmt.Printf("时间基准 t0=%s（假时钟，按事件时间推进）\n", base.Format(time.RFC3339))
	fmt.Println("语义参数: 乱序宽限 L=10s, 迟到保留期 R=30s, 未来容忍=2s")
	fmt.Println()

	// 同一批事件，故意乱序 + 重复投递。Ingest 只计入窗口；
	// 中途 Advance() 让已稳定（越过乱序宽限）的窗口流式出警。
	steps := []struct {
		sec     int
		id      string
		typ     string
		note    string
		advance bool
	}{
		{0, "evt-0", "ssh.auth_failed", "第1次失败", false},
		{40, "evt-2", "ssh.auth_failed", "乱序：先到 t40", false},
		{20, "evt-1", "ssh.auth_failed", "乱序：后到 t20（仍在宽限内）", false},
		{20, "evt-1", "ssh.auth_failed", "重复投递同一事件", false},
		{55, "evt-3", "ssh.auth_failed", "到达后推进水位线", true},
		{120, "evt-4", "ssh.auth_failed", "超出抑制窗口 -> 另起一条", false},
	}
	for _, st := range steps {
		clk.Set(base.Add(time.Duration(st.sec) * time.Second))
		raw := syslog(st.id, "tenant-a", "host-web-01", st.typ, base.Add(time.Duration(st.sec)*time.Second))
		r := e.Ingest(event.SourceSyslog, raw)
		fmt.Printf("[%s] %-6s %-30s -> status=%-11s timing=%-7s duplicate=%-5v\n",
			clk.Now().Format("15:04:05"), st.id, st.note,
			r.Status, orDash(string(r.Timing)), r.Duplicate)
		if r.Detail != "" {
			fmt.Printf("            └ %s\n", r.Detail)
		}
		if st.advance {
			adv := e.Advance()
			for _, a := range adv.Results {
				fmt.Printf("            >> Advance 稳定出警: created=%v merged=%v\n",
					shortIDs(a.CreatedAlerts), shortIDs(a.MergedAlerts))
			}
		}
	}

	fmt.Println("\n--- 坏记录不静默丢弃（按原因拒绝/隔离） ---")
	bad := []struct {
		src event.Source
		raw string
	}{
		{event.SourceJSON, `{not json`},
		{event.SourceJSON, `{"id":"x","tenant":"tenant-a","entity":"h","type":"ssh.auth_failed"}`}, // 缺 ts
		{event.SourceSyslog, `id=x tenant=tenant-a entity=h type=ssh.auth_failed ts=not-a-time`},
	}
	for _, b := range bad {
		r := e.Ingest(b.src, b.raw)
		fmt.Printf("  %-9s %-55s -> %s / %s\n", b.src, truncate(b.raw, 55), r.Status, r.RejectReason)
	}

	fmt.Println("\n--- 排空窗口，落地最终结论 ---")
	drain := e.Drain()
	for _, d := range drain.Results {
		if len(d.CreatedAlerts)+len(d.MergedAlerts) > 0 {
			fmt.Printf("  drain: created=%v merged=%v\n", shortIDs(d.CreatedAlerts), shortIDs(d.MergedAlerts))
		}
	}

	fmt.Println("\n=== 最终告警（tenant-a）===")
	for _, a := range e.ListAlerts("tenant-a") {
		fmt.Printf("  %s 状态=%-6s 实体=%-11s v%d 首次=%s 抑制合并命中=%d\n",
			a.ID, a.Status, a.Entity, a.RuleVersion, a.FirstEventAt.Format("15:04:05"), a.SuppressedCount)
		fmt.Printf("      归并事件轨迹=%v\n", a.MergedEventIDs)
	}

	fmt.Println("\n=== 告警生命周期：确认 -> 关闭 -> 重复关闭(幂等) ===")
	if as := e.ListAlerts("tenant-a"); len(as) > 0 {
		id := as[0].ID
		t1, _ := e.Acknowledge("tenant-a", id, "alice", -1)
		t2, _ := e.Close("tenant-a", id, "alice", -1)
		t3, _ := e.Close("tenant-a", id, "alice", -1)
		fmt.Printf("  ack changed=%-5v | close changed=%-5v | close again changed=%v(幂等)\n",
			t1.Changed, t2.Changed, t3.Changed)
		_, err := e.Close("tenant-b", id, "mallory", -1)
		fmt.Printf("  跨租户关闭尝试: %v（已拒绝并审计）\n", err)
	}

	fmt.Println("\n=== 审计轨迹（按时间顺序，节选）===")
	for _, r := range e.AuditTrail("tenant-a") {
		fmt.Printf("  #%02d %s %-17s %-13s %s -> %s %s\n",
			r.Seq, r.Time.Format("15:04:05"), r.Action, r.Operator,
			shortID(r.AlertID), r.To, dashIfEmpty(r.Detail))
	}
	for _, r := range e.AuditTrail("tenant-b") {
		fmt.Printf("  #%02d %s %-17s tenant-b: %s\n", r.Seq, r.Time.Format("15:04:05"), r.Action, r.Detail)
	}
}

func syslog(id, tenant, entity, typ string, ts time.Time) string {
	return fmt.Sprintf("id=%s tenant=%s entity=%s type=%s severity=high ts=%d",
		id, tenant, entity, typ, ts.Unix())
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func shortID(id string) string {
	if id == "" {
		return "-"
	}
	if len(id) > 14 {
		return id[5:14] // 去掉 "alrt-" 后取 9 位
	}
	return id
}

func shortIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, shortID(id))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func dashIfEmpty(s string) string {
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}
