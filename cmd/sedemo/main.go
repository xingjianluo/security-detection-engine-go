// Command sedemo 用本地事件流演示安全事件检测与告警关联引擎：
// 同一批事件在乱序、重复投递与并发写入下得到一致、可解释的结论。
package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/backfill"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/engine"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

func main() {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	fmt.Println("================ 本地安全事件检测与告警关联引擎演示 ================")
	fmt.Println("时间基准 time_base =", base.Format(time.RFC3339), "(UTC, 事件时间语义)")
	fmt.Println("迟到容忍 allowed_lateness = 30s；滑动窗口=1m；阈值=3；抑制=5m")
	fmt.Println()

	eng, rs, store := engine.New(engine.Config{
		AllowedLateness: 30 * time.Second,
		Parse:           event.ParseConfig{Now: func() time.Time { return base }},
	})

	// 规则 v1（自事件时间 base-1h 生效），随后在 base+8m 更新为 v2（阈值 5）。
	must(rs.Put(detect.Rule{ID: "brute-force", TenantID: "tenant-a", Version: 1,
		EventType: "login_fail", Window: time.Minute, Threshold: 3,
		SuppressFor: 5 * time.Minute, EffectiveAt: base.Add(-time.Hour)}))
	must(rs.Put(detect.Rule{ID: "brute-force", TenantID: "tenant-a", Version: 2,
		EventType: "login_fail", Window: time.Minute, Threshold: 5,
		SuppressFor: 5 * time.Minute, EffectiveAt: base.Add(8 * time.Minute)}))

	jsonRec := func(id, who string, offset time.Duration) string {
		return fmt.Sprintf(`{"id":%q,"type":"login_fail","entity":%q,"ts":%q}`,
			id, who, base.Add(offset).Format(time.RFC3339Nano))
	}
	syslogRec := func(id, who string, offset time.Duration) string {
		return fmt.Sprintf("<%d>%s host sshd: id=%s type=login_fail entity=%s",
			134, base.Add(offset).Format(time.RFC3339Nano), id, who)
	}
	cefRec := func(id, who string, offset time.Duration) string {
		return fmt.Sprintf("CEF:0|Acme|SSHD|1.0|100|Login Failed|5|externalId=%s act=login_fail suser=%s rt=%s",
			id, who, base.Add(offset).Format(time.RFC3339Nano))
	}

	// 同一批事件：故意乱序喂入 + 重复投递 + 一条迟到 + 几条非法记录。
	batch := []struct {
		src event.Source
		raw string
		tag string
	}{
		{event.SourceJSON, jsonRec("e3", "alice", 20*time.Second), "json  e3 t+20s"},
		{event.SourceSyslog, syslogRec("e1", "alice", 0), "syslog e1 t+0s"},
		{event.SourceJSON, jsonRec("e2", "alice", 10*time.Second), "json  e2 t+10s"},
		{event.SourceCEF, cefRec("e6", "alice", 60*time.Second), "cef   e6 t+60s (抑制期内)"},
		{event.SourceJSON, jsonRec("e4", "alice", 40*time.Second), "json  e4 t+40s (抑制期内)"},
		{event.SourceJSON, jsonRec("e5", "alice", 50*time.Second), "json  e5 t+50s (抑制期内)"},
		{event.SourceJSON, jsonRec("b2", "bob", 15*time.Second), "json  b2 t+15s"},
		{event.SourceJSON, jsonRec("b1", "bob", 5*time.Second), "json  b1 t+5s"},
		{event.SourceCEF, cefRec("b3", "bob", 25*time.Second), "cef   b3 t+25s"},
		{event.SourceJSON, jsonRec("e1", "alice", 0), "json  e1 重投（重复）"},
		{event.SourceJSON, `{"id":"bad1","type":"login_fail","entity":"x","ts":"nope"}`, "非法：时间戳格式"},
		{event.SourceJSON, `{"id":"bad2","type":"login_fail"}`, "非法：缺 entity/ts"},
		{event.SourceSyslog, "this is not syslog", "非法：格式不合法"},
	}

	fmt.Println("---- 1) 乱序 + 重复 + 非法记录（此时尚未断言水位，无迟到） ----")
	for _, b := range batch {
		r := eng.Ingest("tenant-a", b.src, b.raw)
		fmt.Printf("  %-28s -> %-9s %s %s\n", b.tag, r.Disposition, r.Reason, r.Detail)
	}

	fmt.Println("\n---- 2) 断言水位 watermark = time_base + 2m，窗口定论 ----")
	fired := eng.Advance(base.Add(2 * time.Minute))
	for _, id := range fired {
		fmt.Println("  新发告警:", id)
	}

	fmt.Println("\n---- 3) 水位之后到达的事件：迟到隔离（不参与检测） ----")
	late := eng.Ingest("tenant-a", event.SourceJSON, jsonRec("L1", "alice", 30*time.Second))
	fmt.Printf("  late e t+30s -> %s (%s) %s\n", late.Disposition, late.Reason, late.Detail)

	fmt.Println("\n---- 4) 受控回补：上游补齐后，把迟到隔离的记录重新纳入并更正结论 ----")
	// 场景：dave 在 t+4m..4m20s 有 3 次失败，前两条先到，水位推进后第 3 条才补发 => 迟到隔离。
	eng.Ingest("tenant-a", event.SourceJSON, jsonRec("d1", "dave", 4*time.Minute))
	eng.Ingest("tenant-a", event.SourceJSON, jsonRec("d2", "dave", 4*time.Minute+10*time.Second))
	eng.Advance(base.Add(5 * time.Minute)) // 只有2条，未达阈值3 => 无结论
	lateD3 := eng.Ingest("tenant-a", event.SourceJSON, jsonRec("d3", "dave", 4*time.Minute+20*time.Second))
	fmt.Printf("  d3（t+4m20s）到达时水位已过 t+5m -> %s（隔离，不参与检测）\n", lateD3.Disposition)
	if dave := store.List("tenant-a"); len(dave) == 0 {
		fmt.Println("  回补前 dave 无任何可见结论")
	}

	bfOp := alert.Operator{ID: "ops-1", TenantID: "tenant-a", Role: alert.RoleOperator}
	bf := eng.Backfill(backfill.Request{
		RequestID: "bf-demo-1", TenantID: "tenant-a",
		From: base.Add(4 * time.Minute), To: base.Add(5 * time.Minute),
		Operator: bfOp, Reason: "upstream re-delivered d3 after recovery",
	})
	fmt.Printf("  回补结果: status=%s replayed=%v 补入事件=%v\n",
		bf.Status, bf.Replayed, bf.Backfilled)
	for _, c := range bf.Corrections {
		fmt.Printf("  更正 kind=%s rule=v%d window=%s..%s\n    原结论=%v 新结论=%s\n    补入=%v 全部合并=%v\n    依据=%s\n",
			c.Kind, c.RuleVersion, c.WindowFrom.Format(time.RFC3339Nano), c.WindowTo.Format(time.RFC3339Nano),
			c.OldAlertIDs, c.NewAlertID, c.AddedEventIDs, c.AllEventIDs, c.Note)
	}
	// 同一请求重复发起：幂等，不重复更正。
	bf2 := eng.Backfill(backfill.Request{
		RequestID: "bf-demo-1", TenantID: "tenant-a",
		From: base.Add(4 * time.Minute), To: base.Add(5 * time.Minute), Operator: bfOp,
	})
	fmt.Printf("  重复发起同一回补: status=%s replayed=%v 更正数=%d（不双算、不重复告警）\n",
		bf2.Status, bf2.Replayed, len(bf2.Corrections))
	// 拒绝示例：越过当前水位 / 跨租户。
	denied := eng.Backfill(backfill.Request{
		RequestID: "bf-demo-bad", TenantID: "tenant-a",
		From: base, To: base.Add(time.Hour), Operator: bfOp,
	})
	fmt.Printf("  越水位回补: status=%s err=%v\n", denied.Status, denied.Err)
	deniedT := eng.Backfill(backfill.Request{
		RequestID: "bf-demo-x", TenantID: "tenant-a",
		From: base.Add(4 * time.Minute), To: base.Add(5 * time.Minute),
		Operator: alert.Operator{ID: "ops-x", TenantID: "tenant-b", Role: alert.RoleAdmin},
	})
	fmt.Printf("  跨租户回补: status=%s err=%v\n", deniedT.Status, deniedT.Err)
	// 原结论保留可查（ListAll 含历史），可见结论唯一（List）。
	fmt.Println("  当前可见的 dave 结论（唯一）:")
	for _, a := range store.List("tenant-a") {
		if a.Entity == "dave" {
			fmt.Printf("    %s root=%s merged=%v\n", a.ID, a.RootID, a.EventIDs)
		}
	}

	fmt.Println("\n---- 5) 规则运行中更新：v2（阈值5）自事件时间 t+8m 生效，历史结论不被改写 ----")
	upd := []string{
		jsonRec("u1", "alice", 8*time.Minute),
		jsonRec("u2", "alice", 8*time.Minute+10*time.Second),
		jsonRec("u3", "alice", 8*time.Minute+20*time.Second),
		jsonRec("u4", "alice", 8*time.Minute+30*time.Second),
	}
	for _, r := range upd {
		eng.Ingest("tenant-a", event.SourceJSON, r)
	}
	// 先推进到 t+7m（只会定论 v1 窗口；v2 事件 t+8m 尚未到达，不受影响）。
	eng.Advance(base.Add(7 * time.Minute))
	fmt.Println("  v2 事件到来前推进水位到 t+7m，历史 v1 告警保持不变")

	fmt.Println("\n---- 6) 并发写入：2 个 goroutine 各写事件，结论唯一 ----")
	// 先并发写入 6 个 t+11m 的事件（在水位 t+7m 之后，不会被判迟到），
	// 再补齐 u1..u4 并统一断言水位到 t+12m；v2 阈值 5 => carol 产生 1 条新告警。
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 3; i++ {
				id := fmt.Sprintf("w%d-%d", worker, i)
				off := 11*time.Minute + time.Duration(worker*6+i*2)*time.Second
				eng.Ingest("tenant-a", event.SourceJSON, jsonRec(id, "carol", off))
			}
		}(w)
	}
	wg.Wait()
	fired = eng.Advance(base.Add(12 * time.Minute))
	fmt.Println("  并发写入 + v2 事件(alice 4次未达阈值5)后新发告警:", fired)

	fmt.Println("\n---- 7) 告警生命周期：确认/关闭/重开幂等，越权与跨租户被拒绝 ----")
	op := func(id, tenant string, role alert.Role) alert.Operator {
		return alert.Operator{ID: id, TenantID: tenant, Role: role}
	}
	if len(fired) > 0 {
		id := fired[0]
		show := func(action string, err error, a *alert.Alert) {
			if err != nil {
				fmt.Printf("  %-22s -> 拒绝: %v\n", action, err)
			} else {
				fmt.Printf("  %-22s -> 状态=%s\n", action, a.Status)
			}
		}
		a, e := store.Ack(id, op("ops-1", "tenant-a", alert.RoleOperator), "开始处置")
		show("Ack(operator)", e, a)
		a, e = store.Ack(id, op("ops-1", "tenant-a", alert.RoleOperator), "重复确认")
		show("Ack 重复(幂等)", e, a)
		_, e = store.Ack(id, op("viewer-1", "tenant-a", alert.RoleViewer), "")
		show("Ack(viewer 越权)", e, nil)
		_, e = store.Ack(id, op("ops-x", "tenant-b", alert.RoleAdmin), "")
		show("Ack(跨租户)", e, nil)
		a, e = store.Close(id, op("ops-1", "tenant-a", alert.RoleOperator), "处置完成")
		show("Close", e, a)
		_, e = store.Ack(id, op("ops-1", "tenant-a", alert.RoleOperator), "closed 上 Ack")
		show("Ack(closed 非法)", e, nil)
		a, e = store.Reopen(id, op("ops-1", "tenant-a", alert.RoleAdmin), "再次发生")
		show("Reopen(admin)", e, a)
		a, e = store.Reopen(id, op("ops-1", "tenant-a", alert.RoleAdmin), "重复重开")
		show("Reopen 重复(幂等)", e, a)
	}

	fmt.Println("\n---- 8) 最终告警与审计 ----")
	for _, a := range store.List("tenant-a") {
		fmt.Printf("  告警 %s\n    rule=v%d entity=%s status=%s created(event_time)=%s\n    合并事件=%v suppress_merged=%d\n",
			a.ID, a.RuleVersion, a.Entity, a.Status, a.CreatedAt.Format(time.RFC3339Nano),
			a.EventIDs, a.SuppressedCount)
	}
	if len(fired) > 0 {
		log, _ := store.AuditLog(fired[0], op("ops-1", "tenant-a", alert.RoleOperator))
		fmt.Println("  审计轨迹（", fired[0], "）:")
		for _, en := range log {
			fmt.Printf("    #%d %-14s %s: %s -> %s by %s (%s)\n",
				en.Seq, en.Action, en.At.Format("15:04:05"), en.FromState, en.ToState,
				en.OperatorID, en.Reason)
		}
	}
	fmt.Println("  被拒绝的越权/非法尝试:")
	for _, d := range store.DeniedAttempts() {
		fmt.Printf("    #%d %-5s action=%-6s by %s -> %s\n",
			d.Seq, d.TenantID, d.Action, d.OperatorID, d.Reason)
	}

	fmt.Println("\n---- 9) 隔离区（拒绝 + 迟到，均未静默丢弃） ----")
	for _, q := range eng.Quarantine() {
		fmt.Printf("  %-9s reason=%-20s %s\n", q.Disposition, q.Reason, q.Detail)
	}
	fmt.Println("\n演示结束。")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
