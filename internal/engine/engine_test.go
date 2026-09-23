package engine

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/audit"
	"github.com/xingjianluo/security-detection-engine-go/internal/clock"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
	"github.com/xingjianluo/security-detection-engine-go/internal/rule"
)

// 固定时间基准与语义参数（单测中打印）：
//
//	t0=2026-09-24T10:00:00Z
//	L（允许乱序宽限）=10s, R（迟到保留期）=30s, future tolerance=1s
//	规则 r1：类型 fail，阈值 3，窗口 10s，抑制间隔 8s
const (
	lateness  = 10 * time.Second
	retention = 30 * time.Second
)

var t0 = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

func newTestEngine(t *testing.T) (*Engine, *clock.FakeClock) {
	t.Helper()
	clk := clock.NewFakeClock(t0)
	e := New(Config{AllowedLateness: lateness, Retention: retention, FutureTolerance: time.Second}, clk)
	r := rule.Rule{
		ID: "r1", EventType: "fail", Threshold: 3,
		Window: 10 * time.Second, Suppression: 8 * time.Second,
	}
	if _, err := e.UpsertRule("t1", "admin", r, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.UpsertRule("t2", "admin", r, time.Time{}); err != nil {
		t.Fatal(err)
	}
	return e, clk
}

func jsonEvent(id string, sec int, typ string) string {
	return fmt.Sprintf(
		`{"id":%q,"tenant":"t1","entity":"host-1","type":%q,"severity":"high","ts":%q}`,
		id, typ, t0.Add(time.Duration(sec)*time.Second).Format(time.RFC3339))
}

func jsonEventTenant(tenant, id string, sec int, typ, entity string) string {
	return fmt.Sprintf(
		`{"id":%q,"tenant":%q,"entity":%q,"type":%q,"severity":"high","ts":%q}`,
		id, tenant, entity, typ, t0.Add(time.Duration(sec)*time.Second).Format(time.RFC3339))
}

// alertSummary 是与顺序无关的结论快照，用于跨顺序/跨并发复现比对。
type alertSummary struct {
	id           string
	tenant       string
	rule         string
	entity       string
	status       alert.Status
	merged       string // 排序后的事件集合
	suppressed   int
	firstEventAt time.Time
}

func snapshot(t *testing.T, e *Engine, tenant string) []alertSummary {
	t.Helper()
	as := e.ListAlerts(tenant)
	out := make([]alertSummary, 0, len(as))
	for _, a := range as {
		ids := append([]string(nil), a.MergedEventIDs...)
		sort.Strings(ids)
		out = append(out, alertSummary{
			id: a.ID, tenant: a.Tenant, rule: a.RuleID, entity: a.Entity,
			status: a.Status, merged: strings.Join(ids, ","), suppressed: a.SuppressedCount,
			firstEventAt: a.FirstEventAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].firstEventAt.Equal(out[j].firstEventAt) {
			return out[i].firstEventAt.Before(out[j].firstEventAt)
		}
		return out[i].id < out[j].id
	})
	return out
}

// runScenario 以给定物理到达顺序提交事件序列。每条事件投递前把处理时间(假时钟)
// 对齐到其事件时间——表示"事件在发生时被即时处理"，从而未来事件判定只针对真正异常记录。
// 最后 Drain，返回结论快照。
func runScenario(t *testing.T, e *Engine, clk *clock.FakeClock, label string, raws []string) []alertSummary {
	t.Helper()
	ids := make([]string, len(raws))
	for i, r := range raws {
		ids[i] = eventID(r)
	}
	t.Logf("[%s] 时间基准=%s L=%s R=%s；事件到达顺序=%v",
		label, t0.Format(time.RFC3339), lateness, retention, ids)
	for _, raw := range raws {
		if ts, ok := eventTS(raw); ok {
			clk.Set(ts)
		}
		res := e.Ingest(event.SourceJSON, raw)
		t.Logf("  %-3s @%s -> status=%-11s timing=%-7s dup=%-5v created=%v merged=%v %s",
			eventID(raw), clk.Now().Format("15:04:05"),
			res.Status, res.Timing, res.Duplicate,
			res.CreatedAlerts, res.MergedAlerts, res.Detail)
	}
	drain := e.Drain()
	for i, dr := range drain.Results {
		t.Logf("  drain[%d] -> created=%v merged=%v", i, dr.CreatedAlerts, dr.MergedAlerts)
	}
	return snapshot(t, e, "t1")
}

func eventID(raw string) string {
	// 仅用于日志展示，简单提取 "id":"..."。
	const key = `"id":"`
	i := strings.Index(raw, key)
	if i < 0 {
		return "?"
	}
	rest := raw[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return "?"
	}
	return rest[:j]
}

// eventTS 仅用于测试：提取测试 JSON 中的 RFC3339 "ts" 字段。
func eventTS(raw string) (time.Time, bool) {
	const key = `"ts":"`
	i := strings.Index(raw, key)
	if i < 0 {
		return time.Time{}, false
	}
	rest := raw[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339, rest[:j])
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// TestReproducibleAcrossArrivalOrders 是端到端核心：同一批事件三种到达顺序，
// 告警集合（ID、状态、合并事件集合、抑制计数、首次事件时间）必须逐项一致。
func TestReproducibleAcrossArrivalOrders(t *testing.T) {
	secs := []int{0, 4, 6, 12, 14}
	mk := func() []string {
		rs := make([]string, len(secs))
		for i, s := range secs {
			rs[i] = jsonEvent(fmt.Sprintf("e%d", i), s, "fail")
		}
		return rs
	}

	e1, clk1 := newTestEngine(t)
	asc := mk()
	gotAsc := runScenario(t, e1, clk1, "ascending", asc)

	e2, clk2 := newTestEngine(t)
	rev := mk()
	{
		out := make([]string, len(rev))
		for i := range rev {
			out[i] = rev[len(rev)-1-i]
		}
		rev = out
	}
	gotRev := runScenario(t, e2, clk2, "descending", rev)

	e3, clk3 := newTestEngine(t)
	base := mk()
	shuf := []string{base[3], base[0], base[4], base[1], base[2]}
	gotShuf := runScenario(t, e3, clk3, "shuffled", shuf)

	t.Logf("判定依据 ascending : %s", fmtSummaries(gotAsc))
	t.Logf("判定依据 descending: %s", fmtSummaries(gotRev))
	t.Logf("判定依据 shuffled  : %s", fmtSummaries(gotShuf))
	if !summariesEqual(gotAsc, gotRev) || !summariesEqual(gotAsc, gotShuf) {
		t.Fatalf("结论随到达顺序变化：\n asc=%+v\n rev=%+v\n shuf=%+v", gotAsc, gotRev, gotShuf)
	}
	if len(gotAsc) == 0 {
		t.Fatal("expected at least one alert")
	}
}

func fmtSummaries(xs []alertSummary) string {
	var b strings.Builder
	for i, x := range xs {
		if i > 0 {
			b.WriteString(" | ")
		}
		fmt.Fprintf(&b, "%s{%s merged=[%s] suppressed=%d}", x.id, x.status, x.merged, x.suppressed)
	}
	return b.String()
}

// 比较时忽略 ID 吗？不忽略——ID 由 (租户,规则,首触发事件) 确定性派生，顺序一致时必须相同。
func summariesEqual(a, b []alertSummary) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRejectionAndQuarantineReasons 验证坏记录不静默丢弃，且原因可区分。
func TestRejectionAndQuarantineReasons(t *testing.T) {
	e, clk := newTestEngine(t)
	cases := []struct {
		name    string
		source  event.Source
		raw     string
		status  event.Status
		reason  event.RejectReason
		quar    event.QuarantineReason
		advance time.Duration
	}{
		{"unknown source", event.Source("kafka"), "x", event.StatusRejected, event.RejectUnknownSource, "", 0},
		{"syntax invalid", event.SourceJSON, `{broken`, event.StatusRejected, event.RejectSyntax, "", 0},
		{"missing field", event.SourceJSON,
			`{"id":"x","tenant":"t1","type":"fail","ts":"2026-09-24T10:00:00Z"}`,
			event.StatusRejected, event.RejectMissingEntity, "", 0},
		{"bad timestamp", event.SourceSyslog, `id=x tenant=t1 entity=h type=fail ts=garbage`, event.StatusRejected, event.RejectBadTimestamp, "", 0},
		{"future timestamp", event.SourceJSON,
			jsonEvent("fut", 600, "fail"), event.StatusQuarantined, "", event.QuarantineFuture, 0},
		{"expired beyond retention", event.SourceJSON,
			"", event.StatusQuarantined, "", event.QuarantineExpired, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "expired beyond retention" {
				// 先把 t1 水位线推到很后，再投递远超保留期的旧事件。
				clk.Set(t0.Add(200 * time.Second))
				e.Ingest(event.SourceJSON, jsonEvent("far", 200, "other"))
				e.Drain()
				tc.raw = jsonEvent("old", 100, "fail") // watermark=190; 190-30=160 > 100 => expired
			}
			res := e.Ingest(tc.source, tc.raw)
			t.Logf("  %-28s -> status=%-11s reject=%-22q quarantine=%-18q detail=%s",
				tc.name, res.Status, res.RejectReason, res.Quarantine, res.Detail)
			if res.Status != tc.status {
				t.Fatalf("status=%s want %s", res.Status, tc.status)
			}
			if tc.reason != "" && res.RejectReason != tc.reason {
				t.Fatalf("reject reason=%q want %q", res.RejectReason, tc.reason)
			}
			if tc.quar != "" && res.Quarantine != tc.quar {
				t.Fatalf("quarantine=%q want %q", res.Quarantine, tc.quar)
			}
		})
	}

	// 每一条坏记录都必须可审计追溯（拒绝/隔离都算）。
	var rejected, quarantined int
	for _, r := range e.AuditTrail("") {
		switch r.Action {
		case audit.ActionEventRejected:
			rejected++
		case audit.ActionEventQuarantined:
			quarantined++
		}
	}
	if rejected < 4 || quarantined < 2 {
		t.Fatalf("bad records must be audited: rejected=%d quarantined=%d", rejected, quarantined)
	}
	t.Logf("判定依据：坏记录审计计数 rejected=%d quarantined=%d", rejected, quarantined)
}

// TestIngestBatchPreservesOrder 并发批处理结果必须与输入同序。
func TestIngestBatchPreservesOrder(t *testing.T) {
	e, clk := newTestEngine(t)
	clk.Set(t0.Add(30 * time.Second))
	raws := []string{
		jsonEvent("b0", 0, "fail"),
		`{bad`,
		jsonEvent("b1", 4, "fail"),
		jsonEvent("b0", 0, "fail"), // 重复
		jsonEvent("b2", 8, "fail"),
	}
	out := e.IngestBatch(event.SourceJSON, raws)
	if len(out.Results) != len(raws) {
		t.Fatalf("result count=%d want %d", len(out.Results), len(raws))
	}
	// 结果位置必须与输入同序：index 1 固定是语法错误记录（不依赖并发调度）。
	if out.Results[1].Status != event.StatusRejected ||
		out.Results[1].RejectReason != event.RejectSyntax {
		t.Fatalf("result slot 1 must be the syntax error, got %+v", out.Results[1])
	}
	// 同一事件 ID 的两份并发投递：恰好一份被判重复、一份被接受（唯一胜者）。
	var dupCount, acceptedCount int
	for _, r := range out.Results {
		if r.Duplicate {
			dupCount++
		}
		if r.Status == event.StatusAccepted {
			acceptedCount++
		}
	}
	// b0 两份 + b1 + b2 = 4 份 accepted 状态；其中重复恰 1 份。
	if acceptedCount != 4 || dupCount != 1 {
		t.Fatalf("accepted=%d dup=%d, want accepted=4 dup=1", acceptedCount, dupCount)
	}
	e.Drain()
	if len(e.ListAlerts("t1")) != 1 {
		t.Fatalf("one alert expected after dedup batch + drain")
	}
}

// TestDuplicateDeliveryEndToEnd 验证重复投递只产生一份结论。
func TestDuplicateDeliveryEndToEnd(t *testing.T) {
	e, clk := newTestEngine(t)
	raws := []string{
		jsonEvent("d0", 0, "fail"), jsonEvent("d0", 0, "fail"),
		jsonEvent("d1", 4, "fail"), jsonEvent("d2", 8, "fail"),
	}
	sums := runScenario(t, e, clk, "duplicate", raws)
	// 去重后仅 3 个不同事件，恰好一条告警。
	if len(sums) != 1 {
		t.Fatalf("want exactly 1 alert, got %d: %s", len(sums), fmtSummaries(sums))
	}
	if counts := strings.Count(sums[0].merged, "d0"); counts != 1 {
		t.Fatalf("d0 must appear once in merged set, got %q", sums[0].merged)
	}
}

// TestConcurrentWritesFinalStateUnique 多 goroutine 并发写入同一批事件，
// 重复 ID + 乱序并存；最终状态必须唯一，且与串行提交一致。
func TestConcurrentWritesFinalStateUnique(t *testing.T) {
	base := []string{
		jsonEvent("c0", 0, "fail"), jsonEvent("c1", 4, "fail"),
		jsonEvent("c2", 8, "fail"), jsonEvent("c0", 0, "fail"), // 重复
		jsonEvent("c3", 12, "fail"),
	}

	runConcurrent := func() []alertSummary {
		e, clk := newTestEngine(t)
		// 并发写入期间不在 goroutine 内推进时钟（那会产生数据竞争）；
		// 预置处理时间晚于全部事件，专注验证并发提交的最终状态唯一性。
		clk.Set(t0.Add(30 * time.Second))
		var wg sync.WaitGroup
		for _, raw := range base {
			wg.Add(1)
			go func(raw string) { defer wg.Done(); e.Ingest(event.SourceJSON, raw) }(raw)
		}
		wg.Wait()
		e.Drain()
		return snapshot(t, e, "t1")
	}

	got1 := runConcurrent()
	got2 := runConcurrent()
	t.Logf("判定依据 并发运行#1: %s", fmtSummaries(got1))
	t.Logf("判定依据 并发运行#2: %s", fmtSummaries(got2))
	if !summariesEqual(got1, got2) {
		t.Fatalf("concurrent runs disagree:\n %+v\n %+v", got1, got2)
	}

	// 串行基线。
	es, clkS := newTestEngine(t)
	var serial []string
	serial = append(serial, base...)
	want := runScenario(t, es, clkS, "serial-baseline", serial)
	if !summariesEqual(got1, want) {
		t.Fatalf("concurrent result differs from serial baseline:\n conc=%+v\n serial=%+v", got1, want)
	}
}

// TestAlertLifecycleAuditAndTenantIsolation 覆盖确认/关闭/重开幂等、CAS、
// 跨租户拒绝，以及全部变更与拒绝均有审计记录。
func TestAlertLifecycleAuditAndTenantIsolation(t *testing.T) {
	e, clk := newTestEngine(t)
	ingestAt := func(raw string) {
		if ts, ok := eventTS(raw); ok {
			clk.Set(ts)
		}
		e.Ingest(event.SourceJSON, raw)
	}
	ingestAt(jsonEvent("a0", 0, "fail"))
	ingestAt(jsonEvent("a1", 4, "fail"))
	e.Drain()
	// @4 只有 2 个事件，不足以触发；补第三个。
	ingestAt(jsonEvent("a2", 8, "fail"))
	e.Drain()

	alerts := e.ListAlerts("t1")
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert, got %d", len(alerts))
	}
	id := alerts[0].ID

	// 正常确认。
	tr, err := e.Acknowledge("t1", id, "alice", -1)
	if err != nil || tr.To != alert.StatusAcked || !tr.Changed {
		t.Fatalf("ack: %+v %v", tr, err)
	}
	verAck := tr.Version
	// 基于过期版本关闭 -> CAS 冲突。
	if _, err := e.Close("t1", id, "alice", verAck-1); !errorsIs(err, alert.ErrVersionConflict) {
		t.Fatalf("stale version close must conflict, got %v", err)
	}
	// 正确版本关闭。
	trc, err := e.Close("t1", id, "alice", verAck)
	if err != nil || trc.To != alert.StatusClosed {
		t.Fatalf("close: %+v %v", trc, err)
	}
	// 重复关闭幂等。
	if tr2, err := e.Close("t1", id, "alice", -1); err != nil || tr2.Changed {
		t.Fatalf("idempotent close: changed=%v err=%v", tr2.Changed, err)
	}
	// 重开。
	if tr3, err := e.Reopen("t1", id, "alice", -1); err != nil || !tr3.Changed || tr3.To != alert.StatusOpen {
		t.Fatalf("reopen: %+v %v", tr3, err)
	}

	// 跨租户读取/操作被拒绝。
	if _, err := e.GetAlert("t2", id); !errorsIs(err, alert.ErrCrossTenant) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := e.Close("t2", id, "mallory", -1); !errorsIs(err, alert.ErrCrossTenant) {
		t.Fatalf("cross-tenant close: %v", err)
	}
	// 越权不改变状态。
	cur, _ := e.GetAlert("t1", id)
	if cur.Status != alert.StatusOpen {
		t.Fatalf("cross-tenant attempt mutated state: %s", cur.Status)
	}

	// 审计覆盖：变更与拒绝都必须可追溯。
	recs := e.AuditTrail("t1")
	counts := map[audit.Action]int{}
	for _, r := range recs {
		counts[r.Action]++
	}
	t.Logf("判定依据：t1 审计动作计数 = %+v", counts)
	for _, act := range []audit.Action{
		audit.ActionAlertCreate, audit.ActionAlertAck, audit.ActionAlertClose,
		audit.ActionAlertReopen, audit.ActionAccessDenied,
	} {
		if counts[act] == 0 {
			t.Fatalf("audit trail missing action %s (all=%d)", act, len(recs))
		}
	}
	// 跨租户拒绝记录落在操作者所声明的租户下（t2），可独立追溯。
	if n := len(e.AuditTrail("t2")); n == 0 {
		t.Fatal("cross-tenant denial must be auditable under t2")
	}
}

// TestRuleUpdateFreezesAndReapplies 端到端验证规则运行中更新：
// 已进入事件绑定旧版本；更新后新事件按新版本评估；未完成窗口的语义确定。
func TestRuleUpdateFreezesAndReapplies(t *testing.T) {
	e, clk := newTestEngine(t)
	// v1: 阈值3。先只进入 2 个未完成窗口的事件（处理时间对齐各自事件时间）。
	ingestAt := func(raw string) {
		if ts, ok := eventTS(raw); ok {
			clk.Set(ts)
		}
		e.Ingest(event.SourceJSON, raw)
	}
	ingestAt(jsonEvent("u0", 0, "fail"))
	ingestAt(jsonEvent("u1", 4, "fail"))

	// 在处理时间 t0+5 更新为阈值 5、窗口 30s（v2，事件时间生效点 t0+5）。
	// 这里只验证"阈值/版本切分"语义，滑动窗口边界由检测器测试单独覆盖。
	clk.Set(t0.Add(5 * time.Second))
	if _, err := e.UpsertRule("t1", "admin", rule.Rule{
		ID: "r1", EventType: "fail", Threshold: 5,
		Window: 30 * time.Second, Suppression: 8 * time.Second,
	}, t0.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}

	// @6 的事件在 v2 发布后进入，绑定 v2（阈值5）；与旧 v1 的 u0/u1 不跨版本累计。
	ingestAt(jsonEvent("u2", 6, "fail"))
	ingestAt(jsonEvent("u3", 7, "fail"))
	e.Drain()
	if got := len(e.ListAlerts("t1")); got != 0 {
		t.Fatalf("unfinished windows across cutover must not silently merge versions, alerts=%d", got)
	}

	// 继续按 v2 累积到 5 个事件（u2,u3,u4,u5 + 1 个新事件）应触发一条 v2 告警。
	ingestAt(jsonEvent("u4", 8, "fail"))
	ingestAt(jsonEvent("u5", 9, "fail"))
	ingestAt(jsonEvent("u6", 10, "fail"))
	e.Drain()
	alerts := e.ListAlerts("t1")
	if len(alerts) != 1 || alerts[0].RuleVersion != 2 {
		t.Fatalf("want one v2 alert, got %+v", alerts)
	}
	t.Logf("判定依据：版本切分后触发告警 id=%s ruleVersion=v%d merged=%v",
		alerts[0].ID, alerts[0].RuleVersion, alerts[0].MergedEventIDs)

	// 规则更新本身被审计（仅统计 t1/r1：newTestEngine 同时为 t2 预置了同名规则）。
	var updates int
	for _, r := range e.AuditTrail("t1") {
		if r.Action == audit.ActionRuleUpdate && r.RuleID == "r1" && r.Version == 2 {
			updates++
		}
	}
	if updates != 1 {
		t.Fatalf("r1 v2 rule update audit count=%d, want 1", updates)
	}
}

func errorsIs(err, target error) bool {
	return err != nil && strings.Contains(err.Error(), target.Error())
}

// TestStressConcurrentMixedWriters 多写入者并发投递重复+乱序混合流，
// 重复运行多次，每次最终结论必须与单线程确定性重放一致。
func TestStressConcurrentMixedWriters(t *testing.T) {
	// 构造一组事件：20 个不同事件，其中 5 个再额外重复一次。
	var payloads []string
	for i := 0; i < 20; i++ {
		payloads = append(payloads, jsonEvent(fmt.Sprintf("s%02d", i), i, "fail"))
	}
	for i := 0; i < 5; i++ {
		payloads = append(payloads, jsonEvent(fmt.Sprintf("s%02d", i*3), i*3, "fail"))
	}

	// 参考基线：与并发运行采用相同的"提交边界"——全部去重后的事件先到齐
	// （处理时间预置在事件之后，期间不做 Pump），最后统一 Drain。
	//
	// 说明：检测 finding 集合本身与物理到达顺序无关（见
	// TestReproducibleAcrossArrivalOrders）；但抑制锚点是"最早的稳定阈值穿越时刻"，
	// 它取决于穿越何时在水位线下变稳定，因此构造可复现对照时必须固定提交边界。
	reference := func() []alertSummary {
		e, clk := newTestEngine(t)
		clk.Set(t0.Add(60 * time.Second))
		seen := map[string]bool{}
		var uniq []string
		for _, p := range payloads {
			id := eventID(p)
			if seen[id] {
				continue
			}
			seen[id] = true
			uniq = append(uniq, p)
		}
		for _, p := range uniq {
			r := e.Ingest(event.SourceJSON, p)
			if r.Quarantine != "" || r.RejectReason != "" {
				t.Fatalf("reference ingest rejected: %s %s", r.RejectReason, r.Quarantine)
			}
		}
		e.Drain()
		return snapshot(t, e, "t1")
	}()

	for iter := 0; iter < 5; iter++ {
		e, clk := newTestEngine(t)
		clk.Set(t0.Add(60 * time.Second)) // 预置处理时间，避免 goroutine 内推进时钟
		shuffled := append([]string(nil), payloads...)
		// 简单确定性洗牌（依赖迭代号，不引入随机不确定性）。
		for i := range shuffled {
			j := (i*7 + iter*13) % len(shuffled)
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}

		var wg sync.WaitGroup
		jobs := make(chan string)
		for w := 0; w < 6; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for raw := range jobs {
					e.Ingest(event.SourceJSON, raw)
				}
			}()
		}
		for _, p := range shuffled {
			jobs <- p
		}
		close(jobs)
		wg.Wait()
		e.Drain()

		got := snapshot(t, e, "t1")
		if !summariesEqual(got, reference) {
			t.Fatalf("stress iter %d disagrees with reference:\n got=%s\n ref=%s",
				iter, fmtSummaries(got), fmtSummaries(reference))
		}
		t.Logf("stress iter %d: 并发结论与单线程基线一致（告警数=%d）", iter, len(got))
	}
}
