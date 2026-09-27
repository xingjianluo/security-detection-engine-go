package engine

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/backfill"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

func bfOp(tenant string, role alert.Role) alert.Operator {
	return alert.Operator{ID: "ops-1", TenantID: tenant, Role: role}
}

func recAt(id, entity string, t time.Time) rawRec {
	return jsonRec(id, entity, "login_fail", t)
}

func setupBackfillEngine(t *testing.T, maxAge time.Duration) (*Engine, *detect.RuleSet, *alert.Store) {
	t.Helper()
	eng, rs, store := New(Config{
		AllowedLateness: 30 * time.Second,
		Parse:           event.ParseConfig{Now: func() time.Time { return tBase }},
		MaxBackfillAge:  maxAge,
	})
	if err := rs.Put(detect.Rule{ID: "brute", TenantID: "t1", Version: 1,
		EventType: "login_fail", Window: time.Minute, Threshold: 3,
		SuppressFor: 5 * time.Minute, EffectiveAt: tBase.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := rs.Put(detect.Rule{ID: "brute", TenantID: "t2", Version: 1,
		EventType: "login_fail", Window: time.Minute, Threshold: 3,
		SuppressFor: 5 * time.Minute, EffectiveAt: tBase.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return eng, rs, store
}

// 端到端：2 个事件先到 -> 水位定论（无告警）；第 3 个迟到隔离；
// 回补把第 3 个事件补入 -> 新增更正告警，原"无结论"变为有结论，可见结论唯一。
func TestBackfillLateEventCreatesCorrection(t *testing.T) {
	eng, _, store := setupBackfillEngine(t, 24*time.Hour)

	eng.Ingest("t1", event.SourceJSON, recAt("e1", "alice", tBase).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("e2", "alice", tBase.Add(10*time.Second)).raw)
	fired := eng.Advance(tBase.Add(2 * time.Minute))
	if len(fired) != 0 {
		t.Fatalf("threshold 3 with 2 events must not fire, got %v", fired)
	}
	// 第 3 个事件在水位之后到达 -> 迟到隔离。
	late := eng.Ingest("t1", event.SourceJSON, recAt("e3", "alice", tBase.Add(20*time.Second)).raw)
	if late.Disposition != event.DispLate {
		t.Fatalf("want late, got %s", late.Disposition)
	}
	if len(store.List("t1")) != 0 {
		t.Fatalf("no visible alert expected before backfill")
	}

	res := eng.Backfill(backfill.Request{
		RequestID: "bf-1", TenantID: "t1",
		From: tBase, To: tBase.Add(2 * time.Minute),
		Operator: bfOp("t1", alert.RoleOperator), Reason: "upstream re-delivered",
	})
	if res.Status != backfill.StatusAcceptedChanged {
		t.Fatalf("want accepted_changed, got %s err=%v", res.Status, res.Err)
	}
	if fmt.Sprint(res.Backfilled) != "[e3]" {
		t.Fatalf("backfilled events = %v, want [e3]", res.Backfilled)
	}
	if len(res.Corrections) != 1 || res.Corrections[0].Kind != backfill.ChangeAdded {
		t.Fatalf("want 1 added correction, got %+v", res.Corrections)
	}
	corr := res.Corrections[0]
	if fmt.Sprint(corr.AllEventIDs) != "[e1 e2 e3]" || fmt.Sprint(corr.AddedEventIDs) != "[e3]" {
		t.Fatalf("correction events wrong: all=%v added=%v", corr.AllEventIDs, corr.AddedEventIDs)
	}
	t.Logf("更正: kind=%s new=%s window=%s..%s all=%v added=%v",
		corr.Kind, corr.NewAlertID, corr.WindowFrom, corr.WindowTo, corr.AllEventIDs, corr.AddedEventIDs)

	// 可见结论唯一：List 只看到 1 条更正告警。
	vis := store.List("t1")
	if len(vis) != 1 || vis[0].ID != corr.NewAlertID {
		t.Fatalf("visible alerts = %+v, want only %s", vis, corr.NewAlertID)
	}
	// 历史视图为空（added 情形没有原结论）；隔离记录带可追溯标记。
	if len(store.ListAll("t1")) != 1 {
		t.Fatal("added correction should leave exactly 1 stored alert")
	}
	q := eng.Quarantine()
	if len(q) != 1 || q[0].BackfilledBy != "bf-1" {
		t.Fatalf("late record must be marked backfilled by bf-1, got %+v", q)
	}
	// 在线关联器/水位未被回补污染：后续新事件正常检测。
	eng.Ingest("t1", event.SourceJSON, recAt("n1", "carol", tBase.Add(3*time.Minute)).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("n2", "carol", tBase.Add(3*time.Minute+10*time.Second)).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("n3", "carol", tBase.Add(3*time.Minute+20*time.Second)).raw)
	eng.Advance(tBase.Add(4 * time.Minute))
	carol := store.List("t1")
	var carolAlert *alert.Alert
	for _, a := range carol {
		if a.Entity == "carol" {
			carolAlert = a
		}
	}
	if carolAlert == nil || len(carolAlert.EventIDs) != 3 {
		t.Fatalf("online detection after backfill must still work: %+v", carol)
	}
}

// 原结论已存在；迟到事件补入后窗口/合并事件改变 => 原告警保留可查但被替代，
// 可见结论唯一，新结论沿同一更正链（RootID）可追溯到原结论。
func TestBackfillRevisesExistingAlert(t *testing.T) {
	eng, _, store := setupBackfillEngine(t, 24*time.Hour)
	eng.Ingest("t1", event.SourceJSON, recAt("e1", "alice", tBase).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("e2", "alice", tBase.Add(10*time.Second)).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("e3", "alice", tBase.Add(20*time.Second)).raw)
	fired := eng.Advance(tBase.Add(2 * time.Minute))
	if len(fired) != 1 {
		t.Fatalf("baseline must fire 1 alert, got %v", fired)
	}
	origID := fired[0]

	// 迟到的 e2b（t+15s）本应让阈值在 t+15s 就穿越，改变首发窗口。
	late := eng.Ingest("t1", event.SourceJSON, recAt("e2b", "alice", tBase.Add(15*time.Second)).raw)
	if late.Disposition != event.DispLate {
		t.Fatalf("want late, got %s", late.Disposition)
	}

	res := eng.Backfill(backfill.Request{
		RequestID: "bf-rev", TenantID: "t1",
		From: tBase, To: tBase.Add(2 * time.Minute),
		Operator: bfOp("t1", alert.RoleAdmin), Reason: "gap filled",
	})
	if res.Status != backfill.StatusAcceptedChanged {
		t.Fatalf("want changed, got %s err=%v", res.Status, res.Err)
	}
	if len(res.Corrections) != 1 || res.Corrections[0].Kind != backfill.ChangeRevised {
		t.Fatalf("want 1 revised correction, got %+v", res.Corrections)
	}
	c := res.Corrections[0]
	if fmt.Sprint(c.OldAlertIDs) != "["+origID+"]" {
		t.Fatalf("revised must point to original %s, got %v", origID, c.OldAlertIDs)
	}
	if fmt.Sprint(c.AddedEventIDs) != "[e2b]" || fmt.Sprint(c.AllEventIDs) != "[e1 e2 e2b]" {
		t.Fatalf("revised events wrong: added=%v all=%v", c.AddedEventIDs, c.AllEventIDs)
	}

	// 可见结论唯一：只有更正告警；原告警被标记 superseded 但仍可查。
	vis := store.List("t1")
	if len(vis) != 1 || vis[0].ID != c.NewAlertID {
		t.Fatalf("visible = %+v, want only %s", vis, c.NewAlertID)
	}
	all := store.ListAll("t1")
	if len(all) != 2 {
		t.Fatalf("history must keep original + correction, got %d", len(all))
	}
	var old *alert.Alert
	for _, a := range all {
		if a.ID == origID {
			old = a
		}
	}
	if old == nil || old.Status != alert.StatusSuperseded || old.SupersededBy != c.NewAlertID {
		t.Fatalf("original must be superseded by correction: %+v", old)
	}
	if vis[0].RootID != old.RootID {
		t.Fatalf("correction must share RootID with original: %s vs %s", vis[0].RootID, old.RootID)
	}
	// 原告警的审计里可查到被谁、因哪次回补替代。
	log, _ := store.AuditLog(origID, bfOp("t1", alert.RoleOperator))
	var hasSupersede bool
	for _, en := range log {
		if en.Action == "supersede" && en.Reason != "" {
			hasSupersede = true
			t.Logf("原结论审计: %s -> %s (%s)", en.Action, en.ToState, en.Reason)
		}
	}
	if !hasSupersede {
		t.Fatal("original alert must carry a supersede audit entry")
	}
	// 已被替代的原结论不再接受生命周期变更；对更正告警操作正常。
	if _, err := store.Ack(origID, bfOp("t1", alert.RoleOperator), ""); err == nil {
		t.Fatal("ack on superseded alert must be rejected")
	}
	if a, err := store.Ack(c.NewAlertID, bfOp("t1", alert.RoleOperator), "handling correction"); err != nil || a.Status != alert.StatusAcked {
		t.Fatalf("ack correction alert: %+v %v", a, err)
	}
}

// 回补候选没有新事件（结论不变）：accepted_unchanged，不产生告警/审计噪音；
// 同一 RequestID 重复发起返回幂等缓存（Replayed），不双算、不重复产出。
func TestBackfillUnchangedAndIdempotent(t *testing.T) {
	eng, _, store := setupBackfillEngine(t, 24*time.Hour)
	eng.Ingest("t1", event.SourceJSON, recAt("e1", "alice", tBase).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("e2", "alice", tBase.Add(10*time.Second)).raw)
	eng.Advance(tBase.Add(2 * time.Minute)) // 只有2个事件，无告警
	// 一条迟到但与检测无关的事件（别的实体/类型不匹配规则 -> 实际仍会被收集，
	// 但不产生结论）。这里用"没有任何迟到记录"的空回补验证不变语义。
	trailBefore := len(store.AuditTrail())

	res := eng.Backfill(backfill.Request{
		RequestID: "bf-empty", TenantID: "t1",
		From: tBase, To: tBase.Add(2 * time.Minute),
		Operator: bfOp("t1", alert.RoleOperator), Reason: "nothing missing",
	})
	if res.Status != backfill.StatusAcceptedUnchanged {
		t.Fatalf("want unchanged, got %s err=%v", res.Status, res.Err)
	}
	if len(res.Corrections) != 0 || len(res.Backfilled) != 0 {
		t.Fatalf("unchanged backfill must have no corrections/backfilled: %+v", res)
	}
	if len(store.List("t1")) != 0 {
		t.Fatal("unchanged backfill must not create alerts")
	}
	if len(store.AuditTrail()) != trailBefore {
		t.Fatal("unchanged backfill must not add audit noise")
	}

	// 同 RequestID 再发起一次：命中缓存、Replayed=true、仍无变化。
	res2 := eng.Backfill(backfill.Request{
		RequestID: "bf-empty", TenantID: "t1",
		From: tBase, To: tBase.Add(2 * time.Minute),
		Operator: bfOp("t1", alert.RoleOperator),
	})
	if !res2.Replayed || res2.Status != backfill.StatusAcceptedUnchanged {
		t.Fatalf("repeated request must be replayed unchanged, got %+v", res2)
	}
	if len(store.AuditTrail()) != trailBefore {
		t.Fatal("idempotent replay must not add audit noise")
	}
	t.Log("结论不变：accepted_unchanged，无告警/审计噪音；重复请求幂等返回")
}

// 重叠回补（不同 RequestID，范围重叠）：第一次产生更正后，第二次重算基线已含
// 补入事件，结论一致 => unchanged，不重复更正、不重复产出告警。
func TestBackfillOverlappingNoDoubleCount(t *testing.T) {
	eng, _, store := setupBackfillEngine(t, 24*time.Hour)
	eng.Ingest("t1", event.SourceJSON, recAt("e1", "alice", tBase).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("e2", "alice", tBase.Add(10*time.Second)).raw)
	eng.Advance(tBase.Add(2 * time.Minute))
	eng.Ingest("t1", event.SourceJSON, recAt("e3", "alice", tBase.Add(20*time.Second)).raw) // 迟到

	r1 := eng.Backfill(backfill.Request{
		RequestID: "bf-a", TenantID: "t1",
		From: tBase, To: tBase.Add(time.Minute),
		Operator: bfOp("t1", alert.RoleOperator),
	})
	if r1.Status != backfill.StatusAcceptedChanged || len(r1.Corrections) != 1 {
		t.Fatalf("first overlapping backfill should change: %+v", r1)
	}
	firstNew := r1.Corrections[0].NewAlertID

	// 不同 RequestID 但覆盖重叠范围（更宽）：候选已被回补（BackfilledBy=bf-a），
	// 且事件已在日志中，重算结果一致 => unchanged。
	r2 := eng.Backfill(backfill.Request{
		RequestID: "bf-b", TenantID: "t1",
		From: tBase.Add(-time.Minute), To: tBase.Add(2 * time.Minute),
		Operator: bfOp("t1", alert.RoleOperator),
	})
	if r2.Status != backfill.StatusAcceptedUnchanged {
		t.Fatalf("overlapping backfill must be unchanged, got %s (%+v)", r2.Status, r2.Corrections)
	}
	if len(r2.Backfilled) != 0 {
		t.Fatalf("overlapping backfill must not re-admit events, got %v", r2.Backfilled)
	}
	vis := store.List("t1")
	if len(vis) != 1 || vis[0].ID != firstNew {
		t.Fatalf("overlapping backfills must leave exactly one correction, got %+v", vis)
	}
	// 被跳过的重复候选应可交代。
	t.Logf("重叠回补：skipped_dup=%v, 可见结论仍唯一=%s", r2.SkippedDup, vis[0].ID)
}

// 拒绝情形必须可区分：跨租户、越权、越过水位、超出可回补年限、非法区间。
func TestBackfillRejectionCauses(t *testing.T) {
	eng, _, _ := setupBackfillEngine(t, time.Hour)
	eng.Ingest("t1", event.SourceJSON, recAt("e1", "alice", tBase).raw)
	eng.Advance(tBase.Add(2 * time.Minute))

	cases := []struct {
		name string
		req  backfill.Request
		want error
	}{
		{"cross_tenant", backfill.Request{RequestID: "x1", TenantID: "t1",
			From: tBase, To: tBase.Add(time.Minute),
			Operator: bfOp("t2", alert.RoleAdmin)}, backfill.ErrCrossTenant},
		{"viewer_forbidden", backfill.Request{RequestID: "x2", TenantID: "t1",
			From: tBase, To: tBase.Add(time.Minute),
			Operator: alert.Operator{ID: "v", TenantID: "t1", Role: alert.RoleViewer}},
			backfill.ErrPermissionDenied},
		{"beyond_watermark", backfill.Request{RequestID: "x3", TenantID: "t1",
			From: tBase, To: tBase.Add(10 * time.Minute),
			Operator: bfOp("t1", alert.RoleOperator)}, backfill.ErrRangeNotFinalized},
		{"beyond_horizon", backfill.Request{RequestID: "x4", TenantID: "t1",
			From: tBase.Add(-2 * time.Hour), To: tBase.Add(2 * time.Minute),
			Operator: bfOp("t1", alert.RoleOperator)}, backfill.ErrBeyondHorizon},
		{"invalid_range", backfill.Request{RequestID: "x5", TenantID: "t1",
			From: tBase.Add(time.Minute), To: tBase,
			Operator: bfOp("t1", alert.RoleOperator)}, backfill.ErrInvalidRange},
	}
	for _, c := range cases {
		res := eng.Backfill(c.req)
		if res.Status != backfill.StatusRejected {
			t.Fatalf("%s: want rejected, got %s", c.name, res.Status)
		}
		if !errors.Is(res.Err, c.want) {
			t.Fatalf("%s: err=%v want %v", c.name, res.Err, c.want)
		}
		t.Logf("[%s] rejected: %v", c.name, res.Err)
	}
	// 拒绝也按 RequestID 幂等登记：再次提交得到同一拒绝结论。
	again := eng.Backfill(cases[0].req)
	if again.Status != backfill.StatusRejected || !again.Replayed {
		t.Fatalf("rejected request replay must be replayed rejected, got %+v", again)
	}
}

// 跨租户互不影响：只回补 t1，t2 的计数/抑制/结论与隔离记录完全不被触碰。
func TestBackfillCrossTenantIsolation(t *testing.T) {
	eng, _, store := setupBackfillEngine(t, 24*time.Hour)

	// t1：2 个事件 + 1 个迟到（回补后应触发）。
	eng.Ingest("t1", event.SourceJSON, recAt("a1", "alice", tBase).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("a2", "alice", tBase.Add(10*time.Second)).raw)
	// t2：完整 3 个事件，独立触发一条告警。
	eng.Ingest("t2", event.SourceJSON, recAt("b1", "bob", tBase).raw)
	eng.Ingest("t2", event.SourceJSON, recAt("b2", "bob", tBase.Add(10*time.Second)).raw)
	eng.Ingest("t2", event.SourceJSON, recAt("b3", "bob", tBase.Add(20*time.Second)).raw)
	eng.Advance(tBase.Add(2 * time.Minute))
	// t1 的迟到事件；再给 t2 一条迟到（回补 t1 时绝不能动它）。
	eng.Ingest("t1", event.SourceJSON, recAt("a3", "alice", tBase.Add(20*time.Second)).raw)
	eng.Ingest("t2", event.SourceJSON, recAt("b4", "bob", tBase.Add(30*time.Second)).raw)

	t2Before := store.List("t2")
	if len(t2Before) != 1 || fmt.Sprint(t2Before[0].EventIDs) != "[b1 b2 b3]" {
		t.Fatalf("t2 baseline alert wrong: %+v", t2Before)
	}

	res := eng.Backfill(backfill.Request{
		RequestID: "bf-t1", TenantID: "t1",
		From: tBase, To: tBase.Add(2 * time.Minute),
		Operator: bfOp("t1", alert.RoleOperator),
	})
	if res.Status != backfill.StatusAcceptedChanged {
		t.Fatalf("t1 backfill should change, got %s", res.Status)
	}
	if fmt.Sprint(res.Backfilled) != "[a3]" {
		t.Fatalf("only t1's a3 must be backfilled, got %v", res.Backfilled)
	}

	// t2 可见结论与合并事件原封不动。
	t2After := store.List("t2")
	if len(t2After) != 1 || t2After[0].ID != t2Before[0].ID ||
		fmt.Sprint(t2After[0].EventIDs) != "[b1 b2 b3]" {
		t.Fatalf("t2 must be untouched by t1 backfill: %+v", t2After)
	}
	// t2 的迟到隔离记录不应被标记为已回补。
	var b4Open bool
	for _, q := range eng.Quarantine() {
		if q.EventID == "b4" && q.BackfilledBy == "" {
			b4Open = true
		}
	}
	if !b4Open {
		t.Fatal("t2 late record b4 must remain un-backfilled")
	}
	// t1 看到自己的更正；t2 看不到 t1 的任何东西。
	t1Vis := store.List("t1")
	if len(t1Vis) != 1 || t1Vis[0].TenantID != "t1" {
		t.Fatalf("t1 visible correction wrong: %+v", t1Vis)
	}
	if len(store.ListAll("t2")) != 1 {
		t.Fatal("t2 must still have exactly its single alert in history")
	}
	t.Logf("租户隔离：t1 更正=%v；t2 保持 %s merged=%v 不变",
		t1Vis[0].ID, t2After[0].ID, t2After[0].EventIDs)
}

// 并发回补 + 并发在线写入交错：最终结论唯一、可复现，无数据竞争（-race）。
func TestBackfillConcurrent(t *testing.T) {
	mk := func(parallel int) []string {
		eng, _, store := setupBackfillEngine(t, 24*time.Hour)
		// 基线：t1 alice 2 事件；多个迟到事件 a3..a8 被隔离。
		eng.Ingest("t1", event.SourceJSON, recAt("a1", "alice", tBase).raw)
		eng.Ingest("t1", event.SourceJSON, recAt("a2", "alice", tBase.Add(10*time.Second)).raw)
		eng.Advance(tBase.Add(2 * time.Minute))
		for i := 0; i < 6; i++ {
			id := fmt.Sprintf("a%d", i+3)
			off := time.Duration(15+i*5) * time.Second
			eng.Ingest("t1", event.SourceJSON, recAt(id, "alice", tBase.Add(off)).raw)
		}

		var wg sync.WaitGroup
		// 多个运维并发发起【同一 RequestID】的回补：幂等保证只执行一次，终态确定。
		for w := 0; w < parallel; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				eng.Backfill(backfill.Request{
					RequestID: "bf-same", TenantID: "t1",
					From: tBase, To: tBase.Add(2 * time.Minute),
					Operator: bfOp("t1", alert.RoleOperator),
				})
			}()
		}
		// 同时有新事件在 t+10m.. 正常写入（水位之后，不迟到）。
		for w := 0; w < parallel; w++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				for i := 0; i < 3; i++ {
					id := fmt.Sprintf("live-%d-%d", n, i)
					off := 10*time.Minute + time.Duration(n*3+i)*time.Second
					eng.Ingest("t1", event.SourceJSON, recAt(id, "carol", tBase.Add(off)).raw)
				}
			}(w)
		}
		wg.Wait()
		eng.Advance(tBase.Add(12 * time.Minute))

		var ids []string
		for _, a := range store.List("t1") {
			ids = append(ids, a.ID)
		}
		return ids
	}

	seq := mk(1)
	par := mk(6)
	t.Logf("串行最终可见告警=%v", seq)
	t.Logf("并发最终可见告警=%v", par)
	if fmt.Sprint(seq) != fmt.Sprint(par) {
		t.Fatalf("concurrent backfill final state not reproducible:\n%v\n%v", seq, par)
	}
	// alice 时间窗上只能有一条当前生效结论（多个重叠回补不得产生多条矛盾告警）。
	var aliceCur int
	for _, id := range par {
		if strings.Contains(id, "brute|alice") || strings.Contains(id, "brute:alice") {
			aliceCur++
		}
	}
	if aliceCur != 1 {
		t.Fatalf("exactly one current alice conclusion required, got %d (%v)", aliceCur, par)
	}
}

// 回补的历史记录必须按其自身事件时间匹配当时生效的规则版本，
// 即使规则在"现在"已改为 v2。
func TestBackfillUsesRuleVersionAtEventTime(t *testing.T) {
	eng, rs, store := New(Config{
		AllowedLateness: 30 * time.Second,
		Parse:           event.ParseConfig{Now: func() time.Time { return tBase }},
		MaxBackfillAge:  24 * time.Hour,
	})
	// v1 阈值3（自 base-1h 生效）；v2 阈值5（自 base+5m 生效）。迟到事件在 v1 期内。
	if err := rs.Put(detect.Rule{ID: "brute", TenantID: "t1", Version: 1,
		EventType: "login_fail", Window: time.Minute, Threshold: 3,
		SuppressFor: 5 * time.Minute, EffectiveAt: tBase.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := rs.Put(detect.Rule{ID: "brute", TenantID: "t1", Version: 2,
		EventType: "login_fail", Window: time.Minute, Threshold: 5,
		SuppressFor: 5 * time.Minute, EffectiveAt: tBase.Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}

	eng.Ingest("t1", event.SourceJSON, recAt("v1a", "dave", tBase).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("v1b", "dave", tBase.Add(10*time.Second)).raw)
	eng.Advance(tBase.Add(2 * time.Minute)) // 阈值3，仅2事件 => 无 v1 告警
	// 迟到事件 v1c 在 v1 窗口内（t+20s < v2 生效 t+5m）；补入后 v1 阈值3 首次成立。
	eng.Ingest("t1", event.SourceJSON, recAt("v1c", "dave", tBase.Add(20*time.Second)).raw)
	// 水位已越过 v2 生效点（模拟"现在规则已是 v2"）。
	eng.Ingest("t1", event.SourceJSON, recAt("v2x", "dave", tBase.Add(6*time.Minute)).raw)
	eng.Advance(tBase.Add(7 * time.Minute))

	if len(store.List("t1")) != 0 {
		t.Fatalf("baseline must have no v1 alert (only 2 events), got %+v", store.List("t1"))
	}

	res := eng.Backfill(backfill.Request{
		RequestID: "bf-ver", TenantID: "t1",
		From: tBase, To: tBase.Add(2 * time.Minute),
		Operator: bfOp("t1", alert.RoleOperator),
	})
	if res.Status != backfill.StatusAcceptedChanged {
		t.Fatalf("want changed, got %s err=%v", res.Status, res.Err)
	}
	c := res.Corrections[0]
	if c.RuleVersion != 1 {
		t.Fatalf("backfilled event at t+20s must use rule v1, got v%d", c.RuleVersion)
	}
	if fmt.Sprint(c.AllEventIDs) != "[v1a v1b v1c]" {
		t.Fatalf("v1 correction should merge v1a,v1b,v1c, got %v", c.AllEventIDs)
	}
	// 更正告警携带 v1 版本；v2 期的事件 v2x 不被卷入。
	corr := store.List("t1")
	var newDave *alert.Alert
	for _, a := range corr {
		if a.ID == c.NewAlertID {
			newDave = a
		}
	}
	if newDave == nil || newDave.RuleVersion != 1 {
		t.Fatalf("correction alert must be v1: %+v", newDave)
	}
	t.Logf("规则版本：迟到事件按事件时间套用 v1（当前已是 v2），更正 %s 合并=%v",
		c.NewAlertID, c.AllEventIDs)
}

// 多次水位推进后，关联器内部早已裁剪旧事件；回补依赖的是完整事件日志，
// shadow 重算仍应得到与"全量重放"一致的结论。
func TestBackfillAfterMultipleWatermarks(t *testing.T) {
	eng, _, store := setupBackfillEngine(t, 24*time.Hour)
	// 每两个事件推进一次水位，旧事件在在线关联器中被裁剪。
	eng.Ingest("t1", event.SourceJSON, recAt("m1", "erin", tBase).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("m2", "erin", tBase.Add(10*time.Second)).raw)
	eng.Advance(tBase.Add(30 * time.Second))
	// m4 落在距 m1 超过 1 分钟的位置（窗口已滑出 m1），单靠 m2,m4 不触发。
	eng.Ingest("t1", event.SourceJSON, recAt("m4", "erin", tBase.Add(70*time.Second)).raw)
	eng.Advance(tBase.Add(80 * time.Second))
	// m3（t+20s）延迟很久才到，迟到隔离。补入后 m1,m2,m3 落在同一分钟 => 触发。
	eng.Ingest("t1", event.SourceJSON, recAt("m3", "erin", tBase.Add(20*time.Second)).raw)
	eng.Advance(tBase.Add(2 * time.Minute))

	if len(store.List("t1")) != 0 {
		t.Fatalf("only m1,m2,m4 spread out: no alert expected, got %+v", store.List("t1"))
	}
	res := eng.Backfill(backfill.Request{
		RequestID: "bf-multi", TenantID: "t1",
		From: tBase, To: tBase.Add(2 * time.Minute),
		Operator: bfOp("t1", alert.RoleOperator),
	})
	// m1,m2,m3 落在 1 分钟窗口 => 回补后应新增结论（m4 在 t+40s 可能并入抑制命中）。
	if res.Status != backfill.StatusAcceptedChanged {
		t.Fatalf("want changed after multi-watermark backfill, got %s err=%v", res.Status, res.Err)
	}
	var corr backfill.Correction
	for _, c := range res.Corrections {
		if c.Entity == "erin" {
			corr = c
		}
	}
	if corr.NewAlertID == "" {
		t.Fatalf("expected erin correction, got %+v", res.Corrections)
	}
	// 必须包含 m1,m2,m3（日志跨多次水位仍完整）。
	joined := fmt.Sprint(corr.AllEventIDs)
	for _, want := range []string{"m1", "m2", "m3"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("correction %s must contain %s", joined, want)
		}
	}
	t.Logf("多水位后回补：%s 全部合并=%v（journal 完整，不依赖在线关联器残留状态）",
		corr.NewAlertID, corr.AllEventIDs)
}

// 乱序+重复投递的迟到记录回补：重复的迟到重投不会被二次纳入。
func TestBackfillOutOfOrderDuplicateDelivery(t *testing.T) {
	eng, _, store := setupBackfillEngine(t, 24*time.Hour)
	eng.Ingest("t1", event.SourceJSON, recAt("o1", "frank", tBase).raw)
	eng.Ingest("t1", event.SourceJSON, recAt("o2", "frank", tBase.Add(10*time.Second)).raw)
	eng.Advance(tBase.Add(2 * time.Minute))
	// o3 迟到，且被上游重复投递两次（不同原始形式：一次 json 一次 cef，同一 ID）。
	r1 := eng.Ingest("t1", event.SourceJSON, recAt("o3", "frank", tBase.Add(20*time.Second)).raw)
	r2 := eng.Ingest("t1", event.SourceCEF, cefRec("o3", "frank", "login_fail", tBase.Add(20*time.Second)).raw)
	if r1.Disposition != event.DispLate || r2.Disposition != event.DispDuplicate {
		t.Fatalf("o3 late then duplicate: got %s/%s (dup-before-lateness priority)",
			r1.Disposition, r2.Disposition)
	}
	res := eng.Backfill(backfill.Request{
		RequestID: "bf-ood", TenantID: "t1",
		From: tBase, To: tBase.Add(2 * time.Minute),
		Operator: bfOp("t1", alert.RoleOperator),
	})
	if res.Status != backfill.StatusAcceptedChanged {
		t.Fatalf("want changed, got %s", res.Status)
	}
	if fmt.Sprint(res.Backfilled) != "[o3]" {
		t.Fatalf("duplicate late redelivery must be admitted once, got %v", res.Backfilled)
	}
	vis := store.List("t1")
	if len(vis) != 1 || fmt.Sprint(vis[0].EventIDs) != "[o1 o2 o3]" {
		t.Fatalf("single correction merging o1,o2,o3 expected, got %+v", vis)
	}
	// 回补后再以正常入口重投 o3：仍是重复，不产生第二条结论。
	r3 := eng.Ingest("t1", event.SourceJSON, recAt("o3", "frank", tBase.Add(20*time.Second)).raw)
	if r3.Disposition != event.DispDuplicate {
		t.Fatalf("o3 after backfill redelivery must be duplicate, got %s", r3.Disposition)
	}
	t.Log("乱序+重复迟到：o3 仅纳入一次，结论唯一；回补后重投仍判重复")
}
