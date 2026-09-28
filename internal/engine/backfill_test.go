package engine

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

// 构造：阈值 3、窗口 1min、抑制 1h 的规则；返回已断言水位到 tBase+10min 的引擎，
// 此时 e1/e2/e3 已在 tBase+20s 穿越并物化为一条 open 告警。
func setupCorrectedWindow(t *testing.T) (*Engine, *detect.RuleSet, *alert.Store) {
	t.Helper()
	eng, rs, store := New(testCfg())
	if err := rs.Put(detect.Rule{ID: "brute", TenantID: "t1", Version: 1,
		EventType: "login_fail", Window: time.Minute, Threshold: 3,
		SuppressFor: time.Hour, EffectiveAt: tBase.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id string
		at time.Duration
	}{
		{"e1", 0}, {"e2", 10 * time.Second}, {"e3", 20 * time.Second},
	} {
		if r := eng.Ingest("t1", event.SourceJSON,
			jsonRec(tc.id, "alice", "login_fail", tBase.Add(tc.at)).raw); r.Disposition != event.DispAccepted {
			t.Fatalf("ingest %s: %s %s", tc.id, r.Disposition, r.Detail)
		}
	}
	if ids := eng.Advance(tBase.Add(10 * time.Minute)); len(ids) != 1 {
		t.Fatalf("want exactly 1 initial alert, got %v", ids)
	}
	return eng, rs, store
}

// 回补改变结论后：正常查询只能看到一条当前有效结论（更正后的），
// 旧结论保留可查、可顺着它找到更正记录与补入事件，且不再是活跃告警。
func TestBackfillChangedVisibleUniqueAndTraceable(t *testing.T) {
	eng, _, store := setupCorrectedWindow(t)
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}

	oldAlerts := store.List("t1")
	if len(oldAlerts) != 1 {
		t.Fatalf("baseline: want 1 alert, got %d", len(oldAlerts))
	}
	oldID := oldAlerts[0].ID

	// L@t+5s 在水位断言之后才到达 => 被判迟到隔离。
	if r := eng.Ingest("t1", event.SourceJSON,
		jsonRec("L1", "alice", "login_fail", tBase.Add(5*time.Second)).raw); r.Disposition != event.DispLate {
		t.Fatalf("want late, got %s", r.Disposition)
	}

	res := eng.Backfill(BackfillRequest{RequestID: "bf1", TenantID: "t1", Operator: op,
		Start: tBase, End: tBase.Add(5 * time.Minute), Reason: "upstream resent L1"})
	if res.Status != BackfillApplied {
		t.Fatalf("want applied_changed, got %s (%v)", res.Status, res.Corrections)
	}
	if len(res.Corrections) != 1 {
		t.Fatalf("want 1 correction, got %d", len(res.Corrections))
	}
	corr := res.Corrections[0]
	if corr.Kind != alert.CorrectionChanged {
		t.Fatalf("want changed, got %s", corr.Kind)
	}

	// 正常查询：同一（租户,规则,实体,时间窗）只能看到一条有效结论。
	list := store.List("t1")
	if len(list) != 1 {
		t.Fatalf("normal List must show exactly 1 effective conclusion, got %d: %+v", len(list), list)
	}
	cur := list[0]
	if !cur.IsCorrection || cur.CorrectionID != corr.ID || cur.Superseded {
		t.Fatalf("visible conclusion must be the corrected one: %+v", cur)
	}
	if cur.Status != alert.StatusOpen {
		t.Fatalf("corrected alert starts life open, got %s", cur.Status)
	}
	// 补入 L1@t+5s 后阈值在 t+10s 即穿越，合并 e1,L1,e2（e3 留在后续窗口，不再成警）。
	if s := sig(cur.EventIDs); s != sig([]string{"e1", "L1", "e2"}) {
		t.Fatalf("corrected alert must merge e1,L1,e2, got %v", cur.EventIDs)
	}

	// 旧结论：Get 仍可查，但已是 superseded 终态，不再出现在活跃查询里。
	old, err := store.Get(oldID, op)
	if err != nil {
		t.Fatal(err)
	}
	if !old.Superseded || old.SupersededBy != corr.ID {
		t.Fatalf("old alert must point at correction %s: %+v", corr.ID, old)
	}
	if old.Status != alert.StatusSuperseded {
		t.Fatalf("old alert status must be superseded (not a listable actionable state), got %s", old.Status)
	}

	// 顺着旧结论能找到更正记录，再找到补入事件与最终结论。
	got, err := store.GetCorrection(old.SupersededBy, op)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.OriginalAlertIDs) != 1 || got.OriginalAlertIDs[0] != oldID {
		t.Fatalf("correction must reference original alert, got %v", got.OriginalAlertIDs)
	}
	if got.CorrectedAlertID != cur.ID {
		t.Fatalf("correction must reference new alert %s, got %s", cur.ID, got.CorrectedAlertID)
	}
	if s := sig(got.AddedEventIDs); s != sig([]string{"L1"}) {
		t.Fatalf("correction must record added event L1, got %v", got.AddedEventIDs)
	}

	// 旧结论不能再被处置（不能"列表看着能处置、处置又被拒"——它压根不该出现在列表）。
	for name, fn := range map[string]func() error{
		"ack":    func() error { _, e := store.Ack(oldID, op, ""); return e },
		"close":  func() error { _, e := store.Close(oldID, op, ""); return e },
		"reopen": func() error { _, e := store.Reopen(oldID, op, ""); return e },
	} {
		if err := fn(); !errors.Is(err, alert.ErrAlertSuperseded) {
			t.Fatalf("%s on superseded alert: %v, want ErrAlertSuperseded", name, err)
		}
	}

	// 同一 RequestID 重复/乱序再发起：幂等，不多结论也不多更正。
	res2 := eng.Backfill(BackfillRequest{RequestID: "bf1", TenantID: "t1", Operator: op,
		Start: tBase, End: tBase.Add(5 * time.Minute)})
	if res2.Status != BackfillIdempotent {
		t.Fatalf("replay must be idempotent, got %s", res2.Status)
	}
	if len(store.List("t1")) != 1 || len(store.ListCorrections("t1")) != 1 {
		t.Fatal("replay must not add conclusions or corrections")
	}
	t.Logf("唯一可见结论=%s；旧结论=%s 已留痕并指向更正=%s", cur.ID, oldID, corr.ID)
	_ = fmt.Sprint(got)
}

// 同一时间窗被第二次回补再次更正：最新更正唯一可见，前两条结论都留痕且
// 形成可追溯链；已被取代的更正告警同样不能再处置、也不会冒出并列结论。
func TestBackfillChainedCorrectionsSingleEffective(t *testing.T) {
	eng, _, store := setupCorrectedWindow(t)
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}

	ingestLate := func(id string, at time.Duration) {
		t.Helper()
		if r := eng.Ingest("t1", event.SourceJSON,
			jsonRec(id, "alice", "login_fail", tBase.Add(at)).raw); r.Disposition != event.DispLate {
			t.Fatalf("ingest %s: %s", id, r.Disposition)
		}
	}
	ingestLate("L1", 5*time.Second)
	r1 := eng.Backfill(BackfillRequest{RequestID: "bf-a", TenantID: "t1", Operator: op,
		Start: tBase, End: tBase.Add(5 * time.Minute)})
	if r1.Status != BackfillApplied {
		t.Fatalf("first backfill: %s", r1.Status)
	}
	first := store.List("t1")[0]

	// 第二次回补：再补一条更早的迟到事件 L0@t+2s，并扩大圈选窗口。
	ingestLate("L0", 2*time.Second)
	r2 := eng.Backfill(BackfillRequest{RequestID: "bf-b", TenantID: "t1", Operator: op,
		Start: tBase, End: tBase.Add(6 * time.Minute)})
	if r2.Status != BackfillApplied {
		t.Fatalf("second backfill: %s", r2.Status)
	}

	list := store.List("t1")
	if len(list) != 1 {
		t.Fatalf("after chained corrections exactly 1 effective conclusion, got %d", len(list))
	}
	latest := list[0]
	if latest.ID == first.ID {
		t.Fatal("effective conclusion must be the latest correction")
	}
	if !latest.IsCorrection || latest.CorrectionID != r2.Corrections[0].ID {
		t.Fatalf("latest visible must reference 2nd correction: %+v", latest)
	}
	// 正向链：最新结论记录了它取代了谁（第一次更正告警）。
	if len(latest.Supersedes) == 0 {
		t.Fatal("latest correction must record Supersedes link")
	}
	var supFirst bool
	for _, id := range latest.Supersedes {
		if id == first.ID {
			supFirst = true
		}
	}
	if !supFirst {
		t.Fatalf("latest correction must supersede the first correction %s, got %v", first.ID, latest.Supersedes)
	}

	// 留痕视图：原始 + 第一次更正 + 最新更正共三条记录，只有最新一条非 superseded。
	hist := store.ListHistory("t1")
	if len(hist) != 3 {
		t.Fatalf("history must retain all 3 conclusions, got %d", len(hist))
	}
	var active int
	for _, a := range hist {
		if !a.Superseded {
			active++
		}
		if a.Superseded && a.Status != alert.StatusSuperseded {
			t.Fatalf("superseded record %s status=%s", a.ID, a.Status)
		}
	}
	if active != 1 {
		t.Fatalf("exactly 1 non-superseded record allowed, got %d", active)
	}

	// 第一次更正告警已被取代：处置一律拒绝，且它指向第二次更正。
	if _, err := store.Close(first.ID, op, "x"); !errors.Is(err, alert.ErrAlertSuperseded) {
		t.Fatalf("closing superseded correction: %v", err)
	}
	if first.SupersededBy != r2.Corrections[0].ID {
		// first 是快照，重新取一次
		again, _ := store.Get(first.ID, op)
		if again.SupersededBy != r2.Corrections[0].ID {
			t.Fatalf("first correction must point to 2nd correction, got %s", again.SupersededBy)
		}
	}
	// 两条更正记录都可查。
	corrs := store.ListCorrections("t1")
	if len(corrs) != 2 {
		t.Fatalf("want 2 correction records, got %d", len(corrs))
	}
}

// added：基线窗口无告警（旧阈值下事件数不够），补入迟到事件后新增成立；
// 该窗口只出现更正后的一条活跃告警。
func TestBackfillAddedCreatesSingleEffective(t *testing.T) {
	eng, _, store := New(testCfg())
	_ = eng.Rules().Put(detect.Rule{ID: "r", TenantID: "t1", Version: 1, EventType: "login_fail",
		Window: time.Minute, Threshold: 3, SuppressFor: time.Hour, EffectiveAt: tBase.Add(-time.Hour)})
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}
	// 只到 2 个事件 => 无告警。
	for _, tc := range []struct {
		id string
		at time.Duration
	}{{"n1", 0}, {"n2", 10 * time.Second}} {
		if r := eng.Ingest("t1", event.SourceJSON,
			jsonRec(tc.id, "carol", "login_fail", tBase.Add(tc.at)).raw); r.Disposition != event.DispAccepted {
			t.Fatalf("ingest %s: %s", tc.id, r.Disposition)
		}
	}
	eng.Advance(tBase.Add(10 * time.Minute))
	if len(store.List("t1")) != 0 {
		t.Fatal("baseline must have no alert")
	}
	// 迟到的第 3 个事件补入 => 新增成立。
	if r := eng.Ingest("t1", event.SourceJSON,
		jsonRec("n3", "carol", "login_fail", tBase.Add(20*time.Second)).raw); r.Disposition != event.DispLate {
		t.Fatalf("want late, got %s", r.Disposition)
	}
	res := eng.Backfill(BackfillRequest{RequestID: "bfa", TenantID: "t1", Operator: op,
		Start: tBase, End: tBase.Add(5 * time.Minute)})
	if res.Status != BackfillApplied || len(res.Corrections) != 1 ||
		res.Corrections[0].Kind != alert.CorrectionAdded {
		t.Fatalf("want single added correction, got %s %+v", res.Status, res.Corrections)
	}
	list := store.List("t1")
	if len(list) != 1 || !list[0].IsCorrection || list[0].CorrectionID != res.Corrections[0].ID {
		t.Fatalf("exactly 1 corrected alert expected, got %+v", list)
	}
	hist := store.ListHistory("t1")
	if len(hist) != 1 {
		t.Fatalf("added correction has no original records, history=%d", len(hist))
	}
}

// 并发重叠回补 + 查询/新事件写入交叉：最终可见结论仍唯一，且多次运行结果稳定。
func TestBackfillConcurrentOverlapsSingleEffective(t *testing.T) {
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}

	run := func(seed int64) []string {
		eng, rs, store := New(testCfg())
		_ = rs.Put(detect.Rule{ID: "brute", TenantID: "t1", Version: 1, EventType: "login_fail",
			Window: time.Minute, Threshold: 3, SuppressFor: time.Hour,
			EffectiveAt: tBase.Add(-time.Hour)})
		for _, tc := range []struct {
			id string
			at time.Duration
		}{{"e1", 0}, {"e2", 10 * time.Second}, {"e3", 20 * time.Second}} {
			eng.Ingest("t1", event.SourceJSON, jsonRec(tc.id, "alice", "login_fail",
				tBase.Add(tc.at)).raw)
		}
		eng.Advance(tBase.Add(10 * time.Minute))

		// 4 条互相重叠的迟到事件，分给 4 个不同 RequestID（各自补一条），
		// 每个请求都并发重复发起两次（同 ID 幂等）。
		lates := []struct {
			req string
			id  string
			at  time.Duration
		}{
			{"bf-1", "L1", 5 * time.Second},
			{"bf-2", "L2", 8 * time.Second},
			{"bf-3", "L3", 12 * time.Second},
			{"bf-4", "L4", 15 * time.Second},
		}
		for _, l := range lates {
			if r := eng.Ingest("t1", event.SourceJSON,
				jsonRec(l.id, "alice", "login_fail", tBase.Add(l.at)).raw); r.Disposition != event.DispLate {
				t.Fatalf("ingest %s: %s", l.id, r.Disposition)
			}
		}

		var wg sync.WaitGroup
		// 并发读（正常查询视图）与并发回补交叉进行。
		stop := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					for _, a := range store.List("t1") {
						if a.Superseded {
							t.Errorf("reader must never see superseded alert in List: %s", a.ID)
						}
					}
				}
			}
		}()

		jobs := make(chan struct {
			req string
			at  time.Duration
		}, 16)
		for w := 0; w < 6; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					r := eng.Backfill(BackfillRequest{RequestID: j.req, TenantID: "t1",
						Operator: op, Start: tBase, End: tBase.Add(j.at)})
					switch r.Status {
					case BackfillApplied, BackfillNoChange, BackfillIdempotent:
					default:
						t.Errorf("unexpected status %s", r.Status)
					}
				}
			}()
		}
		// 用随机但有界的乱序投递任务；每个请求投两次（重叠 + 重复）。
		type job = struct {
			req string
			at  time.Duration
		}
		var allJobs []job
		for _, l := range lates {
			allJobs = append(allJobs, job{l.req, 5 * time.Minute}, job{l.req, 5 * time.Minute})
		}
		rnd := rand.New(rand.NewSource(seed))
		rnd.Shuffle(len(allJobs), func(i, j int) { allJobs[i], allJobs[j] = allJobs[j], allJobs[i] })
		for _, j := range allJobs {
			jobs <- j
		}
		close(jobs)
		close(stop)
		wg.Wait()

		list := store.List("t1")
		if len(list) != 1 {
			t.Fatalf("concurrent overlapping backfills must leave exactly 1 effective conclusion, got %d: %+v",
				len(list), list)
		}
		cur := list[0]
		// 所有迟到事件要么被某次回补认领并入最终结论，要么留在隔离区；
		// 同一事件绝不能被算两遍。
		seen := map[string]int{}
		for _, id := range cur.EventIDs {
			seen[id]++
		}
		for id, n := range seen {
			if n != 1 {
				t.Fatalf("event %s counted %d times in final conclusion", id, n)
			}
		}
		// 历史链上每一代结论都只有一条"未被取代"。
		var active int
		for _, a := range store.ListHistory("t1") {
			if !a.Superseded {
				active++
			}
		}
		if active != 1 {
			t.Fatalf("history must have exactly 1 active record, got %d", active)
		}
		return cur.EventIDs
	}

	ref := run(1)
	for _, seed := range []int64{2, 3, 42} {
		got := run(seed)
		if sig(got) != sig(ref) {
			t.Fatalf("final conclusion not stable across schedules: %v vs %v", got, ref)
		}
	}
	t.Logf("并发重叠回补后唯一最终结论合并事件=%v", ref)
}

// 跨租户互不影响：t1 的回补/更正不改变 t2 的结论；t2 也看不到 t1 的更正。
// 跨租户、越权、超范围的回补一律拒绝，且拒绝不影响任何既有结论。
func TestBackfillTenantIsolationAndRejection(t *testing.T) {
	eng, rs, store := New(testCfg())
	put := func(tenant string) {
		t.Helper()
		if err := rs.Put(detect.Rule{ID: "brute", TenantID: tenant, Version: 1,
			EventType: "login_fail", Window: time.Minute, Threshold: 3,
			SuppressFor: time.Hour, EffectiveAt: tBase.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	put("t1")
	put("t2")
	ingest := func(tenant, id string) {
		t.Helper()
		for i, p := range []string{"a", "b", "c"} {
			r := eng.Ingest(tenant, event.SourceJSON, jsonRec(id+"-"+p, "h",
				"login_fail", tBase.Add(time.Duration(i*10)*time.Second)).raw)
			if r.Disposition != event.DispAccepted {
				t.Fatalf("ingest %s/%s: %s", tenant, id, r.Disposition)
			}
		}
	}
	ingest("t1", "1")
	ingest("t2", "2")
	eng.Advance(tBase.Add(10 * time.Minute))
	if len(store.List("t1")) != 1 || len(store.List("t2")) != 1 {
		t.Fatalf("baseline alerts: t1=%d t2=%d", len(store.List("t1")), len(store.List("t2")))
	}
	t2before := store.List("t2")[0]

	// t1 迟到事件 + 回补更正。
	if r := eng.Ingest("t1", event.SourceJSON,
		jsonRec("1-late", "h", "login_fail", tBase.Add(5*time.Second)).raw); r.Disposition != event.DispLate {
		t.Fatalf("want late: %s", r.Disposition)
	}
	op1 := alert.Operator{ID: "o1", TenantID: "t1", Role: alert.RoleOperator}
	res := eng.Backfill(BackfillRequest{RequestID: "bf-t1", TenantID: "t1", Operator: op1,
		Start: tBase, End: tBase.Add(5 * time.Minute)})
	if res.Status != BackfillApplied {
		t.Fatalf("t1 backfill: %s", res.Status)
	}
	// t2 结论原封不动。
	t2after := store.List("t2")
	if len(t2after) != 1 || t2after[0].ID != t2before.ID || t2after[0].Superseded {
		t.Fatalf("t2 conclusion must be untouched: %+v", t2after)
	}
	if len(store.ListCorrections("t2")) != 0 || len(store.ListCorrections("t1")) != 1 {
		t.Fatal("corrections must stay inside tenant")
	}

	// 跨租户/越权/超范围拒绝。
	deny := func(name string, req BackfillRequest, want error) {
		t.Helper()
		r := eng.Backfill(req)
		if r.Status != BackfillRejected || !errors.Is(r.Reject, want) {
			t.Fatalf("%s: %v/%v want %v", name, r.Status, r.Reject, want)
		}
	}
	deny("cross-tenant", BackfillRequest{RequestID: "x1", TenantID: "t2",
		Operator: alert.Operator{ID: "o1", TenantID: "t1", Role: alert.RoleAdmin},
		Start:    tBase, End: tBase.Add(time.Minute)}, ErrBackfillCrossTenant)
	deny("viewer", BackfillRequest{RequestID: "x2", TenantID: "t1",
		Operator: alert.Operator{ID: "v", TenantID: "t1", Role: alert.RoleViewer},
		Start:    tBase, End: tBase.Add(time.Minute)}, ErrBackfillUnauthorized)
	deny("too-wide", BackfillRequest{RequestID: "x3", TenantID: "t1", Operator: op1,
		Start: tBase, End: tBase.Add(25 * time.Hour)}, ErrBackfillTooWide)
	deny("beyond-watermark", BackfillRequest{RequestID: "x4", TenantID: "t1", Operator: op1,
		Start: tBase, End: tBase.Add(time.Hour)}, ErrBackfillBeyondWatermark)

	// 被拒绝后既有结论不变：t1 仍唯一可见、t2 不变、无额外更正。
	if len(store.List("t1")) != 1 || len(store.List("t2")) != 1 {
		t.Fatalf("rejections must not mutate conclusions: t1=%d t2=%d",
			len(store.List("t1")), len(store.List("t2")))
	}
	if len(store.ListCorrections("t1")) != 1 {
		t.Fatal("rejected backfills must not register corrections")
	}
	// 被拒绝尝试留痕（含跨租户目标标注）。
	trail := store.AuditTrail()
	var sawBackfillDeny bool
	for _, e := range trail {
		if e.Action == "backfill" {
			sawBackfillDeny = true
			t.Logf("denied backfill audit: tenant=%s op=%s reason=%s",
				e.TenantID, e.OperatorID, e.Reason)
		}
	}
	if !sawBackfillDeny {
		t.Fatal("rejected backfills must appear in audit trail")
	}
	// 跨租户读取更正也被拒。
	if _, err := store.GetCorrection(res.Corrections[0].ID,
		alert.Operator{ID: "x", TenantID: "t2", Role: alert.RoleAdmin}); !errors.Is(err, alert.ErrCrossTenant) {
		t.Fatalf("cross-tenant correction read: %v", err)
	}
}

// 结论不变时零噪音：补入不改变任何窗口结论的迟到事件，不新增告警也不新增更正；
// 但补入事件仍被认领（再发起一次是幂等重放，不会重算第二遍）。
func TestBackfillNoChangeZeroNoise(t *testing.T) {
	eng, _, store := setupCorrectedWindow(t)
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}

	// 迟到事件落在窗口穿越点之后很久，不改变 t+20s 已成立的窗口结论。
	if r := eng.Ingest("t1", event.SourceJSON,
		jsonRec("late90", "alice", "login_fail", tBase.Add(90*time.Second)).raw); r.Disposition != event.DispLate {
		t.Fatalf("want late, got %s", r.Disposition)
	}
	alertsBefore, corrBefore := len(store.List("t1")), len(store.ListCorrections("t1"))
	res := eng.Backfill(BackfillRequest{RequestID: "bf-quiet", TenantID: "t1", Operator: op,
		Start: tBase.Add(30 * time.Second), End: tBase.Add(5 * time.Minute)})
	if res.Status != BackfillNoChange {
		t.Fatalf("want no_change, got %s corrs=%d", res.Status, len(res.Corrections))
	}
	if len(res.Corrections) != 0 {
		t.Fatal("no-change must produce no corrections")
	}
	if len(store.List("t1")) != alertsBefore || len(store.ListCorrections("t1")) != corrBefore {
		t.Fatal("no-change must add neither alerts nor corrections")
	}
	if len(res.ReplayedEvents) != 1 || res.ReplayedEvents[0] != "late90" {
		t.Fatalf("event should still be claimed once, got %v", res.ReplayedEvents)
	}
	// 同 ID 再发起：幂等重放，不再认领、不再重算。
	res2 := eng.Backfill(BackfillRequest{RequestID: "bf-quiet", TenantID: "t1", Operator: op,
		Start: tBase.Add(30 * time.Second), End: tBase.Add(5 * time.Minute)})
	if res2.Status != BackfillIdempotent {
		t.Fatalf("want idempotent replay, got %s", res2.Status)
	}
	if len(store.List("t1")) != alertsBefore {
		t.Fatal("replay must not add noise either")
	}
}

// 回补与新事件在线写入、查询并发交叉：跑完结论可稳定复现（多 seed 一致）。
func TestBackfillConcurrentWithIngest(t *testing.T) {
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}

	run := func(seed int64) []string {
		eng, rs, store := New(testCfg())
		_ = rs.Put(detect.Rule{ID: "r", TenantID: "t1", Version: 1, EventType: "x",
			Window: 10 * time.Minute, Threshold: 3, SuppressFor: 10 * time.Hour,
			EffectiveAt: tBase.Add(-time.Hour)})
		// 先在线写入 3 个事件并定论为一条告警。
		for i := 0; i < 3; i++ {
			eng.Ingest("t1", event.SourceJSON, jsonRec(fmt.Sprintf("on%d", i), "z",
				"x", tBase.Add(time.Duration(i)*time.Minute)).raw)
		}
		eng.Advance(tBase.Add(30 * time.Minute))
		if len(store.List("t1")) != 1 {
			t.Fatalf("baseline: %d", len(store.List("t1")))
		}
		// 一批更晚时间窗（已在水位之内）的迟到事件，供多个重叠回补争抢。
		var lates []string
		for i := 0; i < 6; i++ {
			id := fmt.Sprintf("late%d", i)
			if r := eng.Ingest("t1", event.SourceJSON, jsonRec(id, "z",
				"x", tBase.Add(time.Duration(20+i)*time.Minute)).raw); r.Disposition != event.DispLate {
				t.Fatalf("ingest %s: %s", id, r.Disposition)
			}
			lates = append(lates, id)
		}

		rnd := rand.New(rand.NewSource(seed))
		var wg sync.WaitGroup
		// 并发查询：任何时刻 List 只暴露未取代的有效结论。
		stop := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					seen := map[string]bool{}
					for _, a := range store.List("t1") {
						if seen[a.RuleID+"|"+a.Entity+"|"+a.FireAt.Format(time.RFC3339Nano)] {
							t.Errorf("duplicate effective conclusion for same window visible")
						}
						seen[a.RuleID+"|"+a.Entity+"|"+a.FireAt.Format(time.RFC3339Nano)] = true
						if a.Superseded {
							t.Errorf("superseded alert leaked into List")
						}
					}
				}
			}
		}()
		// 并发回补：3 个不同 RequestID，每个重复投递 2 次，区间互相重叠。
		jobs := make(chan string, 12)
		for w := 0; w < 5; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for req := range jobs {
					r := eng.Backfill(BackfillRequest{RequestID: req, TenantID: "t1", Operator: op,
						Start: tBase.Add(15 * time.Minute), End: tBase.Add(28 * time.Minute)})
					if r.Status == BackfillRejected {
						t.Errorf("unexpected rejection: %v", r.Reject)
					}
				}
			}()
		}
		var reqs []string
		for i := 0; i < 3; i++ {
			reqs = append(reqs, fmt.Sprintf("mix-%d", i), fmt.Sprintf("mix-%d", i))
		}
		rnd.Shuffle(len(reqs), func(i, j int) { reqs[i], reqs[j] = reqs[j], reqs[i] })
		for _, r := range reqs {
			jobs <- r
		}
		close(jobs)
		close(stop)
		wg.Wait()

		// 最终：历史链中每个窗口至多一条有效；全部迟到事件合计不被重复计数。
		counts := map[string]int{}
		var active int
		for _, a := range store.ListHistory("t1") {
			if !a.Superseded {
				active++
			}
			for _, id := range a.EventIDs {
				counts[id]++
			}
		}
		for id, n := range counts {
			if n > 1 {
				t.Fatalf("event %s counted in %d retained conclusions", id, n)
			}
		}
		// 至少基线那一代 + 回补更正代；有效结论数必须 <= 窗口数，且全部非 superseded。
		if active == 0 {
			t.Fatal("must retain at least one effective conclusion")
		}
		var out []string
		for id := range counts {
			out = append(out, id)
		}
		_ = lates
		return out
	}

	ref := run(7)
	for _, seed := range []int64{8, 99, 12345} {
		got := run(seed)
		if sig(got) != sig(ref) {
			t.Fatalf("final retained event set unstable: %v vs %v", got, ref)
		}
	}
}

// 被拒绝的回补不得影响其它时间段的既有结论。
func TestBackfillRejectLeavesOtherWindowsIntact(t *testing.T) {
	eng, rs, store := New(testCfg())
	_ = rs.Put(detect.Rule{ID: "r", TenantID: "t1", Version: 1, EventType: "x",
		Window: time.Minute, Threshold: 2, SuppressFor: 0, EffectiveAt: tBase.Add(-time.Hour)})
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}
	// 两个相隔足够远的时间窗（窗口 1min），各自独立成警。
	for _, tc := range []struct {
		id string
		at time.Duration
	}{{"p1", 0}, {"p2", 10 * time.Second}, {"q1", 10 * time.Minute}, {"q2", 10*time.Minute + 10*time.Second}} {
		eng.Ingest("t1", event.SourceJSON, jsonRec(tc.id, "z", "x", tBase.Add(tc.at)).raw)
	}
	eng.Advance(tBase.Add(20 * time.Minute))
	before := store.List("t1")
	if len(before) != 2 {
		t.Fatalf("baseline want 2 windows, got %d", len(before))
	}
	beforeSig := map[string]string{}
	for _, a := range before {
		beforeSig[a.FireAt.Format(time.RFC3339Nano)] = sig(a.EventIDs)
	}
	// 非法/超范围请求全部拒绝。
	for _, req := range []BackfillRequest{
		{RequestID: "", TenantID: "t1", Operator: op, Start: tBase, End: tBase.Add(time.Minute)},
		{RequestID: "bad1", TenantID: "t1", Operator: op, Start: tBase.Add(20 * time.Minute), End: tBase},
		{RequestID: "bad2", TenantID: "", Operator: op, Start: tBase, End: tBase.Add(time.Minute)},
		{RequestID: "bad3", TenantID: "t1", Operator: op, Start: tBase, End: tBase.Add(30 * time.Hour)},
	} {
		r := eng.Backfill(req)
		if r.Status != BackfillRejected {
			t.Fatalf("want rejected, got %s", r.Status)
		}
	}
	after := store.List("t1")
	if len(after) != 2 {
		t.Fatalf("rejections must not touch other windows, got %d", len(after))
	}
	for _, a := range after {
		if got := sig(a.EventIDs); got != beforeSig[a.FireAt.Format(time.RFC3339Nano)] {
			t.Fatalf("window %s mutated after rejected backfill", a.FireAt)
		}
	}
}

// 回补路径的乱序 + 重复投递：同一批补投事件以乱序、跨来源、重复方式提交，
// 多次运行（不同打乱种子）结论必须一致，且重复事件不被算两遍。
func TestBackfillExtraOutOfOrderAndDuplicate(t *testing.T) {
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}

	run := func(seed int64) (events []string, replayed []string, corrN int) {
		eng, rs, store := New(testCfg())
		_ = rs.Put(detect.Rule{ID: "r", TenantID: "t1", Version: 1, EventType: "login_fail",
			Window: time.Minute, Threshold: 3, SuppressFor: time.Hour,
			EffectiveAt: tBase.Add(-time.Hour)})
		// 在线只有 1 个事件（不成警）；另外 3 个靠回补 Extra 补投。
		eng.Ingest("t1", event.SourceJSON, jsonRec("o1", "dan", "login_fail", tBase).raw)
		eng.Advance(tBase.Add(10 * time.Minute))

		// 同 ID 用三种来源形式各写一遍（重复投递必须去重），再整体打乱。
		mk := func(id string, at time.Duration) []RawRecord {
			return []RawRecord{
				{Source: event.SourceJSON, Raw: jsonRec(id, "dan", "login_fail", tBase.Add(at)).raw},
				{Source: event.SourceSyslog, Raw: syslogRec(id, "dan", "login_fail", tBase.Add(at)).raw},
				{Source: event.SourceCEF, Raw: cefRec(id, "dan", "login_fail", tBase.Add(at)).raw},
			}
		}
		var extras []RawRecord
		for _, tc := range []struct {
			id string
			at time.Duration
		}{{"x1", 10 * time.Second}, {"x2", 20 * time.Second}, {"x3", 30 * time.Second}} {
			extras = append(extras, mk(tc.id, tc.at)...)
		}
		rnd := rand.New(rand.NewSource(seed))
		rnd.Shuffle(len(extras), func(i, j int) { extras[i], extras[j] = extras[j], extras[i] })

		res := eng.Backfill(BackfillRequest{RequestID: "bf-ooo", TenantID: "t1", Operator: op,
			Start: tBase, End: tBase.Add(5 * time.Minute), Extra: extras})
		if res.Status != BackfillApplied {
			t.Fatalf("seed %d: want applied, got %s", seed, res.Status)
		}
		// 3 个唯一补投事件都应被认领重放（9 条原始记录去重为 3）。
		if sig(res.ReplayedEvents) != sig([]string{"x1", "x2", "x3"}) {
			t.Fatalf("seed %d: replayed unique events wrong: %v", seed, res.ReplayedEvents)
		}
		cur := store.List("t1")
		if len(cur) != 1 {
			t.Fatalf("seed %d: exactly 1 effective conclusion, got %d", seed, len(cur))
		}
		return cur[0].EventIDs, res.ReplayedEvents, len(store.ListCorrections("t1"))
	}

	refEvents, refReplayed, refCorr := run(int64(1))
	for _, seed := range []int64{2, 3, 777} {
		evs, rep, n := run(seed)
		if sig(evs) != sig(refEvents) || sig(rep) != sig(refReplayed) || n != refCorr {
			t.Fatalf("seed %d not reproducible: %v %v %d vs %v %v %d",
				seed, evs, rep, n, refEvents, refReplayed, refCorr)
		}
	}
	// 阈值在 t+20s 穿越：合并 o1,x1,x2（x3 已认领但落在穿越之后，留待后续窗口）。
	if sig(refEvents) != sig([]string{"o1", "x1", "x2"}) {
		t.Fatalf("duplicates must be deduped; want o1,x1,x2 once each, got %v", refEvents)
	}
	t.Logf("乱序+跨来源+重复补投：唯一结论合并=%v，去重后认领=%v", refEvents, refReplayed)
}
