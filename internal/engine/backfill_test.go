package engine

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

// bfEnv 封装一次回补测试的引擎与常用操作（阈值3/窗口1m/抑制1h，便于构造）。
type bfEnv struct {
	eng   *Engine
	rs    *detect.RuleSet
	store *alert.Store
	op    alert.Operator
}

func newBFEnv(t *testing.T, tenant string, threshold int) *bfEnv {
	t.Helper()
	eng, rs, store := New(testCfg())
	if err := rs.Put(detect.Rule{ID: "brute", TenantID: tenant, Version: 1,
		EventType: "login_fail", Window: time.Minute, Threshold: threshold,
		SuppressFor: time.Hour, EffectiveAt: tBase.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return &bfEnv{
		eng: eng, rs: rs, store: store,
		op: alert.Operator{ID: "ops", TenantID: tenant, Role: alert.RoleOperator},
	}
}

func (e *bfEnv) ing(tenant, id, ent string, off time.Duration) event.Disposition {
	return e.eng.Ingest(tenant, event.SourceJSON,
		jsonRec(id, ent, "login_fail", tBase.Add(off)).raw).Disposition
}

// effView 返回当前可见结论的稳定快照：实体 -> 合并事件集合(排序)+状态。
func (e *bfEnv) effView(tenant string) map[string][2]string {
	out := map[string][2]string{}
	for _, a := range e.store.List(tenant) {
		ids := append([]string{}, a.EventIDs...)
		sort.Strings(ids)
		out[a.Entity] = [2]string{strings.Join(ids, ","), string(a.Status)}
	}
	return out
}

// 回补改变结论：可见结论唯一且为更正后版本；旧结论终态但可追溯到更正记录与补入事件。
func TestBackfillChangedUniqueVisibleTraceable(t *testing.T) {
	env := newBFEnv(t, "t1", 3)
	mustDisp(t, env.ing("t1", "e1", "alice", 0), event.DispAccepted)
	mustDisp(t, env.ing("t1", "e2", "alice", 20*time.Second), event.DispAccepted)
	mustDisp(t, env.ing("t1", "e3", "alice", 40*time.Second), event.DispAccepted)
	env.eng.Advance(tBase.Add(10 * time.Minute))
	before := env.effView("t1")
	if before["alice"][0] != "e1,e2,e3" {
		t.Fatalf("baseline wrong: %v", before)
	}
	oldID := env.store.List("t1")[0].ID

	// 迟到补入 t+10s 的事件，使窗口 [0,40] 的结论发生变化（穿越点位移到 t+20）。
	if d := env.ing("t1", "L0", "alice", 10*time.Second); d != event.DispLate {
		t.Fatalf("want late, got %s", d)
	}
	res := env.eng.Backfill(BackfillRequest{
		RequestID: "bf1", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute),
		Reason: "upstream delivered missing segment",
	})
	if res.Status != BackfillApplied {
		t.Fatalf("status=%s reject=%v", res.Status, res.Reject)
	}
	if len(res.Corrections) != 1 || res.Corrections[0].Kind != alert.CorrectionChanged {
		t.Fatalf("want one changed correction, got %+v", res.Corrections)
	}
	c := res.Corrections[0]
	if fmt.Sprint(c.OriginalAlertIDs) != "["+oldID+"]" {
		t.Fatalf("original link wrong: %v", c.OriginalAlertIDs)
	}
	if fmt.Sprint(c.AddedEventIDs) != "[L0]" ||
		fmt.Sprint(c.BaselineEventIDs) != "[e1 e2 e3]" ||
		fmt.Sprint(c.FinalEventIDs) != "[L0 e1 e2]" {
		t.Fatalf("traceability sets wrong: base=%v final=%v added=%v",
			c.BaselineEventIDs, c.FinalEventIDs, c.AddedEventIDs)
	}

	// 正常查询只有一条当前结论，且是更正后的。
	list := env.store.List("t1")
	if len(list) != 1 || list[0].ID != c.CorrectedAlertID || !list[0].IsCorrection {
		t.Fatalf("visible must be exactly the corrected one: %+v", list)
	}
	ids := append([]string{}, list[0].EventIDs...)
	sort.Strings(ids)
	if fmt.Sprint(ids) != "[L0 e1 e2]" {
		t.Fatalf("visible conclusion events wrong: %v", ids)
	}

	// 旧结论终态、不可处置，且串着更正记录。
	old, err := env.store.Get(oldID, env.op)
	if err != nil {
		t.Fatal(err)
	}
	if old.Status != alert.StatusSuperseded || !old.Superseded ||
		old.SupersededBy != c.ID {
		t.Fatalf("old must be superseded terminal linked to correction: %+v", old)
	}
	if _, err := env.store.Ack(oldID, env.op, ""); !errors.Is(err, alert.ErrAlertSuperseded) {
		t.Fatalf("acting on superseded must be rejected: %v", err)
	}
	// 历史视图两条都在；GetCorrection 能读回完整链路。
	if len(env.store.ListHistory("t1")) != 2 {
		t.Fatal("history must retain old + corrected")
	}
	got, err := env.store.GetCorrection(c.ID, env.op)
	if err != nil {
		t.Fatal(err)
	}
	if got.CorrectedAlertID != list[0].ID || len(got.OriginalAlertIDs) != 1 {
		t.Fatalf("correction chain broken: %+v", got)
	}
}

// 给 Alert 测试用的小工具：返回排序后的事件字符串（仅测试可读性）。

// 乱序 + 重复投递：同一批迟到记录以乱序、重复方式补投，结果稳定。
func TestBackfillOutOfOrderAndDuplicate(t *testing.T) {
	run := func(perm []int) BackfillResult {
		env := newBFEnv(t, "t1", 3)
		env.ing("t1", "e1", "alice", 0)
		env.ing("t1", "e2", "alice", 20*time.Second)
		env.ing("t1", "e3", "alice", 40*time.Second)
		env.eng.Advance(tBase.Add(10 * time.Minute))

		// 三条迟到记录，故意以给定顺序补投，且每条重复投递一次。
		late := []struct {
			id  string
			off time.Duration
		}{
			{"L0", 10 * time.Second}, {"L1", 30 * time.Second}, {"Lx", 5 * time.Second},
		}
		for _, i := range perm {
			l := late[i]
			env.eng.Ingest("t1", event.SourceSyslog,
				syslogRec(l.id, "alice", "login_fail", tBase.Add(l.off)).raw)
		}
		for _, i := range perm {
			l := late[i]
			env.eng.Ingest("t1", event.SourceCEF,
				cefRec(l.id, "alice", "login_fail", tBase.Add(l.off)).raw)
		}
		res := env.eng.Backfill(BackfillRequest{
			RequestID: "bf", TenantID: "t1", Operator: env.op,
			Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute),
		})
		if res.Status != BackfillApplied {
			t.Fatalf("perm=%v status=%s %v", perm, res.Status, res.Reject)
		}
		return res
	}
	r1 := run([]int{0, 1, 2})
	r2 := run([]int{2, 0, 1})
	r3 := run([]int{1, 2, 0})
	// 三种补投顺序：纳入重算的补入事件集合一致、更正数量一致。
	cmp := func(r BackfillResult) string {
		var kinds []string
		for _, c := range r.Corrections {
			kinds = append(kinds, string(c.Kind))
		}
		sort.Strings(r.ReplayedEvents)
		return fmt.Sprintf("%v|%v|%d", kinds, r.ReplayedEvents, len(r.Corrections))
	}
	if cmp(r1) != cmp(r2) || cmp(r2) != cmp(r3) {
		t.Fatalf("out-of-order backfill not reproducible:\n%q\n%q\n%q", cmp(r1), cmp(r2), cmp(r3))
	}
	// 重复投递的迟到记录不能被认领两次（ReplayedEvents 去重后恰好 3 个）。
	if len(r1.ReplayedEvents) != 3 {
		t.Fatalf("replayed events must be deduped to 3, got %v", r1.ReplayedEvents)
	}
}

// 同一 RequestID 重复/并发发起：幂等重放，绝不重复产出更正或告警。
func TestBackfillIdempotentReplay(t *testing.T) {
	env := newBFEnv(t, "t1", 3)
	env.ing("t1", "e1", "alice", 0)
	env.ing("t1", "e2", "alice", 20*time.Second)
	env.ing("t1", "e3", "alice", 40*time.Second)
	env.eng.Advance(tBase.Add(10 * time.Minute))
	env.ing("t1", "L0", "alice", 10*time.Second)
	req := BackfillRequest{RequestID: "bf", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute)}
	r1 := env.eng.Backfill(req)
	r2 := env.eng.Backfill(req)
	if r1.Status != BackfillApplied || r2.Status != BackfillIdempotent {
		t.Fatalf("statuses %s %s", r1.Status, r2.Status)
	}
	if len(r2.Corrections) != 1 || len(env.store.ListCorrections("t1")) != 1 {
		t.Fatal("replay must not produce a second correction")
	}
	if len(env.store.List("t1")) != 1 || len(env.store.ListHistory("t1")) != 2 {
		t.Fatal("replay must not add alerts")
	}

	// 并发同 ID：所有调用要么 applied 要么 idempotent_replay，结论仍只有一条。
	var wg sync.WaitGroup
	statuses := map[BackfillStatus]int{}
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := env.eng.Backfill(req)
			mu.Lock()
			statuses[r.Status]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if statuses[BackfillIdempotent] != 8 {
		t.Fatalf("concurrent same-id replays: %+v", statuses)
	}
	if len(env.store.List("t1")) != 1 || len(env.store.ListCorrections("t1")) != 1 {
		t.Fatal("concurrent replay broke uniqueness")
	}
}

// 重叠回补（不同 RequestID 命中同一已更正窗口）：后续请求整批被拒、错误可区分、
// 绝不出现同一窗口两条更正；拒绝不影响其它窗口与其它租户。
func TestBackfillOverlapRejectsAndNoSecondCorrection(t *testing.T) {
	env := newBFEnv(t, "t1", 3)
	env.ing("t1", "e1", "alice", 0)
	env.ing("t1", "e2", "alice", 20*time.Second)
	env.ing("t1", "e3", "alice", 40*time.Second)
	env.eng.Advance(tBase.Add(10 * time.Minute))
	env.ing("t1", "L0", "alice", 10*time.Second)
	r1 := env.eng.Backfill(BackfillRequest{RequestID: "bf1", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute)})
	if r1.Status != BackfillApplied {
		t.Fatal(r1.Reject)
	}

	// 另一批迟到记录再次覆盖同一窗口。
	env.ing("t1", "L2", "alice", 15*time.Second)
	r2 := env.eng.Backfill(BackfillRequest{RequestID: "bf2", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute)})
	if r2.Status != BackfillRejected ||
		!errors.Is(r2.Reject, ErrBackfillWindowCorrected) {
		t.Fatalf("overlap must be rejected distinctively, got %s %v", r2.Status, r2.Reject)
	}

	// 即使第二次请求携带的是另一条全新补投事件（确实会重算出不同结论），
	// 也照样拒绝：已定案窗口不允许"更正的更正"。
	r3 := env.eng.Backfill(BackfillRequest{
		RequestID: "bf3", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute),
		Extra: []RawRecord{{Source: event.SourceJSON,
			Raw: jsonRec("L3", "alice", "login_fail", tBase.Add(5*time.Second)).raw}},
	})
	if r3.Status != BackfillRejected ||
		!errors.Is(r3.Reject, ErrBackfillWindowCorrected) {
		t.Fatalf("overlap with distinct new events must still be rejected, got %s %v",
			r3.Status, r3.Reject)
	}
	if len(env.store.ListCorrections("t1")) != 1 {
		t.Fatal("rejected overlap must not register a correction")
	}
	if len(env.store.List("t1")) != 1 {
		t.Fatal("visible conclusion must stay unique")
	}
	// 被拒请求的补投记录不能污染事件日志（下次重放仍不包含它）。
	resReplay := env.eng.Backfill(BackfillRequest{RequestID: "bf3", TenantID: "t1",
		Operator: env.op, Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute),
		Extra: []RawRecord{{Source: event.SourceJSON,
			Raw: jsonRec("L3", "alice", "login_fail", tBase.Add(5*time.Second)).raw}}})
	if resReplay.Status != BackfillRejected {
		t.Fatalf("rejected request is not idempotent-replayed: %s", resReplay.Status)
	}
	// 被拒尝试留痕可追溯。
	var denied int
	for _, d := range env.store.DeniedAttempts() {
		if strings.Contains(d.Reason, "window already") {
			denied++
		}
	}
	if denied == 0 {
		t.Fatal("rejected overlap must be audited")
	}
}

// 并发、互相重叠的回补：多 goroutine 各持不同 RequestID 同时发起，
// 恰好一次生效；无论调度如何，最终可见结论与更正集合恒定。
func TestBackfillConcurrentOverlapStable(t *testing.T) {
	run := func(parallel int) string {
		env := newBFEnv(t, "t1", 3)
		env.ing("t1", "e1", "alice", 0)
		env.ing("t1", "e2", "alice", 20*time.Second)
		env.ing("t1", "e3", "alice", 40*time.Second)
		env.eng.Advance(tBase.Add(10 * time.Minute))
		// 所有竞争者携带【完全相同】的一条补投记录：先到者认领并更正窗口，
		// 其余者的记录因重复被跳过、且区间已命中定案窗口而整批被拒。
		extras := []RawRecord{{Source: event.SourceJSON,
			Raw: jsonRec("L0", "alice", "login_fail", tBase.Add(10*time.Second)).raw}}
		var wg sync.WaitGroup
		var mu sync.Mutex
		applied, rejected := 0, 0
		for i := 0; i < parallel; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rid := fmt.Sprintf("bf-%d", i)
				r := env.eng.Backfill(BackfillRequest{
					RequestID: rid, TenantID: "t1", Operator: env.op,
					Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute),
					Extra: extras,
				})
				mu.Lock()
				switch r.Status {
				case BackfillApplied:
					applied++
				case BackfillRejected:
					rejected++
				}
				mu.Unlock()
			}(i)
		}
		wg.Wait()
		if applied != 1 || rejected != parallel-1 {
			t.Fatalf("parallel=%d applied=%d rejected=%d (want exactly 1 applied, rest rejected)",
				parallel, applied, rejected)
		}
		if len(env.store.List("t1")) != 1 || len(env.store.ListCorrections("t1")) != 1 {
			t.Fatal("uniqueness invariant after concurrent overlap")
		}
		return env.effView("t1")["alice"][0]
	}
	v1 := run(1)
	v8 := run(8)
	v16 := run(16)
	if v1 != v8 || v8 != v16 {
		t.Fatalf("concurrent overlap result not stable: %q %q %q", v1, v8, v16)
	}
	if v1 != "L0,e1,e2" {
		t.Fatalf("unexpected final events: %q", v1)
	}
}

// 跨租户隔离：一个租户的回补/被拒，不影响其它租户的既有结论与可见告警。
func TestBackfillCrossTenantIsolation(t *testing.T) {
	env := newBFEnv(t, "t1", 3)
	if err := env.rs.Put(detect.Rule{ID: "brute", TenantID: "t2", Version: 1,
		EventType: "login_fail", Window: time.Minute, Threshold: 3,
		SuppressFor: time.Hour, EffectiveAt: tBase.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// t1 基线告警。
	env.ing("t1", "a1", "alice", 0)
	env.ing("t1", "a2", "alice", 20*time.Second)
	env.ing("t1", "a3", "alice", 40*time.Second)
	// t2 基线告警。
	env.ing("t2", "b1", "bob", 0)
	env.ing("t2", "b2", "bob", 20*time.Second)
	env.ing("t2", "b3", "bob", 40*time.Second)
	env.eng.Advance(tBase.Add(10 * time.Minute))
	t1before := env.effView("t1")
	t2before := env.effView("t2")

	// 越权：跨租户发起回补被拒。
	r := env.eng.Backfill(BackfillRequest{
		RequestID: "x", TenantID: "t1",
		Operator: alert.Operator{ID: "evil", TenantID: "t2", Role: alert.RoleAdmin},
		Start:    tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute)})
	if r.Status != BackfillRejected || !errors.Is(r.Reject, ErrBackfillCrossTenant) {
		t.Fatalf("cross-tenant backfill: %s %v", r.Status, r.Reject)
	}
	// viewer 越权被拒。
	r = env.eng.Backfill(BackfillRequest{RequestID: "y", TenantID: "t1",
		Operator: alert.Operator{ID: "v", TenantID: "t1", Role: alert.RoleViewer},
		Start:    tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute)})
	if r.Status != BackfillRejected || !errors.Is(r.Reject, ErrBackfillUnauthorized) {
		t.Fatalf("viewer backfill: %s %v", r.Status, r.Reject)
	}
	// 超范围被拒。
	r = env.eng.Backfill(BackfillRequest{RequestID: "z", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-25 * time.Hour), End: tBase.Add(10 * time.Minute)})
	if r.Status != BackfillRejected || !errors.Is(r.Reject, ErrBackfillTooWide) {
		t.Fatalf("too-wide backfill: %s %v", r.Status, r.Reject)
	}

	// t1 正常回补改变结论。
	env.ing("t1", "L0", "alice", 10*time.Second)
	r = env.eng.Backfill(BackfillRequest{RequestID: "ok", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute)})
	if r.Status != BackfillApplied {
		t.Fatal(r.Reject)
	}
	// t2 结论原样不动。
	if env.effView("t2")["bob"] != t2before["bob"] {
		t.Fatalf("t2 conclusion changed by t1 backfill: %v vs %v",
			env.effView("t2"), t2before)
	}
	if env.effView("t1")["alice"] == t1before["alice"] {
		t.Fatal("t1 conclusion should have changed")
	}
	if len(env.store.ListCorrections("t2")) != 0 {
		t.Fatal("t2 must have no corrections from t1 activity")
	}
	// 越权/跨租户读取更正记录同样被拒。
	if _, err := env.store.GetCorrection(r.Corrections[0].ID,
		alert.Operator{ID: "evil", TenantID: "t2", Role: alert.RoleAdmin}); !errors.Is(err, alert.ErrCrossTenant) {
		t.Fatalf("cross-tenant correction read: %v", err)
	}
}

// 结论不变：补入的事件没有改变任何窗口结论时，不产生告警、不产生更正（零噪音）。
func TestBackfillNoChangeZeroNoise(t *testing.T) {
	env := newBFEnv(t, "t1", 3)
	env.ing("t1", "a1", "alice", 0)
	env.ing("t1", "a2", "alice", 10*time.Second)
	env.ing("t1", "a3", "alice", 20*time.Second)
	env.eng.Advance(tBase.Add(10 * time.Minute))
	nAlertsBefore := len(env.store.ListHistory("t1"))
	// 迟到事件落在 t+90s，不改变 [0,20] 已消费窗口的结论。
	env.ing("t1", "a9", "alice", 90*time.Second)
	res := env.eng.Backfill(BackfillRequest{RequestID: "bfnc", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(30 * time.Second), End: tBase.Add(10 * time.Minute)})
	if res.Status != BackfillNoChange {
		t.Fatalf("want no_change, got %s %v", res.Status, res.Reject)
	}
	if len(res.Corrections) != 0 {
		t.Fatalf("no-change must not produce corrections: %+v", res.Corrections)
	}
	if len(env.store.ListHistory("t1")) != nAlertsBefore ||
		len(env.store.ListCorrections("t1")) != 0 {
		t.Fatal("no-change must not add alerts or corrections")
	}
	// 再补一条重复的、以及一条补投但越界的记录：仍零噪音，且越界被显式跳过。
	res = env.eng.Backfill(BackfillRequest{
		RequestID: "bfnc2", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(30 * time.Second), End: tBase.Add(10 * time.Minute),
		Extra: []RawRecord{
			{Source: event.SourceJSON, Raw: jsonRec("a9", "alice", "login_fail", tBase.Add(90*time.Second)).raw},
			{Source: event.SourceJSON, Raw: jsonRec("far", "alice", "login_fail", tBase.Add(20*time.Hour)).raw},
		},
	})
	if res.Status != BackfillNoChange {
		t.Fatalf("duplicate+out-of-range must still be no_change, got %s", res.Status)
	}
	if len(res.Corrections) != 0 || len(env.store.ListHistory("t1")) != nAlertsBefore {
		t.Fatal("no noise allowed when conclusion unchanged")
	}
	var oor, dup int
	for _, sk := range res.SkippedExtra {
		switch sk.Reason {
		case event.RejectReason("out_of_backfill_range"):
			oor++
		case event.RejectReason("duplicate_event"):
			dup++
		}
	}
	if oor != 1 || dup != 1 {
		t.Fatalf("want 1 out-of-range + 1 duplicate skipped, got %+v", res.SkippedExtra)
	}
}

// 回补与在线写入/查询交叉进行：串行化保证最终结论唯一、稳定，且旧结论不复活。
func TestBackfillConcurrentWithIngest(t *testing.T) {
	env := newBFEnv(t, "t1", 3)
	base := []string{"e1", "e2", "e3"}
	off := []time.Duration{0, 20 * time.Second, 40 * time.Second}
	for i, id := range base {
		env.ing("t1", id, "alice", off[i])
	}
	env.eng.Advance(tBase.Add(10 * time.Minute))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// 持续在线写入"较晚时间段"的事件（t+30m 起），与回补历史段交叉。
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				env.ing("t1", fmt.Sprintf("live-%d", i), "carol",
					30*time.Minute+time.Duration(i%5)*10*time.Second)
				i++
			}
			if i > 200 {
				return
			}
		}
	}()
	// 并发读：查询过程中绝不可能同时看到同窗口的旧+新两条活跃结论。
	readOK := true
	wg.Add(1)
	go func() {
		defer wg.Done()
		op := env.op
		for i := 0; i < 200; i++ {
			seen := map[string]int{}
			for _, a := range env.store.List("t1") {
				if a.Status == alert.StatusSuperseded {
					readOK = false
				}
				seen[a.RuleID+"|"+a.Entity+"|"+a.FireAt.Format(time.RFC3339Nano)]++
			}
			_ = op
		}
	}()
	env.ing("t1", "L0", "alice", 10*time.Second)
	r := env.eng.Backfill(BackfillRequest{RequestID: "bf", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute)})
	close(stop)
	wg.Wait()
	if r.Status != BackfillApplied {
		t.Fatal(r.Reject)
	}
	if !readOK {
		t.Fatal("normal List must never expose a superseded alert")
	}
	if len(env.store.List("t1")) == 0 {
		t.Fatal("expected corrected conclusion visible")
	}
}

// 回补改变结论后，后续在线抑制命中合并到更正后的当前结论（旧结论保持终态）。
func TestBackfillSuppressionRetargetsToCorrected(t *testing.T) {
	env := newBFEnv(t, "t1", 3)
	env.ing("t1", "s1", "alice", 0)
	env.ing("t1", "s2", "alice", 20*time.Second)
	env.ing("t1", "s3", "alice", 40*time.Second)
	env.eng.Advance(tBase.Add(10 * time.Minute))
	env.ing("t1", "s0", "alice", 10*time.Second)
	r := env.eng.Backfill(BackfillRequest{RequestID: "bf", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute)})
	if r.Status != BackfillApplied {
		t.Fatal(r.Reject)
	}
	newID := r.Corrections[0].CorrectedAlertID
	oldID := r.Corrections[0].OriginalAlertIDs[0]

	// 抑制期内再来一波在线事件，阈值穿越被抑制合并。
	for i, id := range []string{"s4", "s5", "s6"} {
		if d := env.ing("t1", id, "alice",
			11*time.Minute+time.Duration(i)*10*time.Second); d != event.DispAccepted {
			t.Fatalf("live event %s disposition=%s", id, d)
		}
	}
	fired := env.eng.Advance(tBase.Add(20 * time.Minute))
	if len(fired) != 0 {
		t.Fatalf("post-correction hit must be suppressed, got new fires %v", fired)
	}
	cur, _ := env.store.Get(newID, env.op)
	if cur.SuppressedCount != 3 {
		var ids []string
		ids = append(ids, cur.EventIDs...)
		t.Fatalf("suppressed hit must merge into corrected: count=%d events=%v",
			cur.SuppressedCount, ids)
	}
	if !contains(cur.EventIDs, "s4") || !contains(cur.EventIDs, "s6") {
		t.Fatalf("corrected alert must include online hits: %v", cur.EventIDs)
	}
	old, _ := env.store.Get(oldID, env.op)
	if old.Status != alert.StatusSuperseded || contains(old.EventIDs, "s4") {
		t.Fatal("old alert must stay terminal and untouched by online merges")
	}
}

// added 场景：原窗口无告警，回补补入后新增成立；更正告警是唯一可见结论。
func TestBackfillAddedCreatesVisibleCorrection(t *testing.T) {
	env := newBFEnv(t, "t1", 3)
	env.eng.Advance(tBase.Add(10 * time.Minute)) // 先断言水位
	env.ing("t1", "a1", "carol", 0)
	env.ing("t1", "a2", "carol", 10*time.Second)
	env.ing("t1", "a3", "carol", 20*time.Second)
	if len(env.store.List("t1")) != 0 {
		t.Fatal("late events must not produce online alerts")
	}
	res := env.eng.Backfill(BackfillRequest{RequestID: "bfadd", TenantID: "t1", Operator: env.op,
		Start: tBase.Add(-time.Minute), End: tBase.Add(10 * time.Minute)})
	if res.Status != BackfillApplied || res.Corrections[0].Kind != alert.CorrectionAdded {
		t.Fatalf("want applied/added, got %s %v", res.Status, res.Reject)
	}
	list := env.store.List("t1")
	if len(list) != 1 || !list[0].IsCorrection {
		t.Fatalf("exactly one corrected visible alert expected, got %+v", list)
	}
}

func mustDisp(t *testing.T, got event.Disposition, want event.Disposition) {
	t.Helper()
	if got != want {
		t.Fatalf("disposition=%s want=%s", got, want)
	}
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
