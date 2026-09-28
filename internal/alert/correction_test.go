package alert

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func opOf(id, tenant string, role Role) Operator {
	return Operator{ID: id, TenantID: tenant, Role: role}
}

func sampleAlert(id, tenant, rule, ent string, fireAt time.Time, ids ...string) Alert {
	return Alert{
		ID: id, TenantID: tenant, RuleID: rule, RuleVersion: 1, Entity: ent,
		CreatedAt: fireAt.Add(-20 * time.Second), FireAt: fireAt, EventIDs: ids,
	}
}

// 回补改变结论后：List 只看到更正后的唯一当前结论；旧结论 superseded 终态、
// 可通过 Get / ListHistory / Correction 记录完整追溯。
func TestCorrectionChangedUniqueVisibleAndTraceable(t *testing.T) {
	s := newTestStore(t)
	tenant := "t1"
	old, err := s.Create(sampleAlert("fire:r:alice:1", tenant, "r", "alice",
		baseT.Add(40*time.Second), "e1", "e2", "e3"))
	if err != nil {
		t.Fatal(err)
	}
	op := opOf("ops", tenant, RoleOperator)

	corr := Correction{
		ID: "corrrec:bf:r:alice:40", RequestID: "bf", TenantID: tenant,
		RuleID: "r", RuleVersion: 1, Entity: "alice", Kind: CorrectionChanged,
		WindowStart: baseT, WindowEnd: old.FireAt,
		OriginalAlertIDs: []string{old.ID},
		AddedEventIDs:    []string{"L0"},
		BaselineEventIDs: []string{"e1", "e2", "e3"},
		FinalEventIDs:    []string{"L0", "e1", "e2"},
		Reason:           "late event changed the window",
		OperatorID:       "ops",
	}
	newAlert := sampleAlert("corr:fire:r:alice:1:bf", tenant, "r", "alice",
		baseT.Add(20*time.Second), "L0", "e1", "e2")
	gotA, _, err := s.ApplyCorrection(corr, &newAlert)
	if err != nil {
		t.Fatalf("apply changed: %v", err)
	}
	if !gotA.IsCorrection || gotA.CorrectionID != corr.ID || gotA.Status != StatusOpen {
		t.Fatalf("corrected alert flags wrong: %+v", gotA)
	}

	// 正常查询只能看到一条当前有效结论。
	list := s.List(tenant)
	if len(list) != 1 || list[0].ID != gotA.ID {
		t.Fatalf("List must show only the corrected conclusion, got %+v", idsOf(list))
	}
	// 旧结论进入 superseded 终态。
	oldAfter, _ := s.Get(old.ID, op)
	if oldAfter.Status != StatusSuperseded || !oldAfter.Superseded ||
		oldAfter.SupersededBy != corr.ID {
		t.Fatalf("old alert must be superseded terminal, got %+v", oldAfter)
	}
	// 终态上的任何处置都被拒绝（且错误可区分），不会"列表能处置、处置又被拒"。
	if _, err := s.Ack(old.ID, op, ""); !errors.Is(err, ErrAlertSuperseded) {
		t.Fatalf("ack superseded: %v", err)
	}
	if _, err := s.Close(old.ID, op, ""); !errors.Is(err, ErrAlertSuperseded) {
		t.Fatalf("close superseded: %v", err)
	}
	if _, err := s.Reopen(old.ID, op, ""); !errors.Is(err, ErrAlertSuperseded) {
		t.Fatalf("reopen superseded: %v", err)
	}
	// 更正后的当前结论可以正常走生命周期。
	if a, err := s.Ack(gotA.ID, op, "handling"); err != nil || a.Status != StatusAcked {
		t.Fatalf("ack corrected: %v %v", a, err)
	}

	// 旧结论仍可追溯：历史列表、单条读取、更正记录互相串得起来。
	hist := s.ListHistory(tenant)
	if len(hist) != 2 {
		t.Fatalf("history must retain both, got %d", len(hist))
	}
	c2, err := s.GetCorrection(corr.ID, op)
	if err != nil {
		t.Fatal(err)
	}
	if len(c2.OriginalAlertIDs) != 1 || c2.OriginalAlertIDs[0] != old.ID ||
		c2.CorrectedAlertID != gotA.ID {
		t.Fatalf("correction trace chain broken: %+v", c2)
	}
	// 顺着旧告警能找到更正记录；顺着更正记录能找到补入事件与最终事件集合。
	if oldAfter.SupersededBy != c2.ID {
		t.Fatal("old alert must point at the correction")
	}
	if fmt.Sprint(c2.AddedEventIDs) != "[L0]" ||
		fmt.Sprint(c2.FinalEventIDs) != "[L0 e1 e2]" {
		t.Fatalf("traceability event sets wrong: %+v", c2)
	}

	// 旧告警的审计轨迹保留状态转换 + 取代记录。
	log, _ := s.AuditLog(old.ID, op)
	var actions []string
	for _, e := range log {
		actions = append(actions, e.Action)
	}
	t.Logf("old alert audit: %v", actions)
	found := false
	for _, a := range actions {
		if a == "supersede" {
			found = true
		}
	}
	if !found {
		t.Fatal("supersede must be audited on the old alert")
	}
}

// 同一窗口不允许第二条更正：无论是再次取代旧结论，还是去取代更正告警，都拒绝且无副作用。
func TestCorrectionWindowUniqueness(t *testing.T) {
	s := newTestStore(t)
	tenant := "t1"
	old, _ := s.Create(sampleAlert("fire:r:alice:1", tenant, "r", "alice",
		baseT.Add(40*time.Second), "e1", "e2", "e3"))
	corr1 := Correction{
		ID: "c1", RequestID: "bf1", TenantID: tenant, RuleID: "r", Entity: "alice",
		Kind: CorrectionChanged, WindowStart: baseT, WindowEnd: old.FireAt,
		OriginalAlertIDs: []string{old.ID}, FinalEventIDs: []string{"L", "e1", "e2"},
	}
	new1 := sampleAlert("corr:a1", tenant, "r", "alice", baseT.Add(20*time.Second), "L", "e1", "e2")
	if _, _, err := s.ApplyCorrection(corr1, &new1); err != nil {
		t.Fatal(err)
	}

	// 1) 同窗口身份再来一条更正（不同 correctionID）-> 拒绝。
	corr2 := corr1
	corr2.ID = "c2"
	corr2.RequestID = "bf2"
	_, _, err := s.ApplyCorrection(corr2, &new1)
	if !errors.Is(err, ErrWindowAlreadyCorrected) {
		t.Fatalf("second correction by window key: %v", err)
	}
	// 2) 试图把"更正告警"当原结论再更正一次 -> 同样拒绝。
	corr3 := Correction{
		ID: "c3", RequestID: "bf3", TenantID: tenant, RuleID: "r", Entity: "alice",
		Kind: CorrectionChanged, WindowStart: baseT, WindowEnd: new1.FireAt,
		OriginalAlertIDs: []string{new1.ID}, FinalEventIDs: []string{"L2"},
	}
	new3 := sampleAlert("corr:a3", tenant, "r", "alice", baseT.Add(15*time.Second), "L2")
	if _, _, err := s.ApplyCorrection(corr3, &new3); !errors.Is(err, ErrWindowAlreadyCorrected) {
		t.Fatalf("correcting a correction must be rejected: %v", err)
	}
	if len(s.ListCorrections(tenant)) != 1 {
		t.Fatal("rejected corrections must not be registered")
	}
	if len(s.List(tenant)) != 1 || s.List(tenant)[0].ID != new1.ID {
		t.Fatal("visible conclusion must remain the first correction")
	}

	// 3) 同 correctionID 重放 => 幂等返回同一结论。
	a3, c3got, err := s.ApplyCorrection(corr1, &new1)
	if err != nil || a3.ID != new1.ID || c3got.ID != "c1" {
		t.Fatalf("idempotent replay: %v %v %v", a3, c3got, err)
	}
	if len(s.ListCorrections(tenant)) != 1 {
		t.Fatal("idempotent replay must not double-register")
	}
}

// withdrawn：原结论进入终态，没有替代告警；再想合并抑制命中会被明确拒绝。
func TestCorrectionWithdrawnTerminal(t *testing.T) {
	s := newTestStore(t)
	tenant := "t1"
	old, _ := s.Create(sampleAlert("fire:r:alice:1", tenant, "r", "alice",
		baseT.Add(40*time.Second), "e1", "e2"))
	corr := Correction{
		ID: "cw", RequestID: "bf", TenantID: tenant, RuleID: "r", Entity: "alice",
		Kind: CorrectionWithdrawn, WindowStart: baseT, WindowEnd: old.FireAt,
		OriginalAlertIDs: []string{old.ID}, BaselineEventIDs: []string{"e1", "e2"},
	}
	a, got, err := s.ApplyCorrection(corr, nil)
	if err != nil || a != nil || got.Kind != CorrectionWithdrawn {
		t.Fatalf("withdrawn apply: %v %v %v", a, got, err)
	}
	if len(s.List(tenant)) != 0 {
		t.Fatal("withdrawn window must have no visible alert")
	}
	hist, _ := s.Get(old.ID, opOf("o", tenant, RoleOperator))
	if hist.Status != StatusSuperseded {
		t.Fatalf("withdrawn old alert terminal status=%s", hist.Status)
	}
	// 撤回没有替代告警：抑制命中无法被承接，返回可区分错误（由上层清理抑制期）。
	if err := s.MergeSuppressed(old.ID, tenant, []string{"x"}, old.ID); !errors.Is(err, ErrAlertSuperseded) {
		t.Fatalf("merge into withdrawn: %v", err)
	}
}

// 更正后的当前结论承接在线抑制命中（重定向），旧结论保持终态不被复活。
func TestSuppressedMergeRedirectsToCorrected(t *testing.T) {
	s := newTestStore(t)
	tenant := "t1"
	old, _ := s.Create(sampleAlert("fire:r:alice:1", tenant, "r", "alice",
		baseT.Add(40*time.Second), "e1", "e2", "e3"))
	corr := Correction{
		ID: "c", RequestID: "bf", TenantID: tenant, RuleID: "r", Entity: "alice",
		Kind: CorrectionChanged, WindowStart: baseT, WindowEnd: old.FireAt,
		OriginalAlertIDs: []string{old.ID}, FinalEventIDs: []string{"L", "e1", "e2"},
	}
	neu := sampleAlert("corr:a1", tenant, "r", "alice", baseT.Add(20*time.Second), "L", "e1", "e2")
	if _, _, err := s.ApplyCorrection(corr, &neu); err != nil {
		t.Fatal(err)
	}
	if err := s.MergeSuppressed(old.ID, tenant, []string{"e4", "e5"}, old.ID); err != nil {
		t.Fatalf("redirect merge: %v", err)
	}
	got, _ := s.Get(neu.ID, opOf("o", tenant, RoleOperator))
	if fmt.Sprint(got.EventIDs) != "[L e1 e2 e4 e5]" || got.SuppressedCount != 2 {
		t.Fatalf("suppressed hit must land on corrected alert: %v +%d",
			got.EventIDs, got.SuppressedCount)
	}
	oldAfter, _ := s.Get(old.ID, opOf("o", tenant, RoleOperator))
	if oldAfter.Status != StatusSuperseded || len(oldAfter.EventIDs) != 3 {
		t.Fatal("old alert must stay terminal and untouched")
	}
}

// 跨租户不能读/碰更正记录。
func TestCorrectionTenantIsolation(t *testing.T) {
	s := newTestStore(t)
	old, _ := s.Create(sampleAlert("a", "t1", "r", "alice", baseT, "e1"))
	corr := Correction{
		ID: "c", RequestID: "bf", TenantID: "t1", RuleID: "r", Entity: "alice",
		Kind: CorrectionWithdrawn, WindowStart: baseT, WindowEnd: old.FireAt,
		OriginalAlertIDs: []string{old.ID},
	}
	if _, _, err := s.ApplyCorrection(corr, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCorrection("c", opOf("x", "t2", RoleAdmin)); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("cross-tenant correction read: %v", err)
	}
	// 别租户同规则同实体同窗口的更正互不影响（窗口索引按租户隔离）。
	other := sampleAlert("a2", "t2", "r", "alice", baseT, "x1")
	if _, err := s.Create(other); err != nil {
		t.Fatal(err)
	}
	corr2 := corr
	corr2.ID = "c2"
	corr2.TenantID = "t2"
	corr2.OriginalAlertIDs = []string{"a2"}
	if _, _, err := s.ApplyCorrection(corr2, nil); err != nil {
		t.Fatalf("other tenant same window must be independent: %v", err)
	}
	if len(s.ListCorrections("t1")) != 1 || len(s.ListCorrections("t2")) != 1 {
		t.Fatal("corrections must be isolated per tenant")
	}
}

// 并发交错提交针对同一窗口的更正：恰好一条生效，其余全部拿到可区分拒绝，
// 存储中该窗口始终至多一条更正、一条可见结论。
func TestCorrectionConcurrentApplyUnique(t *testing.T) {
	for round := 0; round < 20; round++ {
		s := newTestStore(t)
		tenant := "t1"
		old, _ := s.Create(sampleAlert("fire:r:alice:1", tenant, "r", "alice",
			baseT.Add(40*time.Second), "e1", "e2", "e3"))
		var wg sync.WaitGroup
		var okN, rejectN int
		var mu sync.Mutex
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				id := fmt.Sprintf("c%d", i)
				c := Correction{
					ID: id, RequestID: "bf" + id, TenantID: tenant, RuleID: "r",
					Entity: "alice", Kind: CorrectionChanged,
					WindowStart: baseT, WindowEnd: old.FireAt,
					OriginalAlertIDs: []string{old.ID}, FinalEventIDs: []string{"L"},
				}
				neu := sampleAlert("corr:a"+id, tenant, "r", "alice",
					baseT.Add(20*time.Second), "L")
				_, _, err := s.ApplyCorrection(c, &neu)
				mu.Lock()
				if err == nil {
					okN++
				} else {
					rejectN++
				}
				mu.Unlock()
			}(i)
		}
		wg.Wait()
		if okN != 1 || rejectN != 7 {
			t.Fatalf("round %d: exactly one correction must win, got ok=%d reject=%d",
				round, okN, rejectN)
		}
		if len(s.List(tenant)) != 1 || len(s.ListCorrections(tenant)) != 1 {
			t.Fatalf("round %d: unique visible conclusion invariant broken", round)
		}
	}
}

func idsOf(as []*Alert) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.ID)
	}
	return out
}

// 批量更正中若有一个窗口冲突，整批回滚：已写入的更正/告警/终态全部撤销，
// 不留下"部分窗口已更正"的中间状态。
func TestApplyCorrectionsBatchAtomicRollback(t *testing.T) {
	s := newTestStore(t)
	tenant := "t1"
	old1, _ := s.Create(sampleAlert("fire:r:alice:1", tenant, "r", "alice",
		baseT.Add(40*time.Second), "e1", "e2", "e3"))
	old2, _ := s.Create(sampleAlert("fire:r:bob:1", tenant, "r", "bob",
		baseT.Add(40*time.Second), "b1", "b2", "b3"))

	type item = struct {
		Corr      Correction
		Corrected *Alert
	}
	// 先让 alice 的窗口已有一条更正（定案）。
	pre := Correction{
		ID: "pre", RequestID: "bf0", TenantID: tenant, RuleID: "r", Entity: "alice",
		Kind: CorrectionChanged, WindowStart: baseT, WindowEnd: old1.FireAt,
		OriginalAlertIDs: []string{old1.ID}, FinalEventIDs: []string{"L", "e1"},
	}
	preA := sampleAlert("corr:pre", tenant, "r", "alice", baseT.Add(20*time.Second), "L", "e1")
	if _, _, err := s.ApplyCorrection(pre, &preA); err != nil {
		t.Fatal(err)
	}

	// 批量：bob 窗口合法，alice 窗口冲突 => 整批失败。
	bobCorr := Correction{
		ID: "bobc", RequestID: "bf1", TenantID: tenant, RuleID: "r", Entity: "bob",
		Kind: CorrectionChanged, WindowStart: baseT, WindowEnd: old2.FireAt,
		OriginalAlertIDs: []string{old2.ID}, FinalEventIDs: []string{"M", "b1"},
	}
	bobA := sampleAlert("corr:bob", tenant, "r", "bob", baseT.Add(20*time.Second), "M", "b1")
	aliCorr := pre
	aliCorr.ID = "ali2"
	aliCorr.RequestID = "bf1"
	items := []item{{Corr: bobCorr, Corrected: &bobA}, {Corr: aliCorr, Corrected: &preA}}
	if _, _, err := s.ApplyCorrections(items); !errors.Is(err, ErrWindowAlreadyCorrected) {
		t.Fatalf("batch must fail with window-corrected: %v", err)
	}
	// bob 的窗口必须完全没被改动（回滚生效）。
	bobAfter, _ := s.Get(old2.ID, opOf("o", tenant, RoleOperator))
	if bobAfter.Superseded || bobAfter.Status == StatusSuperseded {
		t.Fatalf("bob must be rolled back to live state: %+v", bobAfter)
	}
	if _, err := s.Get("corr:bob", opOf("o", tenant, RoleOperator)); !errors.Is(err, ErrAlertNotFound) {
		t.Fatalf("bob corrected alert must be rolled back: %v", err)
	}
	if _, err := s.GetCorrection("bobc", opOf("o", tenant, RoleOperator)); !errors.Is(err, ErrCorrectionNotFound) {
		t.Fatalf("bob correction must be rolled back: %v", err)
	}
	// alice 仍是原来那一条更正；bob 的回滚意味着他那条【原始在线告警】依然有效可见。
	list := s.List(tenant)
	wantVisible := map[string]bool{"corr:pre": true, old2.ID: true}
	if len(list) != len(wantVisible) {
		t.Fatalf("visible count wrong: %+v", idsOf(list))
	}
	for _, a := range list {
		if !wantVisible[a.ID] {
			t.Fatalf("unexpected visible alert: %s", a.ID)
		}
	}
	if len(s.ListCorrections(tenant)) != 1 {
		t.Fatal("no new corrections may survive rollback")
	}
}
