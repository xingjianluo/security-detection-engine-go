package alert

import (
	"errors"
	"testing"
	"time"
)

func corrWindow() (time.Time, time.Time) {
	return baseT, baseT.Add(time.Minute)
}

// 撤回：旧告警进入 superseded 终态；无替代告警；List 不可见、ListHistory 可见。
func TestCorrectionWithdrawLifecycle(t *testing.T) {
	s := newTestStore(t)
	op := Operator{ID: "op1", TenantID: "t1", Role: RoleOperator}
	a, err := s.Create(Alert{ID: "a1", TenantID: "t1", RuleID: "r", Entity: "alice",
		CreatedAt: baseT, FireAt: baseT.Add(20 * time.Second), EventIDs: []string{"e1", "e2", "e3"}})
	if err != nil {
		t.Fatal(err)
	}
	// 先 ack，确认撤回审计记录的是真实前置状态 acked -> superseded。
	if _, err := s.Ack(a.ID, op, "looking"); err != nil {
		t.Fatal(err)
	}
	ws, we := corrWindow()
	corr := Correction{ID: "c1", RequestID: "req1", TenantID: "t1", RuleID: "r",
		Entity: "alice", Kind: CorrectionWithdrawn, WindowStart: ws, WindowEnd: we,
		OriginalAlertIDs: []string{"a1"}, AddedEventIDs: []string{"x1"},
		Reason: "no longer holds", OperatorID: "op1"}
	got, err := s.RegisterWithdrawal(corr)
	if err != nil {
		t.Fatal(err)
	}
	if got.CorrectedAlertID != "" {
		t.Fatal("withdrawn has no replacement alert")
	}
	if len(s.List("t1")) != 0 {
		t.Fatal("withdrawn alert must leave the active view")
	}
	hist := s.ListHistory("t1")
	if len(hist) != 1 || hist[0].Status != StatusSuperseded || !hist[0].Superseded ||
		hist[0].SupersededBy != "c1" {
		t.Fatalf("history must retain superseded record: %+v", hist)
	}
	// 处置一律拒绝，且错误可区分。
	for _, fn := range []func() error{
		func() error { _, e := s.Ack("a1", op, ""); return e },
		func() error { _, e := s.Close("a1", op, ""); return e },
		func() error { _, e := s.Reopen("a1", op, ""); return e },
	} {
		if err := fn(); !errors.Is(err, ErrAlertSuperseded) {
			t.Fatalf("want ErrAlertSuperseded, got %v", err)
		}
	}
	// 撤回审计体现 acked -> superseded。
	log, _ := s.AuditLog("a1", op)
	var saw bool
	for _, e := range log {
		if e.Action == "supersede" {
			saw = true
			if e.FromState != StatusAcked || e.ToState != StatusSuperseded {
				t.Fatalf("supersede audit %s->%s", e.FromState, e.ToState)
			}
		}
	}
	if !saw {
		t.Fatal("supersede audit missing")
	}
	// 幂等：同 correctionID 再登记不重复、不报错。
	if got2, err := s.RegisterWithdrawal(corr); err != nil || got2.ID != "c1" {
		t.Fatalf("idempotent withdrawal: %+v %v", got2, err)
	}
	if len(s.ListCorrections("t1")) != 1 {
		t.Fatal("duplicate withdrawal registered")
	}
}

// 窗口冲突：同一（租户,规则,实体,FireAt）已有另一条有效结论时，
// 新更正必须被拒绝，且不得产生任何半更新。
func TestCorrectionWindowConflictGuard(t *testing.T) {
	s := newTestStore(t)
	a1, _ := s.Create(Alert{ID: "a1", TenantID: "t1", RuleID: "r", Entity: "alice",
		CreatedAt: baseT, FireAt: baseT.Add(20 * time.Second), EventIDs: []string{"e1"}})
	a2, _ := s.Create(Alert{ID: "a2", TenantID: "t1", RuleID: "r", Entity: "alice",
		CreatedAt: baseT, FireAt: baseT.Add(80 * time.Second), EventIDs: []string{"e9"}})
	_ = a1
	_ = a2

	mk := func(id string, orig []string, fireAt time.Time, alertID string) (Correction, Alert) {
		c := Correction{ID: id, RequestID: "r-" + id, TenantID: "t1", RuleID: "r",
			Entity: "alice", Kind: CorrectionChanged, WindowStart: baseT, WindowEnd: fireAt,
			OriginalAlertIDs: orig, FinalEventIDs: []string{"e1", "e2"}}
		na := Alert{ID: alertID, TenantID: "t1", RuleID: "r", Entity: "alice",
			CreatedAt: baseT, FireAt: fireAt, EventIDs: []string{"e1", "e2"}}
		return c, na
	}

	// 想在 a2 的窗口（FireAt=t+80s）插入一条并列更正，但 OriginalAlertIDs 不含 a2：
	// 目标窗口已有有效结论 a2 => 冲突拒绝，什么都不许改。
	c, na := mk("cX", nil, baseT.Add(80*time.Second), "new-x")
	if _, _, err := s.CreateCorrected(c, na); !errors.Is(err, ErrCorrectionConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	if got, _ := s.Get("a2", Operator{TenantID: "t1"}); got.Superseded {
		t.Fatal("conflict must not mutate existing alert")
	}
	if len(s.ListCorrections("t1")) != 0 {
		t.Fatal("conflict must not register correction")
	}

	// 正常更正 a1 的窗口（FireAt=t+20s）成功。
	c2, na2 := mk("c2", []string{"a1"}, baseT.Add(20*time.Second), "new-2")
	out, created, err := s.CreateCorrected(c2, na2)
	if err != nil {
		t.Fatal(err)
	}
	if !out.IsCorrection || out.CorrectionID != "c2" || len(out.Supersedes) != 1 || out.Supersedes[0] != "a1" {
		t.Fatalf("corrected alert links wrong: %+v", out)
	}
	if created.CorrectedAlertID != "new-2" {
		t.Fatalf("correction link: %s", created.CorrectedAlertID)
	}
	// 幂等：同 correctionID 返回既有结论。
	out2, c2got, err := s.CreateCorrected(c2, na2)
	if err != nil || out2.ID != "new-2" || c2got.ID != "c2" {
		t.Fatalf("idempotent correction: %+v %+v %v", out2, c2got, err)
	}
	if len(s.List("t1")) != 2 { // new-2（a1 窗口）+ a2（另一窗口）
		t.Fatalf("active view wrong: %d", len(s.List("t1")))
	}

	// 不取代当前有效结论 new-2，却想在同一窗口再落一条 => 冲突。
	c3, na3 := mk("c3", []string{"a1"}, baseT.Add(20*time.Second), "new-3")
	if _, _, err := s.CreateCorrected(c3, na3); !errors.Is(err, ErrCorrectionConflict) {
		t.Fatalf("parallel correction in same window must conflict, got %v", err)
	}
	if len(s.ListCorrections("t1")) != 1 {
		t.Fatal("conflict must not register a correction")
	}
}

// 已被撤回取代的旧告警不能被另一条更正再取代（同一记录只允许一条取代链）。
func TestCorrectionCannotSupersedeTwice(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.Create(Alert{ID: "a1", TenantID: "t1", RuleID: "r", Entity: "alice",
		CreatedAt: baseT, FireAt: baseT.Add(20 * time.Second)})
	ws, we := corrWindow()
	c1 := Correction{ID: "c1", RequestID: "r1", TenantID: "t1", RuleID: "r", Entity: "alice",
		WindowStart: ws, WindowEnd: we, OriginalAlertIDs: []string{"a1"}}
	if _, err := s.RegisterWithdrawal(c1); err != nil {
		t.Fatal(err)
	}
	// 同一旧告警、另一条更正 ID => 拒绝，且不登记第二条更正。
	c2 := c1
	c2.ID = "c2"
	c2.RequestID = "r2"
	if _, err := s.RegisterWithdrawal(c2); !errors.Is(err, ErrAlertSuperseded) {
		t.Fatalf("double supersede must fail with ErrAlertSuperseded, got %v", err)
	}
	if len(s.ListCorrections("t1")) != 1 {
		t.Fatal("no second correction may be registered")
	}
	// Supersede 公开入口同样拒绝。
	if err := s.Supersede("a1", "c9", "again"); !errors.Is(err, ErrAlertSuperseded) {
		t.Fatalf("Supersede twice: %v", err)
	}
}

// 更正记录的租户隔离。
func TestCorrectionCrossTenant(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.Create(Alert{ID: "a1", TenantID: "t1", RuleID: "r", Entity: "alice",
		CreatedAt: baseT, FireAt: baseT.Add(20 * time.Second)})
	ws, we := corrWindow()
	c := Correction{ID: "c1", RequestID: "req", TenantID: "t1", RuleID: "r", Entity: "alice",
		WindowStart: ws, WindowEnd: we, OriginalAlertIDs: []string{"a1"}}
	if _, err := s.RegisterWithdrawal(c); err != nil {
		t.Fatal(err)
	}
	other := Operator{ID: "x", TenantID: "t2", Role: RoleAdmin}
	if _, err := s.GetCorrection("c1", other); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("cross-tenant get correction: %v", err)
	}
	if len(s.ListCorrections("t2")) != 0 || len(s.ListCorrections("t1")) != 1 {
		t.Fatal("corrections must be tenant scoped")
	}
	denied := s.DeniedAttempts()
	if len(denied) == 0 {
		t.Fatal("cross-tenant attempt must be audited")
	}
}
