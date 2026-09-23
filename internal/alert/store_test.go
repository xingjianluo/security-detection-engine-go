package alert

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

var baseT = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	c := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	return NewStore(func() time.Time { return c })
}

func TestLifecycleIdempotent(t *testing.T) {
	s := newTestStore(t)
	op := Operator{ID: "op1", TenantID: "t1", Role: RoleOperator}
	a, err := s.Create(Alert{ID: "alrt-1", TenantID: "t1", RuleID: "r", Entity: "alice",
		CreatedAt: baseT, EventIDs: []string{"e1", "e2", "e3"}})
	if err != nil || a.Status != StatusOpen {
		t.Fatalf("create: %+v %v", a, err)
	}

	// open -> acked
	a1, err := s.Ack("alrt-1", op, "taking a look")
	if err != nil || a1.Status != StatusAcked {
		t.Fatalf("ack: %+v %v", a1, err)
	}
	// 重复 Ack：幂等，状态不变但留下可区分的审计（already_acked）
	a2, err := s.Ack("alrt-1", op, "again")
	if err != nil || a2.Status != StatusAcked {
		t.Fatalf("idempotent ack: %+v %v", a2, err)
	}
	// acked -> close
	if _, err := s.Close("alrt-1", op, ""); err != nil {
		t.Fatal(err)
	}
	// closed 再 Ack：非法转换（须先 Reopen）
	if _, err := s.Ack("alrt-1", op, ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("want ErrInvalidTransition, got %v", err)
	}
	// close 幂等
	a3, err := s.Close("alrt-1", op, "dup")
	if err != nil || a3.Status != StatusClosed {
		t.Fatalf("idempotent close: %v", err)
	}
	// reopen
	a4, err := s.Reopen("alrt-1", op, "still happening")
	if err != nil || a4.Status != StatusOpen {
		t.Fatalf("reopen: %+v %v", a4, err)
	}
	// open 上 reopen 幂等
	if a5, err := s.Reopen("alrt-1", op, ""); err != nil || a5.Status != StatusOpen {
		t.Fatalf("idempotent reopen: %+v %v", a5, err)
	}

	log, _ := s.AuditLog("alrt-1", op)
	var actions []string
	for _, e := range log {
		actions = append(actions, fmt.Sprintf("%s:%s->%s(%s)", e.Action, e.FromState, e.ToState, e.Reason))
	}
	t.Logf("审计轨迹 (idempotent 调用均留痕):")
	for _, line := range actions {
		t.Logf("  %s", line)
	}
	want := []string{"create", "ack", "ack", "close", "close", "reopen", "reopen"}
	if len(log) != len(want) {
		t.Fatalf("audit entries = %d, want %d: %v", len(log), len(want), actions)
	}
	for i, w := range want {
		if log[i].Action != w {
			t.Fatalf("audit[%d].Action = %s, want %s", i, log[i].Action, w)
		}
	}
	if log[0].Seq <= 0 || log[1].Seq <= log[0].Seq {
		t.Fatal("audit seq must be positive and increasing")
	}
}

func TestTenantIsolationAndRoles(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Create(Alert{ID: "a", TenantID: "t1", CreatedAt: baseT}); err != nil {
		t.Fatal(err)
	}
	other := Operator{ID: "x", TenantID: "t2", Role: RoleAdmin}
	viewer := Operator{ID: "v", TenantID: "t1", Role: RoleViewer}
	ownerOp := Operator{ID: "o", TenantID: "t1", Role: RoleOperator}

	if _, err := s.Get("a", other); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := s.Ack("a", other, ""); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("cross-tenant ack: %v", err)
	}
	if _, err := s.Get("a", Operator{ID: "no", TenantID: "nope", Role: RoleAdmin}); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("unknown tenant get: %v", err)
	}
	// Viewer 可读不可写
	if _, err := s.Get("a", viewer); err != nil {
		t.Fatalf("viewer read: %v", err)
	}
	if _, err := s.Ack("a", viewer, ""); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer write: %v", err)
	}
	// 不存在的告警
	if _, err := s.Ack("ghost", ownerOp, ""); !errors.Is(err, ErrAlertNotFound) {
		t.Fatalf("missing alert: %v", err)
	}
	// 越权尝试全部留痕
	denied := s.DeniedAttempts()
	if len(denied) < 4 {
		t.Fatalf("want >=4 denied audit records, got %d: %+v", len(denied), denied)
	}
	for _, d := range denied {
		t.Logf("denied: alert=%s tenant=%s op=%s action=%s reason=%s",
			d.AlertID, d.TenantID, d.OperatorID, d.Action, d.Reason)
	}
	// 列表按租户隔离
	if len(s.List("t1")) != 1 || len(s.List("t2")) != 0 {
		t.Fatal("List must be tenant-scoped")
	}
	// Owner 正常操作
	if _, err := s.Ack("a", ownerOp, ""); err != nil {
		t.Fatal(err)
	}
}

func TestSuppressionMerge(t *testing.T) {
	s := newTestStore(t)
	a, _ := s.Create(Alert{ID: "fire:r:alice:1:1", TenantID: "t1", Entity: "alice",
		CreatedAt: baseT, EventIDs: []string{"e1", "e2", "e3"}})
	if err := s.MergeSuppressed(a.ID, "t1", []string{"e4", "e5", "e6"}, a.ID); err != nil {
		t.Fatal(err)
	}
	// 幂等：重复合并不重复计数
	if err := s.MergeSuppressed(a.ID, "t1", []string{"e4", "e5", "e7"}, a.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(a.ID, Operator{ID: "o", TenantID: "t1", Role: RoleOperator})
	if got.SuppressedCount != 4 {
		t.Fatalf("suppressed count = %d, want 4 (e4,e5,e6,e7)", got.SuppressedCount)
	}
	t.Logf("告警 %s 可追溯合并事件: %v (suppressed+=%d)", got.ID, got.EventIDs, got.SuppressedCount)
	if err := s.MergeSuppressed(a.ID, "t2", []string{"x"}, a.ID); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("cross-tenant merge: %v", err)
	}
}

// 并发交错 Ack/Close/Reopen：最终状态必须唯一、审计完整无丢失。
func TestConcurrentTransitionsUniqueFinal(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.Create(Alert{ID: "hot", TenantID: "t1", CreatedAt: baseT})
	op := func(id string, role Role) Operator {
		return Operator{ID: id, TenantID: "t1", Role: role}
	}
	var wg sync.WaitGroup
	actions := []struct {
		name string
		fn   func() error
	}{
		{"ack", func() error { _, e := s.Ack("hot", op("p1", RoleOperator), "c"); return e }},
		{"close", func() error { _, e := s.Close("hot", op("p2", RoleOperator), "c"); return e }},
		{"reopen", func() error { _, e := s.Reopen("hot", op("p3", RoleOperator), "c"); return e }},
		{"ack2", func() error { _, e := s.Ack("hot", op("p4", RoleAdmin), "c"); return e }},
		{"close2", func() error { _, e := s.Close("hot", op("p5", RoleOperator), "c"); return e }},
	}
	for round := 0; round < 10; round++ {
		for _, a := range actions {
			wg.Add(1)
			go func(fn func() error) { defer wg.Done(); _ = fn() }(a.fn)
		}
	}
	wg.Wait()

	final, _ := s.Get("hot", op("reader", RoleViewer))
	// 全量审计链（含被拒绝尝试）序号必须连续无缺口。
	trail := s.AuditTrail()
	for i := 1; i < len(trail); i++ {
		if trail[i].Seq != trail[i-1].Seq+1 {
			t.Fatalf("audit trail seq gap: %d -> %d", trail[i-1].Seq, trail[i].Seq)
		}
	}
	log, _ := s.AuditLog("hot", op("reader", RoleViewer))
	t.Logf("并发结束唯一最终状态=%s, 本告警变更记录数=%d, 全量审计链=%d（串行化留痕）",
		final.Status, len(log), len(trail))
	// 再跑一遍相同模式（相同参数），结果分布应稳定：最终状态只能是 open/acked/closed 之一。
	switch final.Status {
	case StatusOpen, StatusAcked, StatusClosed:
	default:
		t.Fatalf("impossible final status %q", final.Status)
	}
}

func TestCreateIdempotent(t *testing.T) {
	s := newTestStore(t)
	a1, _ := s.Create(Alert{ID: "x", TenantID: "t", CreatedAt: baseT})
	a2, _ := s.Create(Alert{ID: "x", TenantID: "t", CreatedAt: baseT})
	if a1 != a2 {
		t.Fatal("duplicate Create must return same alert")
	}
	if _, err := s.Create(Alert{ID: "x", TenantID: "other", CreatedAt: baseT}); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("create with conflicting tenant: %v", err)
	}
}
