package alert

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/rule"
)

var base = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

func finding(tenant string, ruleVer rule.Version, entity, trigger string, atSec int, matched ...string) *detect.Finding {
	if len(matched) == 0 {
		matched = []string{trigger}
	}
	return &detect.Finding{
		Tenant: tenant, RuleID: "r1", RuleVersion: ruleVer, Entity: entity,
		TriggerEventID: trigger, EventTime: base.Add(time.Duration(atSec) * time.Second),
		MatchedEventIDs: matched, Count: len(matched), Threshold: 3,
	}
}

func TestSuppressRepeatedHitsIntoOneAlert(t *testing.T) {
	s := NewStore()
	suppress := 10 * time.Second

	o1, a1 := s.ApplyFinding(finding("t1", 1, "h1", "e0", 0, "e0", "e1", "e2"), suppress, base)
	o2, a2 := s.ApplyFinding(finding("t1", 1, "h1", "e3", 5), suppress, base.Add(5*time.Second))
	o3, a3 := s.ApplyFinding(finding("t1", 1, "h1", "e4", 9), suppress, base.Add(9*time.Second))

	if o1 != OutcomeCreated || a1.Status != StatusOpen {
		t.Fatalf("first hit must create: %s", o1)
	}
	if o2 != OutcomeMerged || a2.ID != a1.ID {
		t.Fatalf("hit within suppression must merge: %s", o2)
	}
	if o3 != OutcomeMerged {
		t.Fatalf("hit at edge of suppression must merge: %s", o3)
	}
	if a3.SuppressedCount != 2 {
		t.Fatalf("suppressed count = %d, want 2", a3.SuppressedCount)
	}
	if !a3.HasEvent("e3") || !a3.HasEvent("e4") {
		t.Fatalf("merged events must be traceable: %v", a3.MergedEventIDs)
	}
	t.Logf("判定依据：一条告警 %s 合并事件轨迹=%v 抑制命中数=%d",
		a3.ID, a3.MergedEventIDs, a3.SuppressedCount)

	// 抑制窗口外（>first+10s）的新命中另起一条告警；旧告警仍保留。
	o4, a4 := s.ApplyFinding(finding("t1", 1, "h1", "e9", 11), suppress, base.Add(11*time.Second))
	if o4 != OutcomeCreated || a4.ID == a1.ID {
		t.Fatalf("hit after suppress-until must create a new alert: %s", o4)
	}
	if len(s.List("t1")) != 2 {
		t.Fatalf("two alerts expected, got %d", len(s.List("t1")))
	}
}

func TestMergeIsIdempotentOnReplay(t *testing.T) {
	s := NewStore()
	o1, a1 := s.ApplyFinding(finding("t1", 1, "h1", "e0", 0, "e0", "e1", "e2"), 10*time.Second, base)
	o2, a2 := s.ApplyFinding(finding("t1", 1, "h1", "e3", 5), 10*time.Second, base.Add(5*time.Second))
	// 确定性重放同样的两个 finding，不得新增告警、不得重复计数。
	s.ApplyFinding(finding("t1", 1, "h1", "e0", 0, "e0", "e1", "e2"), 10*time.Second, base)
	o3, a3 := s.ApplyFinding(finding("t1", 1, "h1", "e3", 5), 10*time.Second, base.Add(5*time.Second))
	if o1 != OutcomeCreated || o2 != OutcomeMerged || o3 != OutcomeIgnoredDup {
		t.Fatalf("replay outcomes: %s %s %s", o1, o2, o3)
	}
	if !a2.HasEvent("e3") || a3.SuppressedCount != 1 || len(s.List("t1")) != 1 {
		t.Fatalf("replay changed state: count=%d alerts=%d", a3.SuppressedCount, len(s.List("t1")))
	}
	if a1.ID != a3.ID {
		t.Fatal("alert identity must be deterministic across replays")
	}
}

func TestLifecycleIdempotent(t *testing.T) {
	s := NewStore()
	_, a := s.ApplyFinding(finding("t1", 1, "h1", "e0", 0), 0, base)
	id := a.ID

	tr, err := s.Acknowledge("t1", id, "alice", -1, base.Add(time.Second))
	if err != nil || !tr.Changed || tr.To != StatusAcked || tr.Version != 2 {
		t.Fatalf("first ack: %+v err=%v", tr, err)
	}
	// 重复确认：幂等 no-op，版本不变。
	tr2, err := s.Acknowledge("t1", id, "alice", -1, base.Add(2*time.Second))
	if err != nil || tr2.Changed || tr2.Version != 2 {
		t.Fatalf("duplicate ack must be idempotent: %+v err=%v", tr2, err)
	}
	// 关闭。
	tr3, err := s.Close("t1", id, "alice", -1, base.Add(3*time.Second))
	if err != nil || !tr3.Changed || tr3.To != StatusClosed {
		t.Fatalf("close: %+v err=%v", tr3, err)
	}
	// Closed 重开合法，且重复重开幂等。
	tr4, err := s.Reopen("t1", id, "alice", -1, base.Add(4*time.Second))
	if err != nil || !tr4.Changed || tr4.To != StatusOpen {
		t.Fatalf("reopen: %+v err=%v", tr4, err)
	}
	tr5, _ := s.Reopen("t1", id, "alice", -1, base.Add(5*time.Second))
	if tr5.Changed {
		t.Fatal("reopen on open alert must be idempotent no-op")
	}
	// Acked -> Reopen 必须非法。
	s.Acknowledge("t1", id, "alice", -1, base.Add(6*time.Second))
	if _, err := s.Reopen("t1", id, "alice", -1, base.Add(7*time.Second)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reopen from acked must be rejected, got %v", err)
	}
	// 关闭幂等。
	s.Close("t1", id, "alice", -1, base.Add(8*time.Second))
	tr7, err := s.Close("t1", id, "alice", -1, base.Add(9*time.Second))
	if err != nil || tr7.Changed {
		t.Fatalf("close on closed must be idempotent: %+v err=%v", tr7, err)
	}
	t.Logf("判定依据：版本轨迹 v1(open) -> %s", trace(s, id))
}

func trace(s *Store, id string) string {
	a, _ := s.Get("t1", id)
	return fmt.Sprintf("v%d(%s, merged=%v)", a.Version, a.Status, a.MergedEventIDs)
}

func TestCASConflictAndFinalStateUnique(t *testing.T) {
	s := NewStore()
	_, a := s.ApplyFinding(finding("t1", 1, "h1", "e0", 0), 0, base)
	id := a.ID

	// 两个并发提交都基于 v1：只有一个成功。
	done := make(chan string, 2)
	transition := func(op string) {
		var tr Transition
		var err error
		switch op {
		case "ack":
			tr, err = s.Acknowledge("t1", id, "u-"+op, 1, base.Add(time.Second))
		case "close":
			tr, err = s.Close("t1", id, "u-"+op, 1, base.Add(time.Second))
		}
		if err != nil {
			done <- op + ":ERR:" + err.Error()
			return
		}
		done <- fmt.Sprintf("%s:%s(changed=%v,v=%d)", op, tr.To, tr.Changed, tr.Version)
	}
	go transition("ack")
	go transition("close")
	r1, r2 := <-done, <-done
	t.Logf("并发提交结果：%s | %s", r1, r2)
	if r1 == r2 {
		t.Fatal("two identical results impossible")
	}
	errs := 0
	if containsErr(r1) {
		errs++
	}
	if containsErr(r2) {
		errs++
	}
	if errs != 1 {
		t.Fatalf("exactly one CAS submission must fail, got %q / %q", r1, r2)
	}
	// 最终状态唯一可解释。
	final, _ := s.Get("t1", id)
	t.Logf("最终唯一状态：%s v%d", final.Status, final.Version)
}

func containsErr(s string) bool {
	return len(s) >= 4 && s[len(s)-len(ErrVersionConflict.Error()):] == ErrVersionConflict.Error()
}

func TestCrossTenantDenied(t *testing.T) {
	s := NewStore()
	_, a := s.ApplyFinding(finding("t1", 1, "h1", "e0", 0), 0, base)

	if _, err := s.Get("t2", a.ID); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("cross-tenant get must be denied, got %v", err)
	}
	if _, err := s.Close("t2", a.ID, "mallory", -1, base); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("cross-tenant close must be denied, got %v", err)
	}
	if _, err := s.Get("t1", "alrt-nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing alert must be ErrNotFound, got %v", err)
	}
	if _, err := s.Close("t1", a.ID, "", -1, base); !errors.Is(err, ErrEmptyOperator) {
		t.Fatalf("operator-less op must be denied, got %v", err)
	}
	if s.List("") != nil {
		t.Fatal("listing with empty tenant must be refused to prevent cross-tenant scan")
	}
	// 越权尝试不得改变状态。
	cur, _ := s.Get("t1", a.ID)
	if cur.Status != StatusOpen {
		t.Fatalf("denied op changed status to %s", cur.Status)
	}
}

func TestClosedAlertAllowsNewFire(t *testing.T) {
	s := NewStore()
	_, a := s.ApplyFinding(finding("t1", 1, "h1", "e0", 0), 0, base)
	if _, err := s.Close("t1", a.ID, "alice", -1, base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// suppress=0：关闭后同键新触发必须能立即起新告警。
	o2, a2 := s.ApplyFinding(finding("t1", 1, "h1", "e5", 5), 0, base.Add(5*time.Second))
	if o2 != OutcomeCreated || a2.ID == a.ID {
		t.Fatalf("new fire after close must create fresh alert, got %s", o2)
	}
}
