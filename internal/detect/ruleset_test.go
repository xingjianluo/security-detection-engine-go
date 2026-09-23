package detect

import (
	"errors"
	"testing"
	"time"
)

func TestRuleSetVersioning(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	rs := NewRuleSet()
	r1 := Rule{ID: "r", TenantID: "t1", Version: 1, EventType: "login_fail",
		Window: time.Minute, Threshold: 3, SuppressFor: 5 * time.Minute,
		EffectiveAt: base}
	r2 := r1
	r2.Version = 2
	r2.Threshold = 5
	r2.EffectiveAt = base.Add(10 * time.Minute)
	if err := rs.Put(r1); err != nil {
		t.Fatal(err)
	}
	if err := rs.Put(r2); err != nil {
		t.Fatal(err)
	}

	// 事件时间 base+5m 仍适用 v1；base+10m 起适用 v2（与更新发生的墙钟时刻无关）。
	got, err := rs.EffectiveAt("t1", "r", base.Add(5*time.Minute))
	if err != nil || got.Version != 1 || got.Threshold != 3 {
		t.Fatalf("at base+5m want v1/3, got %+v err=%v", got, err)
	}
	got, err = rs.EffectiveAt("t1", "r", base.Add(10*time.Minute))
	if err != nil || got.Version != 2 || got.Threshold != 5 {
		t.Fatalf("at base+10m want v2/5, got %+v err=%v", got, err)
	}
	t.Logf("event_time=%s -> rule v%d threshold=%d",
		base.Add(5*time.Minute).Format(time.RFC3339Nano), got.Version-1, 3)
	t.Logf("event_time=%s -> rule v%d threshold=%d",
		base.Add(10*time.Minute).Format(time.RFC3339Nano), got.Version, got.Threshold)

	// 规则生效前 -> not found。
	if _, err := rs.EffectiveAt("t1", "r", base.Add(-time.Second)); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("want ErrRuleNotFound before EffectiveAt, got %v", err)
	}
	// 跨租户隔离。
	if _, err := rs.EffectiveAt("t2", "r", base.Add(20*time.Minute)); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("want ErrRuleNotFound cross-tenant, got %v", err)
	}
	// RulesFor 只返回当时生效版本。
	list := rs.RulesFor("t1", "login_fail", base.Add(5*time.Minute))
	if len(list) != 1 || list[0].Version != 1 {
		t.Fatalf("RulesFor returned %+v", list)
	}
	t.Log("规则更新只影响 EffectiveAt 之后的事件，已判定结论不会被静默改写")
}

func TestRuleSetRejects(t *testing.T) {
	rs := NewRuleSet()
	base := time.Now()
	if err := rs.Put(Rule{ID: "r", Version: 1}); err == nil {
		t.Fatal("want validation error for tenant/window/threshold")
	}
	r := Rule{ID: "r", TenantID: "t", Version: 1, Window: time.Minute,
		Threshold: 1, EffectiveAt: base}
	if err := rs.Put(r); err != nil {
		t.Fatal(err)
	}
	if err := rs.Put(r); err == nil {
		t.Fatal("want duplicate version error")
	}
	r2 := r
	r2.Version = 2
	r2.EffectiveAt = base.Add(-time.Minute) // 早于 v1
	if err := rs.Put(r2); err == nil {
		t.Fatal("want error: EffectiveAt must increase with version")
	}
}
