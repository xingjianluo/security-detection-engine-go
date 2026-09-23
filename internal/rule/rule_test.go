package rule

import (
	"errors"
	"testing"
	"time"
)

func baseRule() Rule {
	return Rule{ID: "r1", Tenant: "t1", Threshold: 3, Window: 10 * time.Second, Suppression: time.Second}
}

func TestVersionSelectionByEventTime(t *testing.T) {
	c := NewCatalog()
	t0 := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	v1, err := c.AddVersion(baseRule())
	if err != nil {
		t.Fatal(err)
	}
	if v1.Version != 1 || !v1.EffectiveFrom.IsZero() {
		t.Fatalf("first version: %+v", v1)
	}

	r2 := baseRule()
	r2.Threshold = 5
	v2, err := c.AddVersion(r2)
	if err == nil {
		t.Fatal("subsequent version without explicit effective-from must be rejected")
	}
	if !errors.Is(err, ErrBadEffective) {
		t.Fatalf("err = %v", err)
	}

	r2.EffectiveFrom = t0
	v2, err = c.AddVersion(r2)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Version != 2 {
		t.Fatalf("version = %d, want 2", v2.Version)
	}

	if got := c.VersionAt("t1", "r1", t0.Add(-time.Hour)); got.Version != 1 {
		t.Fatalf("before cutover should resolve v1, got v%d", got.Version)
	}
	if got := c.VersionAt("t1", "r1", t0); got.Version != 2 {
		t.Fatalf("at/after cutover should resolve v2, got v%d", got.Version)
	}
	if got := c.VersionAt("t1", "r1", t0.Add(time.Hour)); got.Version != 2 {
		t.Fatalf("after cutover should resolve v2, got v%d", got.Version)
	}
}

func TestAddVersionValidation(t *testing.T) {
	c := NewCatalog()
	r := baseRule()
	r.ID = ""
	if _, err := c.AddVersion(r); !errors.Is(err, ErrEmptyID) {
		t.Fatalf("want ErrEmptyID, got %v", err)
	}
	r = baseRule()
	r.Threshold = 0
	if _, err := c.AddVersion(r); !errors.Is(err, ErrBadThreshold) {
		t.Fatalf("want ErrBadThreshold, got %v", err)
	}
	r = baseRule()
	r.Window = 0
	if _, err := c.AddVersion(r); !errors.Is(err, ErrBadWindow) {
		t.Fatalf("want ErrBadWindow, got %v", err)
	}
}

func TestCutoverMonotonicity(t *testing.T) {
	c := NewCatalog()
	t0 := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	if _, err := c.AddVersion(baseRule()); err != nil {
		t.Fatal(err)
	}
	r2 := baseRule()
	r2.EffectiveFrom = t0
	if _, err := c.AddVersion(r2); err != nil {
		t.Fatal(err)
	}
	r3 := baseRule()
	r3.EffectiveFrom = t0.Add(-time.Second)
	if _, err := c.AddVersion(r3); !errors.Is(err, ErrBadEffective) {
		t.Fatalf("non-monotonic effective-from must be rejected, got %v", err)
	}
}

func TestMatchFilters(t *testing.T) {
	r := Rule{ID: "r", Tenant: "t1", EventType: "fail", EntityScope: "host-1", Threshold: 1, Window: time.Second}
	if !r.Match("t1", "fail", "host-1") {
		t.Fatal("should match")
	}
	if r.Match("t2", "fail", "host-1") {
		t.Fatal("tenant mismatch must not match")
	}
	if r.Match("t1", "ok", "host-1") {
		t.Fatal("type mismatch must not match")
	}
	if r.Match("t1", "fail", "host-2") {
		t.Fatal("entity mismatch must not match")
	}
}
