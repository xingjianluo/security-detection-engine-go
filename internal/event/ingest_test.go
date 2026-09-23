package event

import (
	"fmt"
	"testing"
	"time"
)

func mkEvent(id, entity string, t time.Time) *Event {
	return &Event{ID: id, Type: "login_fail", Entity: entity, EventTime: t, ReceivedAt: t}
}

// 两个判定器以完全相反的到达顺序喂入同一批事件（含重复投递），
// 在统一的水位断言后，释放序列与判定类别必须完全一致。
func TestIngestOrderIndependence(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	uniq := []*Event{
		mkEvent("a", "alice", base),
		mkEvent("b", "bob", base.Add(5*time.Second)),
		mkEvent("c", "alice", base.Add(10*time.Second)),
		mkEvent("d", "alice", base.Add(15*time.Second)),
		mkEvent("e", "bob", base.Add(40*time.Second)),
	}
	// 每个序列都额外重投一次 a，验证重复不影响结论。
	fwd := append(append([]*Event{}, uniq...), mkEvent("a", "alice", base))
	rev := []*Event{}
	for i := len(uniq) - 1; i >= 0; i-- {
		rev = append(rev, uniq[i])
	}
	rev = append(rev, mkEvent("a", "alice", base))

	run := func(name string, seq []*Event) []string {
		g := NewIngestor(IngestConfig{AllowedLateness: 30 * time.Second})
		for _, e := range seq {
			g.Admit(e) // 断言水位前不做迟到判定
		}
		out := g.AdvanceWatermark(base.Add(time.Minute))
		var ids []string
		for _, e := range out {
			ids = append(ids, e.ID)
		}
		seen, dup := g.Stats()
		t.Logf("[%s] asserted_wm=%s released=%v seen=%d duplicates=%d",
			name, base.Add(time.Minute).Format(time.RFC3339Nano), ids, seen, dup)
		return ids
	}

	ids1 := run("forward+duplicate", fwd)
	ids2 := run("reverse+duplicate", rev)
	if fmt.Sprint(ids1) != fmt.Sprint(ids2) {
		t.Fatalf("released sequence differs by arrival order: %v vs %v", ids1, ids2)
	}
	want := "[a b c d e]"
	if fmt.Sprint(ids1) != want {
		t.Fatalf("released = %v, want %s (sorted by event_time,entity,id)", ids1, want)
	}
}

func TestIngestLateAfterWatermark(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	g := NewIngestor(IngestConfig{AllowedLateness: 10 * time.Second})
	t.Logf("time_base=%s semantics: event arriving after watermark W with t<=W is late",
		base.Format(time.RFC3339))

	if o := g.Admit(mkEvent("early", "alice", base)); o.Disposition != DispAccepted {
		t.Fatalf("want accepted before any watermark, got %s", o.Disposition)
	}
	g.AdvanceWatermark(base.Add(time.Minute)) // 断言 t<=base+60 均已到齐

	late := mkEvent("late", "alice", base.Add(20*time.Second))
	o := g.Admit(late)
	if o.Disposition != DispLate {
		t.Fatalf("want late, got %s", o.Disposition)
	}
	t.Logf("event late event_time=%s -> %s (%s)",
		late.EventTime.Format(time.RFC3339Nano), o.Disposition, o.Quarantine.Detail)

	// 迟到事件重投：去重优先，判重复且不重复隔离。
	if o2 := g.Admit(mkEvent("late", "alice", base.Add(20*time.Second))); o2.Disposition != DispDuplicate {
		t.Fatalf("redelivered late event: want duplicate, got %s", o2.Disposition)
	}
	// 已正常处理事件的重投也是重复。
	if o3 := g.Admit(mkEvent("early", "alice", base)); o3.Disposition != DispDuplicate {
		t.Fatalf("redelivered normal event: want duplicate, got %s", o3.Disposition)
	}
	t.Logf("redelivery judged as duplicate with dedup-before-lateness priority")

	if q := g.Quarantine(); len(q) != 1 || q[0].Disposition != DispLate {
		t.Fatalf("want exactly 1 late quarantine record, got %+v", q)
	}
	seen, dup := g.Stats()
	if seen != 4 || dup != 2 {
		t.Fatalf("stats seen=%d dup=%d, want 4/2", seen, dup)
	}
	t.Logf("stats: seen=%d duplicates=%d late_quarantined=1", seen, dup)
}

func TestIngestTickOnline(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	g := NewIngestor(IngestConfig{AllowedLateness: 10 * time.Second})
	g.Admit(mkEvent("a", "x", base))
	g.Admit(mkEvent("b", "x", base.Add(5*time.Second)))
	g.Admit(mkEvent("c", "x", base.Add(30*time.Second)))
	out := g.Tick() // 断言 W = base+20
	var ids []string
	for _, e := range out {
		ids = append(ids, e.ID)
	}
	if fmt.Sprint(ids) != "[a b]" {
		t.Fatalf("tick released %v, want [a b]", ids)
	}
	// 在线模式：W=base+20 之后到达的 t=base+10 事件属迟到。
	o := g.Admit(mkEvent("z", "x", base.Add(10*time.Second)))
	if o.Disposition != DispLate {
		t.Fatalf("want late after online tick, got %s", o.Disposition)
	}
	// 但 t=base+25（在 W 之后）仍可接收。
	if o2 := g.Admit(mkEvent("d", "x", base.Add(25*time.Second))); o2.Disposition != DispAccepted {
		t.Fatalf("want accepted for t beyond watermark, got %s", o2.Disposition)
	}
	t.Logf("online Tick W=base+20: released [a b]; t=base+10 late, t=base+25 accepted")
}
