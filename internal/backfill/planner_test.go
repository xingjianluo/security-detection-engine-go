package backfill

import (
	"fmt"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

var tb = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

func pev(id string, t time.Time) *event.Event {
	return &event.Event{ID: id, TenantID: "t1", Type: "x", Entity: "alice", EventTime: t}
}

func fire(fireID, key string, ver int, first time.Time, ids ...string) detect.Decision {
	return detect.Decision{
		FireID: fireID, RuleID: "r", RuleVersion: ver, TenantID: "t1",
		Entity: "alice", AlertKey: key, FirstEventAt: first, EventIDs: ids, IsAlert: true,
	}
}
func supp(mainFireID, key string, ver int, first time.Time, ids ...string) detect.Decision {
	return detect.Decision{
		FireID: mainFireID, RuleID: "r", RuleVersion: ver, TenantID: "t1",
		Entity: "alice", AlertKey: key, FirstEventAt: first, EventIDs: ids,
		IsAlert: false, SuppressedBy: mainFireID,
	}
}
func idx(ids []string, times []time.Time) map[string]*event.Event {
	m := map[string]*event.Event{}
	for i, id := range ids {
		m[id] = pev(id, times[i])
	}
	return m
}

// 基线无结论；补入事件后新窗口首次成立 => added。
func TestPlanAdded(t *testing.T) {
	allIDs := []string{"e1", "e2", "e3"}
	times := []time.Time{tb, tb.Add(10 * time.Second), tb.Add(20 * time.Second)}
	baseline := []detect.Decision{
		fire("f1", "r|alice", 1, tb, "e1", "e2"), // 基线只有2个事件的窗口？构造为阈值3不成立故无
	}
	baseline = nil // 阈值3：基线只有 e1,e2 不触发
	aug := []detect.Decision{
		fire("fire:r:alice:0:1", "r|alice", 1, tb, "e1", "e2", "e3"),
	}
	added := map[string]bool{"e3": true}
	plan := PlanChanges(baseline, aug, idx(allIDs, times), added, tb.Add(-time.Minute), tb.Add(time.Minute))
	if len(plan.Changes) != 1 || plan.Changes[0].Kind != ChangeAdded {
		t.Fatalf("want 1 added change, got %+v", plan.Changes)
	}
	c := plan.Changes[0]
	if fmt.Sprint(c.AllEventIDs) != "[e1 e2 e3]" || fmt.Sprint(c.AddedEventIDs) != "[e3]" {
		t.Fatalf("added change events wrong: all=%v added=%v", c.AllEventIDs, c.AddedEventIDs)
	}
	if len(c.BaselineAnchors) != 0 || c.AugAnchor == "" {
		t.Fatalf("added change must have no baseline ids")
	}
	t.Logf("added: %s all=%v added=%v", c.Note, c.AllEventIDs, c.AddedEventIDs)
}

// 基线已有结论，补入事件改变了合并集合 => revised，并对齐到同一基线组。
func TestPlanRevised(t *testing.T) {
	allIDs := []string{"e1", "e2", "e3", "e4", "e5", "e6"}
	var times []time.Time
	for i, id := range allIDs {
		times = append(times, tb.Add(time.Duration(i)*10*time.Second))
		_ = id
	}
	// 基线：首发 e1,e2,e3；抑制命中 e4,e5,e6 合并进同一结论。
	baseline := []detect.Decision{
		fire("fire:r:alice:0:1", "r|alice", 1, tb, "e1", "e2", "e3"),
		supp("fire:r:alice:0:1", "r|alice", 1, tb, "e4", "e5", "e6"),
	}
	// 补数：补入 e2b（时间介于 e2/e3 之间），首发窗口变成 e1,e2,e2b,e3（阈值穿越提前）。
	augIDs := []string{"e1", "e2", "e2b", "e3", "e4", "e5", "e6"}
	var augTimes []time.Time
	augTimes = append(augTimes, tb, tb.Add(10*time.Second), tb.Add(15*time.Second),
		tb.Add(20*time.Second), tb.Add(30*time.Second), tb.Add(40*time.Second), tb.Add(50*time.Second))
	aug := []detect.Decision{
		fire("fire:r:alice:0:1", "r|alice", 1, tb, "e1", "e2", "e2b"),
		supp("fire:r:alice:0:1", "r|alice", 1, tb, "e3", "e4", "e5", "e6"),
	}
	added := map[string]bool{"e2b": true}
	allIdx := idx(augIDs, augTimes)
	plan := PlanChanges(baseline, aug, allIdx, added, tb.Add(-time.Minute), tb.Add(time.Hour))
	if len(plan.Changes) != 1 || plan.Changes[0].Kind != ChangeRevised {
		t.Fatalf("want 1 revised change, got %+v", plan.Changes)
	}
	c := plan.Changes[0]
	if fmt.Sprint(c.BaselineAnchors) != "[e1]" {
		t.Fatalf("revised must align to baseline anchor, got %v", c.BaselineAnchors)
	}
	if fmt.Sprint(c.AddedEventIDs) != "[e2b]" {
		t.Fatalf("added events wrong: %v", c.AddedEventIDs)
	}
	if c.SuppressedCount != 4 {
		t.Fatalf("suppressed count = %d, want 4 (e3,e4,e5,e6)", c.SuppressedCount)
	}
	t.Logf("revised: %s all=%v", c.Note, c.AllEventIDs)
}

// 补入事件但结论集合完全一致（如补入的是窗口外无关事件） => 无更正、无噪音。
func TestPlanUnchangedNoNoise(t *testing.T) {
	allIDs := []string{"e1", "e2", "e3", "z"}
	times := []time.Time{tb, tb.Add(10 * time.Second), tb.Add(20 * time.Second), tb.Add(90 * time.Second)}
	d := []detect.Decision{
		fire("fire:r:alice:0:1", "r|alice", 1, tb, "e1", "e2", "e3"),
	}
	// z 落在窗口之外，不参与同一结论，补数后结论不变。
	added := map[string]bool{"z": true}
	plan := PlanChanges(d, d, idx(allIDs, times), added, tb.Add(-time.Minute), tb.Add(time.Hour))
	if len(plan.Changes) != 0 {
		t.Fatalf("unchanged backfill must produce no corrections, got %+v", plan.Changes)
	}
}
