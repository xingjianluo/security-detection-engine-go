package detect

import (
	"fmt"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

func ev(tenant, id, entity, typ string, t time.Time) *event.Event {
	return &event.Event{ID: id, TenantID: tenant, Type: typ, Entity: entity, EventTime: t}
}

func feed(t *testing.T, c *Correlator, es []*event.Event, wm time.Time, tag string) []Decision {
	t.Helper()
	for _, e := range es {
		c.Observe(e)
	}
	d := c.AdvanceWatermark(wm)
	var ids []string
	for _, x := range d {
		ids = append(ids, fmt.Sprintf("%s(alert=%v,merged=%v)", x.FireID, x.IsAlert, x.EventIDs))
	}
	t.Logf("[%s] wm=%s decisions=%s", tag, wm.Format(time.RFC3339Nano), ids)
	return d
}

// 3 次登录失败在 1 分钟窗口内触发 1 条告警；随后短时重复命中被抑制为同一条。
func TestCorrelatorFireAndSuppress(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	rs := NewRuleSet()
	r := Rule{ID: "brute", TenantID: "t1", Version: 1, EventType: "login_fail",
		Window: time.Minute, Threshold: 3, SuppressFor: 5 * time.Minute, EffectiveAt: base.Add(-time.Hour)}
	if err := rs.Put(r); err != nil {
		t.Fatal(err)
	}
	c := NewCorrelator(rs)

	es := []*event.Event{
		ev("t1", "e1", "alice", "login_fail", base),
		ev("t1", "e2", "alice", "login_fail", base.Add(10*time.Second)),
		ev("t1", "e3", "alice", "login_fail", base.Add(20*time.Second)),
	}
	d := feed(t, c, es, base.Add(20*time.Second), "first-burst")
	if len(d) != 1 || !d[0].IsAlert || fmt.Sprint(d[0].EventIDs) != "[e1 e2 e3]" {
		t.Fatalf("want 1 new alert merging e1,e2,e3, got %+v", d)
	}
	t.Logf("判定依据: %s", d[0].Reason)

	// 抑制期内再来 3 次（base+30..50s）：产生 1 个抑制命中，复用 FireID，可追溯合并事件。
	es2 := []*event.Event{
		ev("t1", "e4", "alice", "login_fail", base.Add(30*time.Second)),
		ev("t1", "e5", "alice", "login_fail", base.Add(40*time.Second)),
		ev("t1", "e6", "alice", "login_fail", base.Add(50*time.Second)),
	}
	d2 := feed(t, c, es2, base.Add(50*time.Second), "suppressed-burst")
	if len(d2) != 1 || d2[0].IsAlert || d2[0].SuppressedBy != d[0].FireID {
		t.Fatalf("want 1 suppressed hit reusing %s, got %+v", d[0].FireID, d2)
	}
	if fmt.Sprint(d2[0].EventIDs) != "[e4 e5 e6]" {
		t.Fatalf("suppressed hit merged %v", d2[0].EventIDs)
	}
	t.Logf("抑制依据: %s", d2[0].Reason)

	// 抑制期结束后（顺延到 base+5m50s）再次命中 => 新告警。
	es3 := []*event.Event{
		ev("t1", "e7", "alice", "login_fail", base.Add(6*time.Minute)),
		ev("t1", "e8", "alice", "login_fail", base.Add(6*time.Minute+10*time.Second)),
		ev("t1", "e9", "alice", "login_fail", base.Add(6*time.Minute+20*time.Second)),
	}
	d3 := feed(t, c, es3, base.Add(6*time.Minute+20*time.Second), "after-suppression")
	if len(d3) != 1 || !d3[0].IsAlert || d3[0].FireID == d[0].FireID {
		t.Fatalf("want a new alert after suppression window, got %+v", d3)
	}
	t.Logf("抑制期外再次触发新告警 %s merged=%v", d3[0].FireID, d3[0].EventIDs)
}

// 未达阈值不触发；窗口滑出后旧事件不再计数。
func TestCorrelatorWindowSlide(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	rs := NewRuleSet()
	_ = rs.Put(Rule{ID: "r", TenantID: "t", Version: 1, EventType: "x",
		Window: time.Minute, Threshold: 3, SuppressFor: time.Minute, EffectiveAt: base.Add(-time.Hour)})
	c := NewCorrelator(rs)
	es := []*event.Event{
		ev("t", "a", "u", "x", base),
		ev("t", "b", "u", "x", base.Add(70*time.Second)),
	}
	if d := feed(t, c, es, base.Add(70*time.Second), "below-threshold"); len(d) != 0 {
		t.Fatalf("want no decision, got %+v", d)
	}
	// 第三个事件距 a 已超过 1 分钟：窗口内只有 b,c，仍不触发；且 a 已滑出。
	es2 := []*event.Event{ev("t", "c", "u", "x", base.Add(140*time.Second))}
	if d := feed(t, c, es2, base.Add(140*time.Second), "window-expired"); len(d) != 0 {
		t.Fatalf("want no decision after window slide, got %+v", d)
	}
	// 再来两个与 b/c 同分钟的事件：b 与后续的间隔也要检查；直接验证新聚集可触发。
	es3 := []*event.Event{
		ev("t", "d", "u", "x", base.Add(145*time.Second)),
		ev("t", "e", "u", "x", base.Add(150*time.Second)),
	}
	d := feed(t, c, es3, base.Add(150*time.Second), "new-cluster")
	if len(d) != 1 || fmt.Sprint(d[0].EventIDs) != "[c d e]" {
		t.Fatalf("want alert on c,d,e, got %+v", d)
	}
	t.Logf("窗口滑动: a 已滑出, 新聚集 [c d e] 触发; 依据: %s", d[0].Reason)
}

// 规则运行中更新：版本不混合计数，已判定结论不变。
func TestCorrelatorRuleUpdateVersioning(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	rs := NewRuleSet()
	_ = rs.Put(Rule{ID: "r", TenantID: "t", Version: 1, EventType: "x",
		Window: time.Minute, Threshold: 2, SuppressFor: time.Minute, EffectiveAt: base.Add(-time.Hour)})
	_ = rs.Put(Rule{ID: "r", TenantID: "t", Version: 2, EventType: "x",
		Window: time.Minute, Threshold: 5, SuppressFor: time.Minute, EffectiveAt: base.Add(5 * time.Minute)})
	c := NewCorrelator(rs)

	// v1 期间 2 次即触发；结论在 v2 下不会被改写。
	d1 := feed(t, c, []*event.Event{
		ev("t", "a", "u", "x", base),
		ev("t", "b", "u", "x", base.Add(10*time.Second)),
	}, base.Add(10*time.Second), "v1")
	if len(d1) != 1 || d1[0].RuleVersion != 1 {
		t.Fatalf("want v1 alert, got %+v", d1)
	}
	// v2 期间 4 次（阈值 5）不触发，且不会与 v1 已消费事件混合。
	es := []*event.Event{}
	for i := 0; i < 4; i++ {
		es = append(es, ev("t", fmt.Sprintf("c%d", i), "u", "x",
			base.Add(6*time.Minute+time.Duration(i)*10*time.Second)))
	}
	if d2 := feed(t, c, es, base.Add(6*time.Minute+30*time.Second), "v2-below"); len(d2) != 0 {
		t.Fatalf("want no alert under v2 threshold 5, got %+v", d2)
	}
	t.Log("v1 阈值2已触发并消费；v2 阈值5独立累计，4 次不触发；历史结论不变")
}

// 水位幂等：重复推进不重复产出。
func TestCorrelatorIdempotentWatermark(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	rs := NewRuleSet()
	_ = rs.Put(Rule{ID: "r", TenantID: "t", Version: 1, EventType: "x",
		Window: time.Minute, Threshold: 2, SuppressFor: time.Minute, EffectiveAt: base.Add(-time.Hour)})
	c := NewCorrelator(rs)
	c.Observe(ev("t", "a", "u", "x", base))
	c.Observe(ev("t", "b", "u", "x", base.Add(time.Second)))
	d1 := c.AdvanceWatermark(base.Add(time.Second))
	d2 := c.AdvanceWatermark(base.Add(time.Second))
	d3 := c.AdvanceWatermark(base.Add(time.Second - time.Nanosecond))
	if len(d1) != 1 || len(d2) != 0 || len(d3) != 0 {
		t.Fatalf("watermark advance not idempotent: %d %d %d", len(d1), len(d2), len(d3))
	}
}

// 跨实体独立计数，租户隔离。
func TestCorrelatorEntityAndTenant(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	rs := NewRuleSet()
	_ = rs.Put(Rule{ID: "r", TenantID: "t1", Version: 1, EventType: "x",
		Window: time.Minute, Threshold: 2, SuppressFor: time.Minute, EffectiveAt: base.Add(-time.Hour)})
	c := NewCorrelator(rs)
	d := feed(t, c, []*event.Event{
		ev("t1", "a", "alice", "x", base),
		ev("t1", "b", "bob", "x", base),
		ev("t2", "c", "alice", "x", base), // t2 无规则
	}, base, "entities")
	if len(d) != 0 {
		t.Fatalf("no entity reached threshold, t2 has no rule: %+v", d)
	}
	d = feed(t, c, []*event.Event{
		ev("t1", "a2", "alice", "x", base.Add(2*time.Second)),
		ev("t1", "b2", "bob", "x", base.Add(2*time.Second)),
	}, base.Add(2*time.Second), "entities-2")
	if len(d) != 2 {
		t.Fatalf("want one alert per entity, got %+v", d)
	}
}
