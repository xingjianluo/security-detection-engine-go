package detect

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/clock"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
	"github.com/xingjianluo/security-detection-engine-go/internal/rule"
)

const rfc3339n = "2006-01-02T15:04:05.000000000Z07:00"

// testScenario 固定时间基准与窗口参数：
//
//	允许乱序宽限 L=10s，保留期 R=30s，窗口 W=10s，阈值=3，无抑制（在告警层测试抑制）。
type testScenario struct {
	t0  time.Time
	clk *clock.FakeClock
	cat *rule.Catalog
	cfg Config
}

func newScenario(t *testing.T) *testScenario {
	t.Helper()
	t0 := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	cat := rule.NewCatalog()
	_, err := cat.AddVersion(rule.Rule{
		ID: "r1", Tenant: "t1", EventType: "fail",
		Threshold: 3, Window: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 处理时间从事件时间基准起；测试中事件事件时间与处理时间同源，不涉及未来判定。
	return &testScenario{
		t0: t0, clk: clock.NewFakeClock(t0), cat: cat,
		cfg: Config{AllowedLateness: 10 * time.Second, Retention: 30 * time.Second},
	}
}

func (s *testScenario) newDetector() *Detector { return New(s.cat, s.cfg, s.clk) }

func (s *testScenario) ev(id string, offsetSec int, typ string) *event.Event {
	return &event.Event{
		ID: id, Tenant: "t1", Source: event.SourceJSON,
		Entity: "host-1", Type: typ,
		EventTime: s.t0.Add(time.Duration(offsetSec) * time.Second),
	}
}

func (s *testScenario) logSeq(t *testing.T, label string, seq []string) {
	t.Helper()
	t.Logf("[%s] 时间基准 t0=%s ; 参数 L=%s R=%s ; 注入顺序=%v",
		label, s.t0.Format(rfc3339n), s.cfg.AllowedLateness, s.cfg.Retention, seq)
}

func findingKeys(fs []*Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s@%s(matched=%v)",
			f.TriggerEventID, f.EventTime.Format("15:04:05"), f.MatchedEventIDs))
	}
	sort.Strings(out)
	return out
}

// runSequence 以给定顺序注入事件，每条后 Pump；最后 Flush，返回全部触发键。
func (s *testScenario) runSequence(t *testing.T, seq []*event.Event) []string {
	d := s.newDetector()
	var all []string
	for _, e := range seq {
		r := d.Observe(e)
		wm, _ := d.Watermark("t1")
		t.Logf("  注入 %-3s @%s -> timing=%-7s dup=%-5v expired=%-5v explains=%d ; watermark=%s",
			e.ID, e.EventTime.Format("15:04:05"), r.Timing, r.Duplicate, r.Expired, len(r.Explains),
			wm.Format("15:04:05.000"))
		pr := d.Pump("t1")
		for _, f := range pr.Findings {
			all = append(all, fmt.Sprintf("%s@%s(matched=%v)",
				f.TriggerEventID, f.EventTime.Format("15:04:05"), f.MatchedEventIDs))
		}
	}
	pr := d.Flush("t1")
	t.Logf("  Flush: watermark -> %s, findings=%d", pr.WatermarkAfter.Format("15:04:05"), len(pr.Findings))
	for _, f := range pr.Findings {
		all = append(all, fmt.Sprintf("%s@%s(matched=%v)",
			f.TriggerEventID, f.EventTime.Format("15:04:05"), f.MatchedEventIDs))
	}
	sort.Strings(all)
	return all
}

// TestOutOfOrderReproducible 是核心可复现性测试：同一批事件以正序、逆序、
// 洗牌顺序到达，最终触发集合必须完全一致（含每条触发归并的事件列表）。
func TestOutOfOrderReproducible(t *testing.T) {
	offsets := []int{0, 4, 8, 12}
	mkEvents := func(s *testScenario) []*event.Event {
		var es []*event.Event
		for i, off := range offsets {
			es = append(es, s.ev(fmt.Sprintf("e%d", i), off, "fail"))
		}
		return es
	}

	// 顺序 1：正序
	s1 := newScenario(t)
	es1 := mkEvents(s1)
	s1.logSeq(t, "ascending", idsOf(es1))
	gotAsc := s1.runSequence(t, es1)

	// 顺序 2：逆序
	s2 := newScenario(t)
	es2 := mkEvents(s2)
	rev := reverse(es2)
	s2.logSeq(t, "descending", idsOf(rev))
	gotDesc := s2.runSequence(t, rev)

	// 顺序 3：乱序
	s3 := newScenario(t)
	es3 := mkEvents(s3)
	shuf := []*event.Event{es3[2], es3[0], es3[3], es3[1]}
	s3.logSeq(t, "shuffled", idsOf(shuf))
	gotShuf := s3.runSequence(t, shuf)

	t.Logf("判定依据（触发键） ascending  = %v", gotAsc)
	t.Logf("判定依据（触发键） descending = %v", gotDesc)
	t.Logf("判定依据（触发键） shuffled   = %v", gotShuf)
	if fmt.Sprint(gotAsc) != fmt.Sprint(gotDesc) || fmt.Sprint(gotAsc) != fmt.Sprint(gotShuf) {
		t.Fatalf("检测结论随到达顺序变化：\n asc=%v\n desc=%v\n shuf=%v", gotAsc, gotDesc, gotShuf)
	}
	// 阈值 3 / 窗口 10s：@8 窗口 [0,8] 有 e0,e1,e2 三个 => 触发；
	// @12 窗口 [2,12] 有 e1,e2,e3 三个 => 再触发一次。
	if len(gotAsc) != 2 {
		t.Fatalf("want 2 fires, got %d: %v", len(gotAsc), gotAsc)
	}
}

func TestDuplicateDeliveryCountedOnce(t *testing.T) {
	s := newScenario(t)
	d := s.newDetector()
	seq := []*event.Event{s.ev("e0", 0, "fail"), s.ev("e0", 0, "fail"), s.ev("e1", 4, "fail"), s.ev("e2", 8, "fail")}
	s.logSeq(t, "duplicate", idsOf(seq))
	var dupCount int
	for _, e := range seq {
		r := d.Observe(e)
		if r.Duplicate {
			dupCount++
		}
		d.Pump("t1")
	}
	pr := d.Flush("t1")
	t.Logf("判定依据：重复次数=%d 触发数=%d", dupCount, len(pr.Findings))
	if dupCount != 1 {
		t.Fatalf("duplicate count = %d, want 1", dupCount)
	}
	// 去重后仍只有 3 个不同事件，恰好触发一次。
	if len(pr.Findings) != 1 {
		t.Fatalf("want exactly 1 fire after dedup, got %d", len(pr.Findings))
	}
	for _, f := range pr.Findings {
		for _, id := range f.MatchedEventIDs {
			if id == "e0" && count(f.MatchedEventIDs, "e0") != 1 {
				t.Fatalf("e0 counted multiple times in window: %v", f.MatchedEventIDs)
			}
		}
	}
}

func TestLateWithinLatenessAffectsFutureDecision(t *testing.T) {
	s := newScenario(t)
	d := s.newDetector()
	// 先把处理时间推进到 t0+12，并观测足够多事件使水位线抬升到 t0+2：
	// maxObserved=t0+12, L=10s => watermark=t0+2。
	s.clk.Set(s.t0.Add(12 * time.Second))
	steps := []*event.Event{s.ev("e0", 0, "fail"), s.ev("e1", 4, "fail"), s.ev("eM", 12, "other")}
	for _, e := range steps {
		d.Observe(e)
		d.Pump("t1")
	}
	wm, _ := d.Watermark("t1")
	t.Logf("时间基准 t0=%s；补迟到事件前 watermark=%s", s.t0.Format(rfc3339n), wm.Format("15:04:05"))

	// eL@2 恰不早于 watermark(=2)，按 on_time 边界处理；改用 @1 构造严格迟到。
	late := s.ev("eL", 1, "fail")
	r := d.Observe(late)
	if !r.Late {
		t.Fatalf("eL should be classified late, got timing=%q expired=%v", r.Timing, r.Expired)
	}
	t.Logf("判定依据：eL@01 迟到且在保留期内，计入窗口；explains[0].count=%d threshold=%d",
		r.Explains[0].Count, r.Explains[0].Threshold)
	pr := d.Flush("t1")
	// flush 时 @4 冻结，窗口 [-6,4] 内有 e0,eL,e1 三个 => 在 @4 触发；
	// 迟到事件 @1 已处于冻结区，不作为新触发锚点。
	var triggerAt4 *Finding
	for _, f := range pr.Findings {
		if f.TriggerEventID == "e1" {
			triggerAt4 = f
		}
	}
	if triggerAt4 == nil {
		t.Fatalf("late event must let the window fire at e1, findings=%d", len(pr.Findings))
	}
	if count(triggerAt4.MatchedEventIDs, "eL") != 1 {
		t.Fatalf("late event eL must be included in matched set: %v", triggerAt4.MatchedEventIDs)
	}
	t.Logf("判定依据：触发锚点=%s 合并事件=%v", triggerAt4.TriggerEventID, triggerAt4.MatchedEventIDs)
}

func TestExpiredBeyondRetentionQuarantinedUpstream(t *testing.T) {
	s := newScenario(t)
	d := s.newDetector()
	// 把水位线推到 t0+100（观测 t0+110 的事件：watermark=maxObserved-L=t0+100）。
	s.clk.Set(s.t0.Add(110 * time.Second))
	advance := s.ev("far", 110, "other") // 类型不匹配 r1，但仍推进水位线
	if r := d.Observe(advance); r.Expired {
		t.Fatal("first event can never be expired")
	}
	d.Pump("t1")
	wm, _ := d.Watermark("t1")
	t.Logf("时间基准 t0=%s；watermark=%s；保留期=%s；超期边界=%s",
		s.t0.Format(rfc3339n), wm.Format("15:04:05"), s.cfg.Retention,
		wm.Add(-s.cfg.Retention).Format("15:04:05"))

	tooOld := s.ev("old", 50, "fail") // t0+50 < watermark-R = t0+70
	r := d.Observe(tooOld)
	if !r.Expired {
		t.Fatalf("event beyond retention must be marked expired, got timing=%q", r.Timing)
	}
	t.Logf("判定依据：old@50 < watermark-R=70 => expired=true，不进入窗口")

	within := s.ev("near", 75, "fail") // t0+75 >= 70，仍保留（迟到）
	r2 := d.Observe(within)
	if r2.Expired || !r2.Late {
		t.Fatalf("near@75 should be late-retained, got timing=%q expired=%v", r2.Timing, r2.Expired)
	}
}

func TestRuleUpdateDoesNotRewriteFrozenResult(t *testing.T) {
	s := newScenario(t)
	d := s.newDetector()
	// 处理时间 = t0+8；@0/@4/@8 三事件依次进入，全部在发布时只存在 v1(阈值3)。
	// 每次注入后 Pump：@8 注入后 watermark 仍为 t0-2，故触发在 Flush 时统一落地。
	for _, e := range []*event.Event{s.ev("e0", 0, "fail"), s.ev("e1", 4, "fail"), s.ev("e2", 8, "fail")} {
		d.Observe(e)
		d.Pump("t1")
	}
	// 在处理时间 t0+9 发布 v2（阈值 10），生效点同为 t0+9。
	s.clk.Set(s.t0.Add(9 * time.Second))
	cut := s.t0.Add(9 * time.Second)
	if _, err := s.cat.AddVersion(rule.Rule{
		ID: "r1", Tenant: "t1", EventType: "fail",
		Threshold: 10, Window: 10 * time.Second, EffectiveFrom: cut,
	}); err != nil {
		t.Fatal(err)
	}
	// flush 使 v1 的 @8 窗口冻结评估：已按 v1 绑定的三事件必须得出 v1 触发，
	// 不被后发布的 v2 追溯改写。
	pr := d.Flush("t1")
	v1Fires := 0
	for _, f := range pr.Findings {
		if f.RuleVersion == 1 {
			v1Fires++
		}
	}
	if v1Fires != 1 || len(pr.Findings) != 1 {
		t.Fatalf("frozen v1 result must survive rule update, findings=%+v", pr.Findings)
	}

	// @12 的新事件在 v2 已发布后进入，绑定 v2，阈值 10，不触发。
	s.clk.Set(s.t0.Add(12 * time.Second))
	r := d.Observe(s.ev("e3", 12, "fail"))
	if len(r.Explains) != 1 || r.Explains[0].Version != 2 || r.Explains[0].Threshold != 10 {
		t.Fatalf("new event must bind published v2, explains=%+v", r.Explains)
	}
	pr2 := d.Flush("t1")
	for _, f := range pr2.Findings {
		if f.RuleVersion != 2 {
			t.Fatalf("only v2 findings allowed after cutover, got v%d", f.RuleVersion)
		}
	}
	if len(pr2.Findings) != 0 {
		t.Fatalf("threshold 10 cannot be met by one event, findings=%+v", pr2.Findings)
	}
	t.Logf("判定依据：flush 前发布的 v2 不影响已绑定 v1 的事件(v1Fires=1)；cutover 后新事件绑定 v2 且无触发")
}

func idsOf(es []*event.Event) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}

func reverse(es []*event.Event) []*event.Event {
	out := make([]*event.Event, len(es))
	for i := range es {
		out[i] = es[len(es)-1-i]
	}
	return out
}

func count(xs []string, x string) int {
	n := 0
	for _, v := range xs {
		if v == x {
			n++
		}
	}
	return n
}
