package engine

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

var tBase = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

func testCfg() Config {
	return Config{
		AllowedLateness: 30 * time.Second,
		Parse:           event.ParseConfig{Now: func() time.Time { return tBase }},
	}
}

type rawRec struct {
	src event.Source
	raw string
}

func jsonRec(id, entity, typ string, t time.Time) rawRec {
	return rawRec{event.SourceJSON,
		fmt.Sprintf(`{"id":%q,"type":%q,"entity":%q,"ts":%q}`, id, typ, entity, t.Format(time.RFC3339Nano))}
}
func syslogRec(id, entity, typ string, t time.Time) rawRec {
	return rawRec{event.SourceSyslog, fmt.Sprintf(
		"<%d>%s host sshd: id=%s type=%s entity=%s", 134, t.Format(time.RFC3339Nano), id, typ, entity)}
}
func cefRec(id, entity, typ string, t time.Time) rawRec {
	return rawRec{event.SourceCEF, fmt.Sprintf(
		"CEF:0|Acme|SSHD|1.0|100|x|5|externalId=%s act=%s suser=%s rt=%s", id, typ, entity, t.Format(time.RFC3339Nano))}
}

// Snapshot 是一次完整运行的可比较结论。
type Snapshot struct {
	alerts   []string // 告警 ID（按创建时间排序）
	merged   map[string][]string
	statuses map[string]alert.Status
	rejected map[string]int // 拒绝原因 -> 次数
	lateN    int
	dupN     int
}

func runBatch(t *testing.T, recs []rawRec, finalWM time.Time, shuffle bool, seed int64) Snapshot {
	t.Helper()
	eng, rs, store := New(testCfg())
	if err := rs.Put(detect.Rule{ID: "brute", TenantID: "t1", Version: 1,
		EventType: "login_fail", Window: time.Minute, Threshold: 3,
		SuppressFor: 5 * time.Minute, EffectiveAt: tBase.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	order := make([]int, len(recs))
	for i := range order {
		order[i] = i
	}
	if shuffle {
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	}
	resRej := map[string]int{}
	dup, late := 0, 0
	for _, idx := range order {
		r := eng.Ingest("t1", recs[idx].src, recs[idx].raw)
		switch r.Disposition {
		case event.DispRejected:
			resRej[string(r.Reason)]++
		case event.DispDuplicate:
			dup++
		case event.DispLate:
			late++
		}
	}
	eng.Advance(finalWM) // 统一水位断言后定论，结论与到达顺序无关

	snap := Snapshot{merged: map[string][]string{}, statuses: map[string]alert.Status{},
		rejected: resRej, lateN: late, dupN: dup}
	for _, a := range store.List("t1") {
		snap.alerts = append(snap.alerts, a.ID)
		ids := append([]string{}, a.EventIDs...)
		sort.Strings(ids)
		snap.merged[a.ID] = ids
		snap.statuses[a.ID] = a.Status
	}
	return snap
}

// 同一批事件（多来源、乱序、重复投递）在 3 种不同到达顺序下结论必须完全一致。
func TestEngineOrderAndDuplicateReproducible(t *testing.T) {
	recs := []rawRec{
		jsonRec("e1", "alice", "login_fail", tBase),
		syslogRec("e2", "alice", "login_fail", tBase.Add(10*time.Second)),
		cefRec("e3", "alice", "login_fail", tBase.Add(20*time.Second)),
		// 抑制期内第二波 3 次 -> 合并进同一条告警
		jsonRec("e4", "alice", "login_fail", tBase.Add(40*time.Second)),
		syslogRec("e5", "alice", "login_fail", tBase.Add(50*time.Second)),
		cefRec("e6", "alice", "login_fail", tBase.Add(60*time.Second)),
		// 不同实体，独立告警
		jsonRec("b1", "bob", "login_fail", tBase.Add(5*time.Second)),
		jsonRec("b2", "bob", "login_fail", tBase.Add(15*time.Second)),
		jsonRec("b3", "bob", "login_fail", tBase.Add(25*time.Second)),
		// 重复投递（含不同来源形式但同 ID）
		jsonRec("e1", "alice", "login_fail", tBase),
		cefRec("e4", "alice", "login_fail", tBase.Add(40*time.Second)),
	}
	wm := tBase.Add(2 * time.Minute)

	s0 := runBatch(t, recs, wm, false, 0)
	s1 := runBatch(t, recs, wm, true, 1)
	s2 := runBatch(t, recs, wm, true, 99)

	t.Logf("时间基准=%s 最终水位=%s", tBase.Format(time.RFC3339), wm.Format(time.RFC3339Nano))
	t.Logf("顺序0: alerts=%v dup=%d", s0.alerts, s0.dupN)
	t.Logf("顺序1: alerts=%v dup=%d", s1.alerts, s1.dupN)
	t.Logf("顺序2: alerts=%v dup=%d", s2.alerts, s2.dupN)

	if fmt.Sprint(s0.alerts) != fmt.Sprint(s1.alerts) ||
		fmt.Sprint(s1.alerts) != fmt.Sprint(s2.alerts) {
		t.Fatalf("alerts differ across arrival orders:\n%v\n%v\n%v", s0.alerts, s1.alerts, s2.alerts)
	}
	if fmt.Sprint(s0.merged) != fmt.Sprint(s1.merged) ||
		fmt.Sprint(s1.merged) != fmt.Sprint(s2.merged) {
		t.Fatalf("merged events differ:\n%v\n%v\n%v", s0.merged, s1.merged, s2.merged)
	}
	if len(s0.alerts) != 2 {
		t.Fatalf("want 2 alerts (alice suppressed into 1 + bob 1), got %v", s0.alerts)
	}
	if s0.dupN != 2 || s1.dupN != 2 || s2.dupN != 2 {
		t.Fatalf("duplicate count must be order-independent 2, got %d/%d/%d", s0.dupN, s1.dupN, s2.dupN)
	}
	for id, ids := range s0.merged {
		t.Logf("告警 %s 合并事件=%v (可追溯)", id, ids)
	}
	// alice 告警应合并全部 6 个事件（3 首发 + 3 抑制）
	var aliceMerged []string
	for _, ids := range s0.merged {
		if len(ids) == 6 {
			aliceMerged = ids
		}
	}
	if fmt.Sprint(aliceMerged) != "[e1 e2 e3 e4 e5 e6]" {
		t.Fatalf("alice alert must merge e1..e6, got %v", aliceMerged)
	}
}

// 非法记录按可区分原因隔离；迟到事件在显式水位后隔离；均不静默丢弃。
func TestEngineRejectAndLateDistinguishable(t *testing.T) {
	eng, _, _ := New(testCfg())
	cases := []struct {
		name string
		src  event.Source
		raw  string
		want event.Disposition
	}{
		{"parse_error", event.SourceJSON, "{bad", event.DispRejected},
		{"missing_field", event.SourceJSON, `{"id":"x","type":"t"}`, event.DispRejected},
		{"bad_timestamp", event.SourceJSON,
			`{"id":"x","type":"t","entity":"a","ts":"nope"}`, event.DispRejected},
		{"good1", event.SourceJSON,
			jsonRec("g1", "a", "login_fail", tBase).raw, event.DispAccepted},
		{"good2", event.SourceJSON,
			jsonRec("g2", "a", "login_fail", tBase.Add(10*time.Second)).raw, event.DispAccepted},
	}
	for _, c := range cases {
		r := eng.Ingest("t1", c.src, c.raw)
		if r.Disposition != c.want {
			t.Fatalf("%s: got %s want %s detail=%s", c.name, r.Disposition, c.want, r.Detail)
		}
		t.Logf("[%s] -> %s %s %s", c.name, r.Disposition, r.Reason, r.Detail)
	}
	eng.Advance(tBase.Add(time.Minute)) // 断言 t<=base+60 已到齐
	late := eng.Ingest("t1", event.SourceJSON,
		jsonRec("L1", "a", "login_fail", tBase.Add(5*time.Second)).raw)
	if late.Disposition != event.DispLate {
		t.Fatalf("want late, got %s", late.Disposition)
	}
	dup := eng.Ingest("t1", event.SourceSyslog, syslogRec("g1", "a", "login_fail", tBase).raw)
	if dup.Disposition != event.DispDuplicate {
		t.Fatalf("want duplicate, got %s", dup.Disposition)
	}
	q := eng.Quarantine()
	byReason := map[string]int{}
	for _, r := range q {
		byReason[string(r.Reason)]++
	}
	t.Logf("隔离区明细（不静默丢弃）: %+v", byReason)
	if byReason["parse_error"] != 1 || byReason["missing_field"] != 1 ||
		byReason["bad_timestamp"] != 1 || byReason["late_event"] != 1 {
		t.Fatalf("quarantine reasons wrong: %+v", byReason)
	}
}

// 并发写入：多个 goroutine 交错写入同一批事件，最终告警与事件集合一致。
func TestEngineConcurrentWritersConsistent(t *testing.T) {
	// 30 个严格递增的唯一事件，全部落在一个窗口内（阈值 30 => 单条告警合并全部），
	// 外加 2 条重复投递。
	mk := func() (recs []rawRec) {
		for i := 0; i < 30; i++ {
			tt := tBase.Add(time.Duration(i) * 2 * time.Second)
			recs = append(recs, jsonRec(fmt.Sprintf("c%02d", i), "mallory",
				"login_fail", tt))
		}
		recs = append(recs,
			jsonRec("c00", "mallory", "login_fail", tBase),
			jsonRec("c01", "mallory", "login_fail", tBase.Add(2*time.Second)))
		return recs
	}

	run := func(parallel int) Snapshot {
		eng, rs, store := New(testCfg())
		_ = rs.Put(detect.Rule{ID: "r", TenantID: "t1", Version: 1, EventType: "login_fail",
			Window: 10 * time.Minute, Threshold: 30, SuppressFor: time.Hour,
			EffectiveAt: tBase.Add(-time.Hour)})
		recs := mk()
		var wg sync.WaitGroup
		ch := make(chan rawRec)
		for w := 0; w < parallel; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for r := range ch {
					eng.Ingest("t1", r.src, r.raw)
				}
			}()
		}
		for _, r := range recs {
			ch <- r
		}
		close(ch)
		wg.Wait()
		eng.Advance(tBase.Add(time.Hour))
		snap := Snapshot{merged: map[string][]string{}, statuses: map[string]alert.Status{}}
		for _, a := range store.List("t1") {
			snap.alerts = append(snap.alerts, a.ID)
			ids := append([]string{}, a.EventIDs...)
			sort.Strings(ids)
			snap.merged[a.ID] = ids
		}
		return snap
	}

	seq := run(1)
	par := run(8)
	t.Logf("串行写入: alerts=%d merged=%d 条事件", len(seq.alerts), totalMerged(seq))
	t.Logf("8 goroutine 并发写入: alerts=%d merged=%d 条事件", len(par.alerts), totalMerged(par))
	if fmt.Sprint(seq.alerts) != fmt.Sprint(par.alerts) {
		t.Fatalf("alerts differ: %v vs %v", seq.alerts, par.alerts)
	}
	if fmt.Sprint(seq.merged) != fmt.Sprint(par.merged) {
		t.Fatalf("merged events differ under concurrency:\n%v\n%v", seq.merged, par.merged)
	}
	if totalMerged(seq) != 30 {
		t.Fatalf("all 30 unique events must be traceable in alerts, got %d", totalMerged(seq))
	}
	t.Log("并发交错写入最终状态唯一；30 个唯一事件全部可追溯，2 条重复不重复计数")
}

func totalMerged(s Snapshot) int {
	n := 0
	for _, ids := range s.merged {
		n += len(ids)
	}
	return n
}

// 未完成窗口在流结束时通过 Advance 越过窗口右端获得确定性定论。
func TestEngineOpenWindowFinalizedAtEnd(t *testing.T) {
	eng, rs, _ := New(testCfg())
	_ = rs.Put(detect.Rule{ID: "r", TenantID: "t1", Version: 1, EventType: "x",
		Window: 5 * time.Minute, Threshold: 3, SuppressFor: time.Minute,
		EffectiveAt: tBase.Add(-time.Hour)})
	for i := 0; i < 3; i++ {
		r := eng.Ingest("t1", event.SourceJSON,
			jsonRec(fmt.Sprintf("x%d", i), "z", "x", tBase.Add(time.Duration(i)*time.Second)).raw)
		if r.Disposition != event.DispAccepted {
			t.Fatalf("x%d: %s", i, r.Disposition)
		}
	}
	// 没有任何"后续事件"推进水位；流结束时显式 Advance 到窗口右端之后。
	ids := eng.Advance(tBase.Add(10 * time.Minute))
	if len(ids) != 1 {
		t.Fatalf("open window must be finalized at end of stream, got alerts %v", ids)
	}
	t.Logf("未完成窗口在流结束时定论: alert=%s merged 3 events", ids[0])
}
