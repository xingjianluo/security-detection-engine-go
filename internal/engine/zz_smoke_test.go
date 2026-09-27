package engine

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

func rule() detect.Rule {
	return detect.Rule{ID: "brute", TenantID: "t1", Version: 1, EventType: "login_fail",
		Window: time.Minute, Threshold: 3, SuppressFor: time.Hour, EffectiveAt: tBase.Add(-time.Hour)}
}

func TestSmokeMisc(t *testing.T) {
	// --- no change: 补入一个迟到但不影响结论的事件（阈值已在窗口达成，补入事件超出已消费窗口）---
	eng, rs, store := New(testCfg())
	_ = rs.Put(rule())
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}
	eng.Ingest("t1", event.SourceJSON, jsonRec("a1", "alice", "login_fail", tBase).raw)
	eng.Ingest("t1", event.SourceJSON, jsonRec("a2", "alice", "login_fail", tBase.Add(10*time.Second)).raw)
	eng.Ingest("t1", event.SourceJSON, jsonRec("a3", "alice", "login_fail", tBase.Add(20*time.Second)).raw)
	eng.Advance(tBase.Add(10 * time.Minute))
	nBefore := len(store.List("t1"))
	// 迟到事件 a0 在 t=-5s？窗口闭区间 [-5..55]，consume-on-fire 后... 用 t+90s 的迟到事件更稳妥：
	eng.Ingest("t1", event.SourceJSON, jsonRec("a9", "alice", "login_fail", tBase.Add(90*time.Second)).raw)
	res := eng.Backfill(BackfillRequest{RequestID: "bfnc", TenantID: "t1", Operator: op,
		Start: tBase.Add(30 * time.Second), End: tBase.Add(10 * time.Minute)})
	fmt.Println("[nochange] status:", res.Status, "replayed:", res.ReplayedEvents, "corr:", len(res.Corrections))
	if res.Status != BackfillNoChange {
		t.Fatal("want no_change")
	}
	if len(store.List("t1")) != nBefore {
		t.Fatal("no-change must not add noise")
	}

	// --- rejects ---
	eng2, _, _ := New(testCfg())
	_ = rs
	cases := []struct {
		name string
		req  BackfillRequest
		want error
	}{
		{"no-id", BackfillRequest{TenantID: "t1", Operator: op, Start: tBase, End: tBase.Add(time.Minute)}, ErrBackfillNoRequestID},
		{"viewer", BackfillRequest{RequestID: "x", TenantID: "t1", Operator: alert.Operator{ID: "v", TenantID: "t1", Role: alert.RoleViewer}, Start: tBase, End: tBase.Add(time.Minute)}, ErrBackfillUnauthorized},
		{"cross-tenant", BackfillRequest{RequestID: "x", TenantID: "t1", Operator: alert.Operator{ID: "o", TenantID: "t2", Role: alert.RoleAdmin}, Start: tBase, End: tBase.Add(time.Minute)}, ErrBackfillCrossTenant},
		{"bad-range", BackfillRequest{RequestID: "x", TenantID: "t1", Operator: op, Start: tBase.Add(time.Minute), End: tBase}, ErrBackfillBadRange},
		{"too-wide", BackfillRequest{RequestID: "x", TenantID: "t1", Operator: op, Start: tBase, End: tBase.Add(25 * time.Hour)}, ErrBackfillTooWide},
		{"beyond-wm", BackfillRequest{RequestID: "x", TenantID: "t1", Operator: op, Start: tBase, End: tBase.Add(time.Minute)}, ErrBackfillBeyondWatermark},
	}
	for _, c := range cases {
		r := eng2.Backfill(c.req)
		if r.Status != BackfillRejected || !errors.Is(r.Reject, c.want) {
			t.Fatalf("%s: got %v/%v want %v", c.name, r.Status, r.Reject, c.want)
		}
		fmt.Println("[reject]", c.name, "->", r.Reject)
	}
}

func TestSmokeVersion(t *testing.T) {
	// 补入的历史事件必须按其事件时间匹配旧规则版本
	eng, rs, store := New(testCfg())
	_ = rs.Put(detect.Rule{ID: "r", TenantID: "t1", Version: 1, EventType: "login_fail",
		Window: time.Minute, Threshold: 2, SuppressFor: time.Hour, EffectiveAt: tBase.Add(-time.Hour)})
	_ = rs.Put(detect.Rule{ID: "r", TenantID: "t1", Version: 2, EventType: "login_fail",
		Window: time.Minute, Threshold: 5, SuppressFor: time.Hour, EffectiveAt: tBase.Add(5 * time.Minute)})
	op := alert.Operator{ID: "ops", TenantID: "t1", Role: alert.RoleOperator}
	// 旧版期间只有 1 个事件，无告警
	eng.Ingest("t1", event.SourceJSON, jsonRec("v1a", "alice", "login_fail", tBase.Add(10*time.Second)).raw)
	eng.Advance(tBase.Add(10 * time.Minute))
	// 补入旧版期间的迟到第 2 个事件：旧阈值 2 => 应产生 v1 告警（而非用现在的 v2 阈值 5）
	eng.Ingest("t1", event.SourceJSON, jsonRec("v1b", "alice", "login_fail", tBase.Add(20*time.Second)).raw)
	res := eng.Backfill(BackfillRequest{RequestID: "bfv", TenantID: "t1", Operator: op,
		Start: tBase, End: tBase.Add(4 * time.Minute)})
	fmt.Println("[version] status:", res.Status)
	for _, c := range res.Corrections {
		fmt.Println("  corr ruleVersion=", c.RuleVersion, "kind=", c.Kind)
		if c.RuleVersion != 1 {
			t.Fatalf("must use v1 for historical events, got %d", c.RuleVersion)
		}
	}
	for _, a := range store.EffectiveAlerts("t1") {
		fmt.Println("  eff v=", a.RuleVersion, a.EventIDs)
	}
}
