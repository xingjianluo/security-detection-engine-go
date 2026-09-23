package event

import (
	"errors"
	"testing"
	"time"
)

func TestParseAllSources(t *testing.T) {
	ref := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	cfg := ParseConfig{Now: func() time.Time { return ref }}

	cases := []struct {
		name   string
		src    Source
		raw    string
		id     string
		typ    string
		entity string
		ts     time.Time
	}{
		{
			name:   "syslog",
			src:    SourceSyslog,
			raw:    "<134>2026-09-24T09:59:00Z host sshd: id=e1 type=login_fail suser=alice src_ip=10.0.0.1",
			id:     "e1",
			typ:    "login_fail",
			entity: "alice",
			ts:     ref.Add(-time.Minute),
		},
		{
			name:   "json",
			src:    SourceJSON,
			raw:    `{"id":"e2","type":"login_fail","entity":"bob","ts":"2026-09-24T09:59:05Z","attrs":{"src_ip":"10.0.0.2"}}`,
			id:     "e2",
			typ:    "login_fail",
			entity: "bob",
			ts:     ref.Add(-55 * time.Second),
		},
		{
			name:   "cef",
			src:    SourceCEF,
			raw:    "CEF:0|Acme|SSHD|1.0|100|Login Failed|5|externalId=e3 act=login_fail suser=carol rt=2026-09-24T09:59:10Z src=10.0.0.3",
			id:     "e3",
			typ:    "login_fail",
			entity: "carol",
			ts:     ref.Add(-50 * time.Second),
		},
		{
			name:   "json-unix-ms",
			src:    SourceJSON,
			raw:    `{"id":"e4","type":"x","entity":"d","ts":"1780000000000"}`,
			id:     "e4",
			typ:    "x",
			entity: "d",
			ts:     time.UnixMilli(1780000000000).UTC(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Parse(tc.src, tc.raw, cfg)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if e.ID != tc.id || e.Type != tc.typ || e.Entity != tc.entity {
				t.Fatalf("normalization mismatch: %+v", e)
			}
			if !e.EventTime.Equal(tc.ts) {
				t.Fatalf("timestamp = %s, want %s", e.EventTime, tc.ts)
			}
			t.Logf("source=%s id=%s type=%s entity=%s event_time=%s -> accepted",
				tc.src, e.ID, e.Type, e.Entity, e.EventTime.Format(time.RFC3339Nano))
		})
	}
}

func TestParseRejectReasons(t *testing.T) {
	ref := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	cfg := ParseConfig{
		Now:           func() time.Time { return ref },
		MaxFutureSkew: 5 * time.Second,
		MaxAge:        24 * time.Hour,
	}
	cases := []struct {
		name   string
		src    Source
		raw    string
		reason RejectReason
	}{
		{"empty", SourceJSON, " ", ReasonParseError},
		{"malformed_json", SourceJSON, "{not json", ReasonParseError},
		{"malformed_syslog", SourceSyslog, "garbage", ReasonParseError},
		{"malformed_cef", SourceCEF, "CEF:0|a|b", ReasonParseError},
		{"unknown_source", Source("nope"), "whatever", ReasonParseError},
		{"missing_id", SourceJSON, `{"type":"x","entity":"a","ts":"2026-09-24T09:00:00Z"}`, ReasonMissingField},
		{"missing_type", SourceJSON, `{"id":"x","entity":"a","ts":"2026-09-24T09:00:00Z"}`, ReasonMissingField},
		{"missing_entity", SourceJSON, `{"id":"x","type":"t","ts":"2026-09-24T09:00:00Z"}`, ReasonMissingField},
		{"missing_ts", SourceJSON, `{"id":"x","type":"t","entity":"a"}`, ReasonMissingField},
		{"bad_ts", SourceJSON, `{"id":"x","type":"t","entity":"a","ts":"not-a-time"}`, ReasonBadTimestamp},
		{"future_ts", SourceJSON, `{"id":"x","type":"t","entity":"a","ts":"2026-09-25T10:00:00Z"}`, ReasonTimestampFuture},
		{"too_old_ts", SourceJSON, `{"id":"x","type":"t","entity":"a","ts":"2026-09-20T00:00:00Z"}`, ReasonTimestampTooOld},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.src, tc.raw, cfg)
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("expected *ParseError, got %v", err)
			}
			if pe.Reason != tc.reason {
				t.Fatalf("reason = %s, want %s (detail: %s)", pe.Reason, tc.reason, pe.Error())
			}
			t.Logf("raw=%q rejected reason=%s detail=%q", tc.raw, pe.Reason, pe.Error())
		})
	}
}
