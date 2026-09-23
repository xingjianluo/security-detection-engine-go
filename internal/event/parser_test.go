package event

import (
	"testing"
	"time"
)

func TestParsersAcceptAllSources(t *testing.T) {
	cases := []struct {
		name  string
		src   Source
		raw   string
		expTS time.Time
	}{
		{
			name:  "syslog kv unix seconds",
			src:   SourceSyslog,
			raw:   `id=e1 tenant=t1 entity=host-1 type=ssh.auth_failed severity=high ts=1700000000 user=root`,
			expTS: time.Unix(1700000000, 0).UTC(),
		},
		{
			name:  "syslog kv quoted spaces rfc3339",
			src:   SourceSyslog,
			raw:   `id="e 2" tenant=t1 entity=host-2 type=login ts=2026-09-24T10:00:00Z severity="medium low"`,
			expTS: time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC),
		},
		{
			name:  "json rfc3339",
			src:   SourceJSON,
			raw:   `{"id":"e3","tenant":"t1","entity":"h","type":"x","severity":"low","ts":"2026-09-24T10:00:00.5Z","src_ip":"10.0.0.1"}`,
			expTS: time.Date(2026, 9, 24, 10, 0, 0, 500000000, time.UTC),
		},
		{
			name:  "json epoch millis",
			src:   SourceJSON,
			raw:   `{"id":"e4","tenant":"t1","entity":"h","type":"x","ts":1700000000123}`,
			expTS: time.UnixMilli(1700000000123).UTC(),
		},
		{
			name:  "cef extension",
			src:   SourceCEF,
			raw:   `CEF:0|Acme|IAM|1.0|100|Auth failure|7|id=e5 tenant=t1 entity=acct-9 type=auth.fail ts=1700000000`,
			expTS: time.Unix(1700000000, 0).UTC(),
		},
	}
	reg := NewRegistry()
	reg.Register(NewSyslogParser())
	reg.Register(NewJSONParser())
	reg.Register(NewCEFParser())

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := reg.Parse(tc.src, tc.raw)
			if !res.IsAccepted() {
				t.Fatalf("expected accepted, got %s/%s: %s", res.Status, res.Reason, res.Detail)
			}
			e := res.Event
			if !e.EventTime.Equal(tc.expTS) {
				t.Fatalf("event time = %s, want %s", e.EventTime, tc.expTS)
			}
			if e.ID == "" || e.Tenant == "" || e.Entity == "" || e.Type == "" {
				t.Fatalf("normalized event missing core fields: %+v", e)
			}
		})
	}
}

func TestParserRejectionReasonsDistinguishable(t *testing.T) {
	cases := []struct {
		name   string
		src    Source
		raw    string
		reason RejectReason
	}{
		{"unknown source", SourceUnknown, "anything", RejectUnknownSource},
		{"syslog syntax", SourceSyslog, "this is not kv at all !!", RejectSyntax},
		{"syslog empty", SourceSyslog, "   ", RejectSyntax},
		{"json syntax", SourceJSON, `{not json`, RejectSyntax},
		{"json multiple values", SourceJSON, `{"id":"a"} {"id":"b"}`, RejectSyntax},
		{"cef bad prefix", SourceCEF, `LEEF|x`, RejectSyntax},
		{"cef short header", SourceCEF, `CEF:0|a|b`, RejectSyntax},
		{"missing id", SourceJSON, `{"tenant":"t1","entity":"h","type":"x","ts":"2026-09-24T10:00:00Z"}`, RejectMissingID},
		{"missing tenant", SourceSyslog, `id=e entity=h type=x ts=1700000000`, RejectMissingTenant},
		{"missing entity", SourceSyslog, `id=e tenant=t1 type=x ts=1700000000`, RejectMissingEntity},
		{"missing type", SourceSyslog, `id=e tenant=t1 entity=h ts=1700000000`, RejectMissingType},
		{"bad ts string", SourceSyslog, `id=e tenant=t1 entity=h type=x ts=not-a-time`, RejectBadTimestamp},
		{"bad ts missing", SourceJSON, `{"id":"e","tenant":"t1","entity":"h","type":"x"}`, RejectBadTimestamp},
		{"bad ts null", SourceJSON, `{"id":"e","tenant":"t1","entity":"h","type":"x","ts":null}`, RejectBadTimestamp},
		{"bad ts fractional", SourceJSON, `{"id":"e","tenant":"t1","entity":"h","type":"x","ts":1700000000.5}`, RejectBadTimestamp},
		{"zero ts", SourceSyslog, `id=e tenant=t1 entity=h type=x ts=0`, RejectNegativeOrZero},
		{"cef missing ext keys", SourceCEF, `CEF:0|Acme|IAM|1.0|100|Auth failure|7|`, RejectMissingID},
	}
	reg := NewRegistry()
	reg.Register(NewSyslogParser())
	reg.Register(NewJSONParser())
	reg.Register(NewCEFParser())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := reg.Parse(tc.src, tc.raw)
			if res.Status != StatusRejected {
				t.Fatalf("want rejected, got %s (event=%+v)", res.Status, res.Event)
			}
			if res.Reason != tc.reason {
				t.Fatalf("reason=%q, want %q (%s)", res.Reason, tc.reason, res.Detail)
			}
		})
	}
}

func TestParseTimestampAmbiguity(t *testing.T) {
	if _, err := parseTimestamp("2026-09-24 10:00:00"); err == nil {
		t.Fatal("timezone-less local timestamp must be rejected to keep event-time semantics explicit")
	}
	if _, err := parseTimestamp("2026-09-24T10:00:00Z"); err != nil {
		t.Fatalf("RFC3339 should parse: %v", err)
	}
}
