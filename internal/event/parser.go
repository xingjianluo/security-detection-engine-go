package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrEmptyRaw 空报文。
var ErrEmptyRaw = errors.New("empty raw record")

// ParseConfig 控制解析与时间戳合法性校验。
type ParseConfig struct {
	// MaxFutureSkew 允许的事件时间相对接收时间的未来偏移（零值表示不检查）。
	MaxFutureSkew time.Duration
	// MaxAge 允许的事件时间相对接收时间的最大历史年龄（零值表示不限制）。
	MaxAge time.Duration
	// Now 返回当前接收时间，便于测试注入固定基准；nil 时使用 time.Now。
	Now func() time.Time
}

// ParseError 携带可区分的拒绝原因，绝不静默丢弃。
type ParseError struct {
	Reason RejectReason
	Err    error
}

func (e *ParseError) Error() string { return string(e.Reason) + ": " + e.Err.Error() }
func (e *ParseError) Unwrap() error { return e.Err }

func reject(reason RejectReason, format string, args ...any) error {
	return &ParseError{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// Parse 按来源解析一条原始记录为归一化事件，失败时返回 *ParseError。
// 支持的来源：syslog（<pri>RFC3339 host app: k=v k=v）、
// JSON（{id,type,entity,ts,attrs}）、CEF（CEF:0|v|p|ver|sig|name|sev|k=v...）。
func Parse(src Source, raw string, cfg ParseConfig) (*Event, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, &ParseError{Reason: ReasonParseError, Err: ErrEmptyRaw}
	}
	var (
		id, typ, entity, tsText string
		attrs                   map[string]string
		err                     error
	)
	switch src {
	case SourceSyslog:
		id, typ, entity, tsText, attrs, err = parseSyslog(raw)
	case SourceJSON:
		id, typ, entity, tsText, attrs, err = parseJSON(raw)
	case SourceCEF:
		id, typ, entity, tsText, attrs, err = parseCEF(raw)
	default:
		return nil, reject(ReasonParseError, "unknown source %q", src)
	}
	if err != nil {
		return nil, err
	}

	if id == "" {
		return nil, reject(ReasonMissingField, "missing required field: id")
	}
	if typ == "" {
		return nil, reject(ReasonMissingField, "missing required field: type (event %s)", id)
	}
	if entity == "" {
		return nil, reject(ReasonMissingField, "missing required field: entity (event %s)", id)
	}
	if tsText == "" {
		return nil, reject(ReasonMissingField, "missing required field: ts (event %s)", id)
	}

	ts, perr := parseTimestamp(tsText)
	if perr != nil {
		return nil, reject(ReasonBadTimestamp, "event %s: %v", id, perr)
	}

	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	ref := now().UTC()
	if cfg.MaxFutureSkew > 0 && ts.After(ref.Add(cfg.MaxFutureSkew)) {
		return nil, reject(ReasonTimestampFuture,
			"event %s event_time=%s later than reference=%s + %s",
			id, ts.Format(time.RFC3339Nano), ref.Format(time.RFC3339Nano), cfg.MaxFutureSkew)
	}
	if cfg.MaxAge > 0 && ts.Before(ref.Add(-cfg.MaxAge)) {
		return nil, reject(ReasonTimestampTooOld,
			"event %s event_time=%s earlier than reference=%s - %s",
			id, ts.Format(time.RFC3339Nano), ref.Format(time.RFC3339Nano), cfg.MaxAge)
	}

	return &Event{
		ID:        id,
		Source:    src,
		Type:      typ,
		Entity:    entity,
		EventTime: ts,
		Attrs:     attrs,
		Raw:       raw,
	}, nil
}

// parseTimestamp 接受 RFC3339（含纳秒/时区）以及 Unix 秒、毫秒纯数字。
func parseTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		switch {
		case n > 1e12: // 毫秒
			return time.UnixMilli(n).UTC(), nil
		default: // 秒
			return time.Unix(n, 0).UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q", s)
}

// parseSyslog 解析 "<pri>RFC3339 host app: k=v k=v" 形式的简化 syslog。
func parseSyslog(raw string) (id, typ, entity, ts string, attrs map[string]string, err error) {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "<") {
		err = reject(ReasonParseError, "syslog: missing <pri> prefix")
		return
	}
	gt := strings.IndexByte(s, '>')
	if gt < 0 {
		err = reject(ReasonParseError, "syslog: unterminated <pri>")
		return
	}
	rest := s[gt+1:]
	// RFC3339 时间戳到下一个空格为止。
	sp := strings.IndexByte(rest, ' ')
	if sp < 0 {
		err = reject(ReasonParseError, "syslog: missing timestamp/body separator")
		return
	}
	ts = rest[:sp]
	body := rest[sp+1:]
	colon := strings.Index(body, ": ")
	if colon < 0 {
		err = reject(ReasonParseError, "syslog: missing ': ' after app name")
		return
	}
	payload := strings.TrimSpace(body[colon+2:])
	id, typ, entity, attrs = parseKV(payload)
	return
}

// parseJSON 解析结构化 JSON 事件。
func parseJSON(raw string) (id, typ, entity, ts string, attrs map[string]string, err error) {
	var doc struct {
		ID     string            `json:"id"`
		Type   string            `json:"type"`
		Entity string            `json:"entity"`
		TS     string            `json:"ts"`
		Attrs  map[string]string `json:"attrs"`
	}
	if e := json.Unmarshal([]byte(raw), &doc); e != nil {
		err = reject(ReasonParseError, "json: %v", e)
		return
	}
	return doc.ID, doc.Type, doc.Entity, doc.TS, doc.Attrs, nil
}

// parseCEF 解析 "CEF:0|vendor|product|version|signatureID|name|severity|extension(k=v k=v)"。
// 扩展字段约定：externalId=事件ID, act=事件类型, suser=实体, rt=事件时间。
func parseCEF(raw string) (id, typ, entity, ts string, attrs map[string]string, err error) {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "CEF:") {
		err = reject(ReasonParseError, "cef: missing CEF: prefix")
		return
	}
	// 头部 7 段，扩展段是第 8 段；扩展段中允许包含 '|'（CEF 需转义，这里头部先切 7 次）。
	parts := strings.SplitN(s, "|", 8)
	if len(parts) < 8 {
		err = reject(ReasonParseError, "cef: expected 8 pipe-separated sections, got %d", len(parts))
		return
	}
	header := strings.SplitN(parts[0], ":", 2)
	if len(header) != 2 || header[1] != "0" {
		err = reject(ReasonParseError, "cef: unsupported CEF version %q", parts[0])
		return
	}
	id, typ, entity, attrs = parseKV(parts[7])
	ts = attrs["rt"]
	return
}

// parseKV 解析以空格分隔的 key=value 序列；已知字段之外的全部进入 attrs。
func parseKV(s string) (id, typ, entity string, attrs map[string]string) {
	attrs = map[string]string{}
	for _, tok := range strings.Fields(s) {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		k, v := tok[:eq], tok[eq+1:]
		switch k {
		case "id", "externalId":
			id = v
		case "type", "act":
			typ = v
		case "entity", "suser":
			entity = v
		default:
			attrs[k] = v
		}
	}
	return
}
