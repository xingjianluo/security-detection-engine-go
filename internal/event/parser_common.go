package event

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// 归一化字段名（各来源解析器把自己的字段映射到这些标准名）。
const (
	fieldID       = "id"
	fieldTenant   = "tenant"
	fieldEntity   = "entity"
	fieldType     = "type"
	fieldSeverity = "severity"
	fieldTime     = "ts"
)

// normalize 从已抽取的字段映射构造归一化事件并做统一校验。
// 校验范围仅限：必填字段齐全、时间戳可解析且非零/非负。
// 时间语义异常（未来、超期）不在此处判定——它依赖引擎的水位线上下文。
func normalize(src Source, raw string, fields map[string]string) ParseResult {
	required := []struct {
		key    string
		reason RejectReason
	}{
		{fieldID, RejectMissingID},
		{fieldTenant, RejectMissingTenant},
		{fieldEntity, RejectMissingEntity},
		{fieldType, RejectMissingType},
	}
	for _, f := range required {
		if strings.TrimSpace(fields[f.key]) == "" {
			return reject(f.reason, fmt.Sprintf("field %q is required but empty", f.key))
		}
	}
	tsRaw, hasTS := fields[fieldTime]
	if !hasTS || strings.TrimSpace(tsRaw) == "" {
		return reject(RejectBadTimestamp, "field ts is required but empty")
	}
	ts, err := parseTimestamp(tsRaw)
	if err != nil {
		return reject(RejectBadTimestamp, fmt.Sprintf("field ts=%q unparseable: %v", tsRaw, err))
	}
	if !ts.After(time.Unix(0, 0)) {
		return reject(RejectNegativeOrZero, fmt.Sprintf("field ts=%q resolves to non-positive time", tsRaw))
	}

	e := &Event{
		ID:        strings.TrimSpace(fields[fieldID]),
		Tenant:    strings.TrimSpace(fields[fieldTenant]),
		Source:    src,
		Entity:    strings.TrimSpace(fields[fieldEntity]),
		Type:      strings.TrimSpace(fields[fieldType]),
		Severity:  strings.TrimSpace(fields[fieldSeverity]),
		EventTime: ts,
		Metadata:  map[string]string{},
		Raw:       raw,
	}
	for k, v := range fields {
		switch k {
		case fieldID, fieldTenant, fieldEntity, fieldType, fieldSeverity, fieldTime:
			continue
		default:
			e.Metadata[k] = v
		}
	}
	return ParseResult{Status: StatusAccepted, Event: e}
}

func reject(reason RejectReason, detail string) ParseResult {
	return ParseResult{Status: StatusRejected, Reason: reason, Detail: detail}
}

// parseTimestamp 支持三种明确格式：
//  1. RFC3339 / RFC3339Nano（可带小数秒与时区）
//  2. 纯数字：按位数区分为秒(<=11 位)或毫秒(>=12 位) Unix 时间
//
// 歧义格式（如本地无时区时间串）一律拒绝，避免静默采用错误时间语义。
func parseTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	// 纯数字：Unix 秒/毫秒
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		n := int64(len(s))
		if n >= 12 {
			return time.UnixMilli(parseInt64(s)).UTC(), nil
		}
		return time.Unix(parseInt64(s), 0).UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("not RFC3339 nor unix epoch: %q", s)
}

func parseInt64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
