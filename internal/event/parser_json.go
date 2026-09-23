package event

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// jsonRecord 是 JSON 事件的宽松解码结构：
// ts 允许数字（Unix 秒/毫秒）或字符串（RFC3339）；未知字段进入 extra。
type jsonRecord struct {
	ID       string            `json:"id"`
	Tenant   string            `json:"tenant"`
	Entity   string            `json:"entity"`
	Type     string            `json:"type"`
	Severity string            `json:"severity"`
	TS       json.RawMessage   `json:"ts"`
	Extra    map[string]string `json:"-"`
}

func (p *JSONParser) Source() Source { return SourceJSON }

func (p *JSONParser) Parse(raw string) ParseResult {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return reject(RejectSyntax, "empty record")
	}
	var rec jsonRecord
	dec := json.NewDecoder(strings.NewReader(raw))
	if err := dec.Decode(&rec); err != nil {
		return reject(RejectSyntax, fmt.Sprintf("invalid json: %v", err))
	}
	// 任何多余的 JSON 顶层 token 都视为语法不合法（避免静默截断输入）。
	if dec.More() {
		return reject(RejectSyntax, "multiple json values in one record")
	}

	fields := map[string]string{
		fieldID:       rec.ID,
		fieldTenant:   rec.Tenant,
		fieldEntity:   rec.Entity,
		fieldType:     rec.Type,
		fieldSeverity: rec.Severity,
	}
	ts, err := decodeJSONTS(rec.TS)
	if err != nil {
		return reject(RejectBadTimestamp, err.Error())
	}
	fields[fieldTime] = ts

	// 收集额外字段（仅字符串值进入 metadata，其余以 JSON 文本保留）。
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err == nil {
		for k, v := range top {
			switch k {
			case "id", "tenant", "entity", "type", "severity", "ts":
				continue
			}
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				fields[k] = s
			} else {
				fields[k] = strings.TrimSpace(string(v))
			}
		}
	}
	return normalize(SourceJSON, raw, fields)
}

// decodeJSONTS 把 JSON ts 字段统一转成 parseTimestamp 可接受的字符串形式。
func decodeJSONTS(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("field ts is required but missing")
	}
	s := strings.TrimSpace(string(raw))
	if s == "null" {
		return "", fmt.Errorf("field ts must not be null")
	}
	// 字符串：剥掉外层引号后交给统一时间解析。
	if len(s) >= 2 && s[0] == '"' {
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return "", fmt.Errorf("field ts invalid string: %v", err)
		}
		return str, nil
	}
	// 数字：必须是整数（Unix 秒/毫秒）；浮点秒容易丢精度，明确拒绝。
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "", fmt.Errorf("field ts=%q neither string nor number", s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return "", fmt.Errorf("field ts=%v must be integer epoch seconds/millis, fractional rejected", f)
	}
	return strconv.FormatInt(n, 10), nil
}
