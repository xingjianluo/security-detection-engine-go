package event

import (
	"fmt"
	"strings"
)

// 期望的 syslog 行形如（token 以空白分隔，顺序任意，值可用双引号包裹）：
//
//	id=evt-1 tenant=t1 entity=host-1 type=ssh.auth_failed severity=high ts=1700000000
//
// 行首可选 "<facility.priority> " 前缀与形如 "2026-09-24T10:00:00Z host app: "
// 的 syslog 头——若无法识别为标准头，且不含任何 key=value，则按语法错误拒绝。
func (p *SyslogParser) Source() Source { return SourceSyslog }

func (p *SyslogParser) Parse(raw string) ParseResult {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return reject(RejectSyntax, "empty record")
	}
	fields, ok := parseKVLine(raw)
	if !ok {
		return reject(RejectSyntax, fmt.Sprintf("no key=value tokens found in syslog line: %q", raw))
	}
	return normalize(SourceSyslog, raw, fields)
}

// parseKVLine 把 "k=v k2=\"v with space\" ..." 解析为映射。
// 返回 ok=false 表示一个 key=value token 都没有（视为语法不合法，而非字段缺失）。
func parseKVLine(raw string) (map[string]string, bool) {
	tokens, ok := tokenizeKV(raw)
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(tokens))
	for _, kv := range tokens {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(kv[:idx])
		v := strings.TrimSpace(kv[idx+1:])
		v = strings.Trim(v, `"`)
		out[k] = v
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// tokenizeKV 以空白切分，但尊重双引号区域。含 '=' 的 token 才被收集；
// 若整行没有任何含 '=' 的 token，则 ok=false。
func tokenizeKV(raw string) ([]string, bool) {
	var tokens []string
	var cur strings.Builder
	inQuotes := false
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		switch {
		case ch == '"':
			inQuotes = !inQuotes
			cur.WriteByte(ch)
		case (ch == ' ' || ch == '\t') && !inQuotes:
			flush()
		default:
			cur.WriteByte(ch)
		}
	}
	flush()

	var kv []string
	for _, t := range tokens {
		if strings.Contains(t, "=") {
			kv = append(kv, t)
		}
	}
	if len(kv) == 0 {
		return nil, false
	}
	return kv, true
}
