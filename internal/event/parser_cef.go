package event

import (
	"fmt"
	"strings"
)

// CEF 记录格式（以 '|' 分隔的 7 段头部 + 可选 key=value 扩展）：
//
//	CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value key2=value2
//
// 归一化所需字段全部要求出现在扩展段，标准名：id tenant entity type ts(+severity)。
// 头部 Severity 段在扩展未提供 severity 时作为补充。
func (p *CEFParser) Source() Source { return SourceCEF }

func (p *CEFParser) Parse(raw string) ParseResult {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return reject(RejectSyntax, "empty record")
	}
	if !strings.HasPrefix(raw, "CEF:") {
		return reject(RejectSyntax, "record does not start with CEF: prefix")
	}
	// 第 7 个分隔符之后整体为扩展段，扩展值中允许出现 '|'。
	parts := strings.SplitN(raw, "|", 8)
	if len(parts) < 7 {
		return reject(RejectSyntax,
			fmt.Sprintf("cef header must have 7 pipe-delimited fields, got %d", len(parts)-1))
	}
	if parts[0] != "CEF:0" && parts[0] != "CEF:1" {
		return reject(RejectSyntax, fmt.Sprintf("unsupported cef version header %q", parts[0]))
	}
	headerSeverity := ""
	if fs := strings.Fields(parts[6]); len(fs) > 0 {
		headerSeverity = fs[0] // 扩展段已由 SplitN 保证位于 parts[7]
	}

	fields := map[string]string{}
	if len(parts) == 8 {
		if strings.TrimSpace(parts[7]) != "" {
			ext, ok := parseKVLine(parts[7])
			if !ok {
				return reject(RejectSyntax, "cef extension contains no key=value tokens")
			}
			for k, v := range ext {
				fields[k] = v
			}
		}
		// 扩展段为空是合法 CEF 语法；具体缺哪个归一化字段由 normalize 给出可区分原因。
	}
	if strings.TrimSpace(fields[fieldSeverity]) == "" && headerSeverity != "" {
		fields[fieldSeverity] = headerSeverity
	}
	// 扩展段为空是合法 CEF 语法；具体缺哪个归一化字段由 normalize 给出可区分原因。
	return normalize(SourceCEF, raw, fields)
}
