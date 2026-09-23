package event

import "fmt"

// ParseResult 是单条原始记录的解析出口。
//
// 解析层只负责"语法 + 必填字段 + 时间戳可解析性"；
// 时间语义异常（未来/超期）由引擎在掌握水位线后判定为隔离。
type ParseResult struct {
	Event  *Event       // 解析成功时的归一化事件（此时尚未做时间语义判定）
	Status Status       // accepted / rejected
	Reason RejectReason // 拒绝时的可区分原因
	Detail string       // 人类可读细节
}

// IsAccepted 报告解析是否通过。
func (r *ParseResult) IsAccepted() bool { return r.Status == StatusAccepted }

// Parser 把某一来源格式的原始记录解析为归一化事件。
type Parser interface {
	Source() Source
	// Parse 解析原始记录。语法/字段/时间戳错误以 ParseResult{Status:Rejected} 返回，
	// 不 panic、不静默丢弃。
	Parse(raw string) ParseResult
}

// ParseError 携带解析失败的结构化原因，便于在日志中区分失败类型。
type ParseError struct {
	Reason RejectReason
	Detail string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("parse rejected: %s: %s", e.Reason, e.Detail)
}

// Registry 按来源注册并查找解析器。
type Registry struct {
	parsers map[Source]Parser
}

// NewRegistry 创建空解析器注册表。
func NewRegistry() *Registry {
	return &Registry{parsers: map[Source]Parser{}}
}

// Register 注册解析器。
func (r *Registry) Register(p Parser) { r.parsers[p.Source()] = p }

// Get 按来源查找解析器。
func (r *Registry) Get(s Source) (Parser, bool) {
	p, ok := r.parsers[s]
	return p, ok
}

// Parse 使用与来源匹配的解析器解析记录；来源未知时返回可区分的拒绝结果。
func (r *Registry) Parse(s Source, raw string) ParseResult {
	p, ok := r.parsers[s]
	if !ok {
		return ParseResult{Status: StatusRejected, Reason: RejectUnknownSource,
			Detail: fmt.Sprintf("no parser registered for source %q", s)}
	}
	return p.Parse(raw)
}

// --- 具体来源解析器（实现见 parser_*.go） ---

// SyslogParser 解析 "key=value" 风格的 syslog 行。
type SyslogParser struct{}

// NewSyslogParser 创建 syslog 解析器。
func NewSyslogParser() *SyslogParser { return &SyslogParser{} }

// JSONParser 解析 JSON 事件对象。
type JSONParser struct{}

// NewJSONParser 创建 JSON 解析器。
func NewJSONParser() *JSONParser { return &JSONParser{} }

// CEFParser 解析 CEF:0|... 竖线分隔记录（扩展字段为 key=value）。
type CEFParser struct{}

// NewCEFParser 创建 CEF 解析器。
func NewCEFParser() *CEFParser { return &CEFParser{} }
