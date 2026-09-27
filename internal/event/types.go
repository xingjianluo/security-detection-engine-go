// Package event 负责多来源安全事件的解析、归一化、时间语义判定
// （迟到 / 重复 / 正常）与隔离记录。
package event

import "time"

// Source 标识事件的采集来源类型。
type Source string

const (
	SourceSyslog Source = "syslog" // RFC5424 风格的文本 syslog
	SourceJSON   Source = "json"   // JSON 结构化日志
	SourceCEF    Source = "cef"    // Common Event Format
)

// Event 是归一化后的内部事件表示。
type Event struct {
	ID         string            // 事件唯一 ID（用于重复投递判定）
	TenantID   string            // 租户标识（路由与隔离）
	Source     Source            // 采集来源
	Type       string            // 事件类型（参与规则匹配）
	Entity     string            // 关联实体（如用户名、主机、IP）
	EventTime  time.Time         // 事件发生时间（参与所有窗口计算的唯一时间语义）
	ReceivedAt time.Time         // 引擎接收时间（仅用于审计，不参与检测）
	Attrs      map[string]string // 其它归一化属性
	Raw        string            // 原始报文（便于追溯）
}

// Disposition 是事件进入引擎后的判定类别。
type Disposition string

const (
	// DispAccepted 正常事件：被纳入关联计算。
	DispAccepted Disposition = "accepted"
	// DispDuplicate 重复事件：ID 已处理过，不重复参与计算。
	DispDuplicate Disposition = "duplicate"
	// DispLate 迟到事件：事件时间早于水位允许延迟下限，被隔离不参与计算。
	DispLate Disposition = "late"
	// DispRejected 非法事件：解析/校验失败，按原因拒绝。
	DispRejected Disposition = "rejected"
)

// RejectReason 是拒绝事件的可区分原因。
type RejectReason string

const (
	ReasonParseError      RejectReason = "parse_error"         // 报文格式不合法
	ReasonMissingField    RejectReason = "missing_field"       // 必填字段缺失
	ReasonBadTimestamp    RejectReason = "bad_timestamp"       // 时间戳格式不合法
	ReasonTimestampFuture RejectReason = "timestamp_in_future" // 事件时间超过未来容忍上限
	ReasonTimestampTooOld RejectReason = "timestamp_too_old"   // 事件时间早于历史下限
)

// QuarantineRecord 记录被拒绝或被隔离（迟到）的事件，保证不静默丢弃。
type QuarantineRecord struct {
	Raw          string
	Source       Source
	TenantID     string // 归属租户（迟到记录是回补的候选来源，需按租户圈定）
	EventID      string // 归一化事件 ID（迟到记录可用，便于去重与回补追溯）
	Disposition  Disposition
	Reason       RejectReason
	Detail       string
	ReceivedAt   time.Time
	BackfilledBy string // 非空表示该迟到记录已被某次回补请求重新纳入（请求 ID）
	BackfilledAt time.Time
}

// Outcome 是一条原始记录经过入口判定后的结果，四种去向互斥。
type Outcome struct {
	Disposition Disposition
	Event       *Event            // 仅 DispAccepted / DispDuplicate / DispLate 时非空
	Quarantine  *QuarantineRecord // 仅 DispRejected / DispLate 时非空
}

// Watermark 表示事件时间水位：引擎已观察到的最大事件时间。
type Watermark struct {
	t time.Time
}

// NewWatermark 返回给定初始值的水位（零值表示尚未见到任何事件）。
func NewWatermark(initial time.Time) Watermark { return Watermark{t: initial} }

// T 返回水位代表的事件时间。
func (w Watermark) T() time.Time { return w.t }
