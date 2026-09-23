// Package event 定义归一化安全事件模型、解析结果分类以及可区分的拒绝/隔离原因。
package event

import "time"

// Source 标识事件采集来源。
type Source string

const (
	SourceSyslog  Source = "syslog"
	SourceJSON    Source = "json"
	SourceCEF     Source = "cef"
	SourceUnknown Source = ""
)

// Status 是事件经过入口校验后的归一化分类。
type Status string

const (
	// StatusAccepted 解析与字段校验通过，进入事件时间流水线。
	StatusAccepted Status = "accepted"
	// StatusRejected 记录语法/字段/时间戳不合法，按原因拒绝（不参与任何计算）。
	StatusRejected Status = "rejected"
	// StatusQuarantined 记录语法合法但时间语义异常（未来时间、过旧超期等），
	// 被隔离以便人工复核，不参与检测计算。
	StatusQuarantined Status = "quarantined"
)

// RejectReason 给出拒绝的可区分原因。
type RejectReason string

const (
	RejectSyntax         RejectReason = "syntax_invalid"         // 负载无法按来源语法解析
	RejectUnknownSource  RejectReason = "unknown_source"         // 未知来源
	RejectMissingID      RejectReason = "missing_event_id"       // 缺少事件唯一 ID
	RejectMissingTenant  RejectReason = "missing_tenant"         // 缺少租户
	RejectMissingEntity  RejectReason = "missing_entity"         // 缺少实体
	RejectMissingType    RejectReason = "missing_event_type"     // 缺少事件类型
	RejectBadTimestamp   RejectReason = "timestamp_unparseable"  // 时间戳无法解析
	RejectNegativeOrZero RejectReason = "timestamp_non_positive" // 时间戳为零/负值
)

// QuarantineReason 给出隔离的可区分原因。
type QuarantineReason string

const (
	QuarantineFuture  QuarantineReason = "timestamp_in_future" // 事件时间显著晚于处理时间
	QuarantineExpired QuarantineReason = "beyond_retention"    // 迟到超过保留水位线
)

// Timing 描述参与计算的事件相对于水位线的时间语义。
type Timing string

const (
	TimingOnTime Timing = "on_time" // 事件时间 >= 当前水位线，正常参与
	TimingLate   Timing = "late"    // 事件时间 < 当前水位线但仍在允许迟到宽限内
)

// Event 是归一化后的安全事件。所有检测计算只依赖该结构，与来源格式无关。
type Event struct {
	ID        string            // 事件全局唯一 ID（去重依据，缺失则拒绝）
	Tenant    string            // 租户标识
	Source    Source            // 采集来源
	Entity    string            // 关联实体（如主机/账号/IP），检测按实体聚合
	Type      string            // 事件类型（如 ssh.auth_failed）
	Severity  string            // 严重级别（可空）
	EventTime time.Time         // 事件发生时间（事件时间语义的唯一基准）
	Metadata  map[string]string // 归一化后的附加字段
	Raw       string            // 原始负载，便于审计与复核
}

// DedupKey 返回重复判定键。同一事件 ID 的重复投递被视为同一事件。
func (e *Event) DedupKey() string { return e.ID }
