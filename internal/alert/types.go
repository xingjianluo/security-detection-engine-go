// Package alert 管理告警生命周期、租户隔离、权限校验与审计记录。
package alert

import "time"

// Status 告警生命周期状态。
type Status string

const (
	StatusOpen   Status = "open"
	StatusAcked  Status = "acked" // 已确认
	StatusClosed Status = "closed"
	// StatusSuperseded 是终态：该结论已被一次回补更正取代。
	// 记录仍保留可查（Get/ListHistory/AuditLog），但不属于活跃告警，
	// 不出现在正常查询 List 中，也不再接受 Ack/Close/Reopen。
	StatusSuperseded Status = "superseded"
)

// Role 操作者角色。
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// Alert 是一条由关联检测产生的告警。
type Alert struct {
	ID              string
	TenantID        string
	RuleID          string
	RuleVersion     int
	Entity          string
	Status          Status
	CreatedAt       time.Time // 告警时间语义 = 合并事件的最早事件时间
	UpdatedAt       time.Time
	EventIDs        []string // 合并的全部事件 ID（含抑制追加的）
	SuppressedCount int      // 被抑制合并的命中次数
	// FireAt 为阈值穿越点（窗口右端，事件时间）；CreatedAt 是窗口内最早事件时间。
	// 回补按 FireAt 圈定窗口归属，使同一时间窗的结论可对齐、可比对。
	FireAt time.Time
	// Superseded 为 true 表示该结论已被一次回补更正取代，Status 同时为
	// StatusSuperseded 终态；记录仍保留可查，但不再是该（规则,实体,时间窗）
	// 的可见最终结论，也不接受任何生命周期变更。
	Superseded bool
	// SupersededBy 指向取代它的更正记录 ID。
	SupersededBy string
	// Supersedes 仅更正告警携带：被本条更正结论取代的旧结论 ID 列表（便于正向追溯）。
	Supersedes []string
	// IsCorrection 标记该告警是一次回补产生的更正结论（而非首次检测结论）。
	IsCorrection bool
	// CorrectionID 当 IsCorrection 时，指向对应更正记录 ID。
	CorrectionID string
}

// Operator 描述一次操作的操作者。
type Operator struct {
	ID       string
	TenantID string
	Role     Role
}

// AuditEntry 是一次状态变更的不可变审计记录。
type AuditEntry struct {
	Seq        int64
	AlertID    string
	TenantID   string
	Action     string
	OperatorID string
	FromState  Status
	ToState    Status
	At         time.Time // 以墙钟时间记录"谁在什么时候做了什么"
	Reason     string
}
