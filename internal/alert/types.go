// Package alert 管理告警生命周期、租户隔离、权限校验与审计记录。
package alert

import "time"

// Status 告警生命周期状态。
type Status string

const (
	StatusOpen   Status = "open"
	StatusAcked  Status = "acked" // 已确认
	StatusClosed Status = "closed"
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
