// Package alert 管理告警生命周期、租户隔离、权限校验与审计记录。
package alert

import "time"

// Status 告警生命周期状态。
type Status string

const (
	StatusOpen       Status = "open"
	StatusAcked      Status = "acked" // 已确认
	StatusClosed     Status = "closed"
	StatusSuperseded Status = "superseded" // 被回补后的更正结论替代（原结论保留可查，不再是可见最终版）
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
	// RootID 指向该结论链的首发告警 ID；更正产生的替代告警与原结论共享同一 RootID。
	RootID string
	// SupersededBy：该告警已被回补更正时，指向当前生效的替代告警 ID；空表示当前生效。
	SupersededBy string
	// SupersededAt：被替代的墙钟时间（0 表示未被替代）。
	SupersededAt time.Time
}

// Operator 描述一次操作的操作者。
type Operator struct {
	ID       string
	TenantID string
	Role     Role
}

// SupersedeRequest 是一次回补更正的原子请求：把 OldAlertIDs 标记为被替代，
// 并创建 NewAlert 作为当前生效结论，二者共享同一更正链（RootID）。
type SupersedeRequest struct {
	RequestID   string   // 回补请求的幂等键
	OldAlertIDs []string // 被替代的原告警（ChangeAdded 时为空）
	NewAlert    Alert    // 更正后的新告警（ID 须全局唯一、确定性派生）
	Operator    Operator
	Reason      string
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
