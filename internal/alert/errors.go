package alert

import "errors"

// 告警操作的可区分错误原因。
var (
	// ErrNotFound 告警不存在（对非属主租户也返回该错误，避免存在性探测）。
	ErrNotFound = errors.New("alert not found")
	// ErrCrossTenant 跨租户访问被拒绝。
	ErrCrossTenant = errors.New("cross-tenant access denied")
	// ErrVersionConflict CAS 版本冲突：提交基于的版本已过期。
	ErrVersionConflict = errors.New("alert version conflict")
	// ErrInvalidTransition 非法状态转移。
	ErrInvalidTransition = errors.New("invalid alert state transition")
	// ErrEmptyOperator 缺少操作者标识。
	ErrEmptyOperator = errors.New("operator must not be empty")
	// ErrEmptyTenant 租户为空（拒绝跨租户扫描）。
	ErrEmptyTenant = errors.New("tenant must not be empty")
)
