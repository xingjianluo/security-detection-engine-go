package alert

import "errors"

// 可区分的操作失败原因，便于测试断言与调用方解释。
var (
	ErrAlertNotFound     = errors.New("alert not found")
	ErrCrossTenant       = errors.New("cross-tenant access denied")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrInvalidTransition = errors.New("invalid alert state transition")
)
