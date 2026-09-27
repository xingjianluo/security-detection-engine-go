// Package backfill 实现受控的历史回补：运维在确认上游补齐后，按 (租户, 时间段)
// 发起一次回补，把之前因迟到而隔离的记录重新纳入检测，并以【更正】的形式给出
// 新结论——原结论保留可查，可见的最终结论在同一 (租户,规则,实体,时间窗) 上唯一。
package backfill

import (
	"errors"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
)

// 可区分的回补拒绝原因，调用方无需猜测。
var (
	// ErrInvalidRange 时间段非法（空区间、From>To 等）。
	ErrInvalidRange = errors.New("backfill: invalid time range")
	// ErrRangeNotFinalized 回补终点越过当前已断言水位：该段结论尚未定论，不能回补。
	ErrRangeNotFinalized = errors.New("backfill: range extends beyond current watermark")
	// ErrBeyondHorizon 回补起点早于可回补下限（MaxBackfillAge），超出受控范围。
	ErrBeyondHorizon = errors.New("backfill: range older than max backfill age")
	// ErrCrossTenant 操作者租户与回补目标租户不一致（跨租户越权）。
	ErrCrossTenant = alert.ErrCrossTenant
	// ErrPermissionDenied 操作者角色无权发起回补（仅 operator/admin）。
	ErrPermissionDenied = alert.ErrPermissionDenied
)

// Status 回补请求的处理结果三态。
type Status string

const (
	// StatusAcceptedChanged 请求被接受，且真的改变了可见结论（产生了更正或新增）。
	StatusAcceptedChanged Status = "accepted_changed"
	// StatusAcceptedUnchanged 请求被接受，但重算结论与现状一致，不产生任何噪音。
	StatusAcceptedUnchanged Status = "accepted_unchanged"
	// StatusRejected 请求被拒绝（越权/跨租户/超范围），见结果中的 Err。
	StatusRejected Status = "rejected"
)

// Request 是一次受控回补请求。
type Request struct {
	// RequestID 由调用方提供的幂等键：同一请求重复发起返回同一结果，不重复更正。
	RequestID string
	TenantID  string         // 只影响该租户
	From      time.Time      // 回补事件时间下界（含）
	To        time.Time      // 回补事件时间上界（含），不得越过当前水位
	Operator  alert.Operator // 发起者（角色与租户校验）
	Reason    string         // 人工说明（审计）
}

// ChangeKind 区分更正的类型。
type ChangeKind string

const (
	// ChangeAdded 原时间窗上没有结论，补入事件后新增告警。
	ChangeAdded ChangeKind = "added"
	// ChangeRevised 原时间窗上已有告警，补入事件后窗口/合并事件/规则版本发生变化。
	ChangeRevised ChangeKind = "revised"
	// ChangeRevoked 原结论在重算后不再成立（防御性；纯补数场景理论上不出现）。
	ChangeRevoked ChangeKind = "revoked"
)

// Correction 是一次回补对单个 (规则,实体) 结论组的更正结果，可追溯：
// 交代原结论是谁、新结论是谁、补了哪些事件、窗口怎么变。
type Correction struct {
	RequestID     string
	TenantID      string
	RuleID        string
	RuleVersion   int // 更正结论适用的规则版本（按事件时间选出的当时版本）
	Entity        string
	Kind          ChangeKind
	AlertKey      string
	WindowFrom    time.Time // 更正后窗口的最早事件时间
	WindowTo      time.Time // 更正后窗口的最晚事件时间（含抑制命中）
	OldAlertIDs   []string  // 被替代的原告警 ID（Added 时为空；空切片表示无）
	NewAlertID    string    // 更正后的当前生效告警 ID（Revoked 时为空）
	AddedEventIDs []string  // 本次回补新纳入、且并入该结论的事件 ID
	AllEventIDs   []string  // 更正后该结论合并的全部事件 ID
	Note          string
}

// Advisory 是不改变可见结论、但需要向调用方交代的边界影响。
type Advisory struct {
	Kind     string // "out_of_scope_window" 等
	AlertKey string
	EventIDs []string
	Detail   string
}

// Result 是回补请求的完整结果。
type Result struct {
	RequestID       string
	Status          Status
	TenantID        string
	From, To        time.Time
	Replayed        bool         // true 表示命中幂等缓存，未重复执行
	Corrections     []Correction // 实际产生的更正（Unchanged/Rejected 为空）
	Advisories      []Advisory   // 不改变可见结论的边界交代
	Backfilled      []string     // 实际从隔离区重新纳入的事件
	BackfilledCount int          // 实际重新纳入的事件数（日志用）
	SkippedDup      []string     // 候选中因已纳入（重复/已回补）而跳过的事件
	Err             error        // Status=rejected 时的可区分原因
}
