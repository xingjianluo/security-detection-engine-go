package alert

import (
	"sort"
	"sync"
	"time"
)

// 权限规则：
//   - Viewer：只读。Get/List 允许；任何状态变更返回 ErrPermissionDenied。
//   - Operator / Admin：可在自己租户内确认、关闭、重开告警。
//   - 任何对其他租户告警的访问（含读取）返回 ErrCrossTenant，与权限错误可区分。
//
// 生命周期状态机（所有转换幂等）：
//
//	open   --Ack-->    acked    （acked 重复 Ack => 幂等命中）
//	open/acked --Close--> closed（closed 重复 Close => 幂等命中）
//	closed --Reopen--> open     （open/acked 重复 Reopen => 幂等命中）
//	closed --Ack-->    错误 ErrInvalidTransition（须先 Reopen）
//
// 审计：成功的状态变更、抑制合并与幂等命中各产生一条不可变 AuditEntry；
// 被拒绝（越权/跨租户/非法转换）的尝试也记入拒绝审计，可追溯。
type Store struct {
	mu          sync.Mutex
	clock       func() time.Time
	alerts      map[string]*Alert
	audit       map[string][]AuditEntry // alertID -> 有序记录（成功/幂等变更视图）
	all         []AuditEntry            // 全量有序审计链（含被拒绝尝试），序号无缺口
	denied      []AuditEntry            // 被拒绝操作视图
	corrections map[string]*Correction  // correctionID -> 不可变更正记录
	corrOrder   []string                // 更正记录 ID 的登记顺序
	windowIdx   map[windowKey]string    // 窗口身份 -> 更正 ID（同窗口唯一可见结论）
	seq         int64
}

// NewStore 创建告警存储。clock 用于审计与状态变更时间（墙钟时间），nil 时取 time.Now。
func NewStore(clock func() time.Time) *Store {
	if clock == nil {
		clock = time.Now
	}
	return &Store{
		clock:       clock,
		alerts:      map[string]*Alert{},
		audit:       map[string][]AuditEntry{},
		corrections: map[string]*Correction{},
		windowIdx:   map[windowKey]string{},
	}
}

// Create 按检测结论创建告警。ID 必须全局唯一（引擎用确定性 FireID 派生）。
// 相同 ID 的重复创建按幂等处理并返回既有告警。
func (s *Store) Create(a Alert) (*Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.TenantID == "" {
		return nil, ErrInvalidTransition
	}
	if ex, ok := s.alerts[a.ID]; ok {
		if ex.TenantID != a.TenantID {
			return nil, ErrCrossTenant
		}
		return ex, nil
	}
	a.Status = StatusOpen
	now := s.clock().UTC()
	a.CreatedAt = a.CreatedAt.UTC() // 事件时间语义：告警时间=合并的最早事件时间
	a.UpdatedAt = now
	if a.EventIDs == nil {
		a.EventIDs = []string{}
	}
	stored := a
	s.alerts[a.ID] = &stored
	s.appendAuditLocked(AuditEntry{
		AlertID: a.ID, TenantID: a.TenantID, Action: "create",
		FromState: "", ToState: StatusOpen, At: now,
		Reason: "created from correlated detection",
	})
	return &stored, nil
}

// MergeSuppressed 把一次抑制命中合并的事件 ID 追加到既有告警，并计数。
// 重复的事件 ID 不会重复计入（幂等）。
//
// 若目标告警已被一次回补更正取代（superseded）：
//   - 存在替代结论时，命中重定向合并到当前可见的更正告警（旧结论保持终态、不复活）；
//   - 结论被撤回（无替代告警）时返回 ErrAlertSuperseded，由上层决定抑制期如何处理。
func (s *Store) MergeSuppressed(alertID, tenantID string, eventIDs []string, fireID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[alertID]
	if !ok {
		return ErrAlertNotFound
	}
	if a.TenantID != tenantID {
		s.recordDeniedLocked(a, Operator{TenantID: tenantID}, "suppress_merge", ErrCrossTenant)
		return ErrCrossTenant
	}
	if a.Superseded {
		if a.SupersededBy == "" {
			return ErrAlertSuperseded
		}
		corr, ok := s.corrections[a.SupersededBy]
		if !ok || corr.CorrectedAlertID == "" {
			return ErrAlertSuperseded // 撤回结论：没有可承接的活跃告警
		}
		target := s.alerts[corr.CorrectedAlertID]
		s.appendAuditLocked(AuditEntry{
			AlertID: alertID, TenantID: tenantID, Action: "suppress_merge_redirect",
			FromState: StatusSuperseded, ToState: StatusSuperseded, At: s.clock().UTC(),
			Reason: "redirected suppressed hit " + fireID + " to corrected alert " + target.ID,
		})
		a = target // 后续合并写入替代结论
	}
	exist := map[string]bool{}
	for _, id := range a.EventIDs {
		exist[id] = true
	}
	added := 0
	for _, id := range eventIDs {
		if !exist[id] {
			a.EventIDs = append(a.EventIDs, id)
			exist[id] = true
			added++
		}
	}
	sort.Strings(a.EventIDs)
	a.SuppressedCount += added
	if added > 0 {
		a.UpdatedAt = s.clock().UTC()
	}
	s.appendAuditLocked(AuditEntry{
		AlertID: a.ID, TenantID: tenantID, Action: "suppress_merge",
		FromState: a.Status, ToState: a.Status, At: s.clock().UTC(),
		Reason: "merged suppressed hit " + fireID + ": added " +
			itoa(added) + " event(s)",
	})
	return nil
}

// Ack 幂等确认告警。
func (s *Store) Ack(id string, op Operator, reason string) (*Alert, error) {
	return s.transition(id, op, "ack", reason, func(a *Alert) (Status, string, error) {
		switch a.Status {
		case StatusOpen:
			return StatusAcked, "acknowledged", nil
		case StatusAcked:
			return StatusAcked, "already_acked", nil
		default:
			return a.Status, "", ErrInvalidTransition
		}
	})
}

// Close 幂等关闭告警。
func (s *Store) Close(id string, op Operator, reason string) (*Alert, error) {
	return s.transition(id, op, "close", reason, func(a *Alert) (Status, string, error) {
		switch a.Status {
		case StatusOpen, StatusAcked:
			return StatusClosed, "closed", nil
		case StatusClosed:
			return StatusClosed, "already_closed", nil
		default:
			return a.Status, "", ErrInvalidTransition
		}
	})
}

// Reopen 幂等重开告警。
func (s *Store) Reopen(id string, op Operator, reason string) (*Alert, error) {
	return s.transition(id, op, "reopen", reason, func(a *Alert) (Status, string, error) {
		switch a.Status {
		case StatusClosed:
			return StatusOpen, "reopened", nil
		case StatusOpen, StatusAcked:
			return a.Status, "already_open", nil
		default:
			return a.Status, "", ErrInvalidTransition
		}
	})
}

func (s *Store) transition(id string, op Operator, action, reason string,
	step func(a *Alert) (Status, string, error)) (*Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, ErrAlertNotFound
	}
	if a.Superseded {
		// 已被回补更正取代的旧结论保留可查，但不再接受生命周期变更。
		s.recordDeniedLocked(a, op, action, ErrAlertSuperseded)
		return nil, ErrAlertSuperseded
	}
	if a.TenantID != op.TenantID {
		s.recordDeniedLocked(a, op, action, ErrCrossTenant)
		return nil, ErrCrossTenant
	}
	if op.Role != RoleAdmin && op.Role != RoleOperator {
		s.recordDeniedLocked(a, op, action, ErrPermissionDenied)
		return nil, ErrPermissionDenied
	}
	from := a.Status
	to, note, err := step(a)
	if err != nil {
		s.recordDeniedLocked(a, op, action, err)
		return nil, err
	}
	if to != from {
		a.Status = to
		a.UpdatedAt = s.clock().UTC()
	}
	fullReason := note
	if reason != "" {
		fullReason = note + ": " + reason
	}
	s.appendAuditLocked(AuditEntry{
		AlertID: id, TenantID: a.TenantID, Action: action,
		OperatorID: op.ID, FromState: from, ToState: to,
		At: s.clock().UTC(), Reason: fullReason,
	})
	out := *a
	return &out, nil
}

// Get 读取告警（Viewer 可读；强制租户隔离）。
func (s *Store) Get(id string, op Operator) (*Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, ErrAlertNotFound
	}
	if a.TenantID != op.TenantID {
		s.recordDeniedLocked(a, op, "get", ErrCrossTenant)
		return nil, ErrCrossTenant
	}
	out := *a
	return &out, nil
}

// List 是正常业务查询：按租户列出【当前有效】的告警，即未被回补更正取代的
// 最终结论；同一（规则,实体,时间窗）至多一条，按穿越点事件时间排序。
// 被更正取代的旧结论（superseded 终态）不会出现，需要留痕追溯时用
// Get / ListHistory / GetCorrection。
func (s *Store) List(tenantID string) []*Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listByTenantLocked(tenantID, false)
}

// AuditLog 返回某条告警的全部审计记录（按序号有序）；跨租户拒绝。
func (s *Store) AuditLog(id string, op Operator) ([]AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, ErrAlertNotFound
	}
	if a.TenantID != op.TenantID {
		s.recordDeniedLocked(a, op, "audit", ErrCrossTenant)
		return nil, ErrCrossTenant
	}
	out := append([]AuditEntry{}, s.audit[id]...)
	return out, nil
}

// DeniedAttempts 返回被拒绝操作的审计记录（安全追溯用）。
func (s *Store) DeniedAttempts() []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEntry{}, s.denied...)
}

// AuditTrail 返回全量有序审计链（所有变更与拒绝尝试，序号连续无缺口）。
func (s *Store) AuditTrail() []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEntry{}, s.all...)
}

func (s *Store) appendAuditLocked(e AuditEntry) {
	s.seq++
	e.Seq = s.seq
	if e.OperatorID == "" {
		e.OperatorID = "system"
	}
	s.audit[e.AlertID] = append(s.audit[e.AlertID], e)
	s.all = append(s.all, e)
}

func (s *Store) recordDeniedLocked(a *Alert, op Operator, action string, err error) {
	s.seq++
	tenant := op.TenantID
	if a != nil && err == ErrCrossTenant {
		tenant = a.TenantID + " <- attempted_by " + op.TenantID
	}
	rec := AuditEntry{
		Seq: s.seq, AlertID: alertIDOr(a), TenantID: tenant, Action: action,
		OperatorID: op.ID, FromState: statusOr(a), ToState: statusOr(a),
		At: s.clock().UTC(), Reason: "denied: " + err.Error(),
	}
	s.denied = append(s.denied, rec)
	s.all = append(s.all, rec)
}

func alertIDOr(a *Alert) string {
	if a == nil {
		return ""
	}
	return a.ID
}

func statusOr(a *Alert) Status {
	if a == nil {
		return ""
	}
	return a.Status
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
