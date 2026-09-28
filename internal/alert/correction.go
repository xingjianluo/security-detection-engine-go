// 回补更正结论（correction）：回补重算后若某时间窗结论发生变化，
// 原告警不删除、不改写，而是被标记为"已被更正（superseded）"保留可查；
// 更正结果以独立的 Correction 记录承载，可追溯回原结论与补入的事件。
package alert

import (
	"errors"
	"sort"
	"time"
)

// 更正相关的可区分错误。
var (
	// ErrCorrectionNotFound 更正记录不存在。
	ErrCorrectionNotFound = errors.New("correction not found")
	// ErrAlertSuperseded 告警已被一次更正取代，不能再作为最终结论变更。
	ErrAlertSuperseded = errors.New("alert superseded by a correction")
	// ErrCorrectionConflict 同一（规则,实体,时间窗）已存在另一条当前有效结论，
	// 不能再登记一条并列的更正，避免一个窗口出现两条最终版。
	ErrCorrectionConflict = errors.New("correction conflicts with existing effective alert for the same window")
)

// CorrectionKind 描述更正的类型。
type CorrectionKind string

const (
	// CorrectionChanged 原窗口有告警，重算后结论变化（合并事件/窗口不同）。
	CorrectionChanged CorrectionKind = "changed"
	// CorrectionWithdrawn 原窗口有告警，补入事件重算后该窗口不再成立。
	CorrectionWithdrawn CorrectionKind = "withdrawn"
	// CorrectionAdded 原窗口无告警，补入事件后新增成立。
	CorrectionAdded CorrectionKind = "added"
)

// Correction 是一次回补对单个（规则,实体,时间窗）结论的更正记录，不可变。
type Correction struct {
	ID               string
	RequestID        string // 发起回补的请求 ID（幂等键）
	TenantID         string
	RuleID           string
	RuleVersion      int
	Entity           string
	Kind             CorrectionKind
	WindowStart      time.Time // 被更正窗口的左端（事件时间）
	WindowEnd        time.Time // 被更正窗口的右端 = 穿越点 FireAt（事件时间）
	OriginalAlertIDs []string  // 被取代的原结论告警 ID（added 时为空）
	CorrectedAlertID string    // 更正后的新告警 ID（withdrawn 时为空）
	AddedEventIDs    []string  // 本次回补补入、导致结论变化的事件 ID
	BaselineEventIDs []string  // 原结论合并的事件集合（可追溯）
	FinalEventIDs    []string  // 更正后结论合并的事件集合（可追溯）
	Reason           string    // 人类可读的更正说明
	OperatorID       string
	CreatedAt        time.Time // 墙钟时间：更正发生的时刻
}

// supersedeLocked 标记一条既有告警被更正取代并写审计。调用方持锁。
// 旧告警进入 StatusSuperseded 终态：列表不再可见、不可再处置，但记录留痕。
func (s *Store) supersedeLocked(alertID, correctionID, reason string) error {
	a, ok := s.alerts[alertID]
	if !ok {
		return ErrAlertNotFound
	}
	if a.Superseded && a.SupersededBy != correctionID {
		// 同一时间窗不允许两条互相矛盾、都自称最终版的结论。
		return ErrAlertSuperseded
	}
	if a.Superseded {
		return nil // 幂等：已被同一更正取代
	}
	from := a.Status
	a.Superseded = true
	a.Status = StatusSuperseded
	a.SupersededBy = correctionID
	a.UpdatedAt = s.clock().UTC()
	s.appendAuditLocked(AuditEntry{
		AlertID: alertID, TenantID: a.TenantID, Action: "supersede",
		FromState: from, ToState: StatusSuperseded, At: s.clock().UTC(),
		Reason: "superseded by correction " + correctionID + ": " + reason,
	})
	return nil
}

// Supersede 把一条既有告警标记为被某更正记录取代。原记录保留可查。
func (s *Store) Supersede(alertID, correctionID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.supersedeLocked(alertID, correctionID, reason)
}

// registerCorrectionLocked 登记一条不可变更正记录。调用方持锁。
func (s *Store) registerCorrectionLocked(corr Correction) *Correction {
	cp := corr
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = s.clock().UTC()
	}
	if cp.OriginalAlertIDs == nil {
		cp.OriginalAlertIDs = []string{}
	}
	if cp.AddedEventIDs == nil {
		cp.AddedEventIDs = []string{}
	}
	if cp.BaselineEventIDs == nil {
		cp.BaselineEventIDs = []string{}
	}
	if cp.FinalEventIDs == nil {
		cp.FinalEventIDs = []string{}
	}
	stored := cp
	s.corrections[cp.ID] = &stored
	s.corrOrder = append(s.corrOrder, cp.ID)
	return &stored
}

// CreateCorrected 基于重算结论创建一条"更正告警"，并登记其 Correction 记录。
// 同 correctionID 重复调用按幂等处理，返回既有结论。
// 不变量：同一（租户,规则,实体,窗口右端 FireAt）至多一条当前有效结论；
// 若该窗口已存在另一条未被取代的告警，返回 ErrCorrectionConflict（不产生任何改动）。
func (s *Store) CreateCorrected(corr Correction, a Alert) (*Alert, *Correction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.TenantID == "" {
		return nil, nil, ErrInvalidTransition
	}
	if got, ok := s.corrections[corr.ID]; ok { // 幂等
		if ga, ok2 := s.alerts[got.CorrectedAlertID]; ok2 {
			out := *ga
			return &out, got, nil
		}
		return nil, got, nil
	}

	// 先校验：目标窗口不能已有另一条当前有效结论（防止同一窗口两条更正并存）。
	// 本次更正自己要取代的原告警除外（它们随后立即进入 superseded）。
	replacing := map[string]bool{}
	for _, oid := range corr.OriginalAlertIDs {
		replacing[oid] = true
	}
	for _, ex := range s.alerts {
		if ex.TenantID == a.TenantID && ex.RuleID == a.RuleID && ex.Entity == a.Entity &&
			ex.FireAt.Equal(a.FireAt) && !ex.Superseded && !replacing[ex.ID] {
			return nil, nil, ErrCorrectionConflict
		}
	}
	// 取代原结论（changed 有原告警；added 没有）。校验先于变更，避免半更新。
	for _, oid := range corr.OriginalAlertIDs {
		if err := s.supersedeLocked(oid, corr.ID, corr.Reason); err != nil {
			return nil, nil, err
		}
	}

	a.IsCorrection = true
	a.CorrectionID = corr.ID
	a.Supersedes = append([]string{}, corr.OriginalAlertIDs...)
	a.Status = StatusOpen
	now := s.clock().UTC()
	a.CreatedAt = a.CreatedAt.UTC()
	if a.FireAt.IsZero() {
		a.FireAt = a.CreatedAt
	}
	a.FireAt = a.FireAt.UTC()
	a.UpdatedAt = now
	if a.EventIDs == nil {
		a.EventIDs = []string{}
	}
	storedAlert := a
	s.alerts[a.ID] = &storedAlert

	corr.CorrectedAlertID = a.ID
	if corr.Kind == "" {
		corr.Kind = CorrectionChanged
	}
	created := s.registerCorrectionLocked(corr)

	s.appendAuditLocked(AuditEntry{
		AlertID: a.ID, TenantID: a.TenantID, Action: "create_correction",
		FromState: "", ToState: StatusOpen, At: now,
		Reason: "corrected alert from backfill request " + corr.RequestID +
			": " + corr.Reason,
	})
	out := storedAlert
	return &out, created, nil
}

// RegisterWithdrawal 登记一条"撤回"更正（原窗口结论不再成立，无替代告警）。
func (s *Store) RegisterWithdrawal(corr Correction) (*Correction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if got, ok := s.corrections[corr.ID]; ok { // 幂等
		return got, nil
	}
	prior := map[string]Status{}
	for _, oid := range corr.OriginalAlertIDs {
		if a, ok := s.alerts[oid]; ok {
			prior[oid] = a.Status
		}
		if err := s.supersedeLocked(oid, corr.ID, corr.Reason); err != nil {
			return nil, err
		}
	}
	corr.Kind = CorrectionWithdrawn
	corr.CorrectedAlertID = ""
	created := s.registerCorrectionLocked(corr)
	for _, oid := range corr.OriginalAlertIDs {
		s.appendAuditLocked(AuditEntry{
			AlertID: oid, TenantID: corr.TenantID, Action: "withdraw_correction",
			FromState: prior[oid], ToState: StatusSuperseded, At: s.clock().UTC(),
			Reason: "conclusion withdrawn by backfill request " + corr.RequestID +
				": " + corr.Reason,
		})
	}
	return created, nil
}

// ListCorrections 按租户列出全部更正记录（按窗口右端事件时间排序）。
func (s *Store) ListCorrections(tenantID string) []Correction {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Correction
	for _, id := range s.corrOrder {
		c := s.corrections[id]
		if c.TenantID == tenantID {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].WindowEnd.Equal(out[j].WindowEnd) {
			return out[i].WindowEnd.Before(out[j].WindowEnd)
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Entity < out[j].Entity
	})
	return out
}

// GetCorrection 读取单条更正记录（强制租户隔离）。
func (s *Store) GetCorrection(id string, op Operator) (*Correction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.corrections[id]
	if !ok {
		return nil, ErrCorrectionNotFound
	}
	if c.TenantID != op.TenantID {
		s.recordDeniedLocked(nil, op, "get_correction", ErrCrossTenant)
		return nil, ErrCrossTenant
	}
	out := *c
	return &out, nil
}

// EffectiveAlerts 返回租户当前"可见的最终结论"：未被更正取代的告警，
// 同一（规则,实体,时间窗）至多一条，按事件时间排序。被更正取代的旧告警不在其中。
func (s *Store) EffectiveAlerts(tenantID string) []*Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Alert
	for _, a := range s.alerts {
		if a.TenantID == tenantID && !a.Superseded {
			cp := *a
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FireAt.Equal(out[j].FireAt) {
			return out[i].FireAt.Before(out[j].FireAt)
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].Entity != out[j].Entity {
			return out[i].Entity < out[j].Entity
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// RecordDeniedBackfill 把一次被拒绝的回补尝试记入全量审计链（含跨租户/越权/超范围）。
func (s *Store) RecordDeniedBackfill(tenantID string, op Operator, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordDeniedLocked(nil, op, "backfill", errors.New(reason))
	// recordDeniedLocked 以操作者租户记账；跨租户回补时改写为
	// "目标租户 <- attempted_by 操作者租户"，使越权目标可追溯。
	if len(s.all) > 0 {
		rec := s.all[len(s.all)-1]
		if tenantID != "" && tenantID != op.TenantID {
			rec.TenantID = tenantID + " <- attempted_by " + op.TenantID
			s.all[len(s.all)-1] = rec
			if len(s.denied) > 0 {
				s.denied[len(s.denied)-1] = rec
			}
		}
	}
}
