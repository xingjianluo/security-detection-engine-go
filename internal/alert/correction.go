// 回补更正结论（correction）：回补重算后若某时间窗结论发生变化，
// 原告警不删除、不改写，而是被标记为"已被更正（superseded）"保留可查；
// 更正结果以独立的 Correction 记录承载，可追溯回原结论与补入的事件。
//
// 唯一性（同一时间窗只允许一条可见结论）：
//   - 窗口身份 = (租户, 规则, 实体, 穿越点 FireAt)；
//   - 每个窗口至多登记一条 Correction；旧结论被它取代后进入 superseded 终态；
//   - 同一窗口的第二次更正（哪怕来自另一次回补）一律拒绝
//     ErrWindowAlreadyCorrected，不会出现两条都自称最终版的结论。
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
	// ErrWindowAlreadyCorrected 该时间窗已经有一条生效中的更正，不能再被更正一次。
	ErrWindowAlreadyCorrected = errors.New("window already has a correction")
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
// 一条记录严格对应一个窗口身份 (TenantID,RuleID,Entity,WindowEnd)。
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

// windowKey 是时间窗的唯一身份。
type windowKey struct {
	tenant string
	rule   string
	entity string
	fireAt time.Time
}

// supersedeLocked 把一条既有告警置为 superseded 终态并写审计。调用方持锁。
// 已经处于 superseded 的告警只有在指向同一条更正时才幂等放行；
// 被另一条更正指向则拒绝（同一窗口两条更正结论）。
func (s *Store) supersedeLocked(alertID, correctionID, reason string) error {
	a, ok := s.alerts[alertID]
	if !ok {
		return ErrAlertNotFound
	}
	if a.Superseded {
		if a.SupersededBy == correctionID {
			return nil // 幂等：已被同一更正取代
		}
		return ErrWindowAlreadyCorrected
	}
	from := a.Status
	a.Superseded = true
	a.SupersededBy = correctionID
	a.Status = StatusSuperseded // 终态：与"列表可见但不能处置"的矛盾状态彻底切割
	a.UpdatedAt = s.clock().UTC()
	s.appendAuditLocked(AuditEntry{
		AlertID: alertID, TenantID: a.TenantID, Action: "supersede",
		FromState: from, ToState: StatusSuperseded, At: s.clock().UTC(),
		Reason: "superseded by correction " + correctionID + ": " + reason,
	})
	return nil
}

// registerCorrectionLocked 登记一条不可变更正记录与窗口唯一索引。调用方持锁。
func (s *Store) registerCorrectionLocked(corr Correction) *Correction {
	cp := corr
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = s.clock().UTC()
	}
	for _, p := range []*[]string{&cp.OriginalAlertIDs, &cp.AddedEventIDs,
		&cp.BaselineEventIDs, &cp.FinalEventIDs} {
		if *p == nil {
			*p = []string{}
		}
	}
	stored := cp
	s.corrections[cp.ID] = &stored
	s.corrOrder = append(s.corrOrder, cp.ID)
	s.windowIdx[windowKey{cp.TenantID, cp.RuleID, cp.Entity, cp.WindowEnd.UTC()}] = cp.ID
	return &stored
}

// applyRec 记录单条更正已写入的内容，供批量失败时精确回滚。
type applyRec struct {
	corrID        string
	newAlertID    string
	supersededIDs []string
	prevStatus    map[string]Status // 各旧结论更正前的生命周期状态
	wk            windowKey
	wkSet         bool
}

// ApplyCorrections 在一次原子临界区内应用一批单窗口更正（同一回补请求的多个窗口）。
// 任一更正校验失败（窗口已被另一条更正覆盖、原结论缺失/跨租户等）时整批回滚，
// 已写入的更正、告警与终态转换全部撤销，绝不留下"部分窗口已更正"的中间状态。
// 同一 correctionID 重复出现按幂等处理（返回既有结论）。
// 成功时返回与入参一一对应的（更正告警, 更正记录）；withdrawn 条目的告警为 nil。
func (s *Store) ApplyCorrections(items []struct {
	Corr      Correction
	Corrected *Alert
}) ([]*Alert, []*Correction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 仅记录已成功写入的条目，失败回滚时逆序撤销（未写入的条目不占槽位）。
	var applied []applyRec
	// 审计快照：失败时整体恢复，保证审计序号连续，且不会误删本批次之前
	// 已存在的审计（例如早先一次更正留下的 supersede 记录）。
	allSnapshot := append([]AuditEntry(nil), s.all...)
	auditSnapshot := make(map[string][]AuditEntry, len(s.audit))
	for k, v := range s.audit {
		auditSnapshot[k] = append([]AuditEntry(nil), v...)
	}
	seqSnapshot := s.seq

	rollback := func() {
		for i := len(applied) - 1; i >= 0; i-- {
			d := applied[i]
			if d.newAlertID != "" {
				delete(s.alerts, d.newAlertID)
			}
			delete(s.corrections, d.corrID)
			// 从登记顺序中移除（倒序删除，通常是最后一个）。
			for j := len(s.corrOrder) - 1; j >= 0; j-- {
				if s.corrOrder[j] == d.corrID {
					s.corrOrder = append(s.corrOrder[:j], s.corrOrder[j+1:]...)
					break
				}
			}
			if d.wkSet {
				delete(s.windowIdx, d.wk)
			}
			// 旧结论恢复为更正前的生命周期状态。回滚仅发生在同一临界区内、
			// 对外尚未可见，撤销标记并还原状态不破坏可解释性。
			for _, oid := range d.supersededIDs {
				if a, ok := s.alerts[oid]; ok {
					a.Superseded = false
					a.SupersededBy = ""
					a.Status = d.prevStatus[oid]
				}
			}
		}
		s.all = allSnapshot
		s.audit = auditSnapshot
		s.seq = seqSnapshot
	}

	outA := make([]*Alert, len(items))
	outC := make([]*Correction, len(items))
	for i, it := range items {
		aOut, got, dRec, err := s.applyOneLocked(it.Corr, it.Corrected)
		if err != nil {
			rollback()
			return nil, nil, err
		}
		dRec.wk = windowKey{it.Corr.TenantID, it.Corr.RuleID,
			it.Corr.Entity, it.Corr.WindowEnd.UTC()}
		dRec.wkSet = true
		applied = append(applied, dRec)
		outA[i], outC[i] = aOut, got
	}
	return outA, outC, nil
}

// applyOneLocked 执行单条更正并返回回滚信息。调用方持锁。
func (s *Store) applyOneLocked(corr Correction, corrected *Alert) (*Alert, *Correction, applyRec, error) {
	dRec := applyRec{corrID: corr.ID, prevStatus: map[string]Status{}}
	if corr.ID == "" || corr.TenantID == "" || corr.RuleID == "" ||
		corr.Entity == "" || corr.WindowEnd.IsZero() {
		return nil, nil, dRec, ErrInvalidTransition
	}
	// 幂等：同一更正重复提交。
	if got, ok := s.corrections[corr.ID]; ok {
		var out *Alert
		if got.CorrectedAlertID != "" {
			if ga, ok2 := s.alerts[got.CorrectedAlertID]; ok2 {
				cp := *ga
				out = &cp
			}
		}
		return out, got, dRec, nil
	}
	// 窗口唯一：同 (租户,规则,实体,FireAt) 不允许第二条更正。
	wk := windowKey{corr.TenantID, corr.RuleID, corr.Entity, corr.WindowEnd.UTC()}
	if existing, ok := s.windowIdx[wk]; ok && existing != corr.ID {
		return nil, nil, dRec, ErrWindowAlreadyCorrected
	}
	// 原结论存在且已被别的更正取代、或自身就是一条更正结论时，同样拒绝：
	// 一个时间窗至多一条更正，不允许"更正的更正"形成链式多结论。
	for _, oid := range corr.OriginalAlertIDs {
		oa, ok := s.alerts[oid]
		if !ok {
			return nil, nil, dRec, ErrAlertNotFound
		}
		if oa.TenantID != corr.TenantID {
			return nil, nil, dRec, ErrCrossTenant
		}
		if oa.Superseded && oa.SupersededBy != corr.ID {
			return nil, nil, dRec, ErrWindowAlreadyCorrected
		}
		if oa.IsCorrection {
			return nil, nil, dRec, ErrWindowAlreadyCorrected
		}
	}
	if corr.Kind == CorrectionWithdrawn {
		if corrected != nil || len(corr.OriginalAlertIDs) == 0 {
			return nil, nil, dRec, ErrInvalidTransition
		}
	} else {
		if corrected == nil {
			return nil, nil, dRec, ErrInvalidTransition
		}
		if corrected.TenantID != corr.TenantID ||
			corrected.RuleID != corr.RuleID || corrected.Entity != corr.Entity {
			return nil, nil, dRec, ErrInvalidTransition
		}
	}

	// 取代原结论（changed/withdrawn）。
	for _, oid := range corr.OriginalAlertIDs {
		if a, ok := s.alerts[oid]; ok {
			dRec.prevStatus[oid] = a.Status
		}
		if err := s.supersedeLocked(oid, corr.ID, corr.Reason); err != nil {
			return nil, nil, dRec, err
		}
		dRec.supersededIDs = append(dRec.supersededIDs, oid)
	}

	var storedAlert *Alert
	now := s.clock().UTC()
	if corrected != nil {
		corrected.IsCorrection = true
		corrected.CorrectionID = corr.ID
		corrected.Status = StatusOpen
		corrected.CreatedAt = corrected.CreatedAt.UTC()
		if corrected.FireAt.IsZero() {
			corrected.FireAt = corrected.CreatedAt
		}
		corrected.FireAt = corrected.FireAt.UTC()
		corrected.UpdatedAt = now
		if corrected.EventIDs == nil {
			corrected.EventIDs = []string{}
		}
		a := *corrected
		s.alerts[a.ID] = &a
		storedAlert = &a
		dRec.newAlertID = a.ID
		corr.CorrectedAlertID = a.ID
		s.appendAuditLocked(AuditEntry{
			AlertID: a.ID, TenantID: a.TenantID, Action: "create_correction",
			FromState: "", ToState: StatusOpen, At: now,
			Reason: "corrected alert from backfill request " + corr.RequestID +
				": " + corr.Reason,
		})
	} else {
		corr.Kind = CorrectionWithdrawn
		corr.CorrectedAlertID = ""
	}
	if corr.Kind == "" {
		corr.Kind = CorrectionChanged
	}

	created := s.registerCorrectionLocked(corr)

	if created.Kind == CorrectionWithdrawn {
		for _, oid := range created.OriginalAlertIDs {
			s.appendAuditLocked(AuditEntry{
				AlertID: oid, TenantID: corr.TenantID, Action: "withdraw_correction",
				FromState: StatusSuperseded, ToState: StatusSuperseded, At: s.clock().UTC(),
				Reason: "conclusion withdrawn by backfill request " + corr.RequestID +
					": " + corr.Reason,
			})
		}
	}
	return storedAlert, created, dRec, nil
}

// ApplyCorrection 应用单条单窗口更正（见 ApplyCorrections 的批量原子语义）。
// 同一 correctionID 重复调用幂等返回既有结论。
// 窗口已被另一条更正覆盖时返回 ErrWindowAlreadyCorrected，且不产生任何副作用。
func (s *Store) ApplyCorrection(corr Correction, corrected *Alert) (*Alert, *Correction, error) {
	items := []struct {
		Corr      Correction
		Corrected *Alert
	}{{Corr: corr, Corrected: corrected}}
	as, cs, err := s.ApplyCorrections(items)
	if err != nil {
		return nil, nil, err
	}
	return as[0], cs[0], nil
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

// WindowCorrection 返回某窗口身份当前已登记的更正 ID（含旧结论追溯链）。
// 第二个返回值为 false 表示该窗口尚未被任何回补更正。
func (s *Store) WindowCorrection(tenantID, ruleID, entity string, fireAt time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.windowIdx[windowKey{tenantID, ruleID, entity, fireAt.UTC()}]
	return id, ok
}

// IsSealed 报告一条告警是否已经不能再作为回补原结论：
// 它已被一次更正取代（superseded 终态），或它自身就是一条更正结论。
// 告警不存在时返回 ErrAlertNotFound。
func (s *Store) IsSealed(alertID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[alertID]
	if !ok {
		return false, ErrAlertNotFound
	}
	return a.Superseded || a.IsCorrection, nil
}

// ListHistory 按租户返回【全部】告警（含已被更正取代的 superseded 旧结论），
// 按事件时间排序。仅供审计/追溯使用；正常业务查询请用 List（只含当前有效结论）。
func (s *Store) ListHistory(tenantID string) []*Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listByTenantLocked(tenantID, true)
}

// EffectiveAlerts 返回租户当前"可见的最终结论"：未被更正取代的告警，
// 同一（规则,实体,时间窗）至多一条，按穿越点事件时间排序。
// 语义等同于正常查询 List；保留该方法以便按"最终结论"语义显式调用。
func (s *Store) EffectiveAlerts(tenantID string) []*Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listByTenantLocked(tenantID, false)
}

func (s *Store) listByTenantLocked(tenantID string, includeSuperseded bool) []*Alert {
	// 被任何已登记更正引用为"原结论"的告警，其窗口已有更新的可见结论，
	// 正常查询一律隐藏（即使该告警因某种边界尚未打上 superseded 标记）。
	hidden := map[string]bool{}
	if !includeSuperseded {
		for _, c := range s.corrections {
			for _, oid := range c.OriginalAlertIDs {
				hidden[oid] = true
			}
		}
	}
	var out []*Alert
	for _, a := range s.alerts {
		if a.TenantID != tenantID {
			continue
		}
		if !includeSuperseded && (a.Superseded || hidden[a.ID]) {
			continue
		}
		cp := *a
		out = append(out, &cp)
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
