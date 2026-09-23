// Package alert 管理告警生命周期、租户隔离、幂等状态转移与并发提交。
//
// 生命周期：Open -> Acknowledged -> Closed；Closed 可 Reopen 回 Open。
// 所有转移均幂等：重复提交相同目标状态不产生新审计、只返回当前状态。
// 每次状态变更带期望版本号(CAS)，并发提交只有一个成功，失败者可据错误区分原因。
package alert

import (
	"sort"
	"sync"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
)

// Status 是告警生命周期状态。
type Status string

const (
	StatusOpen   Status = "open"
	StatusAcked  Status = "acknowledged"
	StatusClosed Status = "closed"
)

// Action 标识一次生命周期操作。
type Action string

const (
	ActionAcknowledge Action = "acknowledge"
	ActionClose       Action = "close"
	ActionReopen      Action = "reopen"
)

// Alert 是一条关联告警及其合并轨迹。
type Alert struct {
	ID          string
	Tenant      string
	RuleID      string
	RuleVersion int64
	Entity      string
	Status      Status
	// SuppressUntil 抑制锚点：首个触发事件时间 + 规则抑制间隔。
	SuppressUntil time.Time
	FirstEventID  string // 首个触发事件 ID（锚点）
	FirstEventAt  time.Time
	LastEventAt   time.Time
	// MergedEventIDs 归并进本告警的全部事件（含触发与抑制合并、迟到合并），按追加顺序。
	MergedEventIDs []string
	// SuppressedCount 因抑制未另开告警而合并的事件数。
	SuppressedCount int
	Version         int64 // CAS 版本：每次实际变更 +1
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// HasEvent 报告某事件 ID 是否已归并到本告警（幂等合并去重）。
func (a *Alert) HasEvent(id string) bool {
	for _, eid := range a.MergedEventIDs {
		if eid == id {
			return true
		}
	}
	return false
}

// clone 返回告警的深拷贝（MergedEventIDs 切片独立）。
func (a *Alert) clone() *Alert {
	cp := *a
	cp.MergedEventIDs = append([]string(nil), a.MergedEventIDs...)
	return &cp
}

// Transition 描述一次状态变更尝试的结果。
type Transition struct {
	Alert   *Alert
	Action  Action
	Changed bool // false 表示幂等命中（当前状态已是目标语义）
	From    Status
	To      Status
	Version int64 // 变更后的版本
	Reason  string
}

// ApplyFindingOutcome 区分 ApplyFinding 的结果类型。
type ApplyFindingOutcome string

const (
	OutcomeCreated    ApplyFindingOutcome = "created"
	OutcomeMerged     ApplyFindingOutcome = "merged"
	OutcomeIgnoredDup ApplyFindingOutcome = "ignored_duplicate"
)

type activeKey struct {
	tenant string
	ruleID string
	entity string
}

// Store 是告警存储（并发安全），所有写操作需经过租户与版本校验。
type Store struct {
	mu     sync.Mutex
	byID   map[string]*Alert
	active map[activeKey]string // 未关闭(Open/Acked)告警索引，同键最多一条
}

// NewStore 创建空告警存储。
func NewStore() *Store {
	return &Store{byID: map[string]*Alert{}, active: map[activeKey]string{}}
}

// BatchResult 是单个 finding 在批量应用中的归属结果。
type BatchResult struct {
	Outcome ApplyFindingOutcome
	AlertID string
}

// ApplyFindings 在同一把锁内、按事件时间全序批量应用一组检测触发。
//
// 抑制锚点的确定方式与"逐条到达/分多少次 Pump"无关：对每个
// (租户,规则版本,实体)，从最早的、未被现有活跃告警抑制窗口覆盖的触发开始建立
// 新告警，其 [first, first+suppress] 内的后续触发全部并入该告警；
// 超出后再以那个触发为新锚点。这样无论 findings 是逐条还是一次性落地，
// 最终告警与合并轨迹都一致、可复现。
//
// 入参 findings 无需事先排序；返回与入参同序的归属结果。
func (s *Store) ApplyFindings(findings []*detect.Finding, suppressByRule func(ruleID string, v int64) time.Duration, now time.Time) []BatchResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	order := make([]int, len(findings))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := findings[order[a]], findings[order[b]]
		if !x.EventTime.Equal(y.EventTime) {
			return x.EventTime.Before(y.EventTime)
		}
		if x.RuleID != y.RuleID {
			return x.RuleID < y.RuleID
		}
		if x.RuleVersion != y.RuleVersion {
			return x.RuleVersion < y.RuleVersion
		}
		if x.Entity != y.Entity {
			return x.Entity < y.Entity
		}
		return x.TriggerEventID < y.TriggerEventID
	})

	results := make([]BatchResult, len(findings))
	for _, idx := range order {
		f := findings[idx]
		key := activeKey{tenant: f.Tenant, ruleID: f.RuleID, entity: f.Entity}
		if id, ok := s.active[key]; ok {
			a := s.byID[id]
			if a.HasEvent(f.TriggerEventID) {
				results[idx] = BatchResult{Outcome: OutcomeIgnoredDup, AlertID: a.ID}
				continue
			}
			if !f.EventTime.After(a.SuppressUntil) {
				for _, mid := range f.MatchedEventIDs {
					if !a.HasEvent(mid) {
						a.MergedEventIDs = append(a.MergedEventIDs, mid)
					}
				}
				a.SuppressedCount++
				if f.EventTime.After(a.LastEventAt) {
					a.LastEventAt = f.EventTime
				}
				a.Version++
				a.UpdatedAt = now
				results[idx] = BatchResult{Outcome: OutcomeMerged, AlertID: a.ID}
				continue
			}
		}

		id := alertID(f.Tenant, f.RuleID, f.TriggerEventID)
		if a, ok := s.byID[id]; ok {
			results[idx] = BatchResult{Outcome: OutcomeIgnoredDup, AlertID: a.ID}
			continue
		}
		suppress := time.Duration(0)
		if suppressByRule != nil {
			suppress = suppressByRule(f.RuleID, int64(f.RuleVersion))
		}
		a := &Alert{
			ID:             id,
			Tenant:         f.Tenant,
			RuleID:         f.RuleID,
			RuleVersion:    int64(f.RuleVersion),
			Entity:         f.Entity,
			Status:         StatusOpen,
			SuppressUntil:  f.EventTime.Add(suppress),
			FirstEventID:   f.TriggerEventID,
			FirstEventAt:   f.EventTime,
			LastEventAt:    f.EventTime,
			MergedEventIDs: dedupeStrings(append([]string(nil), f.MatchedEventIDs...)),
			Version:        1,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		s.byID[id] = a
		s.active[key] = id
		results[idx] = BatchResult{Outcome: OutcomeCreated, AlertID: id}
	}
	return results
}

// ApplyFinding 接收一个检测触发：
//   - 若存在同(租户,规则,实体)的 Open/Acked 告警且其抑制窗口仍覆盖触发时间，则合并；
//   - 否则创建新告警；触发事件已在该键活跃告警中时幂等忽略。
//
// 返回结果类型与受影响告警（返回拷贝）。
func (s *Store) ApplyFinding(f *detect.Finding, suppress time.Duration, now time.Time) (ApplyFindingOutcome, *Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := activeKey{tenant: f.Tenant, ruleID: f.RuleID, entity: f.Entity}
	if id, ok := s.active[key]; ok {
		a := s.byID[id]
		if a.HasEvent(f.TriggerEventID) {
			return OutcomeIgnoredDup, a.clone()
		}
		// 抑制窗口以首个触发时间为锚点，覆盖 [first, first+suppress]。
		// suppress=0 时只有严格同一事件时间才合并（事件 ID 已去重，故通常另开）。
		if !f.EventTime.After(a.SuppressUntil) {
			for _, mid := range f.MatchedEventIDs {
				if !a.HasEvent(mid) {
					a.MergedEventIDs = append(a.MergedEventIDs, mid)
				}
			}
			// SuppressedCount 以"被抑制的触发(命中)"次数计；触发事件本身必为新事件。
			a.SuppressedCount++
			if f.EventTime.After(a.LastEventAt) {
				a.LastEventAt = f.EventTime
			}
			a.Version++
			a.UpdatedAt = now
			return OutcomeMerged, a.clone()
		}
		// 抑制窗口已过期：旧告警保持打开（它仍未被人工关闭），
		// 新触发另开一条；活跃索引迁移到新告警。
	}

	id := alertID(f.Tenant, f.RuleID, f.TriggerEventID)
	if a, ok := s.byID[id]; ok {
		// 相同确定性 ID（同锚点重放）：幂等。
		return OutcomeIgnoredDup, a.clone()
	}
	suppressUntil := f.EventTime.Add(suppress)
	a := &Alert{
		ID:             id,
		Tenant:         f.Tenant,
		RuleID:         f.RuleID,
		RuleVersion:    int64(f.RuleVersion),
		Entity:         f.Entity,
		Status:         StatusOpen,
		SuppressUntil:  suppressUntil,
		FirstEventID:   f.TriggerEventID,
		FirstEventAt:   f.EventTime,
		LastEventAt:    f.EventTime,
		MergedEventIDs: append([]string(nil), f.MatchedEventIDs...),
		Version:        1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	// 去重 MatchedEventIDs（窗口切片理论上唯一，防御性保持幂等）。
	a.MergedEventIDs = dedupeStrings(a.MergedEventIDs)
	s.byID[id] = a
	s.active[key] = id
	return OutcomeCreated, a.clone()
}

// getLocked 执行存在性 + 租户校验。跨租户与不存在统一返回 ErrNotFound 之外，
// 明确跨租户返回 ErrCrossTenant（调用方据此写越权审计）。
func (s *Store) getLocked(tenant, id string) (*Alert, error) {
	a, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	if a.Tenant != tenant {
		return nil, ErrCrossTenant
	}
	return a, nil
}

// Get 读取告警；跨租户访问返回 ErrCrossTenant。
func (s *Store) Get(tenant, id string) (*Alert, error) {
	if tenant == "" {
		return nil, ErrEmptyTenant
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.getLocked(tenant, id)
	if err != nil {
		return nil, err
	}
	return a.clone(), nil
}

// List 按租户列出告警（按创建时间与 ID 稳定排序）；空租户拒绝以防跨租户扫描。
func (s *Store) List(tenant string) []*Alert {
	if tenant == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Alert
	for _, a := range s.byID {
		if a.Tenant == tenant {
			out = append(out, a.clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstEventAt.Equal(out[j].FirstEventAt) {
			return out[i].FirstEventAt.Before(out[j].FirstEventAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// transition 是三个生命周期操作的统一幂等实现。
func (s *Store) transition(tenant, id, operator string, expectVersion int64, at time.Time, act Action) (Transition, error) {
	if tenant == "" {
		return Transition{}, ErrEmptyTenant
	}
	if operator == "" {
		return Transition{}, ErrEmptyOperator
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	a, err := s.getLocked(tenant, id)
	if err != nil {
		return Transition{}, err
	}
	if expectVersion >= 0 && a.Version != expectVersion {
		return Transition{Alert: a.clone(), Version: a.Version}, ErrVersionConflict
	}

	t := Transition{Alert: a.clone(), Action: act, From: a.Status, Version: a.Version}
	switch act {
	case ActionAcknowledge:
		switch a.Status {
		case StatusOpen:
			a.Status, t.Changed = StatusAcked, true
		case StatusAcked:
			t.Reason = "already acknowledged"
		case StatusClosed:
			return t, ErrInvalidTransition
		}
	case ActionClose:
		switch a.Status {
		case StatusOpen, StatusAcked:
			a.Status, t.Changed = StatusClosed, true
		case StatusClosed:
			t.Reason = "already closed"
		}
	case ActionReopen:
		switch a.Status {
		case StatusClosed:
			a.Status, t.Changed = StatusOpen, true
		case StatusOpen:
			t.Reason = "already open"
		case StatusAcked:
			return t, ErrInvalidTransition
		}
	default:
		return t, ErrInvalidTransition
	}

	if t.Changed {
		a.Version++
		a.UpdatedAt = at
		if act == ActionReopen {
			// 只在槽为空、指向已关闭告警或本告警时重新占用；
			// 不得抢占抑制过期后另起的较新活跃告警。
			k := activeKey{tenant: a.Tenant, ruleID: a.RuleID, entity: a.Entity}
			cur, occupied := s.active[k]
			if !occupied {
				s.active[k] = a.ID
			} else if cur != a.ID {
				if ca := s.byID[cur]; ca != nil && ca.Status == StatusClosed {
					s.active[k] = a.ID
				}
			}
		}
	}
	if act == ActionClose {
		// 仅当活跃槽仍指向自己时释放，避免误删抑制过期后另起的较新告警槽位。
		k := activeKey{tenant: a.Tenant, ruleID: a.RuleID, entity: a.Entity}
		if s.active[k] == a.ID {
			delete(s.active, k)
		}
	}
	t.To = a.Status
	t.Version = a.Version
	t.Alert = a.clone()
	return t, nil
}

// Acknowledge 幂等确认告警（Open->Acked）。expectVersion=-1 表示不校验版本。
func (s *Store) Acknowledge(tenant, id, operator string, expectVersion int64, at time.Time) (Transition, error) {
	return s.transition(tenant, id, operator, expectVersion, at, ActionAcknowledge)
}

// Close 幂等关闭告警（Open/Acked->Closed）。
func (s *Store) Close(tenant, id, operator string, expectVersion int64, at time.Time) (Transition, error) {
	return s.transition(tenant, id, operator, expectVersion, at, ActionClose)
}

// Reopen 幂等重开告警（Closed->Open）。
func (s *Store) Reopen(tenant, id, operator string, expectVersion int64, at time.Time) (Transition, error) {
	return s.transition(tenant, id, operator, expectVersion, at, ActionReopen)
}

// Snapshot 返回某租户全部告警的深拷贝（测试可复现性比对用）。
func (s *Store) Snapshot(tenant string) []*Alert { return s.List(tenant) }

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
