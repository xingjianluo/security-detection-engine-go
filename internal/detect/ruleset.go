package detect

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrRuleNotFound 规则不存在或在指定事件时间点尚无生效版本。
var ErrRuleNotFound = errors.New("rule not found")

// ErrInvalidRule 规则定义非法。
var ErrInvalidRule = errors.New("invalid rule")

type ruleKey struct {
	tenant string
	id     string
}

// RuleSet 保存各租户的规则版本历史，按事件时间查询当时生效的版本。
//
// 版本语义：每个 (租户,规则ID) 维护一条按 Version 递增的历史；
// 事件时间 t 的事件受 EffectiveAt <= t 的最大 Version 约束。
// 因此"规则在运行中更新"不会改变历史事件的适用版本——即使更新发生在
// 墙钟意义上的"之后"，只要事件时间早于新版本 EffectiveAt，就仍按旧版判定。
type RuleSet struct {
	mu    sync.RWMutex
	rules map[ruleKey][]Rule
}

// NewRuleSet 创建空规则集。
func NewRuleSet() *RuleSet {
	return &RuleSet{rules: map[ruleKey][]Rule{}}
}

func validate(r Rule) error {
	switch {
	case r.ID == "":
		return errors.New("rule id is empty")
	case r.TenantID == "":
		return errors.New("tenant id is empty")
	case r.Window <= 0:
		return errors.New("window must be positive")
	case r.Threshold <= 0:
		return errors.New("threshold must be positive")
	}
	return nil
}

// Put 登记一个新版本的规则。Version 必须严格大于历史版本；
// EffectiveAt 允许等于或早于当前墙钟（补录/回放），但同规则的
// EffectiveAt 必须随版本递增，避免同一事件时间出现歧义版本。
func (s *RuleSet) Put(r Rule) error {
	if err := validate(r); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := ruleKey{r.TenantID, r.ID}
	hist := s.rules[k]
	for _, h := range hist {
		if h.Version == r.Version {
			return errors.New("duplicate rule version")
		}
		if !r.EffectiveAt.After(h.EffectiveAt) && r.Version > h.Version {
			return errors.New("EffectiveAt must be non-decreasing across versions")
		}
	}
	hist = append(hist, r)
	sort.Slice(hist, func(i, j int) bool { return hist[i].Version < hist[j].Version })
	s.rules[k] = hist
	return nil
}

// Get 返回规则的最新版本。
func (s *RuleSet) Get(tenantID, ruleID string) (Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hist := s.rules[ruleKey{tenantID, ruleID}]
	if len(hist) == 0 {
		return Rule{}, ErrRuleNotFound
	}
	return hist[len(hist)-1], nil
}

// EffectiveAt 返回事件时间 at 时对指定规则生效的版本；
// 若所有版本的 EffectiveAt 都晚于 at，则该规则当时不存在，返回 ErrRuleNotFound。
func (s *RuleSet) EffectiveAt(tenantID, ruleID string, at time.Time) (Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hist := s.rules[ruleKey{tenantID, ruleID}]
	var chosen Rule
	found := false
	// hist 已按 Version 升序，EffectiveAt 随版本递增，取最后一个满足条件的。
	for _, r := range hist {
		if !r.EffectiveAt.After(at) {
			chosen, found = r, true
		}
	}
	if !found {
		return Rule{}, ErrRuleNotFound
	}
	return chosen, nil
}

// RulesFor 返回事件时间 at 适用于某事件类型的全部规则的当时生效版本。
func (s *RuleSet) RulesFor(tenantID, eventType string, at time.Time) []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Rule
	for k, hist := range s.rules {
		if k.tenant != tenantID {
			continue
		}
		var chosen Rule
		found := false
		for _, r := range hist {
			if r.EventType == eventType && !r.EffectiveAt.After(at) {
				chosen, found = r, true
			}
		}
		if found {
			out = append(out, chosen)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
