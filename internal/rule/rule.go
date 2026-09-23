// Package rule 定义有状态关联检测规则及其不可变版本。
//
// 规则在运行中可以更新；每次更新生成一个带版本号与"事件时间生效点"的不可变版本。
// 事件始终按其事件时间匹配当时生效的规则版本，因此规则更新不会静默改写
// 任何已经判定的结果。
package rule

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Version 是规则版本号（从 1 起单调递增）。
type Version int64

// Rule 是某个版本的不可变规则定义。
type Rule struct {
	ID          string        // 规则 ID（跨版本稳定）
	Version     Version       // 版本号
	Tenant      string        // 所属租户
	EventType   string        // 仅匹配该事件类型；为空表示匹配全部类型
	EntityScope string        // 仅匹配该实体；为空表示实体维度不过滤
	Threshold   int           // 窗口内累计命中阈值（>0 才合法）
	Window      time.Duration // 滑动窗口长度（>0 才合法）
	// Suppression 抑制间隔：同一(规则,实体)在该间隔内重复命中合并进同一条告警。
	Suppression   time.Duration
	EffectiveFrom time.Time // 该版本生效的事件时间起点（零值表示对所有更早事件生效）
	CreatedAt     time.Time // 处理时间意义上的创建时间（仅用于审计）
	Note          string    // 变更说明
}

// Match 报告事件是否满足规则的过滤条件（阈值累计由检测器完成）。
func (r *Rule) Match(tenant, eventType, entity string) bool {
	if r.Tenant != "" && r.Tenant != tenant {
		return false
	}
	if r.EventType != "" && r.EventType != eventType {
		return false
	}
	if r.EntityScope != "" && r.EntityScope != entity {
		return false
	}
	return true
}

// EffectiveAt 报告在给定事件时间点，该版本是否生效。
// EffectiveFrom 为零值表示版本自时间原点生效（首个版本常用）。
func (r *Rule) EffectiveAt(eventTime time.Time) bool {
	if r.EffectiveFrom.IsZero() {
		return true
	}
	return !eventTime.Before(r.EffectiveFrom)
}

// 规则参数错误。
var (
	ErrEmptyID      = errors.New("rule id must not be empty")
	ErrBadThreshold = errors.New("rule threshold must be > 0")
	ErrBadWindow    = errors.New("rule window must be > 0")
	ErrBadSuppress  = errors.New("rule suppression must be >= 0")
	ErrBadEffective = errors.New("rule effective-from must not be earlier than previous version")
	ErrNotFound     = errors.New("rule not found")
)

// Validate 校验规则参数合法性。
func (r *Rule) Validate() error {
	if r.ID == "" {
		return ErrEmptyID
	}
	if r.Threshold <= 0 {
		return ErrBadThreshold
	}
	if r.Window <= 0 {
		return ErrBadWindow
	}
	if r.Suppression < 0 {
		return ErrBadSuppress
	}
	return nil
}

// ruleID 在目录内唯一标识一条跨版本稳定的规则流：规则身份是 (租户, 规则ID)。
type ruleID struct {
	tenant string
	id     string
}

// Catalog 保存每个规则身份的全部不可变版本，并提供事件时间点的版本选择。
type Catalog struct {
	// rules: (tenant,ruleID) -> 按版本升序排列的版本列表
	rules map[ruleID][]*Rule
}

// NewCatalog 创建空规则目录。
func NewCatalog() *Catalog { return &Catalog{rules: map[ruleID][]*Rule{}} }

// AddVersion 追加一个不可变版本（版本号由目录分配并单调递增），返回入库副本。
// 不合法参数、EffectiveFrom 早于上一版本生效点都会得到明确错误。
func (c *Catalog) AddVersion(r Rule) (*Rule, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	key := ruleID{tenant: r.Tenant, id: r.ID}
	versions := c.rules[key]
	if len(versions) > 0 {
		last := versions[len(versions)-1]
		// 后续版本必须给出明确生效点，且不得早于上一版本（否则版本选择出现二义性）。
		if r.EffectiveFrom.IsZero() {
			return nil, fmt.Errorf("%w: rule %s new version requires explicit effective-from",
				ErrBadEffective, r.ID)
		}
		if r.EffectiveFrom.Before(last.EffectiveFrom) {
			return nil, fmt.Errorf("%w: rule %s %s < %s",
				ErrBadEffective, r.ID, r.EffectiveFrom, last.EffectiveFrom)
		}
		r.Version = last.Version + 1
	} else {
		if r.Version != 0 {
			return nil, fmt.Errorf("rule %s first version must not carry caller-assigned version", r.ID)
		}
		r.Version = 1
		// 首个版本若未指定生效点，则自时间原点生效。
		// （若已显式指定，则保留。）
	}
	stored := r
	c.rules[key] = append(versions, &stored)
	return &stored, nil
}

// VersionAt 返回某租户规则在给定事件时间点生效的版本；无生效版本时返回 nil。
// 多版本语义：选择 EffectiveFrom <= at 的最后一个版本；
// 首个版本 EffectiveFrom 为零值时覆盖所有事件时间。
func (c *Catalog) VersionAt(tenant, ruleIDStr string, at time.Time) *Rule {
	versions := c.rules[ruleID{tenant: tenant, id: ruleIDStr}]
	var chosen *Rule
	for _, v := range versions {
		if v.EffectiveAt(at) {
			chosen = v
			// 版本升序，继续找是否有更晚生效的版本。
		}
	}
	return chosen
}

// Get 返回某租户指定规则的指定版本。
func (c *Catalog) Get(tenant, ruleIDStr string, v Version) (*Rule, bool) {
	for _, ver := range c.rules[ruleID{tenant: tenant, id: ruleIDStr}] {
		if ver.Version == v {
			return ver, true
		}
	}
	return nil, false
}

// Versions 返回某租户某规则的全部版本（升序）。
func (c *Catalog) Versions(tenant, ruleIDStr string) []*Rule {
	out := make([]*Rule, len(c.rules[ruleID{tenant: tenant, id: ruleIDStr}]))
	copy(out, c.rules[ruleID{tenant: tenant, id: ruleIDStr}])
	return out
}

// AllVersions 返回目录中全部规则版本（按租户、规则 ID、版本号排序的稳定快照）。
func (c *Catalog) AllVersions() []*Rule {
	keys := make([]ruleID, 0, len(c.rules))
	for k := range c.rules {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].tenant != keys[j].tenant {
			return keys[i].tenant < keys[j].tenant
		}
		return keys[i].id < keys[j].id
	})
	var out []*Rule
	for _, k := range keys {
		out = append(out, c.rules[k]...)
	}
	return out
}
