package detect

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

// 关联与抑制语义（全部时间均为事件时间）：
//
//  1. 计数：对每个 (规则版本, 实体) 维护未消费事件序列。按事件时间升序
//     逐点扫描，窗口 [t-Window, t]（闭区间）内未消费事件数 >= Threshold 时
//     在 t 处【穿越阈值】。事件由 Ingestor 保证全局有序（(t,实体,ID)）。
//  2. 消费：触发时消费窗口内的全部事件，窗口向右滑动到下一个未消费事件。
//     每个事件最多被一条告警合并，结论只取决于有序事件集合，可复现。
//  3. 定论：t 处的穿越在水位到达 t 时即为最终（更早的事件不可能再到达；
//     迟到事件已在入口隔离）。AdvanceWatermark 幂等，重复推进不重复产出。
//  4. 版本：累计器按 (规则ID, 版本号) 独立，窗口绝不跨越规则版本混合计数；
//     规则更新后的事件按新版本起算新窗口（EffectiveAt 语义见 ruleset.go）。
//  5. 抑制：同一 AlertKey（规则ID+实体）在 SuppressFor 间隔内的后续穿越不再
//     产生新告警，而是作为抑制命中携带同一 FireID 与被合并事件 ID 输出，
//     抑制期随每次命中顺延（滚动抑制）。抑制状态跨规则版本连续存续。

type stateKey struct {
	ruleID string
	ver    int
	entity string
}

type keyState struct {
	tenantID   string
	rule       Rule
	unconsumed []*event.Event // 按事件时间有序
}

type suppressState struct {
	fireID   string
	until    time.Time
	alertKey string
}

// Correlator 是有状态关联检测器。
type Correlator struct {
	mu        sync.Mutex
	rules     *RuleSet
	states    map[stateKey]*keyState
	suppress  map[string]*suppressState // AlertKey -> 当前抑制期
	fireCount map[string]int            // AlertKey -> 已产生新告警次数（确定性 FireID 序号）
	watermark time.Time
}

// NewCorrelator 基于规则集创建关联器。
func NewCorrelator(rules *RuleSet) *Correlator {
	return &Correlator{
		rules:     rules,
		states:    map[stateKey]*keyState{},
		suppress:  map[string]*suppressState{},
		fireCount: map[string]int{},
	}
}

// Observe 提交一条事件（调用方保证按事件时间有序；迟到事件应由入口隔离）。
// 事件按其事件时间点适用的规则版本进入对应累计器。
func (c *Correlator) Observe(e *event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.rules.RulesFor(e.TenantID, e.Type, e.EventTime) {
		k := stateKey{r.ID, r.Version, e.Entity}
		st, ok := c.states[k]
		if !ok {
			st = &keyState{tenantID: e.TenantID, rule: r}
			c.states[k] = st
		}
		st.unconsumed = append(st.unconsumed, e)
	}
}

// AdvanceWatermark 将事件时间水位推进到 t，返回因此变为最终的全部判定。
// 返回序列按 (FirstEventAt, AlertKey) 排序；幂等。
func (c *Correlator) AdvanceWatermark(t time.Time) []Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !t.After(c.watermark) {
		return nil
	}
	c.watermark = t

	var decisions []Decision
	for k, st := range c.states {
		decisions = append(decisions, c.evalKey(k, st)...)
	}
	sort.Slice(decisions, func(i, j int) bool {
		if !decisions[i].FirstEventAt.Equal(decisions[j].FirstEventAt) {
			return decisions[i].FirstEventAt.Before(decisions[j].FirstEventAt)
		}
		return decisions[i].AlertKey < decisions[j].AlertKey
	})
	return decisions
}

// evalKey 评估单个累计器在当前水位前的全部穿越（调用方持锁）。
func (c *Correlator) evalKey(k stateKey, st *keyState) []Decision {
	r := st.rule
	var out []Decision

	// 候选窗口 [t-Window, t]（闭区间），右端 t 取每个候选事件的事件时间，
	// 这是累计条件首次满足的时刻；用游标 left 表示窗口内最早未消费事件。
	left := 0
	for right := 0; right < len(st.unconsumed); right++ {
		t := st.unconsumed[right].EventTime
		if t.After(c.watermark) {
			break // 右端尚未到定论时间；后续事件更晚，直接结束
		}
		windowStart := t.Add(-r.Window)
		// 移动 left 使窗口内全部事件 >= windowStart（这些事件仍是候选，不能丢弃）。
		for left <= right && st.unconsumed[left].EventTime.Before(windowStart) {
			left++
		}
		if right-left+1 < r.Threshold {
			continue // 该右端不满足，右端右移后窗口变长，旧事件仍可能重新参与
		}

		// 穿越成立：合并窗口 [windowStart, t] 内全部未消费事件。
		var merged []*event.Event
		consumeUpTo := left - 1
		for p := left; p < len(st.unconsumed) &&
			!st.unconsumed[p].EventTime.Before(windowStart) &&
			!st.unconsumed[p].EventTime.After(t); p++ {
			merged = append(merged, st.unconsumed[p])
			consumeUpTo = p
		}
		ids := make([]string, len(merged))
		for n, e := range merged {
			ids[n] = e.ID
		}

		alertKey := r.ID + "|" + k.entity
		d := Decision{
			RuleID: r.ID, RuleVersion: r.Version, TenantID: st.tenantID,
			Entity: k.entity, AlertKey: alertKey, FireAt: t,
			FirstEventAt: merged[0].EventTime, EventIDs: ids,
		}

		sup := c.suppress[alertKey]
		if sup != nil && !t.After(sup.until) {
			d.FireID = sup.fireID
			d.IsAlert = false
			d.SuppressedBy = sup.fireID
			d.Reason = fmt.Sprintf(
				"threshold %d reached at %s within window %s but within suppression until %s of %s; merged %d events",
				r.Threshold, t.Format(time.RFC3339Nano), r.Window,
				sup.until.Format(time.RFC3339Nano), sup.fireID, len(ids))
			sup.until = t.Add(r.SuppressFor) // 滚动抑制：命中即顺延
		} else {
			fireID := c.newFireID(r, k.entity, d.FirstEventAt)
			d.FireID = fireID
			d.IsAlert = true
			d.Reason = fmt.Sprintf(
				"threshold %d reached: %d events in window %s ending %s (rule v%d); fired %s",
				r.Threshold, len(ids), r.Window, t.Format(time.RFC3339Nano),
				r.Version, fireID)
			c.suppress[alertKey] = &suppressState{
				fireID: fireID, until: t.Add(r.SuppressFor), alertKey: alertKey,
			}
		}
		out = append(out, d)

		// 消费本次窗口内事件；下一个窗口从 consumeUpTo+1 重新起算，左右游标同步。
		left = consumeUpTo + 1
		right = consumeUpTo
	}

	// 先裁剪已消费前缀（防止后续水位推进时重复评估）；再裁剪"永过期"事件：
	// 早于 watermark-Window 的事件不可能再出现在任何剩余（右端更晚）窗口中。
	// 尚未定论但仍在窗口内的事件必须保留。
	drop := left
	horizon := c.watermark.Add(-r.Window)
	for drop < len(st.unconsumed) && st.unconsumed[drop].EventTime.Before(horizon) {
		drop++
	}
	if drop > 0 {
		st.unconsumed = append([]*event.Event{}, st.unconsumed[drop:]...)
	}
	return out
}

// newFireID 生成确定性的 FireID：只依赖规则、实体、首次事件时间与该键第几次
// 新发告警，与 map 遍历顺序、墙钟无关，保证同一事件/规则集合下 ID 可复现。
func (c *Correlator) newFireID(r Rule, entity string, firstEventAt time.Time) string {
	key := r.ID + "|" + entity
	c.fireCount[key]++
	return fmt.Sprintf("fire:%s:%s:%d:%d",
		r.ID, entity, firstEventAt.UnixNano(), c.fireCount[key])
}

// SuppressionView 返回某 AlertKey 当前抑制期（测试与解释用）。
func (c *Correlator) SuppressionView(alertKey string) (fireID string, until time.Time, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.suppress[alertKey]
	if s == nil {
		return "", time.Time{}, false
	}
	return s.fireID, s.until, true
}

// RetargetSuppression 把在线抑制状态中指向 oldFireID 的抑制期改挂到 newFireID。
// 用于回补更正（changed）：后续抑制命中应合并到更正后的当前可见告警，
// 而不是已经 superseded 的旧结论。返回是否发生了重挂。
func (c *Correlator) RetargetSuppression(oldFireID, newFireID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, st := range c.suppress {
		if st.fireID == oldFireID {
			c.suppress[key] = &suppressState{
				fireID: newFireID, until: st.until, alertKey: st.alertKey,
			}
			return true
		}
	}
	return false
}

// ClearSuppressionIf 若某 AlertKey 的在线抑制期当前指向 fireID，则清除它。
// 用于回补撤回（withdrawn）：旧窗口结论不再成立，后续阈值穿越应产生新告警，
// 而不是作为抑制命中挂到一个已消失的旧 FireID 上。
func (c *Correlator) ClearSuppressionIf(alertKey, fireID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st := c.suppress[alertKey]; st != nil && st.fireID == fireID {
		delete(c.suppress, alertKey)
	}
}
