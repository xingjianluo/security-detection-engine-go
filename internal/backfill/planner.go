package backfill

import (
	"fmt"
	"sort"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

// group 是把关联器输出按 AlertKey 归并后的【结论组】：一次新发告警 +
// 其后到下一次新发之间的全部抑制命中，代表该 (规则,实体) 时间窗上的完整结论。
type group struct {
	alertKey     string
	tenantID     string
	ruleID       string
	ruleVersion  int
	entity       string
	fireID       string
	anchor       string    // 结论身份：首发窗口的第一个事件 ID（跨重算稳定）
	firstEventAt time.Time // 窗口语义：组内最早事件时间（结论身份）
	endAt        time.Time // 组内最晚事件时间（含抑制命中）
	eventIDs     []string  // 合并的全部事件 ID（有序去重）
	fireEvents   []string  // 新发告警首次窗口合并的事件 ID
}

// buildGroups 把有序 Decision 序列（关联器已按 (FirstEventAt,AlertKey) 排序）
// 归并为结论组。eventByID 提供事件 ID -> 事件时间的映射，用于组右端时间。
func buildGroups(ds []detect.Decision, eventByID map[string]*event.Event) []group {
	var gs []group
	idx := map[string]int{} // fireID -> group 在 gs 中的下标
	for _, d := range ds {
		if d.IsAlert {
			g := group{
				alertKey: d.AlertKey, tenantID: d.TenantID, ruleID: d.RuleID,
				ruleVersion: d.RuleVersion, entity: d.Entity, fireID: d.FireID,
				anchor:       firstID(d.EventIDs),
				firstEventAt: d.FirstEventAt, endAt: d.FirstEventAt,
				eventIDs:   append([]string{}, d.EventIDs...),
				fireEvents: append([]string{}, d.EventIDs...),
			}
			idx[d.FireID] = len(gs)
			gs = append(gs, g)
			continue
		}
		// 抑制命中并入同 FireID 的主结论组。
		p, ok := idx[d.SuppressedBy]
		if !ok {
			continue // 防御：没有主组的抑制命中忽略
		}
		gs[p].eventIDs = append(gs[p].eventIDs, d.EventIDs...)
	}
	for i := range gs {
		sort.Strings(gs[i].eventIDs)
		gs[i].eventIDs = dedupSorted(gs[i].eventIDs)
		for _, id := range gs[i].eventIDs {
			if ev, ok := eventByID[id]; ok && ev.EventTime.After(gs[i].endAt) {
				gs[i].endAt = ev.EventTime
			}
		}
	}
	return gs
}

func dedupSorted(ids []string) []string {
	if len(ids) <= 1 {
		return ids
	}
	out := ids[:1]
	for _, id := range ids[1:] {
		if id != out[len(out)-1] {
			out = append(out, id)
		}
	}
	return out
}

// GroupChange 是单个结论组在补数前后的差异（规划阶段，尚未绑定真实告警 ID）。
type GroupChange struct {
	Kind            ChangeKind
	AlertKey        string
	TenantID        string
	RuleID          string
	RuleVersion     int
	Entity          string
	WindowFrom      time.Time
	WindowTo        time.Time
	BaselineAnchors []string // 对应基线结论组的锚点事件 ID（Added 为空）
	AugAnchor       string   // 补数后结论组的锚点事件 ID（稳定身份）
	AddedEventIDs   []string // 并入该结论的本次回补事件
	AllEventIDs     []string // 补数后合并的全部事件 ID
	SuppressedCount int      // 补数结论中由抑制命中合并的事件数
	Note            string
}

// Plan 是一次回补重算的完整差异计划。
type Plan struct {
	Changes    []GroupChange
	Advisories []Advisory
}

// inScope 判定结论组（以其窗口最早事件时间为身份）是否落在回补区间（闭区间）。
func inScope(g group, from, to time.Time) bool {
	return !g.firstEventAt.Before(from) && !g.firstEventAt.After(to)
}

// PlanChanges 对比【基线重算】（不含本次补入事件）与【补数重算】（含全部事件）
// 的结论组，得到差异计划。纯函数：只依赖两组 Decision、事件集合与回补区间，
// 不触碰存储/水位/墙钟，因此结果可复现。
//
// 对齐算法：补数只会新增事件，consume-on-fire 分区下补数后的穿越次数单调不减，
// 各 AlertKey 内按顺序做有序贪心交叠对齐——基线组按序匹配第一个事件集合相交的
// 补数组（匹配指针只前进）。由此：
//   - 被基线组匹配上的补数组：事件集合/规则版本有变 => revised，否则不变；
//   - 未被任何基线组匹配的补数组：added（新窗口首次成立）；
//   - 未匹配到补数组的基线组：revoked（纯补数理论上不出现，防御性保留）。
func PlanChanges(baseline, augmented []detect.Decision, eventByID map[string]*event.Event,
	added map[string]bool, from, to time.Time) Plan {
	bGroups := buildGroups(baseline, eventByID)
	aGroups := buildGroups(augmented, eventByID)

	// 按 AlertKey 分组（保持出现顺序）。
	keysOf := func(gs []group) []string {
		seen := map[string]bool{}
		var keys []string
		for _, g := range gs {
			if !seen[g.alertKey] {
				seen[g.alertKey] = true
				keys = append(keys, g.alertKey)
			}
		}
		sort.Strings(keys)
		return keys
	}
	bByKey := map[string][]group{}
	aByKey := map[string][]group{}
	for _, g := range bGroups {
		bByKey[g.alertKey] = append(bByKey[g.alertKey], g)
	}
	for _, g := range aGroups {
		aByKey[g.alertKey] = append(aByKey[g.alertKey], g)
	}

	var plan Plan
	for _, key := range unionKeys(keysOf(bGroups), keysOf(aGroups)) {
		bs := bByKey[key]
		as := aByKey[key]
		matchedA := map[int][]int{} // 补数组下标 -> 匹配到的基线组下标
		matchedB := map[int]bool{}

		j := 0
		for bi, b := range bs {
			bset := toSet(b.eventIDs)
			for j < len(as) {
				if intersects(bset, as[j].eventIDs) {
					matchedA[j] = append(matchedA[j], bi)
					matchedB[bi] = true
					j++
					break
				}
				j++
			}
		}

		// 补数组：revised / added / 不变；越界但吸收了补入事件的 -> advisory。
		for ai, a := range as {
			bis := matchedA[ai]
			inA := addedInSet(a.eventIDs, added)
			if len(bis) == 0 {
				if inScope(a, from, to) {
					plan.Changes = append(plan.Changes, GroupChange{
						Kind: ChangeAdded, AlertKey: a.alertKey, TenantID: a.tenantID,
						RuleID: a.ruleID, RuleVersion: a.ruleVersion, Entity: a.entity,
						WindowFrom: a.firstEventAt, WindowTo: a.endAt,
						AugAnchor: a.anchor, AddedEventIDs: inA, AllEventIDs: a.eventIDs,
						SuppressedCount: len(a.eventIDs) - len(a.fireEvents),
						Note: fmt.Sprintf("backfilled events formed a new window at %s (rule v%d)",
							a.firstEventAt.Format(time.RFC3339Nano), a.ruleVersion),
					})
				} else if len(inA) > 0 {
					plan.Advisories = append(plan.Advisories, Advisory{
						Kind: "out_of_scope_window", AlertKey: a.alertKey, EventIDs: inA,
						Detail: fmt.Sprintf("backfilled events merged into out-of-range window starting %s; left unchanged",
							a.firstEventAt.Format(time.RFC3339Nano)),
					})
				}
				continue
			}
			var oldAnchors []string
			var changed bool
			var oldVersion int
			for _, bi := range bis {
				b := bs[bi]
				oldAnchors = append(oldAnchors, b.anchor)
				if b.ruleVersion != a.ruleVersion || !sameStringSet(b.eventIDs, a.eventIDs) {
					changed = true
				}
				oldVersion = b.ruleVersion
			}
			if changed && inScope(a, from, to) {
				plan.Changes = append(plan.Changes, GroupChange{
					Kind: ChangeRevised, AlertKey: a.alertKey, TenantID: a.tenantID,
					RuleID: a.ruleID, RuleVersion: a.ruleVersion, Entity: a.entity,
					WindowFrom: a.firstEventAt, WindowTo: a.endAt,
					BaselineAnchors: oldAnchors, AugAnchor: a.anchor,
					AddedEventIDs: inA, AllEventIDs: a.eventIDs,
					SuppressedCount: len(a.eventIDs) - len(a.fireEvents),
					Note:            revisionNote(a, oldVersion, bis, bs),
				})
			} else if changed {
				plan.Advisories = append(plan.Advisories, Advisory{
					Kind: "out_of_scope_window", AlertKey: a.alertKey, EventIDs: inA,
					Detail: fmt.Sprintf("window starting %s differs after backfill but is outside requested range; left unchanged",
						a.firstEventAt.Format(time.RFC3339Nano)),
				})
			}
		}

		// 防御性：基线结论在补数重算后消失（纯补数不应发生）。
		for bi, b := range bs {
			if !matchedB[bi] && inScope(b, from, to) {
				plan.Changes = append(plan.Changes, GroupChange{
					Kind: ChangeRevoked, AlertKey: b.alertKey, TenantID: b.tenantID,
					RuleID: b.ruleID, RuleVersion: b.ruleVersion, Entity: b.entity,
					WindowFrom: b.firstEventAt, WindowTo: b.endAt,
					BaselineAnchors: []string{b.anchor},
					Note:            "baseline conclusion no longer holds after backfill (defensive)",
				})
			}
		}
	}

	sortChanges(plan.Changes)
	return plan
}

func revisionNote(a group, oldVersion int, bis []int, bs []group) string {
	msg := fmt.Sprintf("window revised by backfill: rule v%d->v%d", oldVersion, a.ruleVersion)
	if oldVersion == a.ruleVersion {
		msg = fmt.Sprintf("window revised by backfilled events under rule v%d", a.ruleVersion)
	}
	return msg + fmt.Sprintf(", merged %d event(s), window %s..%s",
		len(a.eventIDs), a.firstEventAt.Format(time.RFC3339Nano),
		a.endAt.Format(time.RFC3339Nano))
}

func sortChanges(cs []GroupChange) {
	sort.Slice(cs, func(i, j int) bool {
		if !cs[i].WindowFrom.Equal(cs[j].WindowFrom) {
			return cs[i].WindowFrom.Before(cs[j].WindowFrom)
		}
		return cs[i].AlertKey < cs[j].AlertKey
	})
}

func toSet(ids []string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func intersects(set map[string]bool, ids []string) bool {
	for _, id := range ids {
		if set[id] {
			return true
		}
	}
	return false
}

func addedInSet(ids []string, added map[string]bool) []string {
	var out []string
	for _, id := range ids {
		if added[id] {
			out = append(out, id)
		}
	}
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] { // 两侧均已排序去重
			return false
		}
	}
	return true
}

func unionKeys(a, b []string) []string {
	set := map[string]bool{}
	for _, k := range a {
		set[k] = true
	}
	for _, k := range b {
		set[k] = true
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// firstID 返回首发窗口事件列表的第一个 ID（结论锚点）。
func firstID(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}
