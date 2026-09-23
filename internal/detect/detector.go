// Package detect 实现基于事件时间(event time)与水位线(watermark)的有状态滑动窗口关联检测。
//
// 语义要点：
//   - 事件按 (事件时间, 事件ID) 的全序在窗口关闭(水位线推进)时统一评估，
//     因此在允许乱序宽限内，结论与物理到达顺序无关、可复现。
//   - 一旦某个事件时间点已被水位线覆盖并评估，其结论即冻结；
//     规则更新与迟到事件都不会静默改写已冻结结论。
//   - 迟到但仍在保留期内的事件照常进入窗口状态(影响未来判定)，被单独标记为 late；
//     超过保留期的事件由上层隔离。
//   - 重复事件(同一租户下相同事件 ID)在进入窗口前去重。
//   - 事件在进入系统(Observe)时绑定当时目录中"按事件时间生效"的规则版本，
//     之后规则更新不影响已进入的事件。
package detect

import (
	"sort"
	"sync"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/event"
	"github.com/xingjianluo/security-detection-engine-go/internal/rule"
)

// clock 抽象处理时间来源（避免与 internal/clock 形成不必要的耦合，由引擎适配）。
type Clocker interface {
	Now() time.Time
}

// Finding 是一次阈值穿越所产生的告警候选（触发即一个新的告警生命周期）。
type Finding struct {
	Tenant      string
	RuleID      string
	RuleVersion rule.Version
	Entity      string
	// TriggerEventID 是导致计数穿越阈值的那个事件。
	TriggerEventID string
	// EventTime 是触发事件的事件时间，也是抑制计时的锚点。
	EventTime time.Time
	// MatchedEventIDs 是本次触发窗口切片内累计的全部事件（可解释性）。
	MatchedEventIDs []string
	Count           int
	Threshold       int
	WindowStart     time.Time
	WindowEnd       time.Time
}

// RuleEval 是单条事件针对单个生效规则版本的窗口计入说明。
type RuleEval struct {
	RuleID      string
	Version     rule.Version
	Entity      string
	Matched     bool
	Count       int
	Threshold   int
	WindowStart time.Time
	WindowEnd   time.Time
	// FiredBefore 报告该(规则版本,实体)窗口在本事件之前是否已产生过触发。
	FiredBefore bool
}

// ObserveReport 是事件到达(Observe)时的分类与判定依据。
type ObserveReport struct {
	EventID   string
	Timing    event.Timing // on_time / late；未被接收时为空
	Duplicate bool         // 重复投递
	Expired   bool         // 迟到超过保留期
	OnTime    bool
	Late      bool
	Explains  []RuleEval
}

// PumpReport 是一次水位线推进的评估结果。
type PumpReport struct {
	Tenant                string
	WatermarkBefore       time.Time
	WatermarkAfter        time.Time
	EvaluatedThroughAfter time.Time
	Findings              []*Finding
}

// Config 控制检测器的时间语义参数。
type Config struct {
	// AllowedLateness 允许乱序宽限 L：水位线 = 已观测最大事件时间 - L。
	AllowedLateness time.Duration
	// Retention 迟到保留期 R：事件时间 < 水位线 - R 的事件视为超期隔离。
	Retention time.Duration
}

// bucketKey 唯一标识一个 (规则版本, 实体) 的窗口状态。
type bucketKey struct {
	ruleID  string
	version rule.Version
	entity  string
}

// envelope 是窗口内带冻结光标的事件包装。
type envelope struct {
	time time.Time
	id   string
}

type bucketState struct {
	events []envelope // 始终按 (time, id) 全序排列
	// evalPos 个事件已作为"阈值穿越候选"被评估并冻结（含未达阈值者）。
	evalPos int
}

type tenantState struct {
	maxObserved time.Time
	watermark   time.Time
	seen        map[string]struct{}
	buckets     map[bucketKey]*bucketState
	lastFire    map[bucketKey]time.Time
}

// Detector 是有状态关联检测器（并发安全）。
type Detector struct {
	mu      sync.Mutex
	clock   Clocker
	catalog *rule.Catalog
	cfg     Config
	tenants map[string]*tenantState
}

// New 创建检测器。clk 提供处理时间，用于决定事件到达时"已发布"的规则版本集合。
func New(catalog *rule.Catalog, cfg Config, clk Clocker) *Detector {
	return &Detector{clock: clk, catalog: catalog, cfg: cfg, tenants: map[string]*tenantState{}}
}

func (d *Detector) stateFor(tenant string) *tenantState {
	st := d.tenants[tenant]
	if st == nil {
		st = &tenantState{
			seen:     map[string]struct{}{},
			buckets:  map[bucketKey]*bucketState{},
			lastFire: map[bucketKey]time.Time{},
		}
		d.tenants[tenant] = st
	}
	return st
}

// Observe 接收一条已通过解析与时间戳校验的事件，完成去重、迟到/超期分类，
// 并把事件计入其事件时间点所有生效且匹配的规则版本窗口（不做触发评估）。
func (d *Detector) Observe(e *event.Event) ObserveReport {
	d.mu.Lock()
	defer d.mu.Unlock()

	rep := ObserveReport{EventID: e.ID}
	st := d.stateFor(e.Tenant)

	// 1) 重复优先于一切：同一租户内相同事件 ID 永远只计入一次。
	if _, dup := st.seen[e.ID]; dup {
		rep.Duplicate = true
		return rep
	}

	// 2) 超期：事件时间早于 (水位线 - 保留期)。首条事件到来前无水位线，不判超期。
	if !st.watermark.IsZero() && d.cfg.Retention >= 0 &&
		e.EventTime.Before(st.watermark.Add(-d.cfg.Retention)) {
		rep.Expired = true
		return rep
	}

	// 3) 时间语义分类。
	if st.watermark.IsZero() || !e.EventTime.Before(st.watermark) {
		rep.Timing, rep.OnTime = event.TimingOnTime, true
	} else {
		rep.Timing, rep.Late = event.TimingLate, true
	}
	st.seen[e.ID] = struct{}{}
	if e.EventTime.After(st.maxObserved) {
		st.maxObserved = e.EventTime
	}

	// 4) 绑定规则版本并计入窗口。绑定以"事件到达(处理时间)时已发布、且按事件时间生效"
	//    的最新版本为准。事件一旦绑定即冻结，之后的规则更新对其无追溯力。
	now := d.clock.Now()
	for _, rv := range d.catalog.AllVersions() {
		if rv.Tenant != e.Tenant {
			continue
		}
		// 尚未发布的版本（生效点在未来处理时间）对当前事件不可见。
		if !rv.EffectiveFrom.IsZero() && rv.EffectiveFrom.After(now) {
			continue
		}
		v := d.catalog.VersionAt(e.Tenant, rv.ID, e.EventTime)
		if v == nil || v.Version != rv.Version {
			continue
		}
		if !v.Match(e.Tenant, e.Type, e.Entity) {
			continue
		}
		key := bucketKey{ruleID: v.ID, version: v.Version, entity: e.Entity}
		b := st.buckets[key]
		if b == nil {
			b = &bucketState{}
			st.buckets[key] = b
		}
		insertOrdered(b, envelope{time: e.EventTime, id: e.ID})

		// 到达时的计入说明（最终阈值判定在窗口冻结时给出）。
		ws := e.EventTime.Add(-v.Window)
		count := 0
		for _, env := range b.events {
			if !env.time.Before(ws) && !env.time.After(e.EventTime) {
				count++
			}
		}
		_, fired := st.lastFire[key]
		rep.Explains = append(rep.Explains, RuleEval{
			RuleID:      v.ID,
			Version:     v.Version,
			Entity:      e.Entity,
			Matched:     true,
			Count:       count,
			Threshold:   v.Threshold,
			WindowStart: ws,
			WindowEnd:   e.EventTime,
			FiredBefore: fired,
		})
	}
	return rep
}

// insertOrdered 按 (time, id) 全序插入（迟到事件可能插在已冻结位置之前）。
func insertOrdered(b *bucketState, env envelope) {
	pos := sort.Search(len(b.events), func(i int) bool {
		if b.events[i].time.Equal(env.time) {
			return b.events[i].id >= env.id
		}
		return b.events[i].time.After(env.time)
	})
	b.events = append(b.events, envelope{})
	copy(b.events[pos+1:], b.events[pos:])
	b.events[pos] = env
}

// advance 把某租户水位线推进到 target（不回退），并对新冻结区间做阈值穿越评估。
// 已冻结的候选永不重新评估；迟到插入到冻结位置之前的事件只参与计数、不再触发。
func (d *Detector) advanceLocked(tenant string, target time.Time) PumpReport {
	st := d.stateFor(tenant)
	rep := PumpReport{Tenant: tenant, WatermarkBefore: st.watermark, WatermarkAfter: st.watermark}
	if target.Before(st.watermark) || target.Equal(st.watermark) {
		rep.EvaluatedThroughAfter = st.watermark
		return rep
	}

	keys := make([]bucketKey, 0, len(st.buckets))
	for k := range st.buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ruleID != keys[j].ruleID {
			return keys[i].ruleID < keys[j].ruleID
		}
		if keys[i].version != keys[j].version {
			return keys[i].version < keys[j].version
		}
		return keys[i].entity < keys[j].entity
	})

	for _, key := range keys {
		b := st.buckets[key]
		rv, ok := d.catalog.Get(tenant, key.ruleID, key.version)
		if !ok {
			continue
		}
		// 只评估"水位线推进时新进入冻结区"的候选（pos 从 evalPos 起）。
		for b.evalPos < len(b.events) && !b.events[b.evalPos].time.After(target) {
			cand := b.events[b.evalPos]
			b.evalPos++
			winStart := cand.time.Add(-rv.Window)
			// 切片 [t-W, t] 内全部事件此刻都已关闭（水位线保证），
			// 迟到补录到冻结点之前的事件也计入计数。
			lo := sort.Search(len(b.events), func(i int) bool {
				return !b.events[i].time.Before(winStart)
			})
			var matched []string
			for i := lo; i < len(b.events) && !b.events[i].time.After(cand.time); i++ {
				matched = append(matched, b.events[i].id)
			}
			if len(matched) >= rv.Threshold {
				st.lastFire[key] = cand.time
				rep.Findings = append(rep.Findings, &Finding{
					Tenant:          tenant,
					RuleID:          rv.ID,
					RuleVersion:     rv.Version,
					Entity:          key.entity,
					TriggerEventID:  cand.id,
					EventTime:       cand.time,
					MatchedEventIDs: matched,
					Count:           len(matched),
					Threshold:       rv.Threshold,
					WindowStart:     winStart,
					WindowEnd:       cand.time,
				})
			}
		}
	}

	st.watermark = target
	rep.WatermarkAfter = target
	rep.EvaluatedThroughAfter = target
	return rep
}

// Pump 按当前已观测最大事件时间推进某租户的水位线，
// 对 (上次水位线, 新水位线] 区间按 (事件时间, 事件ID) 全序做阈值穿越评估。
// 已冻结区间永不重新评估。
func (d *Detector) Pump(tenant string) PumpReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.stateFor(tenant)
	if st.maxObserved.IsZero() {
		return PumpReport{Tenant: tenant, EvaluatedThroughAfter: st.watermark}
	}
	target := st.maxObserved.Add(-d.cfg.AllowedLateness)
	if target.Before(st.watermark) {
		target = st.watermark
	}
	return d.advanceLocked(tenant, target)
}

// PumpAll 把全部有数据租户的水位线推进到 maxObserved-L（常规水位线推进，
// 不排空仍处于乱序宽限内的窗口）。按租户名有序返回，全程持锁。
// 与 FlushAll 的区别：FlushAll 推进到 maxObserved 本身，用于排空与最终结论。
func (d *Detector) PumpAll() []PumpReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	tenants := make([]string, 0, len(d.tenants))
	for t := range d.tenants {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)

	out := make([]PumpReport, 0, len(tenants))
	for _, t := range tenants {
		st := d.tenants[t]
		if st.maxObserved.IsZero() {
			continue
		}
		target := st.maxObserved.Add(-d.cfg.AllowedLateness)
		if target.Before(st.watermark) {
			target = st.watermark
		}
		out = append(out, d.advanceLocked(t, target))
	}
	return out
}

// Flush 把某租户水位线推进到已观测最大事件时间本身，排空全部待评估窗口。
func (d *Detector) Flush(tenant string) PumpReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.stateFor(tenant)
	if st.maxObserved.IsZero() {
		return PumpReport{Tenant: tenant, EvaluatedThroughAfter: st.watermark}
	}
	return d.advanceLocked(tenant, st.maxObserved)
}

// FlushAll 排空全部有数据租户的窗口（Drain 用），按租户名有序返回，全程持锁。
func (d *Detector) FlushAll() []PumpReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	tenants := make([]string, 0, len(d.tenants))
	for t := range d.tenants {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)

	out := make([]PumpReport, 0, len(tenants))
	for _, t := range tenants {
		st := d.tenants[t]
		if st.maxObserved.IsZero() {
			continue
		}
		out = append(out, d.advanceLocked(t, st.maxObserved))
	}
	return out
}

// Watermark 返回某租户当前水位线（无数据时返回零值与 false）。
func (d *Detector) Watermark(tenant string) (time.Time, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.tenants[tenant]
	if st == nil || st.watermark.IsZero() {
		return time.Time{}, false
	}
	return st.watermark, true
}
