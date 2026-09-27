package event

import (
	"sort"
	"sync"
	"time"
)

// DefaultAllowedLateness 是默认的迟到容忍度（在线 Tick 的水位滞后量）。
const DefaultAllowedLateness = 30 * time.Second

// Ingestor 是入口判定器：对到达事件做去重、迟到判定与水位管理，
// 保证同一批事件在任意到达顺序、重复投递下得到一致结果。
//
// 时间语义（检测只使用事件时间 EventTime；接收时间 ReceivedAt 仅用于审计）：
//
//  1. 水位必须由生产者显式断言。AdvanceWatermark(W) 表示：事件时间 <= W
//     的所有事件均已到达。此后再到达且事件时间 <= W 的事件判为【迟到】并隔离，
//     不参与检测。尚未断言过任何水位时，任何事件都不可能迟到——因此把一整批
//     事件以任意顺序喂入、最后再推进水位越过批尾，结果与到达顺序完全无关。
//  2. 断言水位 W 时，所有事件时间 <= W 的缓冲事件按 (事件时间, 实体, ID)
//     排序后一次性释放给关联器；跨多次断言的释放序列整体有序。
//  3. 事件 ID 相同的重复投递一律判为【重复】，去重优先于迟到判定
//     （一条迟到事件的重投仍是重复，不重复记账）。
//  4. Tick() 是在线模式的便利方法：以 已观测最大事件时间 - AllowedLateness
//     断言水位。交错使用 Tick 与接收所产生的迟到判定反映真实的流式到达；
//     需要可复现的批处理结论时应使用 AdvanceWatermark 显式边界。
type Ingestor struct {
	mu         sync.Mutex
	allowed    time.Duration
	maxSeen    time.Time            // 已接收正常事件的最大事件时间（仅用于 Tick）
	asserted   time.Time            // 最近一次显式断言的水位（零值表示从未断言）
	seen       map[string]time.Time // ID -> 首次接收时间
	pending    []*Event             // 已接收但尚未随水位断言释放的事件
	quarantine []QuarantineRecord
	seenCnt    int
	dupCnt     int
}

// IngestConfig 控制入口判定。
type IngestConfig struct {
	AllowedLateness time.Duration
}

// NewIngestor 创建入口判定器。
func NewIngestor(cfg IngestConfig) *Ingestor {
	l := cfg.AllowedLateness
	if l <= 0 {
		l = DefaultAllowedLateness
	}
	return &Ingestor{allowed: l, seen: map[string]time.Time{}}
}

// Admit 接收一条归一化事件，返回其去向（正常 / 重复 / 迟到）。
// 正常事件进入缓冲，等待下一次水位断言时有序释放。
func (g *Ingestor) Admit(e *Event) Outcome {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.seenCnt++
	if first, ok := g.seen[e.ID]; ok { // 去重优先于迟到判定
		g.dupCnt++
		detail := "event id " + e.ID + " first received at " +
			first.Format(time.RFC3339Nano)
		return Outcome{
			Disposition: DispDuplicate,
			Event:       e,
			Quarantine: &QuarantineRecord{
				Raw: e.Raw, Source: e.Source, Disposition: DispDuplicate,
				Reason: RejectReason("duplicate_event"),
				Detail: detail, ReceivedAt: e.ReceivedAt,
			},
		}
	}
	g.seen[e.ID] = e.ReceivedAt

	if !g.asserted.IsZero() && !e.EventTime.After(g.asserted) {
		rec := QuarantineRecord{
			Raw: e.Raw, Source: e.Source, TenantID: e.TenantID, EventID: e.ID,
			Disposition: DispLate,
			Reason:      RejectReason("late_event"),
			Detail: "event_time=" + e.EventTime.Format(time.RFC3339Nano) +
				" <= asserted_watermark=" + g.asserted.Format(time.RFC3339Nano),
			ReceivedAt: e.ReceivedAt,
		}
		g.quarantine = append(g.quarantine, rec)
		return Outcome{Disposition: DispLate, Event: e, Quarantine: &rec}
	}

	if e.EventTime.After(g.maxSeen) {
		g.maxSeen = e.EventTime
	}
	g.pending = append(g.pending, e)
	return Outcome{Disposition: DispAccepted, Event: e}
}

// AdvanceWatermark 显式断言水位单调前进到 W，返回事件时间 <= W 的缓冲事件
// （按 (事件时间, 实体, ID) 全局有序）。重复调用或回退均安全（回退被忽略）。
func (g *Ingestor) AdvanceWatermark(W time.Time) []*Event {
	g.mu.Lock()
	defer g.mu.Unlock()
	if W.After(g.asserted) {
		g.asserted = W
	}
	return g.releaseLocked(g.asserted)
}

// Tick 以 已观测最大事件时间 - AllowedLateness 断言水位（在线模式）。
func (g *Ingestor) Tick() []*Event {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.maxSeen.IsZero() {
		return nil
	}
	W := g.maxSeen.Add(-g.allowed)
	if W.After(g.asserted) {
		g.asserted = W
	}
	return g.releaseLocked(g.asserted)
}

// releaseLocked 释放事件时间 <= W 的缓冲事件；调用方持锁。
func (g *Ingestor) releaseLocked(W time.Time) []*Event {
	var released, kept []*Event
	for _, e := range g.pending {
		if !e.EventTime.After(W) {
			released = append(released, e)
		} else {
			kept = append(kept, e)
		}
	}
	g.pending = kept
	sort.Slice(released, func(i, j int) bool {
		if !released[i].EventTime.Equal(released[j].EventTime) {
			return released[i].EventTime.Before(released[j].EventTime)
		}
		if released[i].Entity != released[j].Entity {
			return released[i].Entity < released[j].Entity
		}
		return released[i].ID < released[j].ID
	})
	return released
}

// Quarantine 返回被隔离（迟到）记录的快照。
func (g *Ingestor) Quarantine() []QuarantineRecord {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]QuarantineRecord, len(g.quarantine))
	copy(out, g.quarantine)
	return out
}

// Watermark 返回当前已断言水位（零值表示尚未断言）。
func (g *Ingestor) Watermark() Watermark {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Watermark{t: g.asserted}
}

// MaxObserved 返回已接收正常事件的最大事件时间。
func (g *Ingestor) MaxObserved() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.maxSeen
}

// Stats 返回已接收总数与重复数，便于测试解释判定过程。
func (g *Ingestor) Stats() (seen, duplicates int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.seenCnt, g.dupCnt
}
