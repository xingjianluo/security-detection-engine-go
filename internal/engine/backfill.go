// 受控回补（backfill）：运维确认上游补齐某段数据后，主动发起一次按
// 租户 + 事件时间段圈定范围的回补，把此前被隔离（迟到）的记录重新纳入检测。
//
// 约束：
//   - 只对请求指定的 [Start,End] 时间窗与租户生效；其它租户/时间段结论不变。
//   - 同一 RequestID 重复发起、并发重叠发起均幂等：同一条事件不被算两遍，
//     不重复产出告警，不重复产出更正。
//   - 补入历史按其自身事件时间匹配当时生效的规则版本（复用版本化规则集）。
//   - 结论变化时原结论保留可查，另产出可追溯的更正（Correction）；
//     结论不变不产生任何噪音。
package engine

import (
	"fmt"
	"sort"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

// DefaultMaxBackfillAge 是单次回补允许覆盖的默认最大时间跨度（End-Start）。
const DefaultMaxBackfillAge = 24 * time.Hour

// BackfillStatus 回补请求的处理结果分类，调用方可精确区分。
type BackfillStatus string

const (
	// BackfillApplied 已接受且结论确实发生变化（产生了更正）。
	BackfillApplied BackfillStatus = "applied_changed"
	// BackfillNoChange 已接受并重算，但结论不变，不产生噪音。
	BackfillNoChange BackfillStatus = "accepted_no_change"
	// BackfillIdempotent 同一 RequestID 已处理过，直接返回原结果。
	BackfillIdempotent BackfillStatus = "idempotent_replay"
	// BackfillRejected 因越权/跨租户/超出可回补范围/参数非法被拒绝。
	BackfillRejected BackfillStatus = "rejected"
)

// 回补被拒绝的可区分原因，调用方可精确断言。
var (
	// ErrBackfillUnauthorized 操作者角色无权发起回补（需 operator/admin）。
	ErrBackfillUnauthorized = fmt.Errorf("backfill: permission denied")
	// ErrBackfillCrossTenant 操作者租户与回补目标租户不一致。
	ErrBackfillCrossTenant = fmt.Errorf("backfill: cross-tenant request denied")
	// ErrBackfillBadRange 时间范围非法（零值、起止颠倒）。
	ErrBackfillBadRange = fmt.Errorf("backfill: invalid time range")
	// ErrBackfillTooWide 范围超出最大可回补跨度。
	ErrBackfillTooWide = fmt.Errorf("backfill: range exceeds max backfill age")
	// ErrBackfillBeyondWatermark 回补范围越过已断言水位（只能回补已定论的历史）。
	ErrBackfillBeyondWatermark = fmt.Errorf("backfill: end beyond settled watermark")
	// ErrBackfillNoRequestID 缺少幂等键。
	ErrBackfillNoRequestID = fmt.Errorf("backfill: request id required")
)

// BackfillRequest 是一次受控回补请求。
type BackfillRequest struct {
	// RequestID 调用方提供的幂等键；相同 ID 重复/并发发起返回同一结果。
	RequestID string
	TenantID  string
	Operator  alert.Operator
	// Start/End 为事件时间闭区间 [Start,End]，只重算右端落在该区间的窗口。
	Start time.Time
	End   time.Time
	// Extra 可选：随请求一并补投的原始记录（上游刚补发的那段）。
	Extra []RawRecord
	// Reason 人工说明，记入更正与审计。
	Reason string
}

// RawRecord 是回补请求中携带的一条原始记录。
type RawRecord struct {
	Source event.Source
	Raw    string
}

// BackfillResult 是回补请求的明确结果。
type BackfillResult struct {
	Status         BackfillStatus
	Request        BackfillRequest
	Reject         error              // Status==rejected 时非空（可区分原因）
	Corrections    []alert.Correction // applied 时本次产生的更正
	ReplayedEvents []string           // 本次实际纳入重算的补入事件 ID（去重后）
	SkippedExtra   []SkippedRecord    // 补投记录中无法解析/越界被跳过的条目
}

// SkippedRecord 描述回补补投记录中被跳过的一条。
type SkippedRecord struct {
	Source event.Source
	Reason event.RejectReason
	Detail string
}

// replayGroup 是某 (规则,实体) 在回补区间内的一组有序判定（基线 vs 重算）。
type replayGroup struct {
	ruleID   string
	entity   string
	tenantID string
	base     []detect.Decision
	repl     []detect.Decision
}

func groupKey(d detect.Decision) string { return d.RuleID + "|" + d.Entity }

// Backfill 发起一次受控回补。并发安全：与在线 Ingest/Advance/Tick 串行化。
func (e *Engine) Backfill(req BackfillRequest) BackfillResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	if rej := e.validateBackfillLocked(req); rej != nil {
		e.alerts.RecordDeniedBackfill(req.TenantID, req.Operator, rej.Error())
		return BackfillResult{Status: BackfillRejected, Request: req, Reject: rej}
	}

	// 幂等：同一 RequestID 重复 / 并发重叠发起，返回首次结果，绝不重复产出。
	if prev, ok := e.backfills[req.RequestID]; ok {
		out := *prev
		out.Status = BackfillIdempotent
		return out
	}

	// 1) 收集本次补入事件：区间内、本租户、此前被隔离（迟到）且未被认领的记录，
	//    以及请求中显式补投、通过解析且未在事件日志中的记录。
	added, skipped := e.collectBackfillEventsLocked(req)

	// 2) 基线：重放事件日志（不含补入），得到 [Start,End] 内的既有判定。
	baseDec := e.replayLocked(req.TenantID, req.End, nil)
	// 3) 重算：在事件日志之上叠加补入事件重放。
	replDec := e.replayLocked(req.TenantID, req.End, added)

	// 4) 按 (规则,实体) 分组并只保留穿越点落在区间内的判定。
	groups := alignGroups(baseDec, replDec, req.Start, req.End)

	// 5) 逐组比对，只在结论确实不同的窗口产出更正；相同则零噪音。
	res := &BackfillResult{
		Status:         BackfillNoChange,
		Request:        req,
		ReplayedEvents: eventIDsOf(added),
		SkippedExtra:   skipped,
	}
	for _, g := range groups {
		if corr, changed := e.diffGroupLocked(g, req, addedIDs(added)); changed {
			res.Corrections = append(res.Corrections, *corr)
		}
	}
	if len(res.Corrections) > 0 {
		res.Status = BackfillApplied
	}

	// 6) 认领补入事件，登记幂等台账；无论结论是否改变，补入都只生效一次。
	e.claimBackfillEventsLocked(req, added)
	stored := *res
	e.backfills[req.RequestID] = &stored
	return *res
}

// validateBackfillLocked 校验请求；调用方持锁。
func (e *Engine) validateBackfillLocked(req BackfillRequest) error {
	if req.RequestID == "" {
		return ErrBackfillNoRequestID
	}
	if req.Operator.TenantID != "" && req.Operator.TenantID != req.TenantID {
		return ErrBackfillCrossTenant
	}
	if req.Operator.Role != alert.RoleAdmin && req.Operator.Role != alert.RoleOperator {
		return ErrBackfillUnauthorized
	}
	if req.TenantID == "" || req.Start.IsZero() || req.End.IsZero() || req.End.Before(req.Start) {
		return ErrBackfillBadRange
	}
	if req.End.Sub(req.Start) > e.maxBackfillAge {
		return ErrBackfillTooWide
	}
	wm := e.ingest.Watermark().T()
	if wm.IsZero() || req.End.After(wm) {
		// 只允许回补已定论（水位已越过）的历史，避免与在线未决窗口冲突。
		return ErrBackfillBeyondWatermark
	}
	return nil
}

// collectBackfillEventsLocked 收集补入事件：区间内本租户的未认领迟到记录 +
// 请求显式补投的可解析新事件。返回按事件时间排序、按 ID 去重后的事件。
// 调用方持锁。
func (e *Engine) collectBackfillEventsLocked(req BackfillRequest) ([]*event.Event, []SkippedRecord) {
	var added []*event.Event
	seen := map[string]bool{}
	add := func(ev *event.Event) bool {
		if ev.TenantID != req.TenantID || seen[ev.ID] || e.journalIDs[ev.ID] {
			return false
		}
		if ev.EventTime.Before(req.Start) || ev.EventTime.After(req.End) {
			return false
		}
		seen[ev.ID] = true
		added = append(added, ev)
		return true
	}

	// a) 已隔离的迟到记录（此前上游延迟、被入口判 late）。
	for idx, ev := range e.lateRecords {
		if e.lateClaimed[idx] {
			continue
		}
		add(ev)
		// 记录"该迟到记录是否落在本次范围"，认领时按下标处理。
	}

	// b) 请求显式补投的原始记录：重新解析，跳过非法/越界/重复（非致命）。
	var skipped []SkippedRecord
	for _, rr := range req.Extra {
		parsed, err := event.Parse(rr.Source, rr.Raw, e.parseCfg)
		if err != nil {
			reason := event.ReasonParseError
			var pe *event.ParseError
			if asParseError(err, &pe) {
				reason = pe.Reason
			}
			skipped = append(skipped, SkippedRecord{Source: rr.Source, Reason: reason, Detail: err.Error()})
			continue
		}
		parsed.TenantID = req.TenantID
		if parsed.ReceivedAt.IsZero() {
			if e.parseCfg.Now != nil {
				parsed.ReceivedAt = e.parseCfg.Now()
			} else {
				parsed.ReceivedAt = time.Now()
			}
		}
		if parsed.EventTime.Before(req.Start) || parsed.EventTime.After(req.End) {
			skipped = append(skipped, SkippedRecord{
				Source: rr.Source, Reason: event.RejectReason("out_of_backfill_range"),
				Detail: "event_time " + parsed.EventTime.Format(time.RFC3339Nano) +
					" outside [" + req.Start.Format(time.RFC3339Nano) + "," +
					req.End.Format(time.RFC3339Nano) + "]",
			})
			continue
		}
		if !add(parsed) {
			skipped = append(skipped, SkippedRecord{
				Source: rr.Source, Reason: event.RejectReason("duplicate_event"),
				Detail: "event id " + parsed.ID + " already present or duplicate in request",
			})
		}
	}

	sort.Slice(added, func(i, j int) bool {
		if !added[i].EventTime.Equal(added[j].EventTime) {
			return added[i].EventTime.Before(added[j].EventTime)
		}
		if added[i].Entity != added[j].Entity {
			return added[i].Entity < added[j].Entity
		}
		return added[i].ID < added[j].ID
	})
	return added, skipped
}

// replayLocked 用一个全新的关联器重放：事件日志中该租户、EventTime<=end 的事件，
// 叠加可选补入事件；按 (事件时间,实体,ID) 全局有序提交，水位断言到 end。
// 因规则集版本化，补入的历史事件自动按其事件时间匹配当时生效的规则版本。
// 调用方持锁。该重放不触碰在线关联器状态。
func (e *Engine) replayLocked(tenantID string, end time.Time, extra []*event.Event) []detect.Decision {
	var evs []*event.Event
	for _, ev := range e.journal {
		if ev.TenantID == tenantID && !ev.EventTime.After(end) {
			evs = append(evs, ev)
		}
	}
	evs = append(evs, extra...)
	sort.Slice(evs, func(i, j int) bool {
		if !evs[i].EventTime.Equal(evs[j].EventTime) {
			return evs[i].EventTime.Before(evs[j].EventTime)
		}
		if evs[i].Entity != evs[j].Entity {
			return evs[i].Entity < evs[j].Entity
		}
		return evs[i].ID < evs[j].ID
	})
	c := detect.NewCorrelator(e.rules)
	for _, ev := range evs {
		c.Observe(ev)
	}
	return c.AdvanceWatermark(end)
}

// alignGroups 把基线与重算判定按 (规则,实体) 分组，且只保留穿越点 FireAt
// 落在 [start,end] 内的判定（区间外的既有结论不受本次回补影响）。
func alignGroups(base, repl []detect.Decision, start, end time.Time) []replayGroup {
	gm := map[string]*replayGroup{}
	var order []string
	collect := func(ds []detect.Decision, isBase bool) {
		for _, d := range ds {
			if d.FireAt.Before(start) || d.FireAt.After(end) {
				continue
			}
			k := groupKey(d)
			g := gm[k]
			if g == nil {
				g = &replayGroup{ruleID: d.RuleID, entity: d.Entity, tenantID: d.TenantID}
				gm[k] = g
				order = append(order, k)
			}
			if isBase {
				g.base = append(g.base, d)
			} else {
				g.repl = append(g.repl, d)
			}
		}
	}
	collect(base, true)
	collect(repl, false)
	sort.Strings(order)
	out := make([]replayGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *gm[k])
	}
	return out
}

// diffGroupLocked 比对一个 (规则,实体) 组在区间内的基线与重算判定。
// 两阶段对齐：
//  1. 合并事件集合完全相同的窗口 => 同一窗口，结论不变；
//  2. 剩余未配对窗口按穿越点有序两两交叉配对 => 同一窗口结论变化（changed）；
//     多出来的基线窗口 => 结论撤回（withdrawn）；多出来的重算窗口 => 新增（added）。
//
// 这样单纯"第几次新发"的序号漂移不会造成噪音；只有窗口事件集合真正不同才更正。
// 调用方持锁。
func (e *Engine) diffGroupLocked(g replayGroup, req BackfillRequest, added map[string]bool) (*alert.Correction, bool) {
	baseUsed := make([]bool, len(g.base))
	replUsed := make([]bool, len(g.repl))

	// 阶段 1：相同事件集合 => 结论不变。
	for bi := range g.base {
		for rj := range g.repl {
			if replUsed[rj] {
				continue
			}
			if sig(g.base[bi].EventIDs) == sig(g.repl[rj].EventIDs) {
				baseUsed[bi] = true
				replUsed[rj] = true
				break
			}
		}
	}

	var baseLeft, replLeft []int
	for bi := range g.base {
		if !baseUsed[bi] {
			baseLeft = append(baseLeft, bi)
		}
	}
	for rj := range g.repl {
		if !replUsed[rj] {
			replLeft = append(replLeft, rj)
		}
	}
	// 两侧均按 FireAt 升序（关联器输出已排序）。
	sort.Slice(baseLeft, func(i, j int) bool { return g.base[baseLeft[i]].FireAt.Before(g.base[baseLeft[j]].FireAt) })
	sort.Slice(replLeft, func(i, j int) bool { return g.repl[replLeft[i]].FireAt.Before(g.repl[replLeft[j]].FireAt) })
	if len(baseLeft) == 0 && len(replLeft) == 0 {
		return nil, false // 全部窗口一致：结论不变，零噪音
	}

	corr := alert.Correction{
		RequestID: req.RequestID, TenantID: g.tenantID, RuleID: g.ruleID,
		Entity: g.entity, OperatorID: req.Operator.ID,
	}
	var origIDs []string
	windowStart, windowEnd := time.Time{}, time.Time{}
	markWindow := func(start, end time.Time) {
		if windowStart.IsZero() || start.Before(windowStart) {
			windowStart = start
		}
		if end.After(windowEnd) {
			windowEnd = end
		}
	}

	// 阶段 2a：交叉配对 => changed（旧窗口结论被新窗口取代）。
	n := len(baseLeft)
	if len(replLeft) < n {
		n = len(replLeft)
	}
	for k := 0; k < n; k++ {
		bd, rd := g.base[baseLeft[k]], g.repl[replLeft[k]]
		origIDs = append(origIDs, e.resolveAlertIDLocked(bd))
		corr.BaselineEventIDs = append(corr.BaselineEventIDs, bd.EventIDs...)
		corr.FinalEventIDs = append(corr.FinalEventIDs, rd.EventIDs...)
		markWindow(rd.FirstEventAt, rd.FireAt)
	}
	// 多出来的基线窗口 => withdrawn。
	for _, bi := range baseLeft[n:] {
		bd := g.base[bi]
		origIDs = append(origIDs, e.resolveAlertIDLocked(bd))
		corr.BaselineEventIDs = append(corr.BaselineEventIDs, bd.EventIDs...)
		markWindow(bd.FirstEventAt, bd.FireAt)
	}
	// 多出来的重算窗口 => added。
	var addedDecs []detect.Decision
	for _, rj := range replLeft[n:] {
		rd := g.repl[rj]
		corr.FinalEventIDs = append(corr.FinalEventIDs, rd.EventIDs...)
		addedDecs = append(addedDecs, rd)
		markWindow(rd.FirstEventAt, rd.FireAt)
	}

	hasBase := len(corr.BaselineEventIDs) > 0
	hasFinal := len(corr.FinalEventIDs) > 0
	switch {
	case hasBase && hasFinal:
		corr.Kind = alert.CorrectionChanged
	case hasBase:
		corr.Kind = alert.CorrectionWithdrawn
	default:
		corr.Kind = alert.CorrectionAdded
	}
	corr.OriginalAlertIDs = dedupSorted(origIDs)
	corr.WindowStart = windowStart
	corr.WindowEnd = windowEnd
	corr.AddedEventIDs = intersectAdded(corr.FinalEventIDs, added)
	if len(g.repl) > 0 {
		corr.RuleVersion = g.repl[len(g.repl)-1].RuleVersion
	} else if len(g.base) > 0 {
		corr.RuleVersion = g.base[len(g.base)-1].RuleVersion
	}
	corr.Reason = fmt.Sprintf(
		"backfill %s re-evaluated tenant=%s rule=%s entity=%s window[%s,%s] (%s): %s; added events=%v",
		req.RequestID, g.tenantID, g.ruleID, g.entity,
		windowStart.Format(time.RFC3339Nano), windowEnd.Format(time.RFC3339Nano),
		corr.Kind, req.Reason, corr.AddedEventIDs)
	corr.ID = correctionID(req.RequestID, g.ruleID, g.entity, windowEnd)

	// withdrawn：没有替代告警，只登记撤回更正。
	if corr.Kind == alert.CorrectionWithdrawn {
		got, err := e.alerts.RegisterWithdrawal(corr)
		if err != nil {
			return nil, false
		}
		return got, true
	}

	// changed/added：以重算窗口创建一条确定性的更正告警。
	// 取与 windowEnd 对齐的重算决策作为更正告警载体（added 时唯一，changed 时取最右）。
	var rep *detect.Decision
	for i := range addedDecs {
		d := addedDecs[i]
		if rep == nil || d.FireAt.After(rep.FireAt) {
			rep = &d
		}
	}
	if rep == nil {
		// changed：交叉配对的最后一个重算窗口。
		d := g.repl[replLeft[n-1]]
		rep = &d
	}
	a := alert.Alert{
		ID:       "corr:" + rep.FireID + ":" + req.RequestID,
		TenantID: g.tenantID, RuleID: rep.RuleID, RuleVersion: rep.RuleVersion,
		Entity: rep.Entity, CreatedAt: rep.FirstEventAt, FireAt: rep.FireAt,
		EventIDs: append([]string{}, rep.EventIDs...),
	}
	_, got, err := e.alerts.CreateCorrected(corr, a)
	if err != nil {
		return nil, false
	}
	return got, true
}

// resolveAlertIDLocked 把重放基线决策映射到存储中的真实告警 ID。
// 基线重放用的是全新关联器，FireID 的"该键第几次新发"序号与在线一致，
// 但更正后的再次重放会让旧 FireID 指向已被取代的告警——这里统一通过
// （规则,实体,穿越点 FireAt,合并事件集合）在存储中找到当前可见或已取代的原告警。
// 注意必须在"含已取代旧结论"的全量快照里查找，不能用活跃视图 List。
// 调用方持锁。
func (e *Engine) resolveAlertIDLocked(d detect.Decision) string {
	want := sig(d.EventIDs)
	var candidate string
	for _, a := range e.alerts.AllAlertsForResolve() {
		if a.RuleID != d.RuleID || a.Entity != d.Entity || a.TenantID != d.TenantID {
			continue
		}
		if sig(a.EventIDs) == want {
			return a.ID
		}
		if a.FireAt.Equal(d.FireAt) {
			candidate = a.ID
		}
	}
	if candidate != "" {
		return candidate
	}
	return d.FireID // 兜底（理论上基线告警必然存在于存储）
}

// claimBackfillEventsLocked 把本次补入事件并入事件日志，并认领对应迟到记录。
// 调用方持锁。
func (e *Engine) claimBackfillEventsLocked(req BackfillRequest, added []*event.Event) {
	addedByID := map[string]*event.Event{}
	for _, ev := range added {
		addedByID[ev.ID] = ev
	}
	for idx, ev := range e.lateRecords {
		if e.lateClaimed[idx] {
			continue
		}
		if _, ok := addedByID[ev.ID]; ok {
			e.lateClaimed[idx] = true
		}
	}
	for _, ev := range added {
		if !e.journalIDs[ev.ID] {
			e.journalIDs[ev.ID] = true
			e.journal = append(e.journal, ev)
		}
	}
}

// ---- 小工具 ----

func sig(ids []string) string {
	cp := append([]string{}, ids...)
	sort.Strings(cp)
	out := ""
	for i, id := range cp {
		if i > 0 {
			out += ","
		}
		out += id
	}
	return out
}

func eventIDsOf(evs []*event.Event) []string {
	out := make([]string, 0, len(evs))
	for _, ev := range evs {
		out = append(out, ev.ID)
	}
	sort.Strings(out)
	return out
}

func addedIDs(evs []*event.Event) map[string]bool {
	m := map[string]bool{}
	for _, ev := range evs {
		m[ev.ID] = true
	}
	return m
}

func dedupSorted(ids []string) []string {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func intersectAdded(finalIDs []string, added map[string]bool) []string {
	set := map[string]bool{}
	for _, id := range finalIDs {
		if added[id] {
			set[id] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func correctionID(requestID, ruleID, entity string, end time.Time) string {
	return fmt.Sprintf("corrrec:%s:%s:%s:%d", requestID, ruleID, entity, end.UnixNano())
}
