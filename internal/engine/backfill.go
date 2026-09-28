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
	// ErrBackfillWindowCorrected 范围内某个时间窗已有生效中的更正，
	// 同一窗口不允许第二条更正结论（拒绝整次请求，避免部分生效）。
	ErrBackfillWindowCorrected = fmt.Errorf("backfill: window already corrected")
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

// foldSuppressed 把关联器输出中的抑制命中折叠进其所属的主告警结论：
// 同一 AlertKey 的判定按 FireAt 有序，抑制命中（IsAlert=false, SuppressedBy 非空）
// 携带的事件 ID 合并到当前主告警。折叠后每个输出都代表该窗口的一条完整结论
// （主告警 + 其全部抑制命中），使基线/重算的"结论"可按合并事件集合精确比对。
func foldSuppressed(ds []detect.Decision) []detect.Decision {
	var out []detect.Decision
	idx := map[string]int{} // FireID -> out 下标
	for _, d := range ds {
		if d.IsAlert {
			idx[d.FireID] = len(out)
			out = append(out, d)
			continue
		}
		// 抑制命中：优先归并到重放流中对应的主告警。
		if pos, ok := idx[d.SuppressedBy]; ok {
			out[pos].EventIDs = append(out[pos].EventIDs, d.EventIDs...)
			continue
		}
		// 兜底：主告警不在本次输出（理论上不会发生，防御性保留为独立条目）。
		out = append(out, d)
	}
	for i := range out {
		sort.Strings(out[i].EventIDs)
	}
	return out
}

// corrPlan 是一个窗口的待应用更正（先计算、后统一应用，保证整次回补原子生效）。
type corrPlan struct {
	corr      alert.Correction
	corrected *alert.Alert // withdrawn 时为 nil
}

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

	// 1.5) 范围预检：区间内若已有任何"定案更正"的窗口，整次请求拒绝。
	// 这样即使补入事件已被先到的回补并入基线（重算结果与现状一致、没有 diff），
	// 调用方仍能得到明确的"该窗口已更正、不能再改"信号，而不是一个看似成功的空操作。
	if rej := e.checkCorrectedWindowsLocked(req); rej != nil {
		e.alerts.RecordDeniedBackfill(req.TenantID, req.Operator, rej.Error())
		return BackfillResult{Status: BackfillRejected, Request: req, Reject: rej,
			SkippedExtra: skipped}
	}

	// 2) 基线：重放事件日志（不含补入），得到 [Start,End] 内的既有判定。
	baseDec := foldSuppressed(e.replayLocked(req.TenantID, req.End, nil))
	// 3) 重算：在事件日志之上叠加补入事件重放。
	replDec := foldSuppressed(e.replayLocked(req.TenantID, req.End, added))

	// 4) 按 (规则,实体) 分组并只保留穿越点落在区间内的判定。
	groups := alignGroups(baseDec, replDec, req.Start, req.End)

	// 5) 逐组逐窗口比对，先算出全部待应用更正计划（不触碰任何状态）。
	addedSet := addedIDs(added)
	var plans []corrPlan
	for _, g := range groups {
		ps, err := e.planGroupLocked(g, req, addedSet)
		if err != nil {
			// 窗口已被别的回补更正等：整次请求拒绝，绝不部分生效，
			// 其它租户/其它时间段的既有结论不受影响。
			e.alerts.RecordDeniedBackfill(req.TenantID, req.Operator, err.Error())
			return BackfillResult{Status: BackfillRejected, Request: req, Reject: err,
				SkippedExtra: skipped}
		}
		plans = append(plans, ps...)
	}

	res := &BackfillResult{
		Status:         BackfillNoChange,
		Request:        req,
		ReplayedEvents: eventIDsOf(added),
		SkippedExtra:   skipped,
	}

	// 6) 统一应用：每条更正只对应一个窗口；整批在存储的单个临界区内原子生效，
	//    任一窗口冲突则整批回滚，绝不留下"部分窗口已更正"的中间状态。
	type applyItem = struct {
		Corr      alert.Correction
		Corrected *alert.Alert
	}
	items := make([]applyItem, 0, len(plans))
	for _, p := range plans {
		items = append(items, applyItem{Corr: p.corr, Corrected: p.corrected})
	}
	newAlerts, gotCorrs, err := e.alerts.ApplyCorrections(items)
	if err != nil {
		e.alerts.RecordDeniedBackfill(req.TenantID, req.Operator, err.Error())
		return BackfillResult{Status: BackfillRejected, Request: req, Reject: err,
			SkippedExtra: skipped}
	}
	// 全部更正生效后再同步在线抑制状态，保证后续在线命中写到当前可见结论。
	var applied []alert.Correction
	for i, got := range gotCorrs {
		e.retargetSuppressionLocked(got, newAlerts[i])
		applied = append(applied, *got)
	}
	res.Corrections = applied
	if len(applied) > 0 {
		res.Status = BackfillApplied
	}

	// 7) 认领补入事件，登记幂等台账；无论结论是否改变，补入都只生效一次。
	e.claimBackfillEventsLocked(req, added)
	stored := *res
	e.backfills[req.RequestID] = &stored
	return *res
}

// retargetSuppressionLocked 在更正生效后同步在线关联器的抑制状态。
// 调用方持引擎锁。
func (e *Engine) retargetSuppressionLocked(corr *alert.Correction, newAlert *alert.Alert) {
	switch corr.Kind {
	case alert.CorrectionWithdrawn:
		// 撤回：清掉指向任一旧结论的抑制期，使后续穿越产生新告警。
		for _, oid := range corr.OriginalAlertIDs {
			e.corr.ClearSuppressionIf(corr.RuleID+"|"+corr.Entity, oid)
		}
	default:
		// changed/added：把指向旧结论的抑制期改挂到更正告警。
		if newAlert != nil {
			for _, oid := range corr.OriginalAlertIDs {
				if e.corr.RetargetSuppression(oid, newAlert.ID) {
					return
				}
			}
		}
	}
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

// checkCorrectedWindowsLocked 判断请求区间是否与任何已定案更正的窗口重叠。
// 窗口锚点是原结论穿越点；changed 时补入事件可能让穿越点发生位移，因此同时
// 参考更正后告警的穿越点——只要其中一个落在 [Start,End] 内，本次回补就触及
// 已更正窗口，必须整批拒绝（同一窗口不允许第二条更正）。
// 调用方持引擎锁。
func (e *Engine) checkCorrectedWindowsLocked(req BackfillRequest) error {
	for _, c := range e.alerts.ListCorrections(req.TenantID) {
		inRange := func(t time.Time) bool {
			return !t.Before(req.Start) && !t.After(req.End)
		}
		if inRange(c.WindowEnd.UTC()) {
			return ErrBackfillWindowCorrected
		}
		if c.CorrectedAlertID != "" {
			op := req.Operator
			if a, err := e.alerts.Get(c.CorrectedAlertID, op); err == nil {
				if inRange(a.FireAt.UTC()) {
					return ErrBackfillWindowCorrected
				}
			}
		}
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

// planGroupLocked 比对一个 (规则,实体) 组在区间内的基线与重算窗口结论，
// 为【每一个结论不同的窗口】生成一条独立更正计划（一条 Correction 严格对应
// 一个窗口身份，保证同窗口最终可见结论唯一）。
//
// 两阶段对齐：
//  1. 合并事件集合完全相同的窗口 => 同一窗口，结论不变；
//  2. 剩余未配对窗口按穿越点有序两两交叉配对 => 该窗口结论变化（changed）；
//     多出来的基线窗口 => 结论撤回（withdrawn）；多出来的重算窗口 => 新增（added）。
//
// 这样单纯"第几次新发"的序号漂移不会造成噪音；只有窗口事件集合真正不同才更正。
// 调用方持引擎锁；本函数不产生任何副作用。
func (e *Engine) planGroupLocked(g replayGroup, req BackfillRequest, added map[string]bool) ([]corrPlan, error) {
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
	sort.Slice(baseLeft, func(i, j int) bool { return g.base[baseLeft[i]].FireAt.Before(g.base[baseLeft[j]].FireAt) })
	sort.Slice(replLeft, func(i, j int) bool { return g.repl[replLeft[i]].FireAt.Before(g.repl[replLeft[j]].FireAt) })
	if len(baseLeft) == 0 && len(replLeft) == 0 {
		return nil, nil // 全部窗口一致：结论不变，零噪音
	}

	ruleVer := 0
	if len(g.repl) > 0 {
		ruleVer = g.repl[len(g.repl)-1].RuleVersion
	} else if len(g.base) > 0 {
		ruleVer = g.base[len(g.base)-1].RuleVersion
	}

	var plans []corrPlan

	// 阶段 2a：交叉配对 => changed，每个窗口一条更正。
	n := len(baseLeft)
	if len(replLeft) < n {
		n = len(replLeft)
	}
	for k := 0; k < n; k++ {
		bd, rd := g.base[baseLeft[k]], g.repl[replLeft[k]]
		plan, err := e.buildPlanLocked(req, g, ruleVer,
			[]detect.Decision{bd}, []detect.Decision{rd}, added)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	// 阶段 2b：多出来的基线窗口 => withdrawn（各自独立更正）。
	for _, bi := range baseLeft[n:] {
		plan, err := e.buildPlanLocked(req, g, ruleVer,
			[]detect.Decision{g.base[bi]}, nil, added)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	// 阶段 2c：多出来的重算窗口 => added（各自独立更正）。
	for _, rj := range replLeft[n:] {
		plan, err := e.buildPlanLocked(req, g, ruleVer,
			nil, []detect.Decision{g.repl[rj]}, added)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// buildPlanLocked 为单个窗口构造更正计划。调用方持引擎锁，无副作用。
func (e *Engine) buildPlanLocked(req BackfillRequest, g replayGroup, ruleVer int,
	baseDs, replDs []detect.Decision, added map[string]bool) (corrPlan, error) {
	corr := alert.Correction{
		RequestID: req.RequestID, TenantID: g.tenantID, RuleID: g.ruleID,
		RuleVersion: ruleVer, Entity: g.entity, OperatorID: req.Operator.ID,
	}
	var origIDs []string
	// 窗口身份锚定【原结论】的穿越点：补入事件会让重算的穿越点发生位移，
	// 但它仍是"同一个时间窗的更正"，不能因为右端漂移被当成另一个窗口。
	windowStart, windowEnd := time.Time{}, time.Time{}
	for _, bd := range baseDs {
		origIDs = append(origIDs, e.resolveAlertIDLocked(bd))
		corr.BaselineEventIDs = append(corr.BaselineEventIDs, bd.EventIDs...)
		if windowStart.IsZero() || bd.FirstEventAt.Before(windowStart) {
			windowStart = bd.FirstEventAt
		}
		if bd.FireAt.After(windowEnd) {
			windowEnd = bd.FireAt
		}
	}
	var rep *detect.Decision
	for i := range replDs {
		rd := replDs[i]
		corr.FinalEventIDs = append(corr.FinalEventIDs, rd.EventIDs...)
		// added（无原结论）时窗口边界由重算结论定义。
		if windowStart.IsZero() || rd.FirstEventAt.Before(windowStart) {
			windowStart = rd.FirstEventAt
		}
		if windowEnd.IsZero() || rd.FireAt.After(windowEnd) {
			windowEnd = rd.FireAt
		}
		d := rd
		rep = &d
	}

	hasBase := len(baseDs) > 0
	hasFinal := len(replDs) > 0
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
	corr.Reason = fmt.Sprintf(
		"backfill %s re-evaluated tenant=%s rule=%s entity=%s window[%s,%s] (%s): %s; added events=%v",
		req.RequestID, g.tenantID, g.ruleID, g.entity,
		windowStart.Format(time.RFC3339Nano), windowEnd.Format(time.RFC3339Nano),
		corr.Kind, req.Reason, corr.AddedEventIDs)
	corr.ID = correctionID(req.RequestID, g.ruleID, g.entity, windowEnd)

	// 预检（在统一应用之前，保证多窗口请求要么全过、要么整批拒绝，不留半成品）：
	// 原结论已经被更正（含原结论本身就是更正告警）的窗口不允许再出现第二条更正；
	// 同窗口身份的另一条更正记录同样拒绝。
	if len(corr.OriginalAlertIDs) > 0 {
		for _, oid := range corr.OriginalAlertIDs {
			if sealed, err := e.alerts.IsSealed(oid); err == nil && sealed {
				return corrPlan{}, ErrBackfillWindowCorrected
			}
		}
	}
	if id, ok := e.alerts.WindowCorrection(g.tenantID, g.ruleID, g.entity, windowEnd); ok && id != corr.ID {
		return corrPlan{}, ErrBackfillWindowCorrected
	}

	plan := corrPlan{corr: corr}
	if corr.Kind != alert.CorrectionWithdrawn {
		plan.corrected = &alert.Alert{
			ID:       "corr:" + rep.FireID + ":" + req.RequestID,
			TenantID: g.tenantID, RuleID: rep.RuleID, RuleVersion: rep.RuleVersion,
			Entity: rep.Entity, CreatedAt: rep.FirstEventAt, FireAt: rep.FireAt,
			EventIDs: append([]string{}, rep.EventIDs...),
		}
	}
	return plan, nil
}

// resolveAlertIDLocked 把重放基线决策映射到存储中的真实告警 ID。
// 优先精确命中 FireID（在线与重放的确定性序号一致）；否则按
// （规则,实体,合并事件集合）匹配，再退回到穿越点 FireAt 相同的告警；
// 历史查询包含已被更正取代的旧结论。调用方持引擎锁。
func (e *Engine) resolveAlertIDLocked(d detect.Decision) string {
	want := sig(d.EventIDs)
	var candidate string
	for _, a := range e.alerts.ListHistory(d.TenantID) {
		if a.RuleID != d.RuleID || a.Entity != d.Entity {
			continue
		}
		if a.ID == d.FireID {
			return a.ID
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
