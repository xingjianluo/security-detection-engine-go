package engine

import (
	"fmt"
	"sort"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/backfill"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

// Backfill 是运维发起的受控回补入口：把 (租户, 时间段) 内因迟到被隔离的
// 记录重新纳入检测，并以【更正】形式更新可见结论（原结论保留可查）。
//
// 与在线写入共用引擎全局锁串行化，因此回补进行时新事件照常写入/查询，
// 各租户计数、抑制与告警互不串扰，并发跑完最终结论唯一、可复现。
// 结果三态可区分：accepted_changed / accepted_unchanged / rejected(带原因)。
func (e *Engine) Backfill(req backfill.Request) backfill.Result {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 幂等：同一 RequestID 重复发起直接返回已登记结果。
	if cached, ok := e.backfills.Lookup(req.RequestID); ok {
		cached.Replayed = true
		return cached
	}

	now := e.nowLocked()
	if err := backfill.Validate(req, e.maxAge, now); err != nil {
		return e.backfills.Reject(req, err)
	}
	// 状态相关校验：回补终点不得越过当前已断言水位（该段结论尚未定论）。
	wm := e.ingest.Watermark().T()
	if wm.IsZero() || req.To.After(wm) {
		return e.backfills.Reject(req, backfill.ErrRangeNotFinalized)
	}

	res, err := e.execBackfillLocked(req)
	if err != nil {
		return e.backfills.Reject(req, err)
	}
	// 登记幂等结果（Commit 的 run 已在锁内执行，直接存储）。
	return e.backfills.Store(res)
}

func (e *Engine) nowLocked() time.Time {
	if e.clock != nil {
		return e.clock().UTC()
	}
	return time.Now().UTC()
}

// execBackfillLocked 在引擎锁内执行一次回补（调用方已完成校验）。调用方持锁。
func (e *Engine) execBackfillLocked(req backfill.Request) (backfill.Result, error) {
	res := backfill.Result{
		RequestID: req.RequestID, TenantID: req.TenantID, From: req.From, To: req.To,
	}

	// 1) 收集候选：该租户、时间段内、尚未回补过的迟到隔离记录。
	candIdx := e.lateCandidatesLocked(req)

	// 2) 逐条重新解析并判定（去重优先）：已纳入的跳过，新事件补入日志。
	var added []*event.Event
	addedSet := map[string]bool{}
	now := e.nowLocked()
	for _, qi := range candIdx {
		rec := &e.quarantine[qi]
		ev, perr := e.reparseLateLocked(rec)
		if perr != nil {
			continue // 防御：隔离记录解析失败则跳过（不应发生）
		}
		// 精确过滤：只纳入事件时间落在回补闭区间内的迟到记录。
		if ev.EventTime.Before(req.From) || ev.EventTime.After(req.To) {
			continue
		}
		if _, ok := e.known[ev.ID]; ok {
			res.SkippedDup = append(res.SkippedDup, ev.ID)
			rec.BackfilledBy = req.RequestID // 标记已核对，避免下次重复扫描
			rec.BackfilledAt = now
			continue
		}
		added = append(added, ev)
		addedSet[ev.ID] = true
		res.Backfilled = append(res.Backfilled, ev.ID)
		rec.BackfilledBy = req.RequestID
		rec.BackfilledAt = now
	}
	res.BackfilledCount = len(res.Backfilled)

	// 3) shadow 重算：基线（不含本次补入）与补数（含全部）两套结论对比。
	journal := e.journal[req.TenantID]
	baselineSet := make([]*event.Event, 0, len(journal))
	augmentedSet := make([]*event.Event, 0, len(journal)+len(added))
	for _, ev := range journal {
		augmentedSet = append(augmentedSet, ev)
		if !addedSet[ev.ID] {
			baselineSet = append(baselineSet, ev)
		}
	}
	augmentedSet = append(augmentedSet, added...)
	sortEvents(augmentedSet)

	eventByID := map[string]*event.Event{}
	for _, ev := range augmentedSet {
		eventByID[ev.ID] = ev
	}
	baselineDec := e.shadowRun(baselineSet, req.To)
	augmentedDec := e.shadowRun(augmentedSet, req.To)

	plan := backfill.PlanChanges(baselineDec, augmentedDec, eventByID, addedSet, req.From, req.To)
	res.Advisories = plan.Advisories

	// 4) 物化更正（原结论保留可查，可见结论唯一）。
	for _, ch := range plan.Changes {
		corr := e.materializeChangeLocked(req, ch)
		res.Corrections = append(res.Corrections, corr)
	}

	// 5) 补入事件正式并入租户日志（重算之后，避免影响本次基线）。
	for _, ev := range added {
		e.appendJournalLocked(ev)
	}

	if len(res.Corrections) > 0 {
		res.Status = backfill.StatusAcceptedChanged
	} else {
		res.Status = backfill.StatusAcceptedUnchanged
	}
	return res, nil
}

// lateCandidatesLocked 返回该租户、时间段内、未回补过的迟到隔离记录下标。
func (e *Engine) lateCandidatesLocked(req backfill.Request) []int {
	var idx []int
	for i, rec := range e.quarantine {
		if rec.Disposition != event.DispLate {
			continue
		}
		if rec.TenantID != req.TenantID {
			continue
		}
		if rec.BackfilledBy != "" {
			continue // 已被某次回补处理过
		}
		// 迟到记录的事件时间需落在回补区间内；从 Detail 中不易解析，
		// 这里以重新解析出的事件时间为准（见 reparseLateLocked 后再过滤）。
		// 先做粗筛：无事件时间信息时也纳入，由解析后精确过滤。
		idx = append(idx, i)
	}
	return idx
}

// reparseLateLocked 重新解析迟到隔离记录为归一化事件（调用方持锁）。
// 解析时关闭时间戳合法性检查（迟到记录本就"老"），只还原事件本身。
func (e *Engine) reparseLateLocked(rec *event.QuarantineRecord) (*event.Event, error) {
	cfg := e.parseCfg
	cfg.MaxAge = 0
	cfg.MaxFutureSkew = 0
	ev, err := event.Parse(rec.Source, rec.Raw, cfg)
	if err != nil {
		return nil, err
	}
	ev.TenantID = rec.TenantID
	ev.ReceivedAt = rec.ReceivedAt
	return ev, nil
}

// shadowRun 在隔离的临时关联器上重放事件集合，以 req.To 为定论水位产出结论。
// 不触碰在线关联器/水位/告警存储，因此对在线检测零影响、结果可复现。
// 规则版本按事件时间由 RuleSet 选出（与在线一致）。
func (e *Engine) shadowRun(events []*event.Event, upTo time.Time) []detect.Decision {
	c := detect.NewCorrelator(e.rules)
	for _, ev := range events {
		c.Observe(ev)
	}
	return c.AdvanceWatermark(upTo)
}

// materializeChangeLocked 把一个结论组差异物化为更正：原结论标记被替代、
// 创建延续更正链的新告警、登记锚点，并生成可追溯的 Correction。调用方持锁。
func (e *Engine) materializeChangeLocked(req backfill.Request, ch backfill.GroupChange) backfill.Correction {
	corr := backfill.Correction{
		RequestID: req.RequestID, TenantID: ch.TenantID, RuleID: ch.RuleID,
		RuleVersion: ch.RuleVersion, Entity: ch.Entity, Kind: ch.Kind,
		AlertKey: ch.AlertKey, WindowFrom: ch.WindowFrom, WindowTo: ch.WindowTo,
		AddedEventIDs: append([]string{}, ch.AddedEventIDs...),
		AllEventIDs:   append([]string{}, ch.AllEventIDs...),
		Note:          ch.Note,
	}

	// 解析基线结论组对应的真实告警 ID（锚点是首发窗口的第一个事件 ID，
	// 跨 shadow 重算稳定；可能已被更早的回补更正，锚点会重映射到当前生效告警）。
	var oldAlertIDs []string
	for _, anchor := range ch.BaselineAnchors {
		if info, ok := e.anchors[anchor]; ok {
			oldAlertIDs = append(oldAlertIDs, info.alertID)
		}
	}
	corr.OldAlertIDs = oldAlertIDs

	switch ch.Kind {
	case backfill.ChangeRevoked:
		// 防御性：原结论不再成立，仅标记被替代，不产生替代告警。
		for _, id := range oldAlertIDs {
			_ = e.alerts.Revoke(id, req.RequestID, req.Operator, ch.Note)
		}
		return corr

	case backfill.ChangeAdded, backfill.ChangeRevised:
		newID := fmt.Sprintf("corr:%s:%s", req.RequestID, ch.AlertKey)
		corr.NewAlertID = newID
		newAlert := alert.Alert{
			ID: newID, TenantID: ch.TenantID, RuleID: ch.RuleID,
			RuleVersion: ch.RuleVersion, Entity: ch.Entity,
			CreatedAt: ch.WindowFrom, EventIDs: append([]string{}, ch.AllEventIDs...),
			SuppressedCount: ch.SuppressedCount,
		}
		reason := fmt.Sprintf("backfill %s window %s..%s: %s",
			req.RequestID, ch.WindowFrom.Format(time.RFC3339Nano),
			ch.WindowTo.Format(time.RFC3339Nano), ch.Note)
		stored, err := e.alerts.Supersede(alert.SupersedeRequest{
			RequestID: req.RequestID, OldAlertIDs: oldAlertIDs,
			NewAlert: newAlert, Operator: req.Operator, Reason: reason,
		})
		if err != nil {
			corr.Note += " (materialize error: " + err.Error() + ")"
			return corr
		}
		// 登记/重映射锚点：补数组锚点（首发窗口第一个事件 ID）指向新告警；
		// 被替代结论的锚点也重映射到新告警，使后续回补沿更正链找到当前生效结论。
		if ch.AugAnchor != "" {
			e.anchors[ch.AugAnchor] = anchorInfo{alertID: stored.ID, alertKey: ch.AlertKey, tenantID: ch.TenantID}
		}
		for _, a := range ch.BaselineAnchors {
			e.anchors[a] = anchorInfo{alertID: stored.ID, alertKey: ch.AlertKey, tenantID: ch.TenantID}
		}
		return corr
	}
	return corr
}

// sortEvents 按 (事件时间,实体,ID) 排序（与入口释放序一致）。
func sortEvents(es []*event.Event) {
	sort.Slice(es, func(i, j int) bool {
		if !es[i].EventTime.Equal(es[j].EventTime) {
			return es[i].EventTime.Before(es[j].EventTime)
		}
		if es[i].Entity != es[j].Entity {
			return es[i].Entity < es[j].Entity
		}
		return es[i].ID < es[j].ID
	})
}

// BackfillHistory 返回已登记的全部回补结果（追溯用）。
func (e *Engine) BackfillHistory() []backfill.Result {
	return e.backfills.ResultHistory()
}
