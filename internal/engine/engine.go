// Package engine 编排解析归一化、事件时间水位线检测、告警生命周期与审计，
// 构成一个本地、并发安全、结论可复现的安全事件检测引擎。
package engine

import (
	"fmt"
	"sync"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/audit"
	"github.com/xingjianluo/security-detection-engine-go/internal/clock"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
	"github.com/xingjianluo/security-detection-engine-go/internal/rule"
)

// Config 是引擎配置。
type Config struct {
	AllowedLateness time.Duration // 乱序宽限 L
	Retention       time.Duration // 迟到保留期 R
	FutureTolerance time.Duration // 事件时间领先处理时间多少以内视为正常（超出隔离）
}

// DefaultConfig 返回一组合理默认值（均为事件时间语义参数）。
func DefaultConfig() Config {
	return Config{
		AllowedLateness: 5 * time.Second,
		Retention:       30 * time.Second,
		FutureTolerance: 2 * time.Second,
	}
}

// IngestResult 是一条原始记录的入口处理结果与判定依据。
type IngestResult struct {
	Source       event.Source
	Raw          string
	Parse        event.ParseResult
	Status       event.Status // rejected / quarantined / accepted
	RejectReason event.RejectReason
	Quarantine   event.QuarantineReason
	Timing       event.Timing
	Duplicate    bool
	// CreatedAlerts/MergedAlerts 在同一次提交因窗口关闭而产生/合并告警时给出。
	CreatedAlerts []string
	MergedAlerts  []string
	Detail        string
}

// IngestBatchResult 是一批记录的处理结果（保持输入顺序）。
type IngestBatchResult struct {
	Results []IngestResult
}

// Engine 是检测引擎（并发安全）。锁序固定为 mu -> alert.Store 内部锁，避免死锁。
type Engine struct {
	mu       sync.Mutex
	cfg      Config
	clock    clock.Clock
	registry *event.Registry
	catalog  *rule.Catalog
	detector *detect.Detector
	alerts   *alert.Store
	audit    *audit.Log
}

// New 创建引擎并注册全部内置来源解析器。
func New(cfg Config, c clock.Clock) *Engine {
	reg := event.NewRegistry()
	reg.Register(event.NewSyslogParser())
	reg.Register(event.NewJSONParser())
	reg.Register(event.NewCEFParser())
	cat := rule.NewCatalog()
	e := &Engine{
		cfg:      cfg,
		clock:    c,
		registry: reg,
		catalog:  cat,
		detector: detect.New(cat, detect.Config{
			AllowedLateness: cfg.AllowedLateness,
			Retention:       cfg.Retention,
		}, c),
		alerts: alert.NewStore(),
		audit:  audit.NewLog(),
	}
	return e
}

// Ingest 处理单条原始记录：解析 -> 字段/时间戳拒绝分类 -> 未来/超期隔离 ->
// 去重与时间语义分类 -> 计入窗口 -> 推进水位线并落地触发。
func (e *Engine) Ingest(source event.Source, raw string) IngestResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	res := IngestResult{Source: source, Raw: raw}
	pr := e.registry.Parse(source, raw)
	res.Parse = pr
	if !pr.IsAccepted() {
		res.Status = event.StatusRejected
		res.RejectReason = pr.Reason
		res.Detail = pr.Detail
		// 拒绝记录留痕（此时租户可能尚未解析出来，用来源与原因区分）。
		e.audit.Append(audit.Record{
			Time: e.clock.Now(), Action: audit.ActionEventRejected,
			Operator: "system", To: string(pr.Reason),
			Detail: fmt.Sprintf("source=%s: %s", source, pr.Detail),
			Extra:  map[string]string{"raw": truncateRaw(raw)},
		})
		return res
	}
	ev := pr.Event
	now := e.clock.Now()

	// 未来事件：以处理时间为基准，超出容忍带即隔离（时间戳异常不静默丢弃）。
	if ev.EventTime.After(now.Add(e.cfg.FutureTolerance)) {
		res.Status = event.StatusQuarantined
		res.Quarantine = event.QuarantineFuture
		res.Detail = fmt.Sprintf("event time %s is more than %s ahead of processing time %s",
			ev.EventTime.Format(time.RFC3339Nano), e.cfg.FutureTolerance, now.Format(time.RFC3339Nano))
		e.audit.Append(audit.Record{
			Time: now, Action: audit.ActionEventQuarantined, Tenant: ev.Tenant,
			Operator: "system", RuleID: "", To: string(event.QuarantineFuture),
			Detail: res.Detail, Extra: map[string]string{"event_id": ev.ID},
		})
		return res
	}

	// 进入检测器：去重 / 超期隔离 / 时间语义分类 / 计入窗口。
	rep := e.detector.Observe(ev)
	switch {
	case rep.Duplicate:
		res.Status = event.StatusAccepted
		res.Duplicate = true
		res.Detail = "duplicate delivery: event id already ingested"
		e.audit.Append(audit.Record{
			Time: now, Action: audit.ActionEventDuplicate, Tenant: ev.Tenant,
			Operator: "system", Detail: res.Detail,
			Extra: map[string]string{"event_id": ev.ID},
		})
		return res
	case rep.Expired:
		res.Status = event.StatusQuarantined
		res.Quarantine = event.QuarantineExpired
		res.Detail = fmt.Sprintf("event time %s is earlier than watermark minus retention %s",
			ev.EventTime.Format(time.RFC3339Nano), e.cfg.Retention)
		e.audit.Append(audit.Record{
			Time: now, Action: audit.ActionEventQuarantined, Tenant: ev.Tenant,
			Operator: "system", To: string(event.QuarantineExpired),
			Detail: res.Detail, Extra: map[string]string{"event_id": ev.ID},
		})
		return res
	}
	res.Status = event.StatusAccepted
	res.Timing = rep.Timing
	if rep.Late {
		res.Detail = fmt.Sprintf("late event within allowed lateness %s", e.cfg.AllowedLateness)
	}
	// 注意：Ingest 只把事件计入窗口状态，不立即推进水位线/落地告警。
	// 告警在显式提交边界 Advance（稳定水位线）或 Drain（排空）时统一落地，
	// 这样并发写入的最终状态与 goroutine 交织顺序无关，结论可复现。
	return res
}

// Advance 对全部租户做一次常规水位线推进（到 maxObserved-L），
// 仅让已经"稳定"（其后不可能再出现更早事件）的窗口触发并落地告警。
// 用于需要流式出警、但仍不排空乱序宽限区的场景。
func (e *Engine) Advance() IngestBatchResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock.Now()
	out := IngestBatchResult{}
	for _, pr := range e.detector.PumpAll() {
		res := IngestResult{}
		e.applyPump(pr, now, &res)
		out.Results = append(out.Results, res)
	}
	return out
}

// applyPump 把一次水位线推进产生的触发在同一把存储锁内批量应用。
// 抑制锚点完全由触发的事件时间序列决定（ApplyFindings 内部按事件时间全序定锚点），
// 与触发分多少次 Pump 落地无关，因此结论可复现。
func (e *Engine) applyPump(pr detect.PumpReport, now time.Time, res *IngestResult) {
	findings := pr.Findings
	if len(findings) == 0 {
		return
	}
	suppressOf := func(ruleID string, v int64) time.Duration {
		if rv, ok := e.catalog.Get(pr.Tenant, ruleID, rule.Version(v)); ok {
			return rv.Suppression
		}
		return 0
	}
	results := e.alerts.ApplyFindings(findings, suppressOf, now)
	for i, f := range findings {
		br := results[i]
		a, _ := e.alerts.Get(f.Tenant, br.AlertID)
		if a == nil {
			continue
		}
		switch br.Outcome {
		case alert.OutcomeCreated:
			res.CreatedAlerts = append(res.CreatedAlerts, a.ID)
			e.audit.Append(audit.Record{
				Time: now, Action: audit.ActionAlertCreate, Tenant: a.Tenant, Operator: "system",
				AlertID: a.ID, RuleID: a.RuleID, To: string(a.Status), Version: a.Version,
				Detail: fmt.Sprintf("threshold %d crossed at %s; merged events: %v",
					f.Threshold, f.EventTime.Format(time.RFC3339Nano), f.MatchedEventIDs),
				Extra: map[string]string{
					"entity": a.Entity, "trigger_event": f.TriggerEventID,
					"rule_version": fmt.Sprintf("%d", a.RuleVersion),
				},
			})
		case alert.OutcomeMerged:
			res.MergedAlerts = append(res.MergedAlerts, a.ID)
			e.audit.Append(audit.Record{
				Time: now, Action: audit.ActionAlertMerge, Tenant: a.Tenant, Operator: "system",
				AlertID: a.ID, RuleID: a.RuleID, To: string(a.Status), Version: a.Version,
				Detail: fmt.Sprintf("suppressed hit at %s merged into alert anchored at %s (%s)",
					f.EventTime.Format(time.RFC3339Nano),
					a.FirstEventAt.Format(time.RFC3339Nano), a.FirstEventID),
				Extra: map[string]string{"trigger_event": f.TriggerEventID},
			})
		case alert.OutcomeIgnoredDup:
			// 确定性重放：同锚点/同事件再次落地，不写审计、不改变状态。
			res.MergedAlerts = append(res.MergedAlerts, a.ID)
		}
	}
}

// IngestBatch 并发提交多条记录，返回与输入同序的结果；最终状态与并发交织无关。
// 并发通过引擎单锁串行化，事件时间语义保证串行化顺序不改变检测结论。
func (e *Engine) IngestBatch(source event.Source, raws []string) IngestBatchResult {
	results := make([]IngestResult, len(raws))
	var wg sync.WaitGroup
	for i, raw := range raws {
		wg.Add(1)
		go func(i int, raw string) {
			defer wg.Done()
			results[i] = e.Ingest(source, raw)
		}(i, raw)
	}
	wg.Wait()
	return IngestBatchResult{Results: results}
}

// Drain 关闭全部租户当前可关闭的窗口（水位线推进到已观测最大事件时间）。
func (e *Engine) Drain() IngestBatchResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock.Now()
	out := IngestBatchResult{}
	for _, pr := range e.detector.FlushAll() {
		res := IngestResult{}
		e.applyPump(pr, now, &res)
		out.Results = append(out.Results, res)
	}
	return out
}

// UpsertRule 更新或新增规则：生成一个不可变新版本。
// effectiveFrom 为零值时，首个版本对全部事件时间生效，后续版本取当前处理时间。
func (e *Engine) UpsertRule(tenant, operator string, r rule.Rule, effectiveFrom time.Time) (*rule.Rule, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if tenant == "" {
		return nil, alert.ErrEmptyTenant
	}
	r.Tenant = tenant
	if effectiveFrom.IsZero() && len(e.catalog.Versions(tenant, r.ID)) > 0 {
		effectiveFrom = e.clock.Now()
	}
	if !effectiveFrom.IsZero() {
		r.EffectiveFrom = effectiveFrom
	}
	now := e.clock.Now()
	r.CreatedAt = now
	stored, err := e.catalog.AddVersion(r)
	if err != nil {
		return nil, err
	}
	e.audit.Append(audit.Record{
		Time: now, Action: audit.ActionRuleUpdate, Tenant: tenant,
		Operator: orSystem(operator), RuleID: r.ID, To: fmt.Sprintf("v%d", stored.Version),
		Version: int64(stored.Version),
		Detail: fmt.Sprintf("effective_from=%s threshold=%d window=%s suppression=%s note=%q",
			effStr(stored.EffectiveFrom), stored.Threshold, stored.Window, stored.Suppression, stored.Note),
	})
	return stored, nil
}

func effStr(t time.Time) string {
	if t.IsZero() {
		return "epoch"
	}
	return t.Format(time.RFC3339Nano)
}

func orSystem(op string) string {
	if op == "" {
		return "system"
	}
	return op
}

// truncateRaw 限制审计中原始负载长度，避免超长记录污染审计日志。
func truncateRaw(raw string) string {
	const max = 200
	if len(raw) > max {
		return raw[:max] + "...(truncated)"
	}
	return raw
}

// GetAlert 读取告警；跨租户读取（以及对不存在 ID 的探测）写越权审计。
func (e *Engine) GetAlert(tenant, id string) (*alert.Alert, error) {
	a, err := e.alerts.Get(tenant, id)
	if err != nil {
		e.denyAudit(tenant, id, "", err)
		return nil, err
	}
	return a, nil
}

// ListAlerts 列出租户告警。
func (e *Engine) ListAlerts(tenant string) []*alert.Alert {
	return e.alerts.List(tenant)
}

func (e *Engine) lifecycle(tenant, id, operator string, expectVersion int64,
	do func() (alert.Transition, error)) (alert.Transition, error) {
	t, err := do()
	now := e.clock.Now()
	if err != nil {
		e.denyAudit(tenant, id, operator, err)
		return t, err
	}
	act := map[alert.Action]audit.Action{
		alert.ActionAcknowledge: audit.ActionAlertAck,
		alert.ActionClose:       audit.ActionAlertClose,
		alert.ActionReopen:      audit.ActionAlertReopen,
	}[t.Action]
	if t.Changed {
		e.audit.Append(audit.Record{
			Time: now, Action: act, Tenant: tenant, Operator: orSystem(operator),
			AlertID: id, From: string(t.From), To: string(t.To), Version: t.Version,
			Detail: "state changed",
		})
	} else {
		// 幂等命中也留痕，但标记为 no-op，便于追溯"提交过但未产生新变更"。
		e.audit.Append(audit.Record{
			Time: now, Action: act, Tenant: tenant, Operator: orSystem(operator),
			AlertID: id, From: string(t.From), To: string(t.To), Version: t.Version,
			Detail: "idempotent no-op: " + t.Reason,
		})
	}
	return t, nil
}

// denyAudit 对所有被拒绝的访问/操作留下可追溯审计。
func (e *Engine) denyAudit(tenant, id, operator string, err error) {
	e.audit.Append(audit.Record{
		Time: e.clock.Now(), Action: audit.ActionAccessDenied,
		Tenant: tenant, Operator: orSystem(operator), AlertID: id,
		Detail: err.Error(),
	})
}

// Acknowledge 幂等确认。
func (e *Engine) Acknowledge(tenant, id, operator string, expectVersion int64) (alert.Transition, error) {
	return e.lifecycle(tenant, id, operator, expectVersion, func() (alert.Transition, error) {
		return e.alerts.Acknowledge(tenant, id, operator, expectVersion, e.clock.Now())
	})
}

// Close 幂等关闭。
func (e *Engine) Close(tenant, id, operator string, expectVersion int64) (alert.Transition, error) {
	return e.lifecycle(tenant, id, operator, expectVersion, func() (alert.Transition, error) {
		return e.alerts.Close(tenant, id, operator, expectVersion, e.clock.Now())
	})
}

// Reopen 幂等重开。
func (e *Engine) Reopen(tenant, id, operator string, expectVersion int64) (alert.Transition, error) {
	return e.lifecycle(tenant, id, operator, expectVersion, func() (alert.Transition, error) {
		return e.alerts.Reopen(tenant, id, operator, expectVersion, e.clock.Now())
	})
}

// AuditTrail 返回审计记录（租户过滤；空租户仅供测试导出）。
func (e *Engine) AuditTrail(tenant string) []*audit.Record { return e.audit.List(tenant) }

// Clock 暴露时钟（测试推进时间用）。
func (e *Engine) Clock() clock.Clock { return e.clock }
