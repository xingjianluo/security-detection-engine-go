// Package engine 把解析、入口判定（去重/迟到/水位）、关联检测
// 与告警生命周期编排为一个并发安全的本地引擎。
package engine

import (
	"errors"
	"sync"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
	"github.com/xingjianluo/security-detection-engine-go/internal/detect"
	"github.com/xingjianluo/security-detection-engine-go/internal/event"
)

func asParseError(err error, pe **event.ParseError) bool {
	var target *event.ParseError
	if errors.As(err, &target) {
		*pe = target
		return true
	}
	return false
}

// Result 是一条原始记录的处理结果：去向 + 原因明细。
type Result struct {
	Disposition event.Disposition
	Reason      event.RejectReason
	Detail      string
}

// Engine 并发安全：单一互斥锁把解析、判定、检测提交串行化，
// 因此检测结论只依赖事件时间语义，与 goroutine 调用顺序无关。
type Engine struct {
	mu         sync.Mutex
	ingest     *event.Ingestor
	corr       *detect.Correlator
	rules      *detect.RuleSet
	alerts     *alert.Store
	parseCfg   event.ParseConfig
	quarantine []event.QuarantineRecord
}

// Config 引擎配置。
type Config struct {
	AllowedLateness time.Duration
	Parse           event.ParseConfig
}

// New 创建引擎，并返回其规则集（用于登记规则）与告警存储（用于生命周期操作）。
func New(cfg Config) (*Engine, *detect.RuleSet, *alert.Store) {
	rs := detect.NewRuleSet()
	store := alert.NewStore(cfg.Parse.Now)
	e := &Engine{
		ingest:   event.NewIngestor(event.IngestConfig{AllowedLateness: cfg.AllowedLateness}),
		corr:     detect.NewCorrelator(rs),
		rules:    rs,
		alerts:   store,
		parseCfg: cfg.Parse,
	}
	return e, rs, store
}

// Ingest 处理一条原始记录：解析失败按原因拒绝并隔离；正常事件进入入口判定，
// 去重/迟到在该处分类。已安全释放的事件立即按全局事件时间顺序提交关联器。
// 多个 goroutine 并发调用安全，且结果与调用交错顺序无关。
func (e *Engine) Ingest(tenantID string, src event.Source, raw string) Result {
	e.mu.Lock()
	defer e.mu.Unlock()

	parsed, err := event.Parse(src, raw, e.parseCfg)
	if err != nil {
		// 不静默丢弃：解析失败同样进入隔离（通过 Ingestor 之外的直接记录不便于统一查看，
		// 因此引擎自行维护 rejected 列表，见 rejectedLocked 之前先解析失败处理）。
		return e.rejectLocked(src, raw, err)
	}
	parsed.TenantID = tenantID
	if parsed.ReceivedAt.IsZero() {
		if e.parseCfg.Now != nil {
			parsed.ReceivedAt = e.parseCfg.Now()
		} else {
			parsed.ReceivedAt = time.Now()
		}
	}

	o := e.ingest.Admit(parsed)
	r := Result{Disposition: o.Disposition, Detail: ""}
	if o.Quarantine != nil {
		r.Reason = o.Quarantine.Reason
		r.Detail = o.Quarantine.Detail
		if o.Disposition == event.DispLate {
			e.quarantine = append(e.quarantine, *o.Quarantine)
		}
	}
	return r
}

// Advance 显式断言事件时间水位到 W：安全释放事件、提交检测并把最终结论
// 物化为告警，返回新发告警 ID。流结束时可用它让未完成窗口获得定论。
func (e *Engine) Advance(W time.Time) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	released := e.ingest.AdvanceWatermark(W)
	return e.releaseLocked(released)
}

// Tick 是在线模式便利方法：以 已观测最大事件时间 - AllowedLateness 断言水位。
// 交错接收与 Tick 时，晚于断言水位到达的事件判迟到——这是流式处理的真实语义；
// 需要与到达顺序无关的可复现结论时，先喂入完整事件集合再调用 Advance。
func (e *Engine) Tick() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.releaseLocked(e.ingest.Tick())
}

// releaseLocked 提交已释放事件并物化判定。调用方持锁。
func (e *Engine) releaseLocked(released []*event.Event) []string {
	if len(released) == 0 {
		return nil
	}
	for _, ev := range released {
		e.corr.Observe(ev)
	}
	W := e.ingest.Watermark().T()
	if W.IsZero() {
		return nil
	}
	return e.materialize(e.corr.AdvanceWatermark(W))
}

// materialize 把检测结论物化为告警：新发结论 Create；抑制命中合并到主告警。
func (e *Engine) materialize(ds []detect.Decision) []string {
	var created []string
	for _, d := range ds {
		if d.IsAlert {
			a := alert.Alert{
				ID: d.FireID, TenantID: d.TenantID, RuleID: d.RuleID,
				RuleVersion: d.RuleVersion, Entity: d.Entity,
				CreatedAt: d.FirstEventAt, EventIDs: append([]string{}, d.EventIDs...),
			}
			if got, err := e.alerts.Create(a); err == nil && got.ID == d.FireID && len(got.EventIDs) == len(d.EventIDs) {
				created = append(created, d.FireID)
			}
		} else {
			_ = e.alerts.MergeSuppressed(d.SuppressedBy, d.TenantID, d.EventIDs, d.FireID)
		}
	}
	return created
}

// rejectLocked 将解析失败转成可区分的拒绝结果并登记隔离。调用方持锁。
func (e *Engine) rejectLocked(src event.Source, raw string, err error) Result {
	var pe *event.ParseError
	reason := event.ReasonParseError
	if !asParseError(err, &pe) {
		pe = &event.ParseError{Reason: event.ReasonParseError}
	}
	rec := event.QuarantineRecord{
		Raw: raw, Source: src, Disposition: event.DispRejected,
		Reason: pe.Reason, Detail: err.Error(),
	}
	if e.parseCfg.Now != nil {
		rec.ReceivedAt = e.parseCfg.Now()
	} else {
		rec.ReceivedAt = time.Now()
	}
	e.quarantine = append(e.quarantine, rec)
	return Result{Disposition: event.DispRejected, Reason: reason, Detail: err.Error()}
}

// Quarantine 返回全部被拒绝与被隔离（迟到）记录的快照（不静默丢弃的凭据）。
func (e *Engine) Quarantine() []event.QuarantineRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]event.QuarantineRecord, len(e.quarantine))
	copy(out, e.quarantine)
	return out
}

// Rules 暴露规则集。
func (e *Engine) Rules() *detect.RuleSet { return e.rules }

// Alerts 暴露告警存储。
func (e *Engine) Alerts() *alert.Store { return e.alerts }
