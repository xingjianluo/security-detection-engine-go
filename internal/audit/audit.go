// Package audit 提供只追加(append-only)的审计记录与并发安全的审计日志。
package audit

import (
	"sync"
	"time"
)

// Action 是审计动作类型。
type Action string

const (
	ActionAlertCreate      Action = "alert.create"
	ActionAlertMerge       Action = "alert.merge"
	ActionAlertAck         Action = "alert.acknowledge"
	ActionAlertClose       Action = "alert.close"
	ActionAlertReopen      Action = "alert.reopen"
	ActionRuleUpdate       Action = "rule.update"
	ActionAccessDenied     Action = "access.denied"
	ActionEventRejected    Action = "event.rejected"
	ActionEventQuarantined Action = "event.quarantined"
	ActionEventDuplicate   Action = "event.duplicate"
)

// Record 是一条不可变审计记录。
type Record struct {
	Seq      int64     // 日志内单调序号
	Time     time.Time // 处理时间（来自可注入时钟）
	Action   Action
	Tenant   string
	Operator string // 用户操作时的操作者；系统动作为 "system"
	AlertID  string
	RuleID   string
	From     string
	To       string
	Version  int64
	Detail   string
	Extra    map[string]string
}

// Log 是只追加审计日志（并发安全）。
type Log struct {
	mu      sync.Mutex
	records []*Record
	seq     int64
}

// NewLog 创建空审计日志。
func NewLog() *Log { return &Log{} }

// Append 追加一条审计记录并分配单调序号，返回入库副本。
func (l *Log) Append(r Record) *Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	r.Seq = l.seq
	if r.Extra == nil {
		r.Extra = map[string]string{}
	}
	cp := cloneRecord(&r)
	l.records = append(l.records, cp)
	return cp
}

// List 按追加顺序返回全部记录（可选按租户过滤：空租户表示全部，仅供导出/测试）。
func (l *Log) List(tenant string) []*Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*Record, 0, len(l.records))
	for _, r := range l.records {
		if tenant != "" && r.Tenant != tenant {
			continue
		}
		out = append(out, cloneRecord(r))
	}
	return out
}

// Len 返回记录总数。
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.records)
}

func cloneRecord(r *Record) *Record {
	cp := *r
	if r.Extra != nil {
		cp.Extra = make(map[string]string, len(r.Extra))
		for k, v := range r.Extra {
			cp.Extra[k] = v
		}
	}
	return &cp
}
