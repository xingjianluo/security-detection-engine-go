// Package detect 实现有状态的滑动窗口关联检测、规则版本化与告警抑制。
package detect

import "time"

// Rule 是一条关联检测规则，版本化以保证运行中更新不会静默改写历史结论。
type Rule struct {
	ID          string
	Version     int
	TenantID    string
	EventType   string
	Window      time.Duration // 滑动窗口长度
	Threshold   int           // 窗口内累计命中阈值
	SuppressFor time.Duration // 告警抑制间隔：同一 (规则,实体) 在该间隔内只产生一条告警
	// EffectiveAt 为该版本规则生效的事件时间；事件只受 EffectiveAt <= 事件时间
	// 的最新版本约束，使检测结论只取决于事件时间而非更新发生的墙钟时刻。
	EffectiveAt time.Time
}

// Decision 是窗口被最终判定（水位越过窗口右端 + 容忍延迟）后产出的结论。
type Decision struct {
	FireID       string // 每次阈值穿越的唯一标识；抑制命中与主告警共享同一 FireID
	RuleID       string
	RuleVersion  int
	TenantID     string
	Entity       string
	AlertKey     string    // 抑制键：RuleID + 实体
	FirstEventAt time.Time // 触发告警所合并的最早事件时间（告警时间语义）
	EventIDs     []string  // 该告警合并的全部事件 ID（可追溯）
	SuppressedBy string    // 非空时表示本次命中被该告警 ID 抑制（合并进既有告警）
	IsAlert      bool      // 是否为新发告警（相对抑制命中）
	Reason       string    // 判定依据的人类可读说明
}
