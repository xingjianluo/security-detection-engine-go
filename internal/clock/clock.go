// Package clock 抽象时间来源，使引擎的"处理时间"在测试中可注入、可复现。
//
// 事件时间(event time)始终来自事件负载；本接口只提供处理时间(processing time)，
// 用于审计记录的排序时间戳以及未来事件的异常判定基准。
package clock

import "time"

// Clock 提供当前处理时间。
type Clock interface {
	Now() time.Time
}

// SystemClock 使用机器墙钟时间。
type SystemClock struct{}

// NewSystemClock 创建系统时钟。
func NewSystemClock() *SystemClock { return &SystemClock{} }

// Now 返回当前墙钟时间。
func (c *SystemClock) Now() time.Time { return time.Now() }

// FakeClock 是测试用可控时钟。
type FakeClock struct {
	t time.Time
}

// NewFakeClock 以给定基准时间创建假时钟。
func NewFakeClock(base time.Time) *FakeClock { return &FakeClock{t: base} }

// Now 返回当前假时间。
func (c *FakeClock) Now() time.Time { return c.t }

// Advance 把假时间向前推进 d。
func (c *FakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// Set 直接设置假时间。
func (c *FakeClock) Set(t time.Time) { c.t = t }
