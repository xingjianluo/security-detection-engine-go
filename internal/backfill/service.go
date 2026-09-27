package backfill

import (
	"sync"
	"time"

	"github.com/xingjianluo/security-detection-engine-go/internal/alert"
)

// Service 管理回补请求的幂等注册表。真正的重算副作用由引擎在其全局锁内
// 完成，从而回补与在线写入串行化，租户间计数/抑制/告警互不串扰。
type Service struct {
	mu      sync.Mutex
	results map[string]Result // RequestID -> 已完成结果（幂等缓存）
}

// NewService 创建回补编排器。
func NewService() *Service {
	return &Service{results: map[string]Result{}}
}

// validate 做与引擎状态无关的参数与权限校验；返回带可区分原因的错误。
func validate(req Request, maxAge time.Duration, now time.Time) error {
	if req.RequestID == "" {
		return ErrInvalidRange
	}
	if req.TenantID == "" {
		return ErrInvalidRange
	}
	if req.From.IsZero() || req.To.IsZero() || req.From.After(req.To) {
		return ErrInvalidRange
	}
	if req.Operator.TenantID != req.TenantID {
		return ErrCrossTenant
	}
	if req.Operator.Role != alert.RoleOperator && req.Operator.Role != alert.RoleAdmin {
		return ErrPermissionDenied
	}
	if maxAge > 0 && req.From.Before(now.Add(-maxAge)) {
		return ErrBeyondHorizon
	}
	return nil
}

// Reject 由引擎在状态相关校验（越过水位等）失败时调用，登记一条拒绝结果，
// 使拒绝也可按 RequestID 追溯、并保持幂等。
func (s *Service) Reject(req Request, cause error) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cached, ok := s.results[req.RequestID]; ok {
		cached.Replayed = true
		return cached
	}
	r := Result{
		RequestID: req.RequestID, Status: StatusRejected, TenantID: req.TenantID,
		From: req.From, To: req.To, Err: cause,
	}
	s.results[req.RequestID] = r
	return r
}

// Store 登记一次已执行结果（成功/无变化/拒绝均可），用于幂等；
// 同一 RequestID 已存在时保留先登记者。引擎在其锁内完成重算后调用。
func (s *Service) Store(r Result) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cached, ok := s.results[r.RequestID]; ok {
		return cached
	}
	s.results[r.RequestID] = r
	return r
}

// Lookup 返回已登记的请求结果（引擎状态校验前先查幂等缓存）。
func (s *Service) Lookup(requestID string) (Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[requestID]
	return r, ok
}

// Validate 做参数与权限校验（与引擎水位状态无关的部分）；
// maxAge<=0 表示不限制可回补年龄。引擎在持锁后调用。
func Validate(req Request, maxAge time.Duration, now time.Time) error {
	return validate(req, maxAge, now)
}

// ResultHistory 返回已登记的全部回补结果（追溯/测试用），按登记顺序。
func (s *Service) ResultHistory() []Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Result, 0, len(s.results))
	for _, r := range s.results {
		out = append(out, r)
	}
	return out
}
