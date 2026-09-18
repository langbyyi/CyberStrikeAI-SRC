package approval

import (
	"context"
	"sync"
)

type grantContextKey struct{}
type executionFinalizerContextKey struct{}
type executionOwnershipContextKey struct{}

type executionOwnership struct {
	mu          sync.RWMutex
	transferred bool
}

type ExecutionFinalizer func(context.Context, ExecutionResult) error

func WithGrant(ctx context.Context, grant Grant) context.Context {
	return context.WithValue(ctx, grantContextKey{}, grant)
}

func GrantFromContext(ctx context.Context) (Grant, bool) {
	grant, ok := ctx.Value(grantContextKey{}).(Grant)
	return grant, ok
}

func WithExecutionFinalizer(ctx context.Context, finalizer ExecutionFinalizer) context.Context {
	if finalizer == nil {
		return ctx
	}
	return context.WithValue(ctx, executionFinalizerContextKey{}, finalizer)
}

func ExecutionFinalizerFromContext(ctx context.Context) (ExecutionFinalizer, bool) {
	if ctx == nil {
		return nil, false
	}
	finalizer, ok := ctx.Value(executionFinalizerContextKey{}).(ExecutionFinalizer)
	return finalizer, ok && finalizer != nil
}

// WithExecutionOwnership installs shared ownership state before a tool starts.
// A nested asynchronous adapter can transfer completion responsibility while
// the outer completion callback observes the same state pointer.
func WithExecutionOwnership(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Value(executionOwnershipContextKey{}).(*executionOwnership); ok {
		return ctx
	}
	return context.WithValue(ctx, executionOwnershipContextKey{}, &executionOwnership{})
}

func TransferExecutionOwnership(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	state, ok := ctx.Value(executionOwnershipContextKey{}).(*executionOwnership)
	if !ok || state == nil {
		return false
	}
	state.mu.Lock()
	state.transferred = true
	state.mu.Unlock()
	return true
}

func ExecutionOwnershipTransferred(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	state, ok := ctx.Value(executionOwnershipContextKey{}).(*executionOwnership)
	if !ok || state == nil {
		return false
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.transferred
}

type taskPolicyOverrideContextKey struct{}

// TaskPolicyOverride 是任务作用域的临时审批策略（如批量任务队列），
// 只随 context 传播、在 Authorize 时叠加于全局快照之上，不修改快照本身：
// 全局运行时仍然唯一，项目/会话值永远不选择或改写它。
type TaskPolicyOverride struct {
	Disabled        bool   // off：本次任务跳过全部审批（直通，不落审批单）
	RequireApproval bool   // human / audit_agent：无论全局触发开关状态，一律进入审批
	Reviewer        string // 覆盖审批人：ReviewerHuman / ReviewerAgent
}

func (o TaskPolicyOverride) active() bool {
	return o.Disabled || o.RequireApproval || o.Reviewer != ""
}

func WithTaskPolicyOverride(ctx context.Context, override TaskPolicyOverride) context.Context {
	if !override.active() {
		return ctx
	}
	return context.WithValue(ctx, taskPolicyOverrideContextKey{}, override)
}

func TaskPolicyOverrideFromContext(ctx context.Context) (TaskPolicyOverride, bool) {
	if ctx == nil {
		return TaskPolicyOverride{}, false
	}
	override, ok := ctx.Value(taskPolicyOverrideContextKey{}).(TaskPolicyOverride)
	return override, ok && override.active()
}
