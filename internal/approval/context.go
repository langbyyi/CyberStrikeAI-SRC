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
