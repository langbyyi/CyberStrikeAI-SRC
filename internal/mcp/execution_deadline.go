package mcp

import (
	"context"
	"time"
)

type toolExecutionDeadlineKey struct{}

// WithToolExecutionDeadline sets an execution limit independently of a caller's
// bounded wait. Detached workers retain this explicit limit.
func WithToolExecutionDeadline(ctx context.Context, deadline time.Time) context.Context {
	return context.WithValue(ctx, toolExecutionDeadlineKey{}, deadline)
}
