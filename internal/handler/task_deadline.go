package handler

import (
	"context"
	"errors"
)

// taskDeadlineExceeded distinguishes the task's deadline from a child operation's
// timeout. A run error (including a cancellation cause) may wrap DeadlineExceeded
// while the task itself still has time remaining; it must not exhaust the task budget.
func taskDeadlineExceeded(taskCtx context.Context) bool {
	return taskCtx != nil && errors.Is(taskCtx.Err(), context.DeadlineExceeded)
}
