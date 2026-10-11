package mcp

import (
	"context"
	"go.uber.org/zap"
	"testing"
	"time"
)

func TestExplicitExecutionDeadlineSurvivesDetachedWait(t *testing.T) {
	service := NewExecutionService(nil, zap.NewNop())
	waitCtx, cancelWait := context.WithCancel(context.Background())
	ctx := WithToolExecutionDeadline(waitCtx, time.Now().Add(50*time.Millisecond))
	started := make(chan struct{})
	handle, err := service.Submit(ctx, ExecutionRequest{ToolName: "test-only-deadline", Run: func(runCtx context.Context) (*ToolResult, error) {
		if _, ok := runCtx.Deadline(); !ok {
			t.Error("execution deadline lost")
		}
		close(started)
		<-runCtx.Done()
		return &ToolResult{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	cancelWait()
	snapshot, err := service.Wait(context.Background(), handle.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Execution.Status != ToolExecutionStatusHardTimeout || snapshot.Execution.EndTime == nil {
		t.Fatalf("deadline did not close worker: %#v", snapshot.Execution)
	}
}

func TestExplicitExecutionDeadlineDoesNotExtendExistingHardTimeout(t *testing.T) {
	service := NewExecutionService(nil, zap.NewNop())
	ctx := WithToolExecutionDeadline(context.Background(), time.Now().Add(time.Hour))
	handle, err := service.Submit(ctx, ExecutionRequest{ToolName: "test-only-short-limit", HardTimeout: 20 * time.Millisecond, Run: func(ctx context.Context) (*ToolResult, error) { <-ctx.Done(); return nil, ctx.Err() }})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Wait(context.Background(), handle.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Execution.Status != ToolExecutionStatusHardTimeout {
		t.Fatalf("hard timeout extended: %#v", snapshot.Execution)
	}
}
