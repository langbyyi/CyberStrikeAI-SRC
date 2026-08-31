package app

import (
	"context"
	"errors"
	"testing"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/c2"

	"go.uber.org/zap"
)

func TestC2ApprovalMissingRecordDoesNotExecute(t *testing.T) {
	coordinator := &fakeC2ApprovalCoordinator{authorizeErr: approval.ErrNotFound}
	bridge := NewC2ApprovalBridge(coordinator, zap.NewNop())
	err := bridge.RequestApproval(context.Background(), c2.HITLApprovalRequest{
		TaskID: "task-1", SessionID: "session-1", TaskType: "self_delete", PayloadJSON: `{}`,
	})
	if !errors.Is(err, approval.ErrNotFound) {
		t.Fatalf("err=%v", err)
	}
	if coordinator.claims != 0 || coordinator.completes != 0 {
		t.Fatalf("claims=%d completes=%d", coordinator.claims, coordinator.completes)
	}
}

func TestC2ApprovalClaimsApprovedRequestOnce(t *testing.T) {
	coordinator := &fakeC2ApprovalCoordinator{grant: approval.NewGrantForTesting(approval.GrantSpec{
		ApprovalID: "apr-1", InvocationID: "task-1", ToolName: c2.MCPToolC2Task,
		Arguments: map[string]any{"task_id": "task-1"},
	})}
	bridge := NewC2ApprovalBridge(coordinator, zap.NewNop())
	err := bridge.RequestApproval(context.Background(), c2.HITLApprovalRequest{
		TaskID: "task-1", SessionID: "session-1", TaskType: "self_delete", PayloadJSON: `{}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if coordinator.authorizes != 1 || coordinator.claims != 1 || coordinator.completes != 0 {
		t.Fatalf("approval must claim but not complete, authorizes=%d claims=%d completes=%d",
			coordinator.authorizes, coordinator.claims, coordinator.completes)
	}
	// 任务终态回写真实执行结果（替代旧的"审批通过即 Complete"）。
	bridge.CompleteTask("task-1", true, "task finished")
	if coordinator.completes != 1 {
		t.Fatalf("CompleteTask must write back the execution result, completes=%d", coordinator.completes)
	}
	bridge.CompleteTask("task-1", true, "duplicate")
	if coordinator.completes != 1 {
		t.Fatalf("CompleteTask must be single-shot per task, completes=%d", coordinator.completes)
	}
}

func TestC2ApprovalReusesExistingToolGrant(t *testing.T) {
	coordinator := &fakeC2ApprovalCoordinator{}
	bridge := NewC2ApprovalBridge(coordinator, zap.NewNop())
	ctx := approval.WithExecutionOwnership(approval.WithGrant(context.Background(), approval.NewGrantForTesting(approval.GrantSpec{
		ApprovalID: "apr-tool", ToolName: c2.MCPToolC2Task,
		Arguments: map[string]any{"session_id": "session-1", "task_type": "self_delete"},
	})))
	if err := bridge.RequestApproval(ctx, c2.HITLApprovalRequest{TaskID: "task-1", SessionID: "session-1", TaskType: "self_delete"}); err != nil {
		t.Fatal(err)
	}
	if coordinator.authorizes != 0 {
		t.Fatalf("authorizes=%d", coordinator.authorizes)
	}
	if !approval.ExecutionOwnershipTransferred(ctx) {
		t.Fatal("C2 must transfer execution-result ownership from the MCP caller")
	}
	bridge.CompleteTask("task-1", true, "task finished")
	if coordinator.completes != 1 {
		t.Fatalf("real C2 terminal must complete the reused grant once, completes=%d", coordinator.completes)
	}
}

type fakeC2ApprovalCoordinator struct {
	grant        approval.Grant
	authorizeErr error
	authorizes   int
	claims       int
	completes    int
}

func (f *fakeC2ApprovalCoordinator) Authorize(context.Context, approval.Invocation) (approval.Grant, error) {
	f.authorizes++
	return f.grant, f.authorizeErr
}

func (f *fakeC2ApprovalCoordinator) Claim(context.Context, approval.Grant, string) error {
	f.claims++
	return nil
}

func (f *fakeC2ApprovalCoordinator) Complete(context.Context, approval.Grant, approval.ExecutionResult) error {
	f.completes++
	return nil
}

func TestC2ApprovalDoesNotReuseGrantForDifferentTaskType(t *testing.T) {
	coordinator := &fakeC2ApprovalCoordinator{}
	bridge := NewC2ApprovalBridge(coordinator, zap.NewNop())
	// MCP 层为 self_delete 审批的 grant 不能放行同 ctx 内其他类型的任务。
	ctx := approval.WithGrant(context.Background(), approval.NewGrantForTesting(approval.GrantSpec{
		ApprovalID: "apr-tool", ToolName: c2.MCPToolC2Task,
		Arguments: map[string]any{"session_id": "session-1", "task_type": "self_delete"},
	}))
	if err := bridge.RequestApproval(ctx, c2.HITLApprovalRequest{
		TaskID: "task-2", SessionID: "session-1", TaskType: "kill_proc",
	}); err != nil {
		t.Fatal(err)
	}
	if coordinator.authorizes != 1 {
		t.Fatalf("authorizes=%d, grant for a different task type must not be reused", coordinator.authorizes)
	}
}
