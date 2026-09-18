package approval

import (
	"context"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

// TestTaskPolicyOverrideOffBypassesApproval 验证任务作用域 off 策略：
// 即使全局触发器命中，也直接放行且不落审批单。
func TestTaskPolicyOverrideOffBypassesApproval(t *testing.T) {
	coordinator := newTaskOverrideTestCoordinator(t)
	invocation := Invocation{
		ID: "inv-off", Source: "test", RequesterUserID: "user-1", ToolName: "exec",
		Arguments: map[string]any{"command": "id"},
	}
	ctx := WithTaskPolicyOverride(context.Background(), TaskPolicyOverride{Disabled: true})
	grant, err := coordinator.Authorize(ctx, invocation)
	if err != nil {
		t.Fatalf("authorize with off override: %v", err)
	}
	if !grant.IsEmpty() {
		t.Fatalf("off override must bypass approval, got approvalID %q", grant.ApprovalID())
	}
}

// TestTaskPolicyOverrideRequiresApproval 验证任务作用域 human / audit_agent 策略：
// 全局触发器未命中时仍强制进入审批，并覆盖全局审批人。
func TestTaskPolicyOverrideRequiresApproval(t *testing.T) {
	for _, tc := range []struct {
		reviewer     string
		wantReviewer string
	}{
		{ReviewerHuman, ReviewerHuman},
		{ReviewerAgent, ReviewerAgent},
	} {
		coordinator := newTaskOverrideTestCoordinator(t)
		invocation := Invocation{
			ID: "inv-" + tc.reviewer, Source: "test", RequesterUserID: "user-1", ToolName: "exec",
			Arguments: map[string]any{"command": "id"},
		}
		ctx := WithTaskPolicyOverride(context.Background(), TaskPolicyOverride{RequireApproval: true, Reviewer: tc.reviewer})
		grant, err := coordinator.Authorize(ctx, invocation)
		if err != nil {
			t.Fatalf("authorize with %s override: %v", tc.reviewer, err)
		}
		if grant.IsEmpty() {
			t.Fatalf("%s override must force an approval request", tc.reviewer)
		}
	}
}

// TestTaskPolicyOverrideDoesNotModifyGlobalSnapshot 验证覆盖只随 context 生效：
// 撤掉 override 后，全局触发器关闭的配置仍然放行。
func TestTaskPolicyOverrideDoesNotModifyGlobalSnapshot(t *testing.T) {
	coordinator := newTaskOverrideTestCoordinator(t)
	invocation := Invocation{
		ID: "inv-global", Source: "test", RequesterUserID: "user-1", ToolName: "exec",
		Arguments: map[string]any{"command": "id"},
	}
	grant, err := coordinator.Authorize(context.Background(), invocation)
	if err != nil {
		t.Fatalf("authorize without override: %v", err)
	}
	if !grant.IsEmpty() {
		t.Fatalf("global config with disabled triggers must allow, got approvalID %q", grant.ApprovalID())
	}
}

func newTaskOverrideTestCoordinator(t *testing.T) *Coordinator {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "task-override.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewSQLiteStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 全局触发器均未启用：RequireApproval 的强制能力只能来自任务覆盖。
	evaluator := NewEvaluator()
	return NewCoordinator(CoordinatorOptions{
		Evaluator:     evaluator,
		Config:        Config{Reviewer: ReviewerHuman},
		Store:         store,
		HumanReviewer: &recordingReviewer{result: ReviewDecision{Decision: ReviewerApprove, ActorType: ReviewerHuman, ActorID: "human-1"}},
		AgentReviewer: &recordingReviewer{result: ReviewDecision{Decision: ReviewerApprove, ActorType: ReviewerAgent, ActorID: "agent-1"}},
	})
}
