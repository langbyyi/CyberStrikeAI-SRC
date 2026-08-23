package agentfinalizer

import (
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

func newDecisionTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "finalizer.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func saveDecisionTestExecution(t *testing.T, db *database.DB, id, status string) {
	t.Helper()
	if err := db.SaveToolExecution(&mcp.ToolExecution{
		ID:        id,
		ToolName:  "test::tool",
		Arguments: map[string]interface{}{"input": id},
		Status:    status,
		StartTime: time.Now(),
	}); err != nil {
		t.Fatalf("SaveToolExecution(%s): %v", id, err)
	}
}

func TestDecideBlocksPendingToolExecutions(t *testing.T) {
	db := newDecisionTestDB(t)
	saveDecisionTestExecution(t, db, "run-queued", mcp.ToolExecutionStatusQueued)
	saveDecisionTestExecution(t, db, "run-running", mcp.ToolExecutionStatusRunning)
	saveDecisionTestExecution(t, db, "run-completed", mcp.ToolExecutionStatusCompleted)

	d := Decide(db, Input{
		Response:        "工具还没全部结束时，这只是一段候选输出。",
		MCPExecutionIDs: []string{"run-queued", "run-running", "run-completed"},
	})

	if d.Finalizable || d.Finalized {
		t.Fatalf("pending tools should not be finalizable: %+v", d)
	}
	if d.Status != StatusInProgress || d.CompletionReason != ReasonPendingTools {
		t.Fatalf("status/reason = %s/%s, want %s/%s", d.Status, d.CompletionReason, StatusInProgress, ReasonPendingTools)
	}
	if got, want := len(d.PendingExecutionIDs), 2; got != want {
		t.Fatalf("pending execution count = %d, want %d (%v)", got, want, d.PendingExecutionIDs)
	}
}

func TestDecideBlocksAwaitingHITLAndEmptyCandidate(t *testing.T) {
	hitl := Decide(nil, Input{Response: "等待人工审批", AwaitingHITL: true})
	if hitl.Finalizable || hitl.Status != StatusAwaitingHITL || hitl.CompletionReason != ReasonAwaitingHITL {
		t.Fatalf("HITL decision mismatch: %+v", hitl)
	}

	empty := Decide(nil, Input{Response: "⚠️ Eino 执行完成，但未捕获到助手文本输出。"})
	if empty.Finalizable || empty.Status != StatusBlocked || empty.CompletionReason != ReasonEmptyResponse {
		t.Fatalf("empty candidate decision mismatch: %+v", empty)
	}
}

func TestDecideBlocksWhenExecutionEvidenceIsRequiredButMissing(t *testing.T) {
	d := Decide(nil, Input{
		Response:                 "任务已处理完成。",
		RequireExecutionEvidence: true,
	})
	if d.Finalizable || d.Finalized {
		t.Fatalf("missing required execution evidence should not finalize: %+v", d)
	}
	if d.Status != StatusBlocked || d.CompletionReason != ReasonMissingEvidence {
		t.Fatalf("status/reason = %s/%s, want %s/%s", d.Status, d.CompletionReason, StatusBlocked, ReasonMissingEvidence)
	}
	if d.EvidenceVerified {
		t.Fatalf("missing required execution evidence should be marked unverified: %+v", d)
	}
	if len(d.MissingChecks) == 0 {
		t.Fatalf("missing checks should explain the evidence gap: %+v", d)
	}
}

func TestDecideBlocksWhenOnlyFailedEvidenceIsRecorded(t *testing.T) {
	db := newDecisionTestDB(t)
	saveDecisionTestExecution(t, db, "run-failed", mcp.ToolExecutionStatusFailed)
	saveDecisionTestExecution(t, db, "run-cancelled", mcp.ToolExecutionStatusCancelled)

	d := Decide(db, Input{
		Response:                 "任务已处理完成。",
		MCPExecutionIDs:          []string{"run-failed", "run-cancelled"},
		RequireExecutionEvidence: true,
	})

	if d.Finalizable || d.Finalized {
		t.Fatalf("failed evidence should not satisfy required execution evidence: %+v", d)
	}
	if d.Status != StatusBlocked || d.CompletionReason != ReasonMissingEvidence {
		t.Fatalf("status/reason = %s/%s, want %s/%s", d.Status, d.CompletionReason, StatusBlocked, ReasonMissingEvidence)
	}
}

func TestDecideFinalizesCompletedEvidence(t *testing.T) {
	db := newDecisionTestDB(t)
	saveDecisionTestExecution(t, db, "run-ok", mcp.ToolExecutionStatusCompleted)

	d := Decide(db, Input{
		Response:                 "任务已处理完成，见工具执行记录。",
		MCPExecutionIDs:          []string{"run-ok"},
		RequireExecutionEvidence: true,
	})

	if !d.Finalizable || !d.Finalized || d.Status != StatusCompleted {
		t.Fatalf("completed execution should finalize: %+v", d)
	}
	if !d.EvidenceVerified || len(d.EvidenceRefs) != 1 {
		t.Fatalf("evidence refs mismatch: %+v", d)
	}
}

func TestDecideAllowsInformationalAnswerWhenExecutionEvidenceIsNotRequired(t *testing.T) {
	d := Decide(nil, Input{Response: "这是一个概念解释，不需要执行工具。"})
	if !d.Finalizable || !d.Finalized || d.Status != StatusCompleted {
		t.Fatalf("informational response should finalize when execution evidence is not required: %+v", d)
	}
}

func TestFromRunResultBlocksUnsignaledEinoText(t *testing.T) {
	result := &multiagent.RunResult{
		Response:                   "现在批量探测敏感端点。先重建浏览器端探测环境。",
		CompletionContractRequired: true,
		CompletionState:            multiagent.CompletionUnsignaled,
	}

	d := FromRunResult(nil, result, Input{AgentMode: "eino_single"})
	if d.Finalizable || d.Finalized {
		t.Fatalf("unsignaled Eino output finalized: %+v", d)
	}
	if d.Status != StatusInProgress || d.CompletionReason != ReasonMissingCompletionSignal {
		t.Fatalf("status/reason = %s/%s", d.Status, d.CompletionReason)
	}
	if d.EvidenceVerified || len(d.MissingChecks) == 0 {
		t.Fatalf("missing completion signal lacks diagnostics: %+v", d)
	}
}

func TestFromRunResultFinalizesSignaledInformationalAnswerWithoutExecutionEvidence(t *testing.T) {
	result := &multiagent.RunResult{
		Response:                   "过程正文不应覆盖最终交付。",
		CompletionContractRequired: true,
		CompletionState:            multiagent.CompletionSucceeded,
		CompletionSignal:           "exit",
		FinalResponse:              "这是完整的概念解释。",
	}

	d := FromRunResult(nil, result, Input{AgentMode: "eino_single"})
	if !d.Finalizable || !d.Finalized || d.Status != StatusCompleted {
		t.Fatalf("signaled informational answer did not finalize: %+v", d)
	}
	if d.FinalText != "这是完整的概念解释。" {
		t.Fatalf("final text = %q", d.FinalText)
	}
}

func TestFromRunResultFinalizesPlanExecuteFrameworkResponse(t *testing.T) {
	result := &multiagent.RunResult{
		Response:                   "计划执行完成后的最终汇总。",
		CompletionContractRequired: true,
		CompletionState:            multiagent.CompletionSucceeded,
		CompletionSignal:           "plan_completed",
	}

	d := FromRunResult(nil, result, Input{AgentMode: "eino_plan_execute"})
	if !d.Finalized || d.Status != StatusCompleted || d.CompletionReason != ReasonVerified {
		t.Fatalf("decision = %+v", d)
	}
	if d.FinalText != result.Response {
		t.Fatalf("final text = %q, want framework response %q", d.FinalText, result.Response)
	}
}

func TestFromRunResultExplicitCompletionDoesNotOverrideTerminalGuards(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		awaiting   bool
		wantStatus string
	}{
		{name: "in progress", status: StatusInProgress, wantStatus: StatusInProgress},
		{name: "blocked", status: StatusBlocked, wantStatus: StatusBlocked},
		{name: "failed", status: StatusFailed, wantStatus: StatusFailed},
		{name: "cancelled", status: StatusCancelled, wantStatus: StatusCancelled},
		{name: "awaiting hitl status", status: StatusAwaitingHITL, wantStatus: StatusAwaitingHITL},
		{name: "awaiting hitl flag", awaiting: true, wantStatus: StatusAwaitingHITL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &multiagent.RunResult{
				Response:                   "过程输出",
				Status:                     tt.status,
				CompletionContractRequired: true,
				CompletionState:            multiagent.CompletionSucceeded,
				CompletionSignal:           "exit",
				FinalResponse:              "完整最终答复",
			}
			d := FromRunResult(nil, result, Input{AwaitingHITL: tt.awaiting})
			if d.Finalized || d.Finalizable || d.Status != tt.wantStatus {
				t.Fatalf("decision = %+v, want non-final status %q", d, tt.wantStatus)
			}
		})
	}
}
