package handler

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	agentpkg "cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

func TestAccumulateEinoRunMCPExecutionIDsPreservesEarlierRuns(t *testing.T) {
	ids := accumulateEinoRunMCPExecutionIDs(nil, &multiagent.RunResult{
		MCPExecutionIDs: []string{"run-1", "run-2"},
	})
	ids = accumulateEinoRunMCPExecutionIDs(ids, &multiagent.RunResult{
		MCPExecutionIDs: []string{"run-2", "run-3"},
	})
	ids = accumulateEinoRunMCPExecutionIDs(ids, nil)

	want := []string{"run-1", "run-2", "run-3"}
	if !slices.Equal(ids, want) {
		t.Fatalf("accumulated execution IDs = %v, want %v", ids, want)
	}
}

func TestRobotTaskStatusFollowsBlockedFinalization(t *testing.T) {
	blocked := agentfinalizer.Decision{
		Status:           agentfinalizer.StatusInProgress,
		CompletionReason: agentfinalizer.ReasonMissingCompletionSignal,
	}
	if got := robotTaskStatusAfterFinalization("completed", blocked); got != agentfinalizer.StatusInProgress {
		t.Fatalf("blocked robot status = %q, want %q", got, agentfinalizer.StatusInProgress)
	}

	completed := agentfinalizer.Decision{
		Status:      agentfinalizer.StatusCompleted,
		Finalizable: true,
		Finalized:   true,
	}
	if got := robotTaskStatusAfterFinalization("completed", completed); got != "completed" {
		t.Fatalf("finalized robot status = %q, want completed", got)
	}
}

func TestShouldAutoContinueAfterFinalization(t *testing.T) {
	missingEvidence := agentfinalizer.Decision{
		Status:           agentfinalizer.StatusBlocked,
		CompletionReason: agentfinalizer.ReasonMissingEvidence,
	}
	if !shouldAutoContinueAfterFinalization(missingEvidence, 0) {
		t.Fatal("missing execution evidence should trigger auto-continue")
	}
	if shouldAutoContinueAfterFinalization(missingEvidence, finalizationAutoContinueMaxAttempts) {
		t.Fatal("auto-continue should stop at max attempts")
	}

	missingSignal := agentfinalizer.Decision{
		Status:               agentfinalizer.StatusBlocked,
		CompletionReason:     agentfinalizer.ReasonMissingCompletionSignal,
		CandidateResponseLen: len([]rune("已有可交付的候选答复")),
	}
	if !shouldAutoContinueAfterFinalization(missingSignal, 0) {
		t.Fatal("missing completion signal with a candidate should trigger one bounded finalization retry")
	}
	if shouldAutoContinueAfterFinalization(missingSignal, 1) {
		t.Fatal("missing completion signal should stop after its bounded retry")
	}
	missingSignal.CandidateResponseLen = 0
	if shouldAutoContinueAfterFinalization(missingSignal, 0) {
		t.Fatal("missing completion signal without a candidate must not retry")
	}

	finalized := agentfinalizer.Decision{
		Status:           agentfinalizer.StatusCompleted,
		CompletionReason: agentfinalizer.ReasonVerified,
		Finalizable:      true,
		Finalized:        true,
	}
	if shouldAutoContinueAfterFinalization(finalized, 0) {
		t.Fatal("finalized decision should not auto-continue")
	}

	awaitingHITL := agentfinalizer.Decision{
		Status:           agentfinalizer.StatusAwaitingHITL,
		CompletionReason: agentfinalizer.ReasonAwaitingHITL,
	}
	if shouldAutoContinueAfterFinalization(awaitingHITL, 0) {
		t.Fatal("awaiting HITL should not auto-continue without approval")
	}
}

func TestFinalizationAutoContinuePromptRequestsContinuationAndExplicitFinish(t *testing.T) {
	got := finalizationAutoContinuePrompt(agentfinalizer.Decision{
		CompletionReason: agentfinalizer.ReasonMissingCompletionSignal,
	})
	if !strings.Contains(got, "不得调用除 exit 外的任何工具") || !strings.Contains(got, "直接调用 exit") || !strings.Contains(got, "final_result") {
		t.Fatalf("prompt does not request a completion-only retry: %q", got)
	}
	if strings.Contains(got, "继续执行未完成步骤") || strings.Contains(got, "重新开始") {
		t.Fatalf("prompt may repeat completed work: %q", got)
	}
}

func TestFinalizationBlockedMessagePreservesCandidateWhenCompletionSignalStillMissing(t *testing.T) {
	got := finalizationBlockedMessage(agentfinalizer.Decision{
		Status:           agentfinalizer.StatusBlocked,
		CompletionReason: agentfinalizer.ReasonMissingCompletionSignal,
		FinalText:        "这是模型已经整理好的候选最终答复。",
		MissingChecks:    []string{"agent did not emit an explicit completion signal"},
	})

	if !strings.HasPrefix(got, "这是模型已经整理好的候选最终答复。") {
		t.Fatalf("blocked response discarded the candidate: %q", got)
	}
	if !strings.Contains(got, "未收到显式完成信号") || !strings.Contains(got, "结果可能不完整") {
		t.Fatalf("blocked response lacks a clear non-success notice: %q", got)
	}
}

func TestRequestRequiresExecutionEvidenceUsesExplicitPolicyOnly(t *testing.T) {
	if requestRequiresExecutionEvidence(nil) {
		t.Fatal("nil request should not require execution evidence")
	}
	if requestRequiresExecutionEvidence(&ChatRequest{}) {
		t.Fatal("missing finalization policy should not require execution evidence")
	}
	require := true
	if !requestRequiresExecutionEvidence(&ChatRequest{
		Finalization: ChatFinalizationRequest{RequireExecutionEvidence: &require},
	}) {
		t.Fatal("explicit true policy should require execution evidence")
	}
	require = false
	if requestRequiresExecutionEvidence(&ChatRequest{
		Finalization: ChatFinalizationRequest{RequireExecutionEvidence: &require},
	}) {
		t.Fatal("explicit false policy should not require execution evidence")
	}
}

func TestFinalizationResponsePayloadSetsPhaseFromDecision(t *testing.T) {
	finalized := finalizationResponsePayload(agentfinalizer.Decision{Finalized: true}, nil)
	if got := finalized["phase"]; got != "final_answer" {
		t.Fatalf("finalized phase = %#v", got)
	}

	inProgress := finalizationResponsePayload(agentfinalizer.Decision{
		CompletionReason: agentfinalizer.ReasonMissingCompletionSignal,
	}, nil)
	if got := inProgress["phase"]; got != "commentary" {
		t.Fatalf("in-progress phase = %#v", got)
	}
}

func TestCleanupPendingToolExecutionsAfterIterationAllowsFinalization(t *testing.T) {
	logger := zap.NewNop()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "cleanup-finalization.db"), logger)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	server := mcp.NewServerWithStorage(logger, db)
	server.ConfigureToolWaitTimeoutSeconds(1)
	server.RegisterTool(mcp.Tool{Name: "block", InputSchema: map[string]interface{}{"type": "object"}}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ag := agentpkg.NewAgent(&config.OpenAIConfig{}, &config.AgentConfig{}, server, nil, logger, 10)
	h := &AgentHandler{agent: ag, db: db, logger: logger}

	callCtx := mcp.WithMCPConversationID(context.Background(), "conv-cleanup")
	result, execID, err := server.CallTool(callCtx, "block", nil)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result == nil || !result.IsError || execID == "" {
		t.Fatalf("expected background wait result, result=%#v execID=%q", result, execID)
	}

	decision := agentfinalizer.Decide(db, agentfinalizer.Input{
		Response:        "基于已完成信息的阶段性总结。",
		MCPExecutionIDs: []string{execID},
	})
	if decision.CompletionReason != agentfinalizer.ReasonPendingTools {
		t.Fatalf("decision reason = %s, want pending tools: %+v", decision.CompletionReason, decision)
	}

	var eventType string
	cancelled := h.cleanupPendingToolExecutionsAfterIteration(context.Background(), "conv-cleanup", decision, func(et, _ string, _ interface{}) {
		eventType = et
	})
	if len(cancelled) != 1 || cancelled[0] != execID {
		t.Fatalf("cancelled = %#v, want [%s]", cancelled, execID)
	}
	if eventType != "finalization_pending_tools_cancelled" {
		t.Fatalf("event type = %q", eventType)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		exec, err := db.GetToolExecution(execID)
		if err == nil && exec != nil && exec.Status == mcp.ToolExecutionStatusCancelled {
			after := agentfinalizer.Decide(db, agentfinalizer.Input{
				Response:        "基于已完成信息的阶段性总结。",
				MCPExecutionIDs: []string{execID},
			})
			if !after.Finalizable || !after.Finalized {
				t.Fatalf("decision should finalize after cleanup: %+v", after)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("execution did not become cancelled")
}
