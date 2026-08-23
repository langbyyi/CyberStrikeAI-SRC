package handler

import (
	"slices"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/multiagent"
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
		Status:           agentfinalizer.StatusInProgress,
		CompletionReason: agentfinalizer.ReasonMissingCompletionSignal,
	}
	if shouldAutoContinueAfterFinalization(missingSignal, 0) {
		t.Fatal("missing completion signal must not repeat the entire runner")
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
	if !strings.Contains(got, "继续执行未完成步骤") || !strings.Contains(got, "exit") {
		t.Fatalf("prompt does not request bounded continuation: %q", got)
	}
	if strings.Contains(got, "重新开始") || strings.Contains(got, "最终回复检查通过") {
		t.Fatalf("prompt requests restart or claims success: %q", got)
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
