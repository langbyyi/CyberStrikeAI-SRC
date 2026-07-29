package multiagent

import (
	"fmt"
	"testing"
)

func TestExecutionPhasePivotsWithoutEndingTheRun(t *testing.T) {
	controller := NewExecutionController("target.test")
	negative := SemanticOutcome{
		Kind:             SemanticOutcomeTargetNegative,
		Code:             "spa_shell",
		Fingerprint:      "same-spa-shell",
		EvidenceProgress: false,
	}

	for i := 0; i < 3; i++ {
		callID := fmt.Sprintf("call-%d", i)
		controller.StartProbeBatch([]string{callID})
		controller.RecordSemanticOutcome(callID, "http-framework-test", fmt.Sprintf("sig-%d", i), negative)
		controller.CompleteProbeBatch()
	}

	if got := controller.Phase(); got != ExecutionPhasePivoting {
		t.Fatalf("three no-progress batches must request a pivot, got %q", got)
	}
	if directive := controller.PivotDirective(); directive == "" {
		t.Fatal("pivot must produce one model directive")
	}
	if got := controller.Phase(); got != ExecutionPhaseExploring {
		t.Fatalf("consuming the pivot directive must reopen exploration on a new branch, got %q", got)
	}
	if allowed, reason := controller.CheckToolCallAllowed("http-framework-test", `{"url":"https://target.test/new-branch"}`); !allowed {
		t.Fatalf("a new branch must be allowed after pivot, reason=%q", reason)
	}
}

func TestExecutionPhaseFinalizesAfterGlobalLowValueBudget(t *testing.T) {
	controller := NewExecutionController("target.test")
	negative := SemanticOutcome{
		Kind:             SemanticOutcomeTargetNegative,
		Code:             "spa_shell",
		Fingerprint:      "same-spa-shell",
		EvidenceProgress: false,
	}

	for i := 0; i < 12; i++ {
		callID := fmt.Sprintf("call-%d", i)
		controller.StartProbeBatch([]string{callID})
		controller.RecordSemanticOutcome(callID, "http-framework-test", fmt.Sprintf("sig-%d", i), negative)
		controller.CompleteProbeBatch()
		if controller.Phase() == ExecutionPhasePivoting {
			_ = controller.PivotDirective()
		}
	}

	if got := controller.Phase(); got != ExecutionPhaseFinalizing {
		t.Fatalf("global low-value budget must enter finalization, got %q", got)
	}
	if !controller.FinalizationRequired() {
		t.Fatal("controller must explicitly expose finalization state")
	}
	if allowed, reason := controller.CheckToolCallAllowed("http-framework-test", `{"url":"https://target.test/more"}`); allowed || reason != "finalizing" {
		t.Fatalf("new probes must stop while finalizing, got allowed=%v reason=%q", allowed, reason)
	}
	if allowed, reason := controller.CheckToolCallAllowed("upsert_project_fact", `{"fact":"summary"}`); !allowed {
		t.Fatalf("state writes must remain available for finalization, reason=%q", reason)
	}
}
