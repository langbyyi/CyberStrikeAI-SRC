package multiagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type convergenceSessionFixture struct {
	SessionID     string                   `json:"session_id"`
	Target        string                   `json:"target"`
	ProbeOutcomes []convergenceProbeResult `json:"probe_outcomes"`
	FirstRecord   map[string]interface{}   `json:"first_record"`
	TypeSwap      map[string]interface{}   `json:"type_swap_record"`
	DroppedCallID string                   `json:"dropped_call_id"`
}

type convergenceProbeResult struct {
	Code        string `json:"code"`
	Fingerprint string `json:"fingerprint"`
	Summary     string `json:"summary"`
}

func TestSessionDe13ConvergesAndProducesCleanEvidenceReport(t *testing.T) {
	raw, err := os.ReadFile("testdata/session_de13_convergence.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture convergenceSessionFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fixture.ProbeOutcomes) != 12 {
		t.Fatalf("fixture probe count=%d want=12", len(fixture.ProbeOutcomes))
	}

	state := newPolicyTestState()
	state.controller = NewExecutionController(fixture.Target)
	for i, result := range fixture.ProbeOutcomes {
		callID := fmt.Sprintf("probe-%d", i)
		state.controller.StartProbeBatch([]string{callID})
		state.controller.RecordSemanticOutcome(callID, "http-framework-test", callID, SemanticOutcome{
			Kind:             SemanticOutcomeTargetNegative,
			Code:             result.Code,
			Fingerprint:      result.Fingerprint,
			EvidenceProgress: false,
		})
		state.controller.CompleteProbeBatch()
		state.RecordTool(ToolEvidenceEntry{
			ToolName:   "http-framework-test",
			StatusHint: result.Code,
			Summary:    result.Summary,
		})
		if state.controller.Phase() == ExecutionPhasePivoting {
			if directive := state.controller.PivotDirective(); strings.TrimSpace(directive) == "" {
				t.Fatal("pivot phase must provide a new-branch directive")
			}
		}
	}
	if state.controller.Phase() != ExecutionPhaseFinalizing {
		t.Fatalf("low-value probe budget must finalize, got %q", state.controller.Phase())
	}

	firstArgs, _ := json.Marshal(fixture.FirstRecord)
	first := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", string(firstArgs), state)
	if first.Allowed {
		t.Fatalf("weak evidence must not be recorded: %+v", first)
	}
	state.RememberEvidenceRejection(first.Fingerprint, first.Code)

	swapArgs, _ := json.Marshal(fixture.TypeSwap)
	swap := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", string(swapArgs), state)
	if swap.Allowed || swap.Code != "evidence_previously_rejected" {
		t.Fatalf("type swap must not bypass an evidence rejection: %+v", swap)
	}

	ledger := NewPendingLedger()
	ledger.Drop(toolCallPendingInfo{ToolCallID: fixture.DroppedCallID, ToolName: "record_vulnerability"})
	if ledger.Register(toolCallPendingInfo{ToolCallID: fixture.DroppedCallID, ToolName: "record_vulnerability"}) {
		t.Fatal("late registration resurrected a force-closed tool call")
	}

	got := FinalizeRunResponse(context.Background(), state, "[framework_next_action] 继续扫描并换分类落库", nil)
	for _, forbidden := range []string{"framework_next_action", "pending tool calls", "identity_gap"} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Fatalf("final report leaked internal text %q: %q", forbidden, got)
		}
	}
	for _, required := range []string{"已验证事实", "未确认候选", "限制与下一步"} {
		if !strings.Contains(got, required) {
			t.Fatalf("final report missing %q: %q", required, got)
		}
	}
}
