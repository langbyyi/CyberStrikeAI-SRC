package approval

import (
	"context"
	"errors"
	"testing"
)

type fixedTrigger struct {
	name   string
	result TriggerResult
	err    error
}

func (t fixedTrigger) Name() string { return t.name }
func (t fixedTrigger) Evaluate(context.Context, Invocation) (TriggerResult, error) {
	return t.result, t.err
}

func TestEvaluatorMergesBothTriggersIntoOneAssessment(t *testing.T) {
	evaluator := NewEvaluator(
		fixedTrigger{name: PolicyTypeToolApproval, result: TriggerResult{Matched: true}},
		fixedTrigger{name: PolicyTypeDangerousAction, result: TriggerResult{
			Matched:   true,
			RiskLevel: RiskHigh,
			Findings:  []TriggerFinding{{RuleID: "danger-1", RiskLevel: RiskHigh}},
		}},
	)

	got, err := evaluator.Evaluate(context.Background(), Invocation{ToolName: "exec"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RequiresApproval {
		t.Fatal("merged assessment must require approval")
	}
	if len(got.TriggerSources) != 2 || got.TriggerSources[0] != PolicyTypeDangerousAction || got.TriggerSources[1] != PolicyTypeToolApproval {
		t.Fatalf("trigger sources = %#v", got.TriggerSources)
	}
	if len(got.TriggerFindings) != 1 || got.TriggerFindings[0].Source != PolicyTypeDangerousAction {
		t.Fatalf("findings = %#v", got.TriggerFindings)
	}
	if got.RiskLevel != RiskHigh {
		t.Fatalf("risk = %q, want high", got.RiskLevel)
	}
}

func TestEvaluatorPropagatesEnabledTriggerFailure(t *testing.T) {
	want := errors.New("rules unavailable")
	_, err := NewEvaluator(fixedTrigger{name: PolicyTypeDangerousAction, err: want}).Evaluate(
		context.Background(), Invocation{ToolName: "exec"},
	)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestToolApprovalTriggerUsesGlobalWhitelist(t *testing.T) {
	trigger := NewToolApprovalTrigger(TriggerConfig{Enabled: true, ToolWhitelist: []string{"read_file"}})
	allowed, err := trigger.Evaluate(context.Background(), Invocation{ToolName: "READ_FILE"})
	if err != nil || allowed.Matched {
		t.Fatalf("allowlisted assessment = %+v, err=%v", allowed, err)
	}
	reviewed, err := trigger.Evaluate(context.Background(), Invocation{ToolName: "exec"})
	if err != nil || !reviewed.Matched {
		t.Fatalf("non-allowlisted assessment = %+v, err=%v", reviewed, err)
	}
}
