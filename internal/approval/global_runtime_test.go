package approval

import (
	"context"
	"testing"
)

func TestGlobalRuntimeIgnoresProjectAndConversationForPolicy(t *testing.T) {
	runtime, err := NewGlobalRuntime(Config{
		Reviewer:     ReviewerHuman,
		ToolApproval: TriggerConfig{Enabled: true, ToolWhitelist: []string{"read_file"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := runtime.Evaluate(context.Background(), Invocation{ToolName: "exec", ProjectID: "p1", ConversationID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtime.Evaluate(context.Background(), Invocation{ToolName: "exec", ProjectID: "p2", ConversationID: "c2"})
	if err != nil {
		t.Fatal(err)
	}
	if !first.RequiresApproval || !second.RequiresApproval || len(first.TriggerSources) != len(second.TriggerSources) {
		t.Fatalf("policy changed by metadata: first=%+v second=%+v", first, second)
	}
}

func TestGlobalRuntimeRejectsInvalidRulesWithoutReplacingSnapshot(t *testing.T) {
	runtime, err := NewGlobalRuntime(Config{ToolApproval: TriggerConfig{Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := []Rule{{ID: "bad", Enabled: true, Matcher: RuleMatcher{TextPatterns: []string{"["}}}}
	if err := runtime.Update(runtime.Config(), bad); err == nil {
		t.Fatal("invalid rules must be rejected")
	}
	got, err := runtime.Evaluate(context.Background(), Invocation{ToolName: "exec"})
	if err != nil || !got.RequiresApproval {
		t.Fatalf("previous snapshot was not retained: %+v err=%v", got, err)
	}
}

