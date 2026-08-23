package multiagent

import (
	"testing"

	"github.com/cloudwego/eino/schema"
)

func TestEinoCompletionTrackerIgnoresSubagentExit(t *testing.T) {
	tracker := newEinoCompletionTracker("supervisor", "orchestrator")
	tracker.Observe("researcher", assistantExitMessage("sub result"))

	got := tracker.Snapshot()
	if got.State != CompletionUnsignaled || got.Signal != "" || got.FinalResponse != "" {
		t.Fatalf("subagent exit completed root task: %+v", got)
	}
}

func TestEinoCompletionTrackerCapturesRootExit(t *testing.T) {
	tracker := newEinoCompletionTracker("supervisor", "orchestrator")
	tracker.Observe("orchestrator", assistantExitMessage("final result"))
	if got := tracker.Snapshot(); got.State != CompletionUnsignaled {
		t.Fatalf("unexecuted exit completed root task: %+v", got)
	}

	tracker.Observe("orchestrator", toolExitMsg("final result", "exit-call"))

	got := tracker.Snapshot()
	if got.State != CompletionSucceeded || got.Signal != "exit" || got.FinalResponse != "final result" {
		t.Fatalf("root exit snapshot = %+v", got)
	}
}

func TestEinoCompletionTrackerIgnoresSubagentExitResult(t *testing.T) {
	tracker := newEinoCompletionTracker("supervisor", "orchestrator")
	tracker.Observe("orchestrator", assistantExitMessage("final result"))
	tracker.Observe("researcher", toolExitMsg("final result", "exit-call"))

	if got := tracker.Snapshot(); got.State != CompletionUnsignaled {
		t.Fatalf("subagent exit result completed root task: %+v", got)
	}
}

func TestEinoCompletionTrackerDoesNotInferCompletionFromAssistantText(t *testing.T) {
	tracker := newEinoCompletionTracker("eino_single", "eino_single")
	tracker.Observe("eino_single", schema.AssistantMessage("现在开始批量探测敏感端点。", nil))

	if got := tracker.Snapshot(); got.State != CompletionUnsignaled {
		t.Fatalf("plain assistant text completed task: %+v", got)
	}
}

func TestEinoCompletionTrackerMarksPlanExecuteFrameworkCompletion(t *testing.T) {
	tracker := newEinoCompletionTracker("plan_execute", "planner")
	tracker.MarkFrameworkCompleted()

	got := tracker.Snapshot()
	if got.State != CompletionSucceeded || got.Signal != "plan_completed" {
		t.Fatalf("plan completion snapshot = %+v", got)
	}
}

func TestEinoCompletionTrackerPreservesExplicitExitOnFrameworkCompletion(t *testing.T) {
	tracker := newEinoCompletionTracker("eino_single", "eino_single")
	tracker.Observe("eino_single", assistantExitMessage("explicit final"))
	tracker.Observe("eino_single", toolExitMsg("explicit final", "exit-call"))
	tracker.MarkFrameworkCompleted()

	got := tracker.Snapshot()
	if got.State != CompletionSucceeded || got.Signal != "exit" || got.FinalResponse != "explicit final" {
		t.Fatalf("framework completion replaced explicit exit: %+v", got)
	}
}

func assistantExitMessage(finalResult string) *schema.Message {
	return schema.AssistantMessage("", []schema.ToolCall{{
		ID:   "exit-call",
		Type: "function",
		Function: schema.FunctionCall{
			Name:      "exit",
			Arguments: `{"final_result":"` + finalResult + `"}`,
		},
	}})
}
