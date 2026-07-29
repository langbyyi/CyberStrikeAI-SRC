package handler

import (
	"testing"
	"time"

	"cyberstrike-ai/internal/mcp"
)

func TestSlimToolExecutionPreservesSemanticContext(t *testing.T) {
	start := time.Now()
	exec := &mcp.ToolExecution{
		ID:              "execution-1",
		ToolName:        "http-framework-test",
		Status:          "completed",
		StartTime:       start,
		ConversationID:  "conversation-1",
		SemanticOutcome: mcp.SemanticOutcomeTargetNegative,
		Arguments:       map[string]interface{}{"secret": "must-not-be-copied"},
	}

	got := slimToolExecution(exec)
	if got.ConversationID != exec.ConversationID {
		t.Fatalf("conversationId=%q want=%q", got.ConversationID, exec.ConversationID)
	}
	if got.SemanticOutcome != exec.SemanticOutcome {
		t.Fatalf("semanticOutcome=%q want=%q", got.SemanticOutcome, exec.SemanticOutcome)
	}
	if got.Arguments != nil {
		t.Fatal("slim execution unexpectedly retained arguments")
	}
}

func TestSemanticOutcomeCountsClassifiesLegacyExecutions(t *testing.T) {
	counts := semanticOutcomeCounts([]*mcp.ToolExecution{
		{
			Status: "completed",
			Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "HTTP/1.1 404 Not Found"}}},
		},
		{Status: "failed", Error: "invalid arguments: links 须为数组"},
	})

	if counts[mcp.SemanticOutcomeTargetNegative] != 1 {
		t.Fatalf("target_negative count=%d want=1", counts[mcp.SemanticOutcomeTargetNegative])
	}
	if counts[mcp.SemanticOutcomeInvocationError] != 1 {
		t.Fatalf("invocation_error count=%d want=1", counts[mcp.SemanticOutcomeInvocationError])
	}
}
