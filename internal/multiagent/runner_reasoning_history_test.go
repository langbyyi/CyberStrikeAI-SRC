package multiagent

import (
	"testing"

	"cyberstrike-ai/internal/agent"
)

func TestHistoryToMessagesPreservesReasoningContent(t *testing.T) {
	h := []agent.ChatMessage{
		{Role: "user", Content: "u"},
		{Role: "assistant", Content: "c", ReasoningContent: "r1", ToolCalls: []agent.ToolCall{{ID: "t1", Type: "function", Function: agent.FunctionCall{Name: "f", Arguments: map[string]interface{}{}}}}},
	}
	msgs := historyToMessages(h, nil, nil)
	if len(msgs) != 2 {
		t.Fatalf("len=%d", len(msgs))
	}
	am := msgs[1]
	if am.ReasoningContent != "r1" || am.Content != "c" {
		t.Fatalf("got reasoning=%q content=%q", am.ReasoningContent, am.Content)
	}
}
