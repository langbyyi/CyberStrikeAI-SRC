package multiagent

import (
	"context"
	"testing"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

func TestOrphanToolPrunerDropsToolMessageWithEmptyCallID(t *testing.T) {
	middleware := newOrphanToolPrunerMiddleware(nil, "test")
	state := &adk.ChatModelAgentState{
		Messages: []adk.Message{
			schema.UserMessage("start"),
			schema.ToolMessage("unexpected result", ""),
		},
	}

	_, got, err := middleware.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState() error = %v", err)
	}
	if len(got.Messages) != 1 || got.Messages[0].Role != schema.User {
		t.Fatalf("messages = %#v, want only the original user message", got.Messages)
	}
}

func TestOrphanToolPrunerRepairsToolResultBeforeItsAssistantCall(t *testing.T) {
	middleware := newOrphanToolPrunerMiddleware(nil, "test")
	call := schema.ToolCall{
		ID:   "call-1",
		Type: "function",
		Function: schema.FunctionCall{
			Name:      "scan",
			Arguments: "{}",
		},
	}
	state := &adk.ChatModelAgentState{
		Messages: []adk.Message{
			schema.UserMessage("start"),
			schema.ToolMessage("out-of-order result", call.ID),
			schema.AssistantMessage("", []schema.ToolCall{call}),
		},
	}

	_, got, err := middleware.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState() error = %v", err)
	}
	if len(got.Messages) != 3 {
		t.Fatalf("message count = %d, want user + assistant call + repaired tool result", len(got.Messages))
	}
	if got.Messages[0].Role != schema.User ||
		got.Messages[1].Role != schema.Assistant ||
		got.Messages[2].Role != schema.Tool ||
		got.Messages[2].ToolCallID != call.ID ||
		got.Messages[2].Content == "" {
		t.Fatalf("messages were not normalized into a valid tool round: %#v", got.Messages)
	}
}

func TestOrphanToolPrunerDropsToolCallWithEmptyFunctionName(t *testing.T) {
	middleware := newOrphanToolPrunerMiddleware(nil, "test")
	call := schema.ToolCall{
		ID:   "call-empty-name",
		Type: "function",
		Function: schema.FunctionCall{
			Arguments: "{}",
		},
	}
	state := &adk.ChatModelAgentState{
		Messages: []adk.Message{
			schema.AssistantMessage("unable to select a tool", []schema.ToolCall{call}),
			schema.ToolMessage("unexpected result", call.ID),
		},
	}

	_, got, err := middleware.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState() error = %v", err)
	}
	if len(got.Messages) != 1 ||
		got.Messages[0].Role != schema.Assistant ||
		len(got.Messages[0].ToolCalls) != 0 {
		t.Fatalf("messages = %#v, want the assistant text without an invalid tool call", got.Messages)
	}
}

func TestOrphanToolPrunerDropsToolCallWithInvalidArguments(t *testing.T) {
	middleware := newOrphanToolPrunerMiddleware(nil, "test")
	call := newTestToolCall("call-invalid-json", "scan", "{")
	state := &adk.ChatModelAgentState{
		Messages: []adk.Message{
			schema.AssistantMessage("invalid arguments", []schema.ToolCall{call}),
			schema.ToolMessage("unexpected result", call.ID),
		},
	}

	_, got, err := middleware.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState() error = %v", err)
	}
	if len(got.Messages) != 1 || len(got.Messages[0].ToolCalls) != 0 {
		t.Fatalf("messages = %#v, want invalid tool call and its result removed", got.Messages)
	}
}

func TestOrphanToolPrunerDropsEmptyAssistantAfterInvalidToolCall(t *testing.T) {
	middleware := newOrphanToolPrunerMiddleware(nil, "test")
	call := newTestToolCall("call-invalid", "", "{}")
	state := &adk.ChatModelAgentState{
		Messages: []adk.Message{
			schema.UserMessage("start"),
			schema.AssistantMessage("", []schema.ToolCall{call}),
			schema.ToolMessage("unexpected result", call.ID),
		},
	}

	_, got, err := middleware.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState() error = %v", err)
	}
	if len(got.Messages) != 1 || got.Messages[0].Role != schema.User {
		t.Fatalf("messages = %#v, want only the valid user message", got.Messages)
	}
}

func TestOrphanToolPrunerNormalizesEmptyArguments(t *testing.T) {
	middleware := newOrphanToolPrunerMiddleware(nil, "test")
	call := newTestToolCall("call-empty-args", "scan", "")
	state := &adk.ChatModelAgentState{
		Messages: []adk.Message{
			schema.AssistantMessage("", []schema.ToolCall{call}),
			schema.ToolMessage("ok", call.ID),
		},
	}

	_, got, err := middleware.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState() error = %v", err)
	}
	if got.Messages[0].ToolCalls[0].Function.Arguments != "{}" {
		t.Fatalf("arguments = %q, want {}", got.Messages[0].ToolCalls[0].Function.Arguments)
	}
}

func TestOrphanToolPrunerPreservesValidParallelToolRound(t *testing.T) {
	middleware := newOrphanToolPrunerMiddleware(nil, "test")
	first := newTestToolCall("call-1", "scan", `{"target":"one"}`)
	second := newTestToolCall("call-2", "scan", `{"target":"two"}`)
	state := &adk.ChatModelAgentState{
		Messages: []adk.Message{
			schema.UserMessage("start"),
			schema.AssistantMessage("", []schema.ToolCall{first, second}),
			schema.ToolMessage("second result", second.ID),
			schema.ToolMessage("first result", first.ID),
		},
	}

	_, got, err := middleware.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState() error = %v", err)
	}
	if got != state {
		t.Fatal("valid message sequence was unnecessarily rewritten")
	}
}

func TestOrphanToolPrunerDropsDuplicateToolResult(t *testing.T) {
	middleware := newOrphanToolPrunerMiddleware(nil, "test")
	call := newTestToolCall("call-1", "scan", "{}")
	state := &adk.ChatModelAgentState{
		Messages: []adk.Message{
			schema.AssistantMessage("", []schema.ToolCall{call}),
			schema.ToolMessage("first result", call.ID),
			schema.ToolMessage("duplicate result", call.ID),
		},
	}

	_, got, err := middleware.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState() error = %v", err)
	}
	if len(got.Messages) != 2 || got.Messages[1].Content != "first result" {
		t.Fatalf("messages = %#v, want only the first tool result", got.Messages)
	}
}

func TestOrphanToolPrunerPatchesMissingToolResultBeforeNextMessage(t *testing.T) {
	middleware := newOrphanToolPrunerMiddleware(nil, "test")
	call := newTestToolCall("call-1", "scan", "{}")
	state := &adk.ChatModelAgentState{
		Messages: []adk.Message{
			schema.AssistantMessage("", []schema.ToolCall{call}),
			schema.UserMessage("continue"),
		},
	}

	_, got, err := middleware.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil {
		t.Fatalf("BeforeModelRewriteState() error = %v", err)
	}
	if len(got.Messages) != 3 ||
		got.Messages[1].Role != schema.Tool ||
		got.Messages[1].ToolCallID != call.ID ||
		got.Messages[1].Content != repairedMissingToolResult ||
		got.Messages[2].Role != schema.User {
		t.Fatalf("messages = %#v, want a repaired result before the next user message", got.Messages)
	}
}

func newTestToolCall(id, name, arguments string) schema.ToolCall {
	return schema.ToolCall{
		ID:   id,
		Type: "function",
		Function: schema.FunctionCall{
			Name:      name,
			Arguments: arguments,
		},
	}
}

// assistantToolCallsMsg 构造带 tool_calls 的 assistant 消息（共享测试 helper，context_budget_test 等引用）。
func assistantToolCallsMsg(content string, callIDs ...string) *schema.Message {
	tcs := make([]schema.ToolCall, 0, len(callIDs))
	for _, id := range callIDs {
		tcs = append(tcs, schema.ToolCall{
			ID:   id,
			Type: "function",
			Function: schema.FunctionCall{
				Name:      "stub_tool",
				Arguments: `{}`,
			},
		})
	}
	return schema.AssistantMessage(content, tcs)
}
