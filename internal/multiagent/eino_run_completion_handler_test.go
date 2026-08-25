package multiagent

import (
	"context"
	"os"
	"testing"

	"cyberstrike-ai/internal/einomcp"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

func TestEinoRunCompletionHandlerFlushesOrphansAndCleansCheckpoint(t *testing.T) {
	var events []struct {
		eventType string
		data      map[string]interface{}
	}
	progress := func(eventType, _ string, data interface{}) {
		m, _ := data.(map[string]interface{})
		events = append(events, struct {
			eventType string
			data      map[string]interface{}
		}{eventType: eventType, data: m})
	}
	pending := newEinoPendingToolCalls("conv-1", progress)
	pending.Mark(toolCallPendingInfo{ToolCallID: "call-1", ToolName: "execute", EinoAgent: "lead", EinoRole: "orchestrator"})
	store, err := newFileCheckPointStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(context.Background(), "cp-1", []byte("checkpoint")); err != nil {
		t.Fatal(err)
	}
	cpPath, err := store.path("cp-1")
	if err != nil {
		t.Fatal(err)
	}

	newEinoRunCompletionHandler(einoRunCompletionHandlerConfig{
		ConversationID: "conv-1",
		OrchMode:       "deep",
		Progress:       progress,
		Pending:        pending,
		Checkpoint:     store,
		CheckpointID:   "cp-1",
	}).Complete()

	if pending.Count() != 0 {
		t.Fatalf("pending count = %d, want 0", pending.Count())
	}
	if _, err := os.Stat(cpPath); !os.IsNotExist(err) {
		t.Fatalf("checkpoint should be removed, stat err=%v", err)
	}
	var orphanEvent map[string]interface{}
	var failedToolResult map[string]interface{}
	for _, ev := range events {
		switch ev.eventType {
		case "eino_pending_orphaned":
			orphanEvent = ev.data
		case "tool_result":
			failedToolResult = ev.data
		}
	}
	if orphanEvent == nil || orphanEvent["conversationId"] != "conv-1" || orphanEvent["orchestration"] != "deep" || orphanEvent["pendingCount"] != 1 {
		t.Fatalf("orphan event = %#v", orphanEvent)
	}
	if failedToolResult == nil || failedToolResult["toolCallId"] != "call-1" || failedToolResult["isError"] != true {
		t.Fatalf("failed tool result = %#v", failedToolResult)
	}
}

func TestEinoRunCompletionHandlerNoopWithoutState(t *testing.T) {
	newEinoRunCompletionHandler(einoRunCompletionHandlerConfig{}).Complete()
	var h *einoRunCompletionHandler
	h.Complete()
}

func TestEinoRunCompletionHandlerReconcilesDeliveredPending(t *testing.T) {
	var events []struct {
		eventType string
		data      map[string]interface{}
	}
	progress := func(eventType, _ string, data interface{}) {
		m, _ := data.(map[string]interface{})
		events = append(events, struct {
			eventType string
			data      map[string]interface{}
		}{eventType: eventType, data: m})
	}
	pending := newEinoPendingToolCalls("conv-1", progress)
	pending.Mark(toolCallPendingInfo{ToolCallID: "call-typo", ToolName: "execute-python-cript", EinoAgent: "lead", EinoRole: "orchestrator"})
	pending.Mark(toolCallPendingInfo{ToolCallID: "call-lost", ToolName: "execute", EinoAgent: "lead", EinoRole: "orchestrator"})
	delivered := map[string]string{
		"call-typo": einomcp.ToolErrorPrefix + `The tool name "execute-python-cript" is not registered for this agent.`,
	}

	newEinoRunCompletionHandler(einoRunCompletionHandlerConfig{
		ConversationID: "conv-1",
		OrchMode:       "eino_single",
		Progress:       progress,
		Pending:        pending,
		DeliveredToolResults: func() map[string]string {
			return delivered
		},
	}).Complete()

	if pending.Count() != 0 {
		t.Fatalf("pending count = %d, want 0", pending.Count())
	}
	var reconciled, orphaned, flushed map[string]interface{}
	for _, ev := range events {
		switch ev.eventType {
		case "tool_result":
			if ev.data["toolCallId"] == "call-typo" {
				reconciled = ev.data
			} else {
				flushed = ev.data
			}
		case "eino_pending_orphaned":
			orphaned = ev.data
		}
	}
	if reconciled == nil {
		t.Fatalf("missing reconciled tool_result for delivered call, events = %#v", events)
	}
	if reconciled["isError"] != true {
		t.Fatalf("reconciled tool_result should keep soft-error flag, data = %#v", reconciled)
	}
	if reconciled["reconciledFromModelTrace"] != true {
		t.Fatalf("reconciled tool_result should be tagged, data = %#v", reconciled)
	}
	if got, _ := reconciled["result"].(string); delivered["call-typo"] != got {
		t.Fatalf("reconciled result = %q, want delivered content", got)
	}
	if orphaned == nil || orphaned["pendingCount"] != 1 {
		t.Fatalf("only the undelivered call should be force-closed, orphan event = %#v", orphaned)
	}
	if flushed == nil || flushed["toolCallId"] != "call-lost" || flushed["isError"] != true {
		t.Fatalf("undelivered call should flush as failed, data = %#v", flushed)
	}
}

func TestEinoRunCompletionHandlerSkipsReconcileWithoutLookup(t *testing.T) {
	pending := newEinoPendingToolCalls("conv-1", nil)
	pending.Mark(toolCallPendingInfo{ToolCallID: "call-1", ToolName: "execute"})
	newEinoRunCompletionHandler(einoRunCompletionHandlerConfig{
		ConversationID: "conv-1",
		OrchMode:       "eino_single",
		Pending:        pending,
	}).Complete()
	if pending.Count() != 0 {
		t.Fatalf("pending count = %d, want 0 (fallback flush still clears)", pending.Count())
	}
}

func TestDeliveredToolResultsFromMessages(t *testing.T) {
	msgs := []adk.Message{
		schema.UserMessage("q"),
		{Role: schema.Tool, ToolCallID: "call-1", Content: "ok"},
		{Role: schema.Tool, ToolCallID: "", Content: "no id"},
		schema.AssistantMessage("done", nil),
	}
	got := deliveredToolResultsFromMessages(msgs)
	if len(got) != 1 || got["call-1"] != "ok" {
		t.Fatalf("delivered map = %#v", got)
	}
	if deliveredToolResultsFromMessages(nil) != nil {
		t.Fatal("nil messages should yield nil map")
	}
}
