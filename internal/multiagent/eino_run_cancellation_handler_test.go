package multiagent

import (
	"context"
	"errors"
	"testing"
)

func TestEinoRunCancellationHandlerFlushesPendingAndEmitsError(t *testing.T) {
	runErr := errors.New("context canceled")
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
	want := &RunResult{Response: "partial"}

	result, err := newEinoRunCancellationHandler(einoRunCancellationHandlerConfig{
		Context:        context.Background(),
		ConversationID: "conv-1",
		Progress:       progress,
		Pending:        pending,
		TakePartial: func(got error) (*RunResult, error) {
			if !errors.Is(got, runErr) {
				t.Fatalf("partial err = %v", got)
			}
			return want, got
		},
	}).Handle(runErr)

	if result != want || !errors.Is(err, runErr) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if pending.Count() != 0 {
		t.Fatalf("pending count = %d, want 0", pending.Count())
	}
	var sawError, sawFailedTool bool
	for _, ev := range events {
		if ev.eventType == "error" {
			sawError = ev.data["conversationId"] == "conv-1" && ev.data["source"] == "eino"
		}
		if ev.eventType == "tool_result" {
			sawFailedTool = ev.data["toolCallId"] == "call-1" && ev.data["isError"] == true
		}
	}
	if !sawError || !sawFailedTool {
		t.Fatalf("events = %#v", events)
	}
}

// TestEinoRunCancellationHandlerReconcilesDeliveredBeforeFlush 取消路径回归：
// 结果已送达模型的幽灵 pending（未知工具路径）应先对账补发真实结果，
// 只有真孤儿才被 FlushAsFailed 误报为失败。
func TestEinoRunCancellationHandlerReconcilesDeliveredBeforeFlush(t *testing.T) {
	runErr := errors.New("context canceled")
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
	reconciled := false

	_, _ = newEinoRunCancellationHandler(einoRunCancellationHandlerConfig{
		Context:        context.Background(),
		ConversationID: "conv-1",
		Progress:       progress,
		Pending:        pending,
		TakePartial: func(got error) (*RunResult, error) {
			return nil, got
		},
		ReconcilePending: func() {
			reconciled = true
			delivered := map[string]string{"call-typo": "tool-error: unknown tool reminder"}
			for _, tc := range pending.ExtractDelivered(delivered) {
				_ = tc
			}
		},
	}).Handle(runErr)

	if !reconciled {
		t.Fatal("reconcile hook must run before flush")
	}
	if pending.Count() != 0 {
		t.Fatalf("pending count = %d, want 0", pending.Count())
	}
	var typoResult, lostResult map[string]interface{}
	for _, ev := range events {
		if ev.eventType != "tool_result" {
			continue
		}
		if ev.data["toolCallId"] == "call-typo" {
			typoResult = ev.data
		}
		if ev.data["toolCallId"] == "call-lost" {
			lostResult = ev.data
		}
	}
	if typoResult != nil {
		t.Fatalf("delivered pending should be reconciled silently here, got %#v", typoResult)
	}
	if lostResult == nil || lostResult["isError"] != true {
		t.Fatalf("undelivered pending should flush as failed, got %#v", lostResult)
	}
}

func TestEinoRunCancellationHandlerInterruptContinueProgress(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrInterruptContinue)
	runErr := context.Canceled
	var eventType string
	var data map[string]interface{}

	_, err := newEinoRunCancellationHandler(einoRunCancellationHandlerConfig{
		Context:        ctx,
		ConversationID: "conv-1",
		Progress: func(et, _ string, raw interface{}) {
			eventType = et
			data, _ = raw.(map[string]interface{})
		},
		TakePartial: func(got error) (*RunResult, error) {
			return nil, got
		},
	}).Handle(runErr)

	if !errors.Is(err, runErr) {
		t.Fatalf("err = %v", err)
	}
	if eventType != "progress" || data["kind"] != "interrupt_continue" || data["conversationId"] != "conv-1" {
		t.Fatalf("eventType=%q data=%#v", eventType, data)
	}
}

func TestEinoRunCancellationHandlerNilSafe(t *testing.T) {
	runErr := errors.New("boom")
	var h *einoRunCancellationHandler
	result, err := h.Handle(runErr)
	if result != nil || !errors.Is(err, runErr) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	result, err = newEinoRunCancellationHandler(einoRunCancellationHandlerConfig{}).Handle(runErr)
	if result != nil || !errors.Is(err, runErr) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}
