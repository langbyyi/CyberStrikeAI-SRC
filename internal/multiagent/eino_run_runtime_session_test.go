package multiagent

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

type fakeRuntimeSessionAgent struct {
	runMessages []adk.Message
	runOpts     int
}

func (a *fakeRuntimeSessionAgent) Name(context.Context) string {
	return "lead"
}

func (a *fakeRuntimeSessionAgent) Description(context.Context) string {
	return "fake runtime session agent"
}

func (a *fakeRuntimeSessionAgent) Run(_ context.Context, input *adk.AgentInput, opts ...adk.AgentRunOption) *adk.AsyncIterator[*adk.AgentEvent] {
	if input != nil {
		a.runMessages = input.Messages
	}
	a.runOpts = len(opts)
	iter, gen := adk.NewAsyncIteratorPair[*adk.AgentEvent]()
	gen.Close()
	return iter
}

func TestEinoRunRuntimeSessionStartsRunner(t *testing.T) {
	agent := &fakeRuntimeSessionAgent{}
	drain := newEinoRunEventDrain(einoRunEventDrainConfig{
		ConversationID:   "conv-1",
		OrchMode:         "deep",
		OrchestratorName: "lead",
		BaseMessages:     []adk.Message{schema.UserMessage("base")},
	})
	session := newEinoRunRuntimeSession(einoRunRuntimeSessionConfig{
		Context: context.Background(),
		Args: &einoADKRunLoopArgs{
			ConversationID:   "conv-1",
			OrchMode:         "deep",
			OrchestratorName: "lead",
			DA:               agent,
		},
		Drain:        drain,
		BaseMessages: []adk.Message{schema.UserMessage("base")},
		EmptyHint:    "empty",
	})
	defer session.Close()

	if session.Iterator() == nil {
		t.Fatal("session should start an iterator")
	}
	if len(agent.runMessages) != 1 || agent.runMessages[0].Content != "base" {
		t.Fatalf("run messages = %#v", agent.runMessages)
	}
	if agent.runOpts != 1 {
		t.Fatalf("run opts = %d, want native cancel option", agent.runOpts)
	}
}

func TestEinoRunRuntimeSessionCompletionFlushesPending(t *testing.T) {
	agent := &fakeRuntimeSessionAgent{}
	var events []string
	drain := newEinoRunEventDrain(einoRunEventDrainConfig{
		ConversationID:   "conv-1",
		OrchMode:         "deep",
		OrchestratorName: "lead",
		Progress: func(eventType, _ string, _ interface{}) {
			events = append(events, eventType)
		},
		BaseMessages: []adk.Message{schema.UserMessage("base")},
	})
	session := newEinoRunRuntimeSession(einoRunRuntimeSessionConfig{
		Context: context.Background(),
		Args: &einoADKRunLoopArgs{
			ConversationID:   "conv-1",
			OrchMode:         "deep",
			OrchestratorName: "lead",
			Progress: func(eventType, _ string, _ interface{}) {
				events = append(events, eventType)
			},
			DA: agent,
		},
		Drain:        drain,
		BaseMessages: []adk.Message{schema.UserMessage("base")},
		EmptyHint:    "empty",
	})
	defer session.Close()

	drain.PendingToolCalls().Mark(toolCallPendingInfo{
		ToolCallID: "call-1",
		ToolName:   "execute",
		EinoAgent:  "lead",
		EinoRole:   "orchestrator",
	})
	completed, result, err := session.HandleIteratorEnd()

	if !completed || result != nil || err != nil {
		t.Fatalf("completed=%v result=%#v err=%v", completed, result, err)
	}
	if !containsString(events, "tool_result") || !containsString(events, "eino_pending_orphaned") {
		t.Fatalf("events = %#v, want orphan pending flush", events)
	}
	// 孤儿 pending 是事件观测缺口，不应压制框架完成信号（官方 ReAct 语义：干净结束即完成）。
	if snap := drain.Completion().Snapshot(); snap.State != CompletionSucceeded || snap.Signal != "framework_completed" {
		t.Fatalf("completion snapshot = %#v, want framework_completed", snap)
	}
}

func TestEinoRunRuntimeSessionReconcilesDeliveredPendingFromModelTrace(t *testing.T) {
	agent := &fakeRuntimeSessionAgent{}
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
	drain := newEinoRunEventDrain(einoRunEventDrainConfig{
		ConversationID:   "conv-1",
		OrchMode:         "eino_single",
		OrchestratorName: "lead",
		Progress:         progress,
		BaseMessages:     []adk.Message{schema.UserMessage("base")},
	})
	trace := newModelFacingTraceHolder()
	trace.storeFromState(&adk.ChatModelAgentState{Messages: []adk.Message{
		schema.UserMessage("base"),
		{Role: schema.Tool, ToolCallID: "call-typo", ToolName: "execute-python-cript", Content: "tool-error: unknown tool reminder"},
	}})
	session := newEinoRunRuntimeSession(einoRunRuntimeSessionConfig{
		Context: context.Background(),
		Args: &einoADKRunLoopArgs{
			ConversationID:   "conv-1",
			OrchMode:         "eino_single",
			OrchestratorName: "lead",
			Progress:         progress,
			DA:               agent,
			ModelFacingTrace: trace,
		},
		Drain:        drain,
		BaseMessages: []adk.Message{schema.UserMessage("base")},
		EmptyHint:    "empty",
	})
	defer session.Close()

	drain.PendingToolCalls().Mark(toolCallPendingInfo{
		ToolCallID: "call-typo",
		ToolName:   "execute-python-cript",
		EinoAgent:  "lead",
		EinoRole:   "orchestrator",
	})
	completed, _, _ := session.HandleIteratorEnd()
	if !completed {
		t.Fatal("iterator end should complete the run")
	}
	if drain.PendingToolCalls().Count() != 0 {
		t.Fatalf("pending count = %d, want 0", drain.PendingToolCalls().Count())
	}
	var reconciled map[string]interface{}
	for _, ev := range events {
		if ev.eventType == "tool_result" {
			reconciled = ev.data
		}
	}
	if reconciled == nil || reconciled["toolCallId"] != "call-typo" || reconciled["reconciledFromModelTrace"] != true {
		t.Fatalf("reconciled tool_result = %#v", reconciled)
	}
	for _, ev := range events {
		if ev.eventType == "eino_pending_orphaned" {
			t.Fatal("delivered pending must not be force-closed")
		}
	}
	if snap := drain.Completion().Snapshot(); snap.State != CompletionSucceeded {
		t.Fatalf("completion snapshot = %#v, want succeeded", snap)
	}
}

func TestEinoRunRuntimeSessionMarksCleanFrameworkCompletionForEveryMode(t *testing.T) {
	tests := []struct {
		orchMode string
		state    CompletionState
		signal   string
	}{
		{orchMode: "plan_execute", state: CompletionSucceeded, signal: "plan_completed"},
		{orchMode: "deep", state: CompletionSucceeded, signal: "framework_completed"},
		{orchMode: "supervisor", state: CompletionSucceeded, signal: "framework_completed"},
		{orchMode: "eino_single", state: CompletionSucceeded, signal: "framework_completed"},
	}
	for _, tt := range tests {
		t.Run(tt.orchMode, func(t *testing.T) {
			agent := &fakeRuntimeSessionAgent{}
			drain := newEinoRunEventDrain(einoRunEventDrainConfig{
				ConversationID:   "conv-completion",
				OrchMode:         tt.orchMode,
				OrchestratorName: "lead",
				BaseMessages:     []adk.Message{schema.UserMessage("base")},
			})
			session := newEinoRunRuntimeSession(einoRunRuntimeSessionConfig{
				Context: context.Background(),
				Args: &einoADKRunLoopArgs{
					ConversationID:   "conv-completion",
					OrchMode:         tt.orchMode,
					OrchestratorName: "lead",
					DA:               agent,
				},
				Drain:        drain,
				BaseMessages: []adk.Message{schema.UserMessage("base")},
				EmptyHint:    "empty",
			})
			defer session.Close()

			completed, result, err := session.HandleIteratorEnd()
			if !completed || result != nil || err != nil {
				t.Fatalf("completed=%v result=%#v err=%v", completed, result, err)
			}
			got := drain.Completion().Snapshot()
			if got.State != tt.state || got.Signal != tt.signal {
				t.Fatalf("completion = %+v, want state=%q signal=%q", got, tt.state, tt.signal)
			}
		})
	}
}

// TestEinoRunRuntimeSessionMarksCompletionDespiteOrphanedTool 行为回归（2026-08 生产事故）：
// 未知工具（UnknownToolsHandler）路径不产生 ADK 工具事件，其 pending 只能靠模型侧轨迹对账，
// 对账后仍残留的 pending 属事件观测缺口而非真实在途执行。干净结束的迭代器必须标记完成，
// 否则 missing_completion_signal 会丢弃模型的最终答复。真实运行中的后台 MCP 执行由
// agentfinalizer 基于 DB 状态（ReasonPendingTools）单独拦截。
func TestEinoRunRuntimeSessionMarksCompletionDespiteOrphanedTool(t *testing.T) {
	agent := &fakeRuntimeSessionAgent{}
	drain := newEinoRunEventDrain(einoRunEventDrainConfig{
		ConversationID:   "conv-orphan",
		OrchMode:         "plan_execute",
		OrchestratorName: "planner",
		BaseMessages:     []adk.Message{schema.UserMessage("base")},
	})
	session := newEinoRunRuntimeSession(einoRunRuntimeSessionConfig{
		Context: context.Background(),
		Args: &einoADKRunLoopArgs{
			ConversationID:   "conv-orphan",
			OrchMode:         "plan_execute",
			OrchestratorName: "planner",
			DA:               agent,
		},
		Drain:        drain,
		BaseMessages: []adk.Message{schema.UserMessage("base")},
		EmptyHint:    "empty",
	})
	defer session.Close()

	drain.PendingToolCalls().Mark(toolCallPendingInfo{
		ToolCallID: "orphan-call",
		ToolName:   "execute",
		EinoAgent:  "executor",
		EinoRole:   "orchestrator",
	})
	completed, result, err := session.HandleIteratorEnd()
	if !completed || result != nil || err != nil {
		t.Fatalf("completed=%v result=%#v err=%v", completed, result, err)
	}
	got := drain.Completion().Snapshot()
	if got.State != CompletionSucceeded || got.Signal != "plan_completed" {
		t.Fatalf("orphaned pending must not suppress plan completion, got %+v", got)
	}
}

func TestEinoRunRuntimeSessionCancellationReturnsPartialError(t *testing.T) {
	agent := &fakeRuntimeSessionAgent{}
	var events []string
	drain := newEinoRunEventDrain(einoRunEventDrainConfig{
		ConversationID:   "conv-1",
		OrchMode:         "deep",
		OrchestratorName: "lead",
		Progress: func(eventType, _ string, _ interface{}) {
			events = append(events, eventType)
		},
		BaseMessages: []adk.Message{schema.UserMessage("base")},
	})
	session := newEinoRunRuntimeSession(einoRunRuntimeSessionConfig{
		Context: context.Background(),
		Args: &einoADKRunLoopArgs{
			ConversationID:   "conv-1",
			OrchMode:         "deep",
			OrchestratorName: "lead",
			Progress: func(eventType, _ string, _ interface{}) {
				events = append(events, eventType)
			},
			DA: agent,
		},
		Drain:        drain,
		BaseMessages: []adk.Message{schema.UserMessage("base")},
		EmptyHint:    "empty",
	})
	defer session.Close()

	stopErr := errors.New("stop")
	result, err := session.HandleIteratorContextError(stopErr)

	if result != nil {
		t.Fatalf("result = %#v, want nil without new messages", result)
	}
	if !errors.Is(err, stopErr) {
		t.Fatalf("err = %v, want %v", err, stopErr)
	}
	if !containsString(events, "error") {
		t.Fatalf("events = %#v, want cancellation error event", events)
	}
}

func TestEinoRunRuntimeSessionHandleRunErrorSwallowsTurnLoopPreempt(t *testing.T) {
	agent := &fakeRuntimeSessionAgent{}
	var events []string
	drain := newEinoRunEventDrain(einoRunEventDrainConfig{
		ConversationID:   "conv-1",
		OrchMode:         "deep",
		OrchestratorName: "lead",
		Progress: func(eventType, _ string, _ interface{}) {
			events = append(events, eventType)
		},
		BaseMessages: []adk.Message{schema.UserMessage("base")},
	})
	session := newEinoRunRuntimeSession(einoRunRuntimeSessionConfig{
		Context: context.Background(),
		Args: &einoADKRunLoopArgs{
			ConversationID:   "conv-1",
			OrchMode:         "deep",
			OrchestratorName: "lead",
			Progress: func(eventType, _ string, _ interface{}) {
				events = append(events, eventType)
			},
			DA: agent,
		},
		Drain:        drain,
		BaseMessages: []adk.Message{schema.UserMessage("base")},
		EmptyHint:    "empty",
	})
	defer session.Close()

	got := session.HandleRunError(adk.ErrStreamCanceled)
	if got.Restarted || got.Result != nil || got.Err != nil {
		t.Fatalf("result = %+v, want swallowed preempt", got)
	}
	if containsString(events, "error") || containsString(events, "eino_usage_summary") {
		t.Fatalf("events = %#v, want no fatal/partial events", events)
	}
}

func TestEinoRunRuntimeSessionBuildFinalEmitsUsageSummary(t *testing.T) {
	agent := &fakeRuntimeSessionAgent{}
	var usageEvent map[string]interface{}
	progress := func(eventType, _ string, data interface{}) {
		if eventType != "eino_usage_summary" {
			return
		}
		usageEvent, _ = data.(map[string]interface{})
	}
	drain := newEinoRunEventDrain(einoRunEventDrainConfig{
		ConversationID:   "conv-1",
		OrchMode:         "deep",
		OrchestratorName: "lead",
		Progress:         progress,
		BaseMessages:     []adk.Message{schema.UserMessage("base")},
	})
	session := newEinoRunRuntimeSession(einoRunRuntimeSessionConfig{
		Context: context.Background(),
		Args: &einoADKRunLoopArgs{
			ConversationID:   "conv-1",
			OrchMode:         "deep",
			OrchestratorName: "lead",
			Progress:         progress,
			DA:               agent,
		},
		Drain:        drain,
		BaseMessages: []adk.Message{schema.UserMessage("base")},
		EmptyHint:    "empty",
	})
	defer session.Close()

	drain.Usage().AddUsage(&schema.TokenUsage{PromptTokens: 3, CompletionTokens: 4, TotalTokens: 7})
	_ = session.BuildFinalResult()

	if usageEvent == nil {
		t.Fatal("usage summary event was not emitted")
	}
	if usageEvent["conversationId"] != "conv-1" || usageEvent["orchestration"] != "deep" || usageEvent["reason"] != "final" || usageEvent["totalTokens"] != 7 {
		t.Fatalf("usage event = %#v", usageEvent)
	}
}
