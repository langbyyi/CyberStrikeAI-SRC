package multiagent

import (
	"context"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

type scriptedFinalizeAgent struct {
	mu        sync.Mutex
	responses []string
	runs      int
	panicRun  bool
}

func (a *scriptedFinalizeAgent) Name(context.Context) string        { return "orchestrator" }
func (a *scriptedFinalizeAgent) Description(context.Context) string { return "test agent" }

func (a *scriptedFinalizeAgent) Run(
	context.Context,
	*adk.AgentInput,
	...adk.AgentRunOption,
) *adk.AsyncIterator[*adk.AgentEvent] {
	a.mu.Lock()
	if a.panicRun {
		a.mu.Unlock()
		panic("scripted runner panic")
	}
	index := a.runs
	a.runs++
	response := a.responses[len(a.responses)-1]
	if index < len(a.responses) {
		response = a.responses[index]
	}
	a.mu.Unlock()

	iter, generator := adk.NewAsyncIteratorPair[*adk.AgentEvent]()
	go func() {
		generator.Send(adk.EventFromMessage(
			schema.AssistantMessage(response, nil),
			nil,
			schema.Assistant,
			"",
		))
		generator.Close()
	}()
	return iter
}

func TestRunEinoADKAgentLoopReturnsRecoveredPanic(t *testing.T) {
	result, err := runEinoADKAgentLoop(context.Background(), &einoADKRunLoopArgs{
		OrchMode:         "deep",
		OrchestratorName: "orchestrator",
		ConversationID:   "panic-run",
		DA:               &scriptedFinalizeAgent{panicRun: true},
	}, []adk.Message{schema.UserMessage("test")})
	if err == nil || !strings.Contains(err.Error(), "runner panic") {
		t.Fatalf("runEinoADKAgentLoop() = (%#v, %v), want recovered panic error", result, err)
	}
	if result != nil {
		t.Fatalf("result = %#v, want nil after panic", result)
	}
}

func (a *scriptedFinalizeAgent) RunCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.runs
}

func TestRunEinoADKAgentLoopContinuesBlockedFinalization(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	const conversationID = "finalize-continuation"
	GetConversationExecutionState(conversationID).UpsertCoverage(CoverageItem{
		Path:     "auth.login",
		Status:   "open",
		Priority: "P0",
	})
	agent := &scriptedFinalizeAgent{responses: []string{
		"测试完成，未发现漏洞。",
		"登录接口差分验证已执行，以下是已验证范围和证据。",
	}}
	enabled := true
	result, err := runEinoADKAgentLoop(context.Background(), &einoADKRunLoopArgs{
		OrchMode:         "deep",
		OrchestratorName: "orchestrator",
		ConversationID:   conversationID,
		DA:               agent,
		MwCfg: &config.MultiAgentEinoMiddlewareConfig{
			FinalizeGateEnable: &enabled,
		},
	}, []adk.Message{schema.UserMessage("测试目标")})
	if err != nil {
		t.Fatalf("runEinoADKAgentLoop() error = %v", err)
	}
	if agent.RunCount() != 2 {
		t.Fatalf("agent runs = %d, want 2", agent.RunCount())
	}
	if !strings.Contains(result.Response, "差分验证已执行") {
		t.Fatalf("response = %q, want second run response", result.Response)
	}
	if strings.Contains(result.Response, "finalize_gate_blocked") {
		t.Fatalf("response leaks internal gate marker: %q", result.Response)
	}
}

func TestRunEinoADKAgentLoopBoundsFinalizeContinuation(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	const conversationID = "finalize-continuation-limit"
	GetConversationExecutionState(conversationID).UpsertCoverage(CoverageItem{
		Path:     "auth.login",
		Status:   "open",
		Priority: "P0",
	})
	agent := &scriptedFinalizeAgent{responses: []string{"测试完成，未发现漏洞。"}}
	enabled := true
	result, err := runEinoADKAgentLoop(context.Background(), &einoADKRunLoopArgs{
		OrchMode:         "deep",
		OrchestratorName: "orchestrator",
		ConversationID:   conversationID,
		DA:               agent,
		MwCfg: &config.MultiAgentEinoMiddlewareConfig{
			FinalizeGateEnable: &enabled,
		},
	}, []adk.Message{schema.UserMessage("测试目标")})
	if err != nil {
		t.Fatalf("runEinoADKAgentLoop() error = %v", err)
	}
	if agent.RunCount() != 1+MaxFinalizeContinuationsPerRun {
		t.Fatalf("agent runs = %d, want %d", agent.RunCount(), 1+MaxFinalizeContinuationsPerRun)
	}
	if !strings.Contains(result.Response, "未闭环") {
		t.Fatalf("response = %q, want continuation limit notice", result.Response)
	}
	if strings.Contains(result.Response, "finalize_gate_blocked") {
		t.Fatalf("response leaks internal gate marker: %q", result.Response)
	}
}
