package multiagent

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

type CompletionState string

const (
	CompletionUnsignaled   CompletionState = "unsignaled"
	CompletionSucceeded    CompletionState = "succeeded"
	CompletionBlocked      CompletionState = "blocked"
	CompletionFailed       CompletionState = "failed"
	CompletionCancelled    CompletionState = "cancelled"
	CompletionAwaitingHITL CompletionState = "awaiting_hitl"
)

type einoCompletionSnapshot struct {
	State         CompletionState
	Signal        string
	FinalResponse string
}

type einoCompletionTracker struct {
	mu                   sync.RWMutex
	orchMode             string
	rootAgent            string
	pendingFinalResponse string
	snapshot             einoCompletionSnapshot
}

func newEinoCompletionTracker(orchMode, rootAgent string) *einoCompletionTracker {
	return &einoCompletionTracker{
		orchMode:  strings.TrimSpace(orchMode),
		rootAgent: strings.TrimSpace(rootAgent),
		snapshot:  einoCompletionSnapshot{State: CompletionUnsignaled},
	}
}

func (t *einoCompletionTracker) Observe(agentName string, msg adk.Message) {
	if t == nil || msg == nil || !t.isRoot(agentName) {
		return
	}
	if final := einoExtractExitFinalFromAssistantToolCalls(msg); final != "" {
		t.mu.Lock()
		t.pendingFinalResponse = final
		t.mu.Unlock()
		return
	}
	if !strings.EqualFold(strings.TrimSpace(msg.ToolName), adk.ToolInfoExit.Name) {
		return
	}
	result := strings.TrimSpace(msg.Content)
	if result == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if result != t.pendingFinalResponse {
		return
	}
	t.snapshot = einoCompletionSnapshot{
		State:         CompletionSucceeded,
		Signal:        "exit",
		FinalResponse: result,
	}
}

func (t *einoCompletionTracker) MarkFrameworkCompleted() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// An executed root exit is the strongest completion signal and carries the
	// authoritative final response. A clean framework shutdown must not replace it.
	if t.snapshot.State == CompletionSucceeded && strings.TrimSpace(t.snapshot.Signal) != "" {
		return
	}
	t.snapshot.State = CompletionSucceeded
	if strings.EqualFold(t.orchMode, "plan_execute") {
		t.snapshot.Signal = "plan_completed"
		return
	}
	t.snapshot.Signal = "framework_completed"
}

func (t *einoCompletionTracker) Snapshot() einoCompletionSnapshot {
	if t == nil {
		return einoCompletionSnapshot{State: CompletionUnsignaled}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.snapshot
}

func (t *einoCompletionTracker) isRoot(agentName string) bool {
	agentName = strings.TrimSpace(agentName)
	return agentName == "" || strings.EqualFold(agentName, t.rootAgent)
}

func withEinoExitTool(cfg adk.ToolsConfig) adk.ToolsConfig {
	cfg.Tools = append(append([]tool.BaseTool(nil), cfg.Tools...), &einoAgenticExitTool{})
	returnDirectly := make(map[string]bool, len(cfg.ReturnDirectly)+1)
	for name, enabled := range cfg.ReturnDirectly {
		returnDirectly[name] = enabled
	}
	returnDirectly[adk.ToolInfoExit.Name] = true
	cfg.ReturnDirectly = returnDirectly
	return cfg
}

// einoAgenticExitTool mirrors adk.ExitTool's schema but relies on ReturnDirectly
// instead of adk.SendToolGenAction, which is not compatible with AgenticMessage
// state in Eino v0.9.14.
type einoAgenticExitTool struct{}

func (*einoAgenticExitTool) Info(context.Context) (*schema.ToolInfo, error) {
	return adk.ToolInfoExit, nil
}

func (*einoAgenticExitTool) InvokableRun(_ context.Context, arguments string, _ ...tool.Option) (string, error) {
	final := einoParseExitFinalResultArguments(arguments)
	if final == "" {
		return "", errors.New("exit final_result is required")
	}
	return final, nil
}

func einoExplicitCompletionInstruction(orchMode string) string {
	if strings.EqualFold(strings.TrimSpace(orchMode), "plan_execute") {
		return ""
	}
	return `## 最终交付协议

- 计划、推理、进度说明和工具调用前导语都只是过程信息，不能结束任务。
- 只有用户目标真正完成并形成完整答复时，才调用 exit，并把完整最终答复放入 final_result。
- 纯知识问答可以直接调用 exit，无需为了结束而调用任何外部工具。
- 若任务仍可继续，继续执行；若确实受阻，在 final_result 中明确说明已完成部分和阻塞原因后调用 exit。`
}
