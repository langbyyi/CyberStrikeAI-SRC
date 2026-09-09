package multiagent

import (
	"context"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/toolguard"

	"go.uber.org/zap"
)

func TestEinoToolResultPreservesBlockedOutcomeAfterTextReduction(t *testing.T) {
	for _, blocked := range []bool{true, false} {
		name := "execution_error"
		if blocked {
			name = "safety_block"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			logger := zap.NewNop()
			server := mcp.NewServer(logger)
			guard, err := toolguard.NewManager(toolguard.DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}
			server.SetToolGuard(guard)
			calls := 0
			server.RegisterTool(mcp.Tool{Name: "inspect"}, func(context.Context, map[string]interface{}) (*mcp.ToolResult, error) {
				calls++
				return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "execution failed"}}, IsError: true}, nil
			})
			ag := agent.NewAgent(&config.OpenAIConfig{}, &config.AgentConfig{}, server, nil, logger, 1)
			target := "example.org"
			if blocked {
				target = "example.gov"
			}
			result, err := ag.ExecuteMCPToolForConversation(ctx, "conv-block", "inspect", map[string]interface{}{"target": target})
			if err != nil || result == nil || !result.IsError || result.Blocked != blocked {
				t.Fatalf("agent result = %#v, error = %v", result, err)
			}
			if blocked && calls != 0 || !blocked && calls != 1 {
				t.Fatalf("handler calls = %d, blocked = %v", calls, blocked)
			}
			binder := NewMCPExecutionBinder()
			binder.Bind("call-block", result.ExecutionID)
			var event map[string]interface{}
			emitter := newEinoToolResultProgressEmitter(einoToolResultProgressEmitterConfig{
				FilesystemMonitorAgent: ag,
				MCPExecutionBinder:     binder,
				Progress: func(eventType, _ string, data interface{}) {
					if eventType == "tool_result" {
						event = data.(map[string]interface{})
					}
				},
			})
			// The reduced text deliberately contains no refusal wording. A blocked
			// outcome must survive even if reduction also loses the error prefix.
			const reduced = "The request did not run."
			if !emitter.Emit(ctx, "inspect", reduced, "call-block", !blocked, "worker") {
				t.Fatal("missing tool result event")
			}
			if event["success"] != false || event["isError"] != true || event["result"] != reduced {
				t.Fatalf("event = %#v", event)
			}
			if blocked && (event["blocked"] != true || event["status"] != "blocked" || event["executionId"] != result.ExecutionID) {
				t.Fatalf("blocked event lost its classification: %#v", event)
			}
			if !blocked && event["blocked"] != nil {
				t.Fatalf("ordinary failure was classified as blocked: %#v", event)
			}
			exec, ok := server.GetExecution(result.ExecutionID)
			if !ok || exec.Result == nil || !exec.Result.IsError || exec.Result.Blocked != blocked {
				t.Fatalf("display update lost result flags: %#v", exec)
			}
			wantStatus := "failed"
			if blocked {
				wantStatus = "blocked"
			}
			if ag.MCPExecutionStatus(result.ExecutionID) != wantStatus {
				t.Fatalf("execution status = %q, want %q", exec.Status, wantStatus)
			}
		})
	}
}
