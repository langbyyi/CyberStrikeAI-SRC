package workflow

import (
	"context"
	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"go.uber.org/zap"
	"strings"
	"testing"
	"time"
)

func TestWorkflowToolContextHonorsConfiguredAndParentDeadlines(t *testing.T) {
	before := time.Now()
	ctx, cancel, err := workflowToolContext(context.Background(), "2")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(before.Add(2*time.Second)) || deadline.After(time.Now().Add(2*time.Second)) {
		t.Fatalf("unexpected deadline: %v", deadline)
	}
	parent, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	child, cleanup, err := workflowToolContext(parent, "2")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	<-child.Done()
	if child.Err() != context.DeadlineExceeded {
		t.Fatalf("parent deadline lost: %v", child.Err())
	}
}

func TestWorkflowToolContextRejectsInvalidAndPreservesUnset(t *testing.T) {
	for _, raw := range []string{"0", "-1", "1.5", "9223372036854775807"} {
		if _, _, err := workflowToolContext(context.Background(), raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	ctx, cancel, err := workflowToolContext(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("invented deadline for unset configuration")
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("context cancellation lost")
	}
}

func TestRunToolNodeAppliesTimeoutToActualMCPExecution(t *testing.T) {
	logger := zap.NewNop()
	server := mcp.NewServer(logger)
	observedDeadline := make(chan time.Time, 1)
	server.RegisterTool(mcp.Tool{Name: "test-only-slow-tool", InputSchema: map[string]interface{}{"type": "object"}}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("tool did not receive configured deadline")
		}
		observedDeadline <- deadline
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ag := agent.NewAgent(&config.OpenAIConfig{APIKey: "test-only-key", Model: "test-only-model"}, &config.AgentConfig{}, server, nil, logger, 1)
	node := graphNode{ID: "tool-1", Type: "tool", Config: map[string]interface{}{"tool_name": "test-only-slow-tool", "timeout_seconds": "1"}}
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	output, proceed, status, errText := runToolNode(parent, RunArgs{Agent: ag, ConversationID: "test-only-conversation"}, node, newWorkflowLocalState(nil, "test-only-run"))
	if proceed || status != "failed" || !strings.Contains(errText, "deadline exceeded") {
		t.Fatalf("timeout became success: %v %s %s %#v", proceed, status, errText, output)
	}
	if time.Since(start) >= 3*time.Second {
		t.Fatal("configured timeout not applied")
	}
	select {
	case deadline := <-observedDeadline:
		if deadline.After(start.Add(2 * time.Second)) {
			t.Fatal("tool inherited only parent timeout")
		}
	default:
		t.Fatal("actual MCP handler was not executed")
	}
}

func TestFailedToolOutputDoesNotClaimCompletedStatus(t *testing.T) {
	out := toolOutputMap(graphNode{ID: "tool-1", Type: "tool"}, "tool failed", "lookup", nil, "exec-1", true)
	if out["status"] != "failed" {
		t.Fatalf("failed output claimed success: %#v", out)
	}
	typed, ok := out["typed"].(ToolOutput)
	if !ok || typed.Status != "failed" || !typed.IsError {
		t.Fatalf("typed output disagrees with failure: %#v", out["typed"])
	}
}
