package mcp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
)

func TestApprovalGuardRunsAfterAuthorizationAndExecutesFrozenCallOnce(t *testing.T) {
	server := NewServer(zap.NewNop())
	var authorized atomic.Bool
	var guarded atomic.Int32
	var executed atomic.Int32
	server.SetToolAuthorizer(func(context.Context, string, map[string]interface{}) error {
		authorized.Store(true)
		return nil
	})
	server.SetInvocationGuard(func(ctx context.Context, toolName string, args map[string]interface{}) (context.Context, map[string]interface{}, error) {
		if !authorized.Load() {
			t.Fatal("guard ran before authorization")
		}
		guarded.Add(1)
		return ctx, map[string]interface{}{"command": "frozen"}, nil
	})
	server.RegisterTool(Tool{Name: "exec"}, func(_ context.Context, args map[string]interface{}) (*ToolResult, error) {
		executed.Add(1)
		if args["command"] != "frozen" {
			t.Fatalf("handler args = %+v", args)
		}
		return &ToolResult{Content: []Content{{Type: "text", Text: "ok"}}}, nil
	})

	result, _, err := server.CallTool(context.Background(), "exec", map[string]interface{}{"command": "original"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("CallTool result=%+v err=%v", result, err)
	}
	if guarded.Load() != 1 || executed.Load() != 1 {
		t.Fatalf("guarded=%d executed=%d", guarded.Load(), executed.Load())
	}
}

func TestApprovalGuardRejectsWithoutExecution(t *testing.T) {
	server := NewServer(zap.NewNop())
	var executed atomic.Int32
	server.SetInvocationGuard(func(context.Context, string, map[string]interface{}) (context.Context, map[string]interface{}, error) {
		return nil, nil, errors.New("approval rejected")
	})
	server.RegisterTool(Tool{Name: "exec"}, func(context.Context, map[string]interface{}) (*ToolResult, error) {
		executed.Add(1)
		return &ToolResult{}, nil
	})

	_, _, err := server.CallTool(context.Background(), "exec", nil)
	if err == nil || !strings.Contains(err.Error(), "approval rejected") {
		t.Fatalf("CallTool error = %v", err)
	}
	if executed.Load() != 0 {
		t.Fatalf("executions = %d", executed.Load())
	}
}

func TestApprovalGuardCompletionRunsOnce(t *testing.T) {
	server := NewServer(zap.NewNop())
	var completed atomic.Int32
	server.SetInvocationGuard(func(ctx context.Context, _ string, args map[string]interface{}) (context.Context, map[string]interface{}, error) {
		ctx = WithInvocationCompletion(ctx, func(_ context.Context, _ string, _ map[string]interface{}, result *ToolResult, err error) {
			if err != nil || result == nil || result.IsError {
				t.Fatalf("completion result=%+v err=%v", result, err)
			}
			completed.Add(1)
		})
		return ctx, args, nil
	})
	server.RegisterTool(Tool{Name: "exec"}, func(context.Context, map[string]interface{}) (*ToolResult, error) {
		return &ToolResult{Content: []Content{{Type: "text", Text: "ok"}}}, nil
	})
	if _, _, err := server.CallTool(context.Background(), "exec", nil); err != nil {
		t.Fatal(err)
	}
	if completed.Load() != 1 {
		t.Fatalf("completion calls = %d", completed.Load())
	}
}

func TestDirectMCPHTTPUsesApprovalGuard(t *testing.T) {
	server := NewServer(zap.NewNop())
	var executed atomic.Int32
	server.SetInvocationGuard(func(ctx context.Context, _ string, args map[string]interface{}) (context.Context, map[string]interface{}, error) {
		return ctx, args, nil
	})
	server.RegisterTool(Tool{Name: "exec"}, func(context.Context, map[string]interface{}) (*ToolResult, error) {
		executed.Add(1)
		return &ToolResult{Content: []Content{{Type: "text", Text: "ok"}}}, nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{}}}`))
	w := httptest.NewRecorder()
	server.HandleHTTP(w, req)
	if w.Code != http.StatusOK || executed.Load() != 1 {
		t.Fatalf("HTTP status=%d body=%s executions=%d", w.Code, w.Body.String(), executed.Load())
	}
}

func TestExternalMCPUsesApprovalGuard(t *testing.T) {
	manager := NewExternalMCPManager(zap.NewNop())
	t.Cleanup(manager.StopAll)
	client := &approvalGuardExternalClient{}
	manager.clients["lab"] = client
	manager.SetInvocationGuard(func(ctx context.Context, _ string, args map[string]interface{}) (context.Context, map[string]interface{}, error) {
		return ctx, map[string]interface{}{"target": "frozen"}, nil
	})
	result, _, err := manager.CallTool(context.Background(), "lab::danger", map[string]interface{}{"target": "original"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("CallTool result=%+v err=%v", result, err)
	}
	if client.calls.Load() != 1 || client.target != "frozen" {
		t.Fatalf("calls=%d target=%q", client.calls.Load(), client.target)
	}
}

type approvalGuardExternalClient struct {
	calls  atomic.Int32
	target string
}

func (c *approvalGuardExternalClient) Initialize(context.Context) error          { return nil }
func (c *approvalGuardExternalClient) ListTools(context.Context) ([]Tool, error) { return nil, nil }
func (c *approvalGuardExternalClient) CallTool(_ context.Context, _ string, args map[string]interface{}) (*ToolResult, error) {
	c.calls.Add(1)
	c.target, _ = args["target"].(string)
	return &ToolResult{Content: []Content{{Type: "text", Text: "ok"}}}, nil
}
func (c *approvalGuardExternalClient) Close() error      { return nil }
func (c *approvalGuardExternalClient) IsConnected() bool { return true }
func (c *approvalGuardExternalClient) GetStatus() string { return "connected" }
