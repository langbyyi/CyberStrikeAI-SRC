package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

func TestLogicProbeDiff_ToolRejectsEmptyConversation(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerLogicProbeTools(srv, zap.NewNop())
	// Call without conversation context
	res, _, err := srv.CallTool(context.Background(), builtin.ToolLogicProbeDiff, map[string]interface{}{
		"url":  "http://example.invalid/",
		"mode": "identity_diff",
	})
	if err != nil {
		t.Fatalf("CallTool err: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError for empty conversation, got %+v", res)
	}
	text := toolResultText(res)
	if !strings.Contains(text, "conversation_id") {
		t.Fatalf("msg=%q", text)
	}
}

func TestLogicProbeDiff_ToolRejectsEmptyURL(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerLogicProbeTools(srv, zap.NewNop())
	ctx := mcp.WithMCPConversationID(context.Background(), "test-logic-probe-empty-url")
	res, _, err := srv.CallTool(ctx, builtin.ToolLogicProbeDiff, map[string]interface{}{
		"mode": "param_tamper",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(toolResultText(res), "url") {
		t.Fatalf("msg=%s", toolResultText(res))
	}
}

func TestLogicProbeDiff_ToolIdentityViaHTTPTest(t *testing.T) {
	// Drive pure multiagent probe (same as tool body) with httptest — tool registration is structural above.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "A" {
			_, _ = io.WriteString(w, "body-a")
			return
		}
		_, _ = io.WriteString(w, "body-b")
	}))
	defer srv.Close()

	conv := "test-app-logic-probe-id"
	multiagent.ResetConversationExecutionStateForTest(conv)
	// Mirror tool handler dual-auth recording + probe
	multiagent.GetConversationExecutionState(conv).MarkAuthProbe(true, true)
	res := multiagent.RunLogicProbeDiff(context.Background(), multiagent.LogicProbeRequest{
		URL: srv.URL, Mode: multiagent.LogicProbeModeIdentityDiff,
		AuthA: "A", AuthB: "B", AuthHeader: "Authorization",
		Client: srv.Client(),
	})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if res.BodyHashA == res.BodyHashB {
		t.Fatal("expected different bodies")
	}
	if !multiagent.GetConversationExecutionState(conv).HasDualAuthProbe() {
		t.Fatal("dual auth")
	}
}

func TestBuiltinLogicProbeInAlwaysVisibleBoost(t *testing.T) {
	if !builtin.IsBuiltinTool(builtin.ToolLogicProbeDiff) {
		t.Fatal("IsBuiltinTool")
	}
	found := false
	for _, n := range builtin.GetAllBuiltinTools() {
		if n == builtin.ToolLogicProbeDiff {
			found = true
		}
	}
	if !found {
		t.Fatal("GetAllBuiltinTools missing logic_probe_diff")
	}
}

func TestLogicProbeDiff_RegisteredDescriptionBusinessFirst(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerLogicProbeTools(srv, zap.NewNop())
	var desc string
	for _, tl := range srv.GetAllTools() {
		if tl.Name == builtin.ToolLogicProbeDiff {
			desc = tl.Description
			break
		}
	}
	if desc == "" {
		t.Fatal("tool not registered")
	}
	// Shipped MCP description must centre payment/workflow, not dual-auth entry.
	for _, kw := range []string{"支付", "param_tamper", "流程"} {
		if !strings.Contains(desc, kw) {
			t.Fatalf("missing %q in description: %s", kw, desc)
		}
	}
	// auth_a/auth_b not in required — schema required is only url
	if strings.Contains(desc, "auth_a 必填") {
		t.Fatal("auth must not be required in description")
	}
	if !strings.Contains(desc, multiagent.LogicProbeRecommendedOrder) &&
		!strings.Contains(desc, "param_tamper") {
		t.Fatal("recommended business-first order expected")
	}
}
