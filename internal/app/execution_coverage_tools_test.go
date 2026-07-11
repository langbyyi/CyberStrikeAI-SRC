package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

func toolNameSet(tools []mcp.Tool) map[string]struct{} {
	out := make(map[string]struct{}, len(tools))
	for _, t := range tools {
		out[t.Name] = struct{}{}
	}
	return out
}

func TestRegisterExecutionCoverageTools_PresentAfterClearAndReregister(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerExecutionCoverageTools(srv, zap.NewNop())

	names := toolNameSet(srv.GetAllTools())
	for _, want := range ExecutionCoverageToolNames {
		if _, ok := names[want]; !ok {
			t.Fatalf("after first register missing %q", want)
		}
	}

	// Simulate ApplyConfig: ClearTools then re-register via the same helper
	// used by vulnerabilityRegistrar / registerCoreSessionTools.
	srv.ClearTools()
	if n := len(srv.GetAllTools()); n != 0 {
		t.Fatalf("after ClearTools want 0 tools, got %d", n)
	}

	registerExecutionCoverageTools(srv, zap.NewNop())
	names = toolNameSet(srv.GetAllTools())
	for _, want := range []string{
		builtin.ToolUpsertExecutionCoverage,
		builtin.ToolGetExecutionCoverage,
		builtin.ToolShouldContinueExecution,
	} {
		if _, ok := names[want]; !ok {
			t.Fatalf("after ClearTools+re-register missing coverage tool %q; tools=%v", want, names)
		}
	}
}

func TestRegisterCoreSessionTools_SourceWiresCoverageOnApplyPath(t *testing.T) {
	// Structural: app.go ApplyConfig registrar must call registerCoreSessionTools
	// (which includes coverage), not a subset that drops gate tools.
	src, err := os.ReadFile(filepath.Join("app.go"))
	if err != nil {
		t.Fatalf("read app.go: %v", err)
	}
	text := string(src)
	if !strings.Contains(text, "registerCoreSessionTools(mcpServer, db, cfg, log.Logger)") {
		t.Fatal("app.go must call registerCoreSessionTools on startup and ApplyConfig path")
	}
	// Registrar body should not re-list a partial set without coverage.
	if strings.Count(text, "registerCoreSessionTools") < 2 {
		t.Fatalf("registerCoreSessionTools should be used at least twice (New + ApplyConfig registrar), got %d",
			strings.Count(text, "registerCoreSessionTools"))
	}
	// core_session_tools.go must include coverage registration
	core, err := os.ReadFile(filepath.Join("core_session_tools.go"))
	if err != nil {
		t.Fatalf("read core_session_tools.go: %v", err)
	}
	if !strings.Contains(string(core), "registerExecutionCoverageTools") {
		t.Fatal("registerCoreSessionTools must call registerExecutionCoverageTools")
	}
	if !strings.Contains(string(core), "registerVulnerabilityTools") {
		t.Fatal("registerCoreSessionTools must call registerVulnerabilityTools")
	}
	if !strings.Contains(string(core), "registerLogicProbeTools") {
		t.Fatal("registerCoreSessionTools must call registerLogicProbeTools (logic track)")
	}
}

func TestRegisterLogicProbeTools_PresentAfterClearAndReregister(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerLogicProbeTools(srv, zap.NewNop())
	names := toolNameSet(srv.GetAllTools())
	if _, ok := names[builtin.ToolLogicProbeDiff]; !ok {
		t.Fatal("logic_probe_diff missing after register")
	}
	srv.ClearTools()
	registerLogicProbeTools(srv, zap.NewNop())
	names = toolNameSet(srv.GetAllTools())
	if _, ok := names[builtin.ToolLogicProbeDiff]; !ok {
		t.Fatal("logic_probe_diff missing after ClearTools+re-register")
	}
}

func TestExecutionCoverageTools_RejectEmptyConversationID(t *testing.T) {
	// Criterion C/3: empty conversation_id must return explicit error string,
	// not silently share the multiagent "default" session state.
	srv := mcp.NewServer(zap.NewNop())
	registerExecutionCoverageTools(srv, zap.NewNop())

	// Poison the shared default session; empty-ctx calls must not touch it.
	multiagent.ResetConversationExecutionStateForTest("default")
	multiagent.GetConversationExecutionState("default").UpsertCoverage(multiagent.CoverageItem{
		Path: "poison.default", Status: "open", Priority: "P0",
	})
	before := len(multiagent.GetConversationExecutionState("default").ListCoverage())

	emptyCtx := context.Background()
	tools := []struct {
		name string
		args map[string]interface{}
	}{
		{builtin.ToolUpsertExecutionCoverage, map[string]interface{}{"path": "should.not.write"}},
		{builtin.ToolGetExecutionCoverage, map[string]interface{}{}},
		{builtin.ToolShouldContinueExecution, map[string]interface{}{"intent": "finalize"}},
	}
	for _, tc := range tools {
		res, _, err := srv.CallTool(emptyCtx, tc.name, tc.args)
		if err != nil {
			t.Fatalf("%s CallTool err: %v", tc.name, err)
		}
		if res == nil {
			t.Fatalf("%s nil result", tc.name)
		}
		text := toolResultText(res)
		if !strings.Contains(text, "conversation_id") {
			t.Fatalf("%s must mention conversation_id in error, got: %q", tc.name, text)
		}
		if !res.IsError && !strings.Contains(strings.ToLower(text), "错误") {
			// Prefer IsError=true (same as record_vulnerability)
			t.Fatalf("%s should be error result, IsError=%v text=%q", tc.name, res.IsError, text)
		}
		if !res.IsError {
			t.Fatalf("%s IsError must be true", tc.name)
		}
	}

	after := multiagent.GetConversationExecutionState("default").ListCoverage()
	if len(after) != before {
		t.Fatalf("empty conv must not mutate default session: before=%d after=%d", before, len(after))
	}
	// Ensure upsert did not add should.not.write
	for _, it := range after {
		if it.Path == "should.not.write" {
			t.Fatal("upsert with empty conv wrote into default session")
		}
	}
}

func TestExecutionCoverageTools_WithConversationIDWorks(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerExecutionCoverageTools(srv, zap.NewNop())
	conv := "cov-tool-conv-ok"
	multiagent.ResetConversationExecutionStateForTest(conv)
	ctx := mcp.WithMCPConversationID(context.Background(), conv)

	res, _, err := srv.CallTool(ctx, builtin.ToolUpsertExecutionCoverage, map[string]interface{}{
		"path": "auth.login", "status": "open", "priority": "P0", "note": "probe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("upsert should succeed: %s", toolResultText(res))
	}
	items := multiagent.GetConversationExecutionState(conv).ListCoverage()
	if len(items) != 1 || items[0].Path != "auth.login" {
		t.Fatalf("coverage not written to conv state: %+v", items)
	}

	res2, _, err := srv.CallTool(ctx, builtin.ToolGetExecutionCoverage, map[string]interface{}{})
	if err != nil || res2.IsError {
		t.Fatalf("get: err=%v res=%v", err, res2)
	}
	if !strings.Contains(toolResultText(res2), "auth.login") {
		t.Fatalf("get missing path: %s", toolResultText(res2))
	}

	res3, _, err := srv.CallTool(ctx, builtin.ToolShouldContinueExecution, map[string]interface{}{"intent": "finalize"})
	if err != nil || res3.IsError {
		t.Fatalf("should_continue: err=%v res=%v", err, res3)
	}
	if !strings.Contains(toolResultText(res3), "should_continue=true") {
		t.Fatalf("expected continue: %s", toolResultText(res3))
	}
}

func toolResultText(res *mcp.ToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	// Fallback if Content empty but Text field exists on some versions
	if b.Len() == 0 && res.IsError {
		// still return something searchable
	}
	return b.String()
}

func TestUpsertExecutionCoverage_BreakerRejectsWithoutPollutingState(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerExecutionCoverageTools(srv, zap.NewNop())
	conv := "cov-tool-breaker"
	multiagent.ResetConversationExecutionStateForTest(conv)
	ctx := mcp.WithMCPConversationID(context.Background(), conv)

	// The first MaxRecentUpsertsBeforeWarn-1 calls succeed and write coverage.
	// The next upsert is rejected by the breaker (>= threshold after RecordTool).
	allowed := multiagent.MaxRecentUpsertsBeforeWarn - 1
	for i := 0; i < allowed; i++ {
		res, _, err := srv.CallTool(ctx, builtin.ToolUpsertExecutionCoverage, map[string]interface{}{
			"path": fmt.Sprintf("path.%d", i), "status": "open", "priority": "P1",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("upsert %d should succeed: %s", i, toolResultText(res))
		}
	}
	if n := len(multiagent.GetConversationExecutionState(conv).ListCoverage()); n != allowed {
		t.Fatalf("expected %d coverage items, got %d", allowed, n)
	}

	// Next upsert must be rejected and must NOT add coverage.
	res, _, err := srv.CallTool(ctx, builtin.ToolUpsertExecutionCoverage, map[string]interface{}{
		"path": "path.rejected", "status": "open", "priority": "P1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("expected breaker to reject: %s", toolResultText(res))
	}
	text := toolResultText(res)
	if !strings.Contains(text, "coverage 未写入") {
		t.Fatalf("rejection must state coverage was not written: %s", text)
	}
	if n := len(multiagent.GetConversationExecutionState(conv).ListCoverage()); n != allowed {
		t.Fatalf("rejected call must not write coverage, got %d items want %d", n, allowed)
	}
}

func TestUpsertExecutionCoverage_BreakerSurvivesInterleavedManagementTools(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerExecutionCoverageTools(srv, zap.NewNop())
	conv := "cov-tool-breaker-interleave"
	multiagent.ResetConversationExecutionStateForTest(conv)
	ctx := mcp.WithMCPConversationID(context.Background(), conv)

	// LLM tries to bypass the consecutive counter by interleaving management tools.
	// With sliding-window breaker, upserts still accumulate even across management calls.
	sequence := []struct {
		name string
		args map[string]interface{}
	}{
		{builtin.ToolUpsertExecutionCoverage, map[string]interface{}{"path": "a", "status": "open", "priority": "P1"}},
		{builtin.ToolGetExecutionCoverage, map[string]interface{}{}},
		{builtin.ToolUpsertExecutionCoverage, map[string]interface{}{"path": "b", "status": "open", "priority": "P1"}},
		{builtin.ToolShouldContinueExecution, map[string]interface{}{"intent": "continue"}},
	}
	for _, tc := range sequence {
		res, _, err := srv.CallTool(ctx, tc.name, tc.args)
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("%s should succeed: %s", tc.name, toolResultText(res))
		}
	}

	// Third upsert inside the recent window is rejected (interleaving does NOT bypass).
	res, _, err := srv.CallTool(ctx, builtin.ToolUpsertExecutionCoverage, map[string]interface{}{
		"path": "c", "status": "open", "priority": "P1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("expected breaker after interleaved management tools: %s", toolResultText(res))
	}
}

func TestUpsertExecutionCoverage_TerminalUpsertsDoNotCountTowardBreaker(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerExecutionCoverageTools(srv, zap.NewNop())
	conv := "cov-tool-breaker-terminal"
	multiagent.ResetConversationExecutionStateForTest(conv)
	ctx := mcp.WithMCPConversationID(context.Background(), conv)

	// Non-terminal opens up to threshold-1 (2), leaving room before breaker.
	// Then terminal closures (done/blocked) use unique paths so they never hit
	// the duplicate-terminal guard, and SkipBreaker=true prevents them from
	// counting toward the breaker.
	allowed := multiagent.MaxRecentUpsertsBeforeWarn - 1
	for i := 0; i < allowed; i++ {
		res, _, err := srv.CallTool(ctx, builtin.ToolUpsertExecutionCoverage, map[string]interface{}{
			"path": fmt.Sprintf("path.%d", i), "status": "open", "priority": "P1",
		})
		if err != nil || res.IsError {
			t.Fatalf("open upsert %d: err=%v res=%v", i, err, res)
		}
	}
	// Terminal closures: unique paths to avoid [框架拦截] on duplicate done/blocked.
	for i := 0; i < 5; i++ {
		res, _, err := srv.CallTool(ctx, builtin.ToolUpsertExecutionCoverage, map[string]interface{}{
			"path": fmt.Sprintf("term.path.%d", i),
			"status": "done", "priority": "P1",
		})
		if err != nil || res.IsError {
			t.Fatalf("terminal upsert %d: err=%v res=%v", i, err, res)
		}
	}
}

func TestUpsertExecutionCoverage_BreakerResetsOnRealTestingTool(t *testing.T) {
	srv := mcp.NewServer(zap.NewNop())
	registerExecutionCoverageTools(srv, zap.NewNop())
	conv := "cov-tool-breaker-reset"
	multiagent.ResetConversationExecutionStateForTest(conv)
	ctx := mcp.WithMCPConversationID(context.Background(), conv)

	// Upsert twice, then run real testing tools to slide the window.
	for i := 0; i < 2; i++ {
		res, _, err := srv.CallTool(ctx, builtin.ToolUpsertExecutionCoverage, map[string]interface{}{
			"path": fmt.Sprintf("path.%d", i), "status": "open", "priority": "P1",
		})
		if err != nil || res.IsError {
			t.Fatalf("upsert %d: err=%v res=%v", i, err, res)
		}
	}
	// Fill the window with non-upsert tools so old upserts are evicted.
	for i := 0; i < multiagent.UpsertBreakerWindow; i++ {
		multiagent.GetConversationExecutionState(conv).RecordTool(multiagent.ToolEvidenceEntry{ToolName: "exec"})
	}

	// Now upserting again should succeed because the window no longer has 3 upserts.
	res, _, err := srv.CallTool(ctx, builtin.ToolUpsertExecutionCoverage, map[string]interface{}{
		"path": "path.after_reset", "status": "open", "priority": "P1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("expected reset to allow upsert: %s", toolResultText(res))
	}
}
