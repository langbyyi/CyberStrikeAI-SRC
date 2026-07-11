package multiagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestApplyFinalizeGate_OpenP0BlocksWrapUp(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-gate-p0"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.UpsertCoverage(CoverageItem{
		Path:     "cand.sqli.param:id",
		Status:   "open",
		Priority: "P0",
		Note:     "SQL syntax error on id",
	})

	orig := "针对目标完成扫描，未发现漏洞，测试完成。"
	out, blocked := ApplyFinalizeGate(conv, orig)
	if !blocked {
		t.Fatal("expected finalize gate to block wrap-up with open P0")
	}
	if out == orig {
		t.Fatal("response must be rewritten/appended, not original-only")
	}
	if !strings.Contains(out, "finalize_gate_blocked") {
		t.Fatalf("missing finalize_gate_blocked marker: %s", out)
	}
	if !strings.Contains(out, "cand.sqli.param:id") {
		t.Fatalf("open path not listed: %s", out)
	}
	if !strings.Contains(out, "未发现漏洞") {
		t.Fatalf("should keep original text: %s", out)
	}
}

func TestApplyFinalizeGate_TableWrapUpPhrases(t *testing.T) {
	t.Parallel()
	phrases := []string{
		"未发现漏洞",
		"测试完成",
		"暂未发现安全问题",
		"可以结束",
		"no vulnerabilities found",
		"testing complete",
		"扫描完成，没有发现漏洞",
	}
	for i, p := range phrases {
		conv := "test-finalize-phrase-" + string(rune('a'+i))
		ResetConversationExecutionStateForTest(conv)
		GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
			Path: "cand.rce.path", Status: "open", Priority: "P1",
		})
		out, blocked := ApplyFinalizeGate(conv, "总结："+p)
		if !blocked {
			t.Fatalf("phrase %q should trigger gate", p)
		}
		if !strings.Contains(out, "finalize_gate_blocked") {
			t.Fatalf("phrase %q missing marker", p)
		}
	}
}

func TestApplyFinalizeGate_AlreadyGatedNoRepeat(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-already"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path: "cand.xss.param:q", Status: "in_progress", Priority: "P0",
	})
	// First gate
	first, blocked := ApplyFinalizeGate(conv, "测试完成，未发现漏洞。")
	if !blocked {
		t.Fatal("first pass should block")
	}
	// Second pass on already gated text must not duplicate
	second, blocked2 := ApplyFinalizeGate(conv, first)
	if blocked2 {
		t.Fatal("already gated text must not re-trigger")
	}
	if second != first {
		t.Fatal("response should be unchanged on second pass")
	}
	if strings.Count(first, "finalize_gate_blocked") != 1 {
		t.Fatalf("marker count=%d", strings.Count(first, "finalize_gate_blocked"))
	}
}

func TestApplyFinalizeGate_NoOpenSkips(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-gate-done"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.UpsertCoverage(CoverageItem{Path: "tool.sqlmap", Status: "done", Priority: "P0"})

	orig := "测试完成，未发现漏洞。"
	out, blocked := ApplyFinalizeGate(conv, orig)
	if blocked {
		t.Fatal("closed coverage should not block")
	}
	if out != orig {
		t.Fatalf("response changed unexpectedly: %q", out)
	}
}

func TestApplyFinalizeGate_OnlyP2DoesNotBlock(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-p2-only"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path: "info.headers", Status: "open", Priority: "P2",
	})
	orig := "测试完成，未发现漏洞。"
	out, blocked := ApplyFinalizeGate(conv, orig)
	if blocked {
		t.Fatal("P2-only open must not finalize-block")
	}
	if out != orig {
		t.Fatalf("got %q", out)
	}
}

func TestApplyFinalizeGate_BlockedStatusIgnored(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-blocked-status"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path: "cand.sqli.param:id", Status: "blocked", Priority: "P0", Note: "WAF",
	})
	orig := "测试完成，未发现漏洞。"
	_, blocked := ApplyFinalizeGate(conv, orig)
	if blocked {
		t.Fatal("blocked status must not count as open")
	}
}

func TestApplyFinalizeGate_NonWrapUpSkips(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-gate-continue"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path: "cand.xss.param:q", Status: "open", Priority: "P1",
	})
	orig := "发现 q 参数反射，继续用 dalfox 验证 XSS。"
	out, blocked := ApplyFinalizeGate(conv, orig)
	if blocked {
		t.Fatal("non wrap-up should not gate")
	}
	if out != orig {
		t.Fatalf("got %q", out)
	}
}

func TestApplyFinalizeGateToRunResult_NilLoggerSafe(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-runresult"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path: "auth.login", Status: "open", Priority: "P1",
	})
	rr := &RunResult{Response: "扫描完成，暂未发现高危问题。"}
	out := ApplyFinalizeGateToRunResult(rr, conv, nil)
	if out == nil || !strings.Contains(out.Response, "finalize_gate_blocked") {
		t.Fatalf("RunResult not gated: %+v", out)
	}
	// nil RunResult
	if ApplyFinalizeGateToRunResult(nil, conv, nil) != nil {
		t.Fatal("nil in → nil out")
	}
}

func TestCoverageShouldBlockFinalize(t *testing.T) {
	t.Parallel()
	conv := "test-cov-should-block"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	// no open
	if ok, _ := CoverageShouldBlockFinalize(st, "测试完成，未发现漏洞"); ok {
		t.Fatal("empty coverage should not block")
	}
	st.UpsertCoverage(CoverageItem{Path: "a", Status: "open", Priority: "P0"})
	ok, reason := CoverageShouldBlockFinalize(st, "测试完成，未发现漏洞")
	if !ok || reason == "" {
		t.Fatalf("expected block, ok=%v reason=%q", ok, reason)
	}
	if ok2, _ := CoverageShouldBlockFinalize(st, "继续验证 id 参数"); ok2 {
		t.Fatal("non wrap-up")
	}
	if ok3, _ := CoverageShouldBlockFinalize(nil, "未发现漏洞"); ok3 {
		t.Fatal("nil state")
	}
}

func TestIsFinalizeWrapUpText(t *testing.T) {
	t.Parallel()
	if !IsFinalizeWrapUpText("未发现漏洞") {
		t.Fatal("expected match")
	}
	if IsFinalizeWrapUpText("继续验证 SQL 注入参数 id") {
		t.Fatal("should not match active work")
	}
	if IsFinalizeWrapUpText("## [finalize_gate_blocked] already") {
		t.Fatal("already gated must not match wrap-up")
	}
}

func TestFinalizeGateWiredInADKRunLoop(t *testing.T) {
	// Structural: both normal and error/partial exit paths must call maybeApplyFinalizeGate.
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(wd, "eino_adk_run_loop.go")
	b, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read eino_adk_run_loop.go: %v", err)
	}
	src := string(b)
	count := strings.Count(src, "maybeApplyFinalizeGate")
	if count < 2 {
		t.Fatalf("expected ≥2 maybeApplyFinalizeGate call sites (normal+error), got %d", count)
	}
	if !strings.Contains(src, "FinalizeGateEffective") {
		t.Fatal("run loop helper must respect FinalizeGateEffective")
	}
}

func TestMaybeApplyFinalizeGate_RespectsKillSwitch(t *testing.T) {
	t.Parallel()
	conv := "test-maybe-gate-kill"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path: "x", Status: "open", Priority: "P0",
	})
	off := false
	cfgOff := config.MultiAgentEinoMiddlewareConfig{FinalizeGateEnable: &off}
	rr := &RunResult{Response: "测试完成，未发现漏洞。"}
	out := maybeApplyFinalizeGate(rr, conv, nil, &cfgOff)
	if strings.Contains(out.Response, "finalize_gate_blocked") {
		t.Fatal("kill switch should skip gate")
	}
	out2 := maybeApplyFinalizeGate(&RunResult{Response: "测试完成，未发现漏洞。"}, conv, nil, nil)
	if !strings.Contains(out2.Response, "finalize_gate_blocked") {
		t.Fatal("nil mw defaults to gate on")
	}
}
