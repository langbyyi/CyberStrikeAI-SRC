package multiagent

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestRunScopedFinalReportExcludesHistoricalCoverage(t *testing.T) {
	state := &ConversationExecutionState{
		Coverage:       map[string]CoverageItem{},
		maxEvidence:    defaultMaxEvidence,
		maxCoverage:    defaultMaxCoverage,
		InjectedSkills: map[string]struct{}{},
		controller:     NewExecutionController("target.test"),
	}
	state.UpsertCoverage(CoverageItem{Path: "historical.open", Status: "open", Priority: "P1", Note: "old"})
	coverageCursor := state.CoverageCursor()
	state.UpsertCoverage(CoverageItem{Path: "current.blocked", Status: "blocked", Priority: "P1", Note: "current"})

	got := BuildDeterministicFinalReportForRun(state, state.EvidenceCursor(), coverageCursor)
	if strings.Contains(got, "historical.open") || !strings.Contains(got, "current.blocked") {
		t.Fatalf("run-scoped report must exclude historical coverage: %q", got)
	}
}

func TestSanitizeFinalResponseRemovesInternalControlText(t *testing.T) {
	input := `已完成验证。

## [identity_gap] 框架提示（非用户消息）
仅影响跨账号测试。

[framework_next_action]
请继续扫描。

[framework_tool_outcome] code=stagnation_blocked retryable=false
当前调用已阻断。`
	got := SanitizeFinalResponse(input)
	for _, marker := range []string{"identity_gap", "framework_next_action", "framework_tool_outcome", "stagnation_blocked"} {
		if strings.Contains(strings.ToLower(got), marker) {
			t.Fatalf("internal marker %q leaked into final response: %q", marker, got)
		}
	}
	if !strings.Contains(got, "已完成验证") {
		t.Fatalf("user-facing content must be retained, got %q", got)
	}
}

func TestPlanningOnlyResponseIsNotAcceptedAsFinal(t *testing.T) {
	for _, value := range []string{
		"我接下来会继续请求更多 API 路径，然后再整理发现。",
		"下一步计划：扩大字典并继续扫描。",
		"[framework_next_action] 请换假设。",
	} {
		if !IsPlanningOnlyFinalResponse(value) {
			t.Fatalf("planning/internal-only response must not be accepted: %q", value)
		}
	}
	if IsPlanningOnlyFinalResponse("已验证 /api/users 返回 404；未发现可复现越权，双身份验证尚未完成。") {
		t.Fatal("evidence-based conclusion must be accepted")
	}
	if IsPlanningOnlyFinalResponse("你好，我可以帮你分析这个问题。") {
		t.Fatal("short conversational replies must not trigger execution finalization")
	}
}

func TestFinalizeRunResponseUsesNoToolFinalizerThenFallback(t *testing.T) {
	state := &ConversationExecutionState{
		Coverage:       map[string]CoverageItem{},
		InjectedSkills: map[string]struct{}{},
		controller:     NewExecutionController("target.test"),
		maxEvidence:    defaultMaxEvidence,
		maxCoverage:    defaultMaxCoverage,
	}
	state.RecordTool(ToolEvidenceEntry{
		ToolName:   "http-framework-test",
		StatusHint: "404",
		Summary:    "GET /api/admin returned stable 404",
	})
	state.UpsertCoverage(CoverageItem{
		Path: "auth.idor_horizontal", Status: "blocked", Priority: "P1", Note: "缺少第二身份",
	})

	finalizerCalls := 0
	got := FinalizeRunResponse(context.Background(), state, "下一步计划：继续扫描。", func(context.Context, string) (string, error) {
		finalizerCalls++
		return "已验证 `/api/admin` 稳定返回 404。未确认正式漏洞；水平越权因缺少第二身份尚未验证。", nil
	})
	if finalizerCalls != 1 {
		t.Fatalf("invalid candidate must invoke one no-tool finalizer, calls=%d", finalizerCalls)
	}
	if IsPlanningOnlyFinalResponse(got) || strings.Contains(got, "identity_gap") {
		t.Fatalf("finalizer output must be clean and conclusive, got %q", got)
	}

	fallback := FinalizeRunResponse(context.Background(), state, "[framework_next_action]", func(context.Context, string) (string, error) {
		return "我接下来会继续扫描。", nil
	})
	for _, required := range []string{"已验证事实", "未确认候选", "限制与下一步", "/api/admin"} {
		if !strings.Contains(fallback, required) {
			t.Fatalf("deterministic fallback missing %q: %q", required, fallback)
		}
	}
}

func TestFinalizeRunResponseCompletesFinalizingPhase(t *testing.T) {
	state := &ConversationExecutionState{
		Coverage:       map[string]CoverageItem{},
		InjectedSkills: map[string]struct{}{},
		controller:     NewExecutionController("target.test"),
		maxEvidence:    defaultMaxEvidence,
		maxCoverage:    defaultMaxCoverage,
	}
	negative := SemanticOutcome{
		Kind:             SemanticOutcomeTargetNegative,
		Code:             "http_404",
		Fingerprint:      "same-negative",
		EvidenceProgress: false,
	}
	for i := 0; i < 12; i++ {
		callID := fmt.Sprintf("call-%d", i)
		state.Controller().StartProbeBatch([]string{callID})
		state.Controller().RecordSemanticOutcome(callID, "http-framework-test", fmt.Sprintf("sig-%d", i), negative)
		state.Controller().CompleteProbeBatch()
		if state.Controller().Phase() == ExecutionPhasePivoting {
			_ = state.Controller().PivotDirective()
		}
	}
	if got := state.Controller().Phase(); got != ExecutionPhaseFinalizing {
		t.Fatalf("setup phase=%q want finalizing", got)
	}

	_ = FinalizeRunResponse(
		context.Background(),
		state,
		"已验证目标路径稳定返回 404，未确认漏洞。",
		nil,
	)

	if got := state.Controller().Phase(); got != ExecutionPhaseFinished {
		t.Fatalf("final report must complete execution phase, got %q", got)
	}
}

func TestStagnationShortCandidateForcesDeterministicReport(t *testing.T) {
	// Reproduces the 14:50:38 bug: a stagnation pivot ends the run with the model
	// emitting a one-line planning fragment ("尝试已知漏洞…"). Without the fix,
	// FinalizeRunResponse returned the fragment verbatim and the user saw no
	// report. With StagnationGates>0 + a short candidate, the deterministic
	// fallback must be produced.
	state := &ConversationExecutionState{
		Coverage:       map[string]CoverageItem{},
		InjectedSkills: map[string]struct{}{},
		controller:     NewExecutionController("target.test"),
		maxEvidence:    defaultMaxEvidence,
		maxCoverage:    defaultMaxCoverage,
	}
	// Record one real evidence entry so the deterministic report is non-empty.
	state.RecordTool(ToolEvidenceEntry{
		ToolName:   "exec",
		StatusHint: "ok",
		Summary:    "GET / returned 200, target reachable",
	})
	// Trigger a pivot via 3 non-novel batches (StagnationGates increments).
	negative := SemanticOutcome{
		Kind:             SemanticOutcomeTargetNegative,
		Code:             "http_404",
		Fingerprint:      "neg-fp",
		EvidenceProgress: false,
	}
	for i := 0; i < 4; i++ {
		callID := fmt.Sprintf("call-%d", i)
		state.Controller().StartProbeBatch([]string{callID})
		state.Controller().RecordSemanticOutcome(callID, "http-framework-test", fmt.Sprintf("sig-%d", i), negative)
		state.Controller().CompleteProbeBatch()
	}
	if state.Controller().StagnationGates() == 0 {
		t.Fatal("stagnation must have fired to set up this test")
	}
	// Consume the pivot directive so phase resets to Exploring (the bug condition).
	_ = state.Controller().PivotDirective()

	// A short planning fragment (the real-world failure input).
	got := FinalizeRunResponse(context.Background(), state,
		"尝试 5vshop 已知漏洞与 IIS 解析特性。", nil)
	for _, required := range []string{"已验证事实", "未确认候选"} {
		if !strings.Contains(got, required) {
			t.Fatalf("stagnation short candidate must force deterministic report with %q, got %q", required, got)
		}
	}
	if strings.Contains(got, "尝试 5vshop 已知漏洞") {
		t.Fatalf("planning fragment must not leak verbatim into final report: %q", got)
	}
}

func TestStagnationLongRealReportIsKept(t *testing.T) {
	// If the model already produced a long, real report, stagnation must NOT
	// overwrite it with the deterministic fallback.
	state := &ConversationExecutionState{
		Coverage:       map[string]CoverageItem{},
		InjectedSkills: map[string]struct{}{},
		controller:     NewExecutionController("target.test"),
		maxEvidence:    defaultMaxEvidence,
		maxCoverage:    defaultMaxCoverage,
	}
	negative := SemanticOutcome{
		Kind:             SemanticOutcomeTargetNegative,
		Code:             "http_404",
		Fingerprint:      "neg-fp2",
		EvidenceProgress: false,
	}
	for i := 0; i < 4; i++ {
		callID := fmt.Sprintf("call-%d", i)
		state.Controller().StartProbeBatch([]string{callID})
		state.Controller().RecordSemanticOutcome(callID, "http-framework-test", fmt.Sprintf("sig2-%d", i), negative)
		state.Controller().CompleteProbeBatch()
	}
	_ = state.Controller().PivotDirective()
	// A genuinely long, real report (>400 runes) with evidence cues must be kept
	// verbatim — stagnation must not overwrite a finished report.
	var longReportBuilder strings.Builder
	longReportBuilder.WriteString("已验证 /api/admin 返回 status=403。这是一个包含完整细节的真实报告。")
	longReportBuilder.WriteString("已验证事实：目标 /api/admin 端点稳定返回 403 禁止访问，/api/users 返回 200 且泄露用户列表。")
	longReportBuilder.WriteString("未确认候选：水平越权因缺少第二身份尚未完成验证，但 /api/users 的响应差异提示潜在 IDOR。")
	longReportBuilder.WriteString("限制与下一步：当前无法注册第二身份，建议补充账号后重测水平越权；同时 /admin 后台存在弱口令面，需进一步枚举。")
	longReportBuilder.WriteString("补充说明：本报告已包含足够长的真实证据描述，长度超过短候选阈值，因此应原样保留，不应被确定性回退覆盖。")
	longReportBuilder.WriteString("详细复现步骤：第一步使用 http-framework-test 向 /api/admin 发送 GET 请求，记录响应状态码与正文长度；第二步对 /api/users 重复相同操作并比对差异；第三步对 /api/orders 尝试水平越权，因缺少第二身份未能完成。")
	longReportBuilder.WriteString("影响评估：/api/users 的信息泄露可能暴露用户邮箱与手机号，属于中等风险；水平越权若成立则为高风险。建议优先补充第二身份完成越权验证。")
	longReportBuilder.WriteString("测试覆盖范围总结：已覆盖认证、授权、注入三个维度，其中认证面返回 403 稳定，注入面未发现可利用点，越权面待补充身份后复测。")
	longReport := longReportBuilder.String()
	if len([]rune(longReport)) <= shortCandidateThreshold {
		t.Fatalf("test setup error: long report must exceed %d runes, got %d", shortCandidateThreshold, len([]rune(longReport)))
	}
	got := FinalizeRunResponse(context.Background(), state, longReport, nil)
	if !strings.Contains(got, "status=403") {
		t.Fatalf("long real report must be preserved, got %q", got)
	}
}
