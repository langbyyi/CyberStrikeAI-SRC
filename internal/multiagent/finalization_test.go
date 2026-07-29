package multiagent

import (
	"context"
	"strings"
	"testing"
)

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
