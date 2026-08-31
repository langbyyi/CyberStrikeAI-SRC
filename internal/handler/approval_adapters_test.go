package handler

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/approval"
)

// 审计上下文契约：Review 的 payload 必须携带规则命中详情；
// buildAuditAgentReviewInput 必须把用户指令与命中规则一起送进审计输入——
// 这是审计 Agent 区分"测试意图"与"真实破坏"的唯一依据。
func TestAuditReviewPayloadCarriesContext(t *testing.T) {
	req := approval.ReviewRequest{
		Invocation: approval.Invocation{
			ToolName: "exec", Source: "eino_middleware",
			Arguments: map[string]any{"command": "curl -X DELETE https://x/api/conversations/1"},
		},
		Assessment: approval.Assessment{RiskLevel: approval.RiskHigh},
	}
	payload := approvalReviewPayload(req)
	if payload["argumentsObj"] == nil {
		t.Fatal("argumentsObj missing from review payload")
	}
	if _, ok := payload["findings"]; !ok {
		t.Fatal("findings missing from review payload")
	}
	input := buildAuditAgentReviewInput("exec", map[string]any{
		"command":     "curl -X DELETE https://x/api/conversations/1",
		"userMessage": "测试一下删除会话接口",
		"riskLevel":   "high",
		"findings":    []any{map[string]any{"ruleId": "danger.script.destructive-http-operation"}},
	})
	for _, want := range []string{"测试一下删除会话接口", "findings", "riskLevel", "DELETE", "danger.script.destructive-http-operation"} {
		if !strings.Contains(input, want) {
			t.Errorf("review input missing %q", want)
		}
	}
}
