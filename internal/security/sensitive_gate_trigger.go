package security

import (
	"context"
	"fmt"

	"cyberstrike-ai/internal/approval"
)

// SensitiveHTTPGateTrigger 把敏感 HTTP 判定接入统一审批流：
// 命中不再由执行器硬编码拒绝，而是强制入队审批，交审计 Agent 或人工裁决。
// 触发器恒开（原执行器硬闸同样无开关）；放行只能来自审批决定，
// 且执行器收到的 grant 与冻结参数由 MCP InvocationGuard 统一校验。
type SensitiveHTTPGateTrigger struct{}

func NewSensitiveHTTPGateTrigger() *SensitiveHTTPGateTrigger { return &SensitiveHTTPGateTrigger{} }

func (t *SensitiveHTTPGateTrigger) Name() string { return "sensitive_http_gate" }

func (t *SensitiveHTTPGateTrigger) Evaluate(_ context.Context, invocation approval.Invocation) (approval.TriggerResult, error) {
	a := AssessSensitiveHTTP(invocation.ToolName, invocation.Arguments)
	if !a.Blocked {
		return approval.TriggerResult{}, nil
	}
	return approval.TriggerResult{
		Matched:   true,
		RiskLevel: approval.RiskHigh,
		Findings: []approval.TriggerFinding{{
			Source:    "sensitive_http_gate",
			RuleID:    a.Reason,
			RiskLevel: approval.RiskHigh,
			Message:   fmt.Sprintf("%s %s（%s）", a.Method, a.Target, a.Reason),
		}},
		PolicyIDs: []string{"sensitive_http_gate"},
	}, nil
}
