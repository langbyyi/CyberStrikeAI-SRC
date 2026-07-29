package mcp

import "strings"

const (
	SemanticOutcomeCompleted         = "completed"
	SemanticOutcomeTargetNegative    = "target_negative"
	SemanticOutcomeExternalTransient = "external_transient"
	SemanticOutcomeInvocationError   = "invocation_error"
	SemanticOutcomePolicyRejected    = "policy_rejected"
	SemanticOutcomeFrameworkDropped  = "framework_dropped"
)

func ClassifyToolExecutionSemanticOutcome(exec *ToolExecution) string {
	if exec == nil {
		return SemanticOutcomeInvocationError
	}
	text := strings.ToLower(strings.TrimSpace(exec.Error + "\n" + toolExecutionResultText(exec.Result)))
	switch {
	case strings.Contains(text, "[framework_tool_outcome]"):
		if strings.Contains(text, "code=policy_rejected") {
			return SemanticOutcomePolicyRejected
		}
		return SemanticOutcomeFrameworkDropped
	case strings.Contains(text, "policy_rejected") ||
		strings.Contains(text, "policy rejected") ||
		strings.Contains(text, "硬拒绝"):
		return SemanticOutcomePolicyRejected
	case strings.Contains(text, "invalid argument") ||
		strings.Contains(text, "须为数组") ||
		strings.Contains(text, "must be an array") ||
		strings.Contains(text, "validation failed") ||
		strings.Contains(text, "syntax error") ||
		strings.Contains(text, "missing required"):
		return SemanticOutcomeInvocationError
	case strings.Contains(text, "connection reset by peer") ||
		strings.Contains(text, "unexpected eof") ||
		strings.Contains(text, "http 429") ||
		strings.Contains(text, "status 429") ||
		strings.Contains(text, "http/1.1 5"):
		return SemanticOutcomeExternalTransient
	case strings.Contains(text, "http/1.1 404") ||
		strings.Contains(text, "http/1.1 405") ||
		strings.Contains(text, "http/1.1 410") ||
		strings.Contains(text, "http/1.1 412") ||
		strings.Contains(text, "connection refused") ||
		strings.Contains(text, "no route to host"):
		return SemanticOutcomeTargetNegative
	case exec.Status == "failed" || exec.Status == "cancelled" || (exec.Result != nil && exec.Result.IsError):
		return SemanticOutcomeInvocationError
	default:
		return SemanticOutcomeCompleted
	}
}

func toolExecutionResultText(result *ToolResult) string {
	if result == nil {
		return ""
	}
	var out strings.Builder
	for _, content := range result.Content {
		if strings.TrimSpace(content.Text) != "" {
			out.WriteString(content.Text)
			out.WriteByte('\n')
		}
	}
	return out.String()
}
