package mcp

import (
	"regexp"
	"strings"
)

const (
	SemanticOutcomeCompleted         = "completed"
	SemanticOutcomeTargetNegative    = "target_negative"
	SemanticOutcomeExternalTransient = "external_transient"
	SemanticOutcomeInvocationError   = "invocation_error"
	SemanticOutcomePolicyRejected    = "policy_rejected"
	SemanticOutcomeFrameworkDropped  = "framework_dropped"
	SemanticOutcomeAuthRejected      = "auth_rejected"
)

var toolExecutionHTTPStatusPattern = regexp.MustCompile(`(?i)\bhttp/(?:1\.[01]|2(?:\.0)?)\s+([1-5]\d\d)\b`)

func ClassifyToolExecutionSemanticOutcome(exec *ToolExecution) string {
	if exec == nil {
		return SemanticOutcomeInvocationError
	}
	resultText := strings.ToLower(strings.TrimSpace(toolExecutionResultText(exec.Result)))
	text := strings.ToLower(strings.TrimSpace(exec.Error + "\n" + resultText))
	httpStatus := toolExecutionHTTPStatus(text)
	targetDatabaseError := strings.TrimSpace(exec.Error) == "" &&
		exec.Status != "failed" && exec.Status != "cancelled" &&
		exec.Result != nil && !exec.Result.IsError &&
		toolExecutionHTTPStatus(resultText) != "" &&
		looksLikeTargetDatabaseError(resultText)
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
	case targetDatabaseError:
		return SemanticOutcomeCompleted
	case strings.Contains(text, "invalid argument") ||
		strings.Contains(text, "须为数组") ||
		strings.Contains(text, "must be an array") ||
		strings.Contains(text, "validation failed") ||
		strings.Contains(text, "syntax error") ||
		strings.Contains(text, "missing required"):
		return SemanticOutcomeInvocationError
	case strings.Contains(text, "connection reset by peer") ||
		strings.Contains(text, "unexpected eof") ||
		strings.Contains(text, "http/2 stream") ||
		strings.Contains(text, "http 429") ||
		strings.Contains(text, "status 429") ||
		httpStatus == "429" ||
		strings.HasPrefix(httpStatus, "5"):
		return SemanticOutcomeExternalTransient
	case httpStatus == "404" ||
		httpStatus == "405" ||
		httpStatus == "410" ||
		httpStatus == "412" ||
		strings.Contains(text, "connection refused") ||
		strings.Contains(text, "no route to host") ||
		strings.Contains(text, "network is unreachable") ||
		strings.Contains(text, "host is unreachable") ||
		strings.Contains(text, "could not resolve") ||
		strings.Contains(text, "name resolution") ||
		looksLikeToolSPAShell(text):
		return SemanticOutcomeTargetNegative
	case httpStatus == "401" || httpStatus == "403" || looksLikeToolAuthRejection(text):
		return SemanticOutcomeAuthRejected
	case exec.Status == "failed" || exec.Status == "cancelled" || (exec.Result != nil && exec.Result.IsError):
		return SemanticOutcomeInvocationError
	default:
		return SemanticOutcomeCompleted
	}
}

// looksLikeToolAuthRejection mirrors the multiagent-layer auth-rejection
// detector so MCP execution paths classify login failures consistently.
func looksLikeToolAuthRejection(text string) bool {
	return strings.Contains(text, "密码错误") ||
		strings.Contains(text, "密码不正确") ||
		strings.Contains(text, "用户名或密码") ||
		strings.Contains(text, "账号或密码") ||
		strings.Contains(text, "账户或密码") ||
		strings.Contains(text, "登录失败") ||
		strings.Contains(text, "登陆失败") ||
		strings.Contains(text, "认证失败") ||
		strings.Contains(text, "没有权限") ||
		strings.Contains(text, "权限不足") ||
		strings.Contains(text, "无权访问") ||
		strings.Contains(text, "login failed") ||
		strings.Contains(text, "login unsuccessful") ||
		strings.Contains(text, "authentication failed") ||
		strings.Contains(text, "auth failed") ||
		strings.Contains(text, "invalid credentials") ||
		strings.Contains(text, "incorrect password") ||
		strings.Contains(text, "wrong password") ||
		strings.Contains(text, "username or password") ||
		strings.Contains(text, "access denied") ||
		strings.Contains(text, "permission denied") ||
		strings.Contains(text, "not authorized") ||
		strings.Contains(text, "unauthorized")
}

func looksLikeTargetDatabaseError(text string) bool {
	return strings.Contains(text, "sql syntax") ||
		strings.Contains(text, "mysql_fetch") ||
		strings.Contains(text, "postgresql") ||
		strings.Contains(text, "ora-")
}

func toolExecutionHTTPStatus(text string) string {
	match := toolExecutionHTTPStatusPattern.FindStringSubmatch(text)
	if len(match) == 2 {
		return match[1]
	}
	return ""
}

func looksLikeToolSPAShell(text string) bool {
	if !strings.Contains(text, "text/html") && !strings.Contains(text, "<html") {
		return false
	}
	return strings.Contains(text, `id="app"`) ||
		strings.Contains(text, `id='app'`) ||
		strings.Contains(text, `id="root"`) ||
		strings.Contains(text, `id='root'`) ||
		strings.Contains(text, "/assets/") && strings.Contains(text, "<script")
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
