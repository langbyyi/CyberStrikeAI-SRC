package multiagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

type SemanticOutcomeKind string

const (
	SemanticOutcomeCompleted         SemanticOutcomeKind = "completed"
	SemanticOutcomeTargetNegative    SemanticOutcomeKind = "target_negative"
	SemanticOutcomeExternalTransient SemanticOutcomeKind = "external_transient"
	SemanticOutcomeInvocationError   SemanticOutcomeKind = "invocation_error"
	SemanticOutcomePolicyRejected    SemanticOutcomeKind = "policy_rejected"
	SemanticOutcomeFrameworkDropped  SemanticOutcomeKind = "framework_dropped"
	SemanticOutcomeAuthRejected      SemanticOutcomeKind = "auth_rejected"
)

type SemanticOutcome struct {
	Kind             SemanticOutcomeKind `json:"kind"`
	Code             string              `json:"code"`
	Fingerprint      string              `json:"fingerprint"`
	Branch           string              `json:"branch,omitempty"`
	EvidenceProgress bool                `json:"evidenceProgress"`
}

var (
	frameworkOutcomeCodePattern = regexp.MustCompile(`(?i)\bcode=([a-z0-9_-]+)`)
	httpStatusPattern           = regexp.MustCompile(`(?i)\bHTTP/\d(?:\.\d)?\s+([1-5]\d\d)\b`)
	assetHashPattern            = regexp.MustCompile(`(?i)([._-])[0-9a-f]{6,}(\.(?:js|css)\b)`)
	invocationGotValuePattern   = regexp.MustCompile(`(?i)(?:,\s*got|;\s*got|\s+got|,\s*received|;\s*received)\s+.+$`)
	invocationUnmarshalPattern  = regexp.MustCompile(`(?i)(json:\s*cannot unmarshal)\s+\S+(\s+into\s+go\s+struct\s+field)`)
)

// ClassifySemanticOutcome separates tool transport success from the meaning of
// the result. Only outcomes that can add a durable fact count as evidence
// progress; stable negative and framework-generated results deliberately do not.
func ClassifySemanticOutcome(toolName, arguments, result string, isError bool) SemanticOutcome {
	tool := normalizedExecutionToolName(toolName)
	low := strings.ToLower(strings.TrimSpace(result))
	kind := SemanticOutcomeCompleted
	code := "completed"
	progress := true

	switch {
	case strings.Contains(low, "[framework_tool_outcome]"):
		kind, code, progress = SemanticOutcomeFrameworkDropped, "framework_dropped", false
		if match := frameworkOutcomeCodePattern.FindStringSubmatch(low); len(match) == 2 {
			code = match[1]
			if code == "policy_rejected" {
				kind = SemanticOutcomePolicyRejected
			}
		}
	case strings.Contains(low, "policy rejected") ||
		strings.Contains(low, "policy_rejected") ||
		strings.Contains(result, "硬拒绝") ||
		strings.Contains(low, "证据不足") ||
		strings.Contains(low, "evidence is insufficient"):
		kind, code, progress = SemanticOutcomePolicyRejected, "policy_rejected", false
	case !isError && semanticHTTPStatus(result) != "" && looksLikeTargetDatabaseError(low):
		kind, code, progress = SemanticOutcomeCompleted, "target_database_error", true
	case isInvocationError(low):
		kind, code, progress = SemanticOutcomeInvocationError, "invalid_arguments", false
	case strings.Contains(low, "connection reset by peer") ||
		strings.Contains(low, "unexpected eof") ||
		strings.Contains(low, "http/2 stream") ||
		strings.Contains(low, "status 429") ||
		strings.Contains(low, "http 429"):
		kind, code, progress = SemanticOutcomeExternalTransient, "connection_reset", false
		if strings.Contains(low, "429") {
			code = "http_429"
		}
	case strings.Contains(low, "connection refused") ||
		strings.Contains(low, "no route to host") ||
		strings.Contains(low, "network is unreachable") ||
		strings.Contains(low, "host is unreachable") ||
		strings.Contains(low, "could not resolve") ||
		strings.Contains(low, "name resolution"):
		kind, code, progress = SemanticOutcomeTargetNegative, "target_unreachable", false
	case looksLikeSPAShell(low):
		kind, code, progress = SemanticOutcomeTargetNegative, "spa_shell", false
	default:
		if status := semanticHTTPStatus(result); status != "" {
			switch status {
			case "401", "403":
				kind, code, progress = SemanticOutcomeAuthRejected, "http_"+status, false
			case "404", "405", "410", "412":
				kind, code, progress = SemanticOutcomeTargetNegative, "http_"+status, false
			case "429":
				kind, code, progress = SemanticOutcomeExternalTransient, "http_429", false
			default:
				if status[0] == '5' {
					kind, code, progress = SemanticOutcomeExternalTransient, "http_5xx", false
				} else if looksLikeAuthRejection(low) {
					// Login failures commonly return HTTP 200 with an inline message
					// ("密码错误", "invalid credentials"). Detect the body text so the
					// controller can cap online brute-force before account lockout.
					kind, code, progress = SemanticOutcomeAuthRejected, "auth_rejected", false
				}
			}
		} else if looksLikeAuthRejection(low) {
			// Text-only result with no HTTP status line.
			kind, code, progress = SemanticOutcomeAuthRejected, "auth_rejected", false
		} else if isError {
			kind, code, progress = SemanticOutcomeInvocationError, "tool_error", false
		}
	}

	branch := semanticOutcomeBranch(arguments)
	fingerprintMaterial := string(kind) + "\x1f" + tool + "\x1f" + code + "\x1f" + branch
	if progress {
		fingerprintMaterial += "\x1f" + ResultFingerprint(toolName, result)
	} else if kind == SemanticOutcomeInvocationError {
		fingerprintMaterial += "\x1f" + normalizeInvocationError(low)
	}
	sum := sha256.Sum256([]byte(fingerprintMaterial))
	return SemanticOutcome{
		Kind:             kind,
		Code:             code,
		Fingerprint:      hex.EncodeToString(sum[:]),
		Branch:           branch,
		EvidenceProgress: progress,
	}
}

func semanticOutcomeBranch(arguments string) string {
	var raw map[string]interface{}
	if json.Unmarshal([]byte(strings.TrimSpace(arguments)), &raw) == nil {
		for _, key := range []string{"coverage", "coverage_path", "branch", "path"} {
			if value, _ := raw[key].(string); strings.TrimSpace(value) != "" {
				return strings.ToLower(strings.TrimSpace(value))
			}
		}
		for _, key := range []string{"target", "host"} {
			if value, _ := raw[key].(string); strings.TrimSpace(value) != "" {
				return strings.ToLower(NormalizePrimaryTarget(value))
			}
		}
		// URL-bearing fields: http-framework-test and similar tools pass the
		// target endpoint as url/endpoint/base_url/uri. Without this, branch is
		// empty and every URL shares one outcome slot, defeating per-target
		// dedup (e.g. repeated probes of /admin/login.php).
		for _, key := range []string{"url", "endpoint", "base_url", "uri"} {
			if value, _ := raw[key].(string); strings.TrimSpace(value) != "" {
				return strings.ToLower(NormalizePrimaryTarget(value))
			}
		}
		// exec/execute tools embed the target inside a shell command string.
		// Fall back to text extraction so curl URLs inside the command still
		// produce a stable branch.
		if cmd, _ := raw["command"].(string); strings.TrimSpace(cmd) != "" {
			if target := ExtractTargetFromText(cmd); target != "" {
				return strings.ToLower(NormalizePrimaryTarget(target))
			}
		}
	}
	if target := ExtractTargetFromText(arguments); target != "" {
		return strings.ToLower(NormalizePrimaryTarget(target))
	}
	return ""
}

// looksLikeAuthRejection detects authentication/authorization failure in a
// response body. Login failures often return HTTP 200 with an inline message
// (e.g. "密码错误", "用户名或密码不正确", "login failed"), so we must match the
// body text rather than rely on status codes alone. Detecting this prevents the
// controller from treating repeated credential attempts as novel evidence and
// caps online brute-force before the target's account-lockout kicks in.
func looksLikeAuthRejection(low string) bool {
	if strings.Contains(low, "密码错误") ||
		strings.Contains(low, "密码不正确") ||
		strings.Contains(low, "用户名或密码") ||
		strings.Contains(low, "账号或密码") ||
		strings.Contains(low, "账户或密码") ||
		strings.Contains(low, "登录失败") ||
		strings.Contains(low, "登陆失败") ||
		strings.Contains(low, "登录密码错误") ||
		strings.Contains(low, "认证失败") ||
		strings.Contains(low, "没有权限") ||
		strings.Contains(low, "权限不足") ||
		strings.Contains(low, "无权访问") ||
		strings.Contains(low, "login failed") ||
		strings.Contains(low, "log in failed") ||
		strings.Contains(low, "login unsuccessful") ||
		strings.Contains(low, "authentication failed") ||
		strings.Contains(low, "auth failed") ||
		strings.Contains(low, "invalid credentials") ||
		strings.Contains(low, "incorrect password") ||
		strings.Contains(low, "wrong password") ||
		strings.Contains(low, "username or password") ||
		strings.Contains(low, "access denied") ||
		strings.Contains(low, "permission denied") ||
		strings.Contains(low, "not authorized") ||
		strings.Contains(low, "unauthorized") {
		return true
	}
	// Account-lockout / attempt-count signals. These are strong indicators that
	// further credential guessing will lock the account — stop after one miss.
	if (strings.Contains(low, "剩余") || strings.Contains(low, "还可") || strings.Contains(low, "尝试")) &&
		(strings.Contains(low, "次") || strings.Contains(low, "times") || strings.Contains(low, "attempts")) {
		if strings.Contains(low, "密码") || strings.Contains(low, "登录") || strings.Contains(low, "password") || strings.Contains(low, "login") {
			return true
		}
	}
	return false
}

func isInvocationError(low string) bool {
	return strings.Contains(low, "invalid argument") ||
		strings.Contains(low, "invalid parameters") ||
		strings.Contains(low, "validation failed") ||
		strings.Contains(low, "must be an array") ||
		strings.Contains(low, "须为数组") ||
		strings.Contains(low, "required field") ||
		strings.Contains(low, "missing required") ||
		strings.Contains(low, "json: cannot unmarshal") ||
		strings.Contains(low, "syntax error") ||
		strings.Contains(low, "unknown field")
}

func looksLikeTargetDatabaseError(low string) bool {
	return strings.Contains(low, "sql syntax") ||
		strings.Contains(low, "mysql_fetch") ||
		strings.Contains(low, "postgresql") ||
		strings.Contains(low, "ora-")
}

func normalizeInvocationError(low string) string {
	low = resultVolatilePattern.ReplaceAllString(low, "<volatile>")
	low = invocationUnmarshalPattern.ReplaceAllString(low, "${1} <actual> ${2}")
	low = strings.Join(strings.Fields(low), " ")
	low = invocationGotValuePattern.ReplaceAllString(low, "")
	if len(low) > 512 {
		low = low[:512]
	}
	return low
}

func semanticHTTPStatus(result string) string {
	match := httpStatusPattern.FindStringSubmatch(result)
	if len(match) == 2 {
		return match[1]
	}
	return BuildStructuredToolSummary("http-framework-test", "", result).HTTPStatus
}

func looksLikeSPAShell(low string) bool {
	if !strings.Contains(low, "text/html") && !strings.Contains(low, "<html") {
		return false
	}
	normalized := assetHashPattern.ReplaceAllString(low, "${1}<hash>${2}")
	return strings.Contains(normalized, `id="app"`) ||
		strings.Contains(normalized, `id='app'`) ||
		strings.Contains(normalized, `id="root"`) ||
		strings.Contains(normalized, `id='root'`) ||
		strings.Contains(normalized, "/assets/") && strings.Contains(normalized, "<script")
}
