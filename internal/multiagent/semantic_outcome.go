package multiagent

import (
	"crypto/sha256"
	"encoding/hex"
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
)

type SemanticOutcome struct {
	Kind             SemanticOutcomeKind `json:"kind"`
	Code             string              `json:"code"`
	Fingerprint      string              `json:"fingerprint"`
	EvidenceProgress bool                `json:"evidenceProgress"`
}

var (
	frameworkOutcomeCodePattern = regexp.MustCompile(`(?i)\bcode=([a-z0-9_-]+)`)
	httpStatusPattern           = regexp.MustCompile(`(?i)\bHTTP/\d(?:\.\d)?\s+([1-5]\d\d)\b`)
	assetHashPattern            = regexp.MustCompile(`(?i)([._-])[0-9a-f]{6,}(\.(?:js|css)\b)`)
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
		}
	case strings.Contains(low, "policy rejected") ||
		strings.Contains(low, "policy_rejected") ||
		strings.Contains(low, "证据不足") ||
		strings.Contains(low, "evidence is insufficient"):
		kind, code, progress = SemanticOutcomePolicyRejected, "policy_rejected", false
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
			case "404", "405", "410", "412":
				kind, code, progress = SemanticOutcomeTargetNegative, "http_"+status, false
			case "429":
				kind, code, progress = SemanticOutcomeExternalTransient, "http_429", false
			default:
				if status[0] == '5' {
					kind, code, progress = SemanticOutcomeExternalTransient, "http_5xx", false
				}
			}
		} else if isError {
			kind, code, progress = SemanticOutcomeInvocationError, "tool_error", false
		}
	}

	fingerprintMaterial := string(kind) + "\x1f" + tool + "\x1f" + code
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
		EvidenceProgress: progress,
	}
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

func normalizeInvocationError(low string) string {
	low = resultVolatilePattern.ReplaceAllString(low, "<volatile>")
	low = strings.Join(strings.Fields(low), " ")
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
