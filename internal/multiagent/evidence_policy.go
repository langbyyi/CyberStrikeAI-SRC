package multiagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

type EvidencePolicyDecision struct {
	Allowed     bool
	Code        string
	Reason      string
	Fingerprint string
}

func EvaluateVulnerabilityEvidencePolicy(toolName, arguments string, state *ConversationExecutionState) EvidencePolicyDecision {
	fingerprint, fields := vulnerabilityEvidenceFingerprint(arguments)
	decision := EvidencePolicyDecision{Allowed: true, Fingerprint: fingerprint}
	if !isL1L2RecordTool(toolName) {
		return decision
	}
	if state != nil {
		if _, rejected := state.EvidenceRejection(fingerprint); rejected {
			return EvidencePolicyDecision{
				Allowed:     false,
				Code:        "evidence_previously_rejected",
				Reason:      "同一证据此前已被策略拒绝，禁止通过更换漏洞类型或分类重复落库",
				Fingerprint: fingerprint,
			}
		}
	}

	joined := strings.ToLower(strings.Join([]string{
		fields["title"], fields["category"], fields["vulnerability_type"],
		fields["description"], fields["proof"], fields["impact"], fields["signal"],
	}, "\n"))
	proof := strings.ToLower(fields["proof"] + "\n" + fields["signal"])

	if strings.Contains(joined, "cors") || strings.Contains(joined, "access-control-allow-origin") {
		wildcard := strings.Contains(joined, "access-control-allow-origin: *") ||
			strings.Contains(joined, `"access-control-allow-origin":"*"`)
		credentials := strings.Contains(joined, "access-control-allow-credentials: true") ||
			strings.Contains(joined, `"access-control-allow-credentials":"true"`)
		if wildcard && credentials {
			return EvidencePolicyDecision{
				Allowed:     false,
				Code:        "cors_wildcard_credentials",
				Reason:      "浏览器不会允许 wildcard ACAO 与 credentials 组合读取凭据响应，该响应头组合本身不足以构成可利用漏洞",
				Fingerprint: fingerprint,
			}
		}
	}

	isXSS := strings.Contains(joined, `"category":"xss"`) ||
		strings.Contains(strings.ToLower(fields["category"]), "xss") ||
		strings.Contains(strings.ToLower(fields["vulnerability_type"]), "xss") ||
		strings.Contains(strings.ToLower(fields["title"]), "xss")
	isJSONP := strings.Contains(joined, "jsonp") || strings.Contains(proof, "callback=")
	if isXSS && isJSONP && !hasBrowserOriginEvidence(proof) {
		return EvidencePolicyDecision{
			Allowed:     false,
			Code:        "jsonp_origin_unproven",
			Reason:      "JSONP callback 反射只证明脚本由嵌入页面执行；缺少目标源浏览器上下文与实际影响证据，不能作为正式 XSS",
			Fingerprint: fingerprint,
		}
	}

	isIDOR := strings.Contains(strings.ToLower(fields["category"]), "idor") ||
		strings.Contains(strings.ToLower(fields["category"]), "越权") ||
		strings.Contains(strings.ToLower(fields["vulnerability_type"]), "idor")
	if normalizedExecutionToolName(toolName) == "record_vulnerability" && isIDOR &&
		(state == nil || !state.HasDualAuthProbe()) && !hasDualIdentityEvidence(proof) {
		return EvidencePolicyDecision{
			Allowed:     false,
			Code:        "idor_dual_identity_missing",
			Reason:      "正式水平越权记录需要两个身份或等价的授权差异证据；单身份对象枚举只能保留为候选",
			Fingerprint: fingerprint,
		}
	}
	return decision
}

func vulnerabilityEvidenceFingerprint(arguments string) (string, map[string]string) {
	fields := make(map[string]string)
	var raw map[string]interface{}
	if json.Unmarshal([]byte(strings.TrimSpace(arguments)), &raw) == nil {
		for _, key := range []string{"title", "category", "vulnerability_type", "target", "vuln_urls", "description", "proof", "impact", "signal"} {
			if value, ok := raw[key].(string); ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
	}
	target := NormalizeCoverageTarget(fields["target"])
	if target == "" {
		target = NormalizeCoverageTarget(fields["vuln_urls"])
	}
	evidence := fields["proof"]
	if evidence == "" {
		evidence = fields["signal"]
	}
	evidence = resultVolatilePattern.ReplaceAllString(strings.ToLower(evidence), "<volatile>")
	evidence = strings.Join(strings.Fields(evidence), " ")
	if len(evidence) > 8000 {
		evidence = evidence[:8000]
	}
	sum := sha256.Sum256([]byte(target + "\x1f" + evidence))
	return hex.EncodeToString(sum[:]), fields
}

func hasBrowserOriginEvidence(proof string) bool {
	for _, marker := range []string{
		"playwright", "selenium", "browser console", "浏览器控制台",
		"document.origin", "location.origin", "executed in target origin",
		"在目标源执行", "document.cookie=", "cookie exfiltration",
	} {
		if strings.Contains(proof, marker) {
			return true
		}
	}
	return false
}

func hasDualIdentityEvidence(proof string) bool {
	for _, pair := range [][2]string{
		{"auth_a", "auth_b"},
		{"account a", "account b"},
		{"账号a", "账号b"},
		{"用户a", "用户b"},
		{"owner token", "attacker token"},
	} {
		if strings.Contains(proof, pair[0]) && strings.Contains(proof, pair[1]) {
			return true
		}
	}
	return false
}
