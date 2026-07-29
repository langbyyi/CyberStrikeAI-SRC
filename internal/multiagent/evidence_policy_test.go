package multiagent

import (
	"strings"
	"testing"
)

func newPolicyTestState() *ConversationExecutionState {
	return &ConversationExecutionState{
		Coverage:           map[string]CoverageItem{},
		InjectedSkills:     map[string]struct{}{},
		controller:         NewExecutionController("target.test"),
		evidenceRejections: map[string]string{},
	}
}

func TestEvidencePolicyRejectsWildcardCredentialCORS(t *testing.T) {
	args := `{
		"title":"【CORS】target+跨域读取",
		"category":"CORS",
		"vulnerability_type":"CORS",
		"target":"https://target.test",
		"proof":"HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
		"impact":"可读取敏感数据"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, newPolicyTestState())
	if decision.Allowed || decision.Code != "cors_wildcard_credentials" {
		t.Fatalf("wildcard ACAO with credentials must not become a formal vulnerability: %+v", decision)
	}
}

func TestEvidencePolicyRequiresBrowserContextForJSONPXSS(t *testing.T) {
	args := `{
		"title":"【XSS】target+JSONP callback 反射",
		"category":"XSS",
		"vulnerability_type":"XSS",
		"target":"https://target.test",
		"proof":"GET /jsonp?callback=alert(1) HTTP/1.1\nHost: target.test\n\nHTTP/1.1 200 OK\nalert(1)({\"ok\":true})",
		"impact":"可执行脚本"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, newPolicyTestState())
	if decision.Allowed || decision.Code != "jsonp_origin_unproven" {
		t.Fatalf("JSONP reflection without browser-origin proof must be rejected: %+v", decision)
	}
}

func TestEvidencePolicyRequiresDualIdentityForFormalIDOR(t *testing.T) {
	args := `{
		"title":"【越权】target+对象读取",
		"category":"越权访问/IDOR",
		"vulnerability_type":"idor_horizontal",
		"target":"https://target.test",
		"proof":"GET /api/orders/2 HTTP/1.1\nHost: target.test\n\nHTTP/1.1 200 OK",
		"impact":"可读取其他用户订单"
	}`
	state := newPolicyTestState()
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state)
	if decision.Allowed || decision.Code != "idor_dual_identity_missing" {
		t.Fatalf("formal IDOR requires an authorization differential: %+v", decision)
	}
	state.MarkAuthProbe(true, true)
	if allowed := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); !allowed.Allowed {
		t.Fatalf("dual identity evidence must release the IDOR gate: %+v", allowed)
	}
}

func TestEvidenceRejectionMemorySurvivesTypeSwap(t *testing.T) {
	state := newPolicyTestState()
	corsArgs := `{"target":"https://target.test","category":"CORS","proof":"HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true"}`
	xssArgs := `{"target":"https://target.test","category":"XSS","vulnerability_type":"XSS","proof":"HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true"}`

	first := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", corsArgs, state)
	state.RememberEvidenceRejection(first.Fingerprint, first.Code)
	second := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", xssArgs, state)
	if second.Allowed || second.Code != "evidence_previously_rejected" {
		t.Fatalf("same evidence must remain rejected after a type swap: %+v", second)
	}
	if strings.TrimSpace(second.Fingerprint) == "" || second.Fingerprint != first.Fingerprint {
		t.Fatalf("evidence fingerprint must ignore category/type swaps: first=%q second=%q", first.Fingerprint, second.Fingerprint)
	}
}
