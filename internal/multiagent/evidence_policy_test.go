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

func TestEvidencePolicyUsesVulnerabilityURLsInsteadOfOrganizationTarget(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(SummarizeToolResult("http-framework-test",
		`{"url":"https://target.test/item?id=1%27"}`,
		"HTTP/1.1 500 Internal Server Error\nSQL syntax error near quote"))
	args := `{"title":"SQL注入","category":"SQL注入","target":"XX大学","vuln_urls":"https://target.test/item?id=1","proof":"GET /item?id=1 HTTP/1.1\nSQL syntax error","impact":"读取数据库"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); !got.Allowed {
		t.Fatalf("organization target must not replace vuln_urls as evidence scope: %+v", got)
	}
}

func TestEvidenceFingerprintScopesOrganizationFindingsByVulnerabilityURL(t *testing.T) {
	a, _ := vulnerabilityEvidenceFingerprint(`{"target":"XX大学","vuln_urls":"https://a.test/item","proof":"same proof"}`)
	b, _ := vulnerabilityEvidenceFingerprint(`{"target":"XX大学","vuln_urls":"https://b.test/item","proof":"same proof"}`)
	if a == b {
		t.Fatal("different vulnerability URLs under one organization must not share rejection memory")
	}
}

func TestEvidencePolicySupportsRepresentativeFormalCategories(t *testing.T) {
	for _, tc := range []struct{ category, marker string }{
		{"文件上传", "uploaded shell.php and requested /uploads/shell.php"},
		{"任意文件读取/下载", "read /etc/passwd root:x:0:0"},
		{"未授权访问", "unauthorized request returned admin data"},
		{"CSRF", "cross-site request changed account email"},
		{"SSTI/模板注入", "template expression {{7*7}} returned 49"},
		{"XXE", "external entity returned /etc/passwd"},
		{"路径穿越", "../ traversal returned /etc/passwd"},
		{"代码执行", "command execution returned uid=1000 gid=1000"},
	} {
		t.Run(tc.category, func(t *testing.T) {
			state := newPolicyTestState()
			state.RecordTool(ToolEvidenceEntry{ToolName: "http-framework-test", StatusHint: "interesting", Length: 100,
				InterestingParams: "url=https://target.test/probe", Summary: "https://target.test/probe " + tc.marker})
			args := `{"title":"` + tc.category + `","category":"` + tc.category + `","target":"XX大学","vuln_urls":"https://target.test/probe","proof":"GET /probe HTTP/1.1\n` + tc.marker + `","impact":"confirmed"}`
			if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); !got.Allowed {
				t.Fatalf("supported category rejected: %+v", got)
			}
		})
	}
}

func TestEvidencePolicyDoesNotUseRequestParametersAsVulnerabilityEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(ToolEvidenceEntry{ToolName: "http-framework-test", StatusHint: "ok", Length: 100,
		InterestingParams: "url=https://target.test/order?amount=1&token=abc",
		Summary:           "HTTP/1.1 200 OK normal order page"})
	args := `{"title":"金额篡改","category":"逻辑缺陷","target":"XX大学","vuln_urls":"https://target.test/order","proof":"GET /order HTTP/1.1\namount tamper accepted","impact":"低价购买"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("normal request parameters must not become observed business-logic evidence: %+v", got)
	}
}

func TestEvidencePolicyDoesNotUseEchoedRequestLineAsLogicEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(ToolEvidenceEntry{ToolName: "http-framework-test", StatusHint: "ok", Length: 100,
		InterestingParams: "url=https://target.test/order?amount=1",
		Summary:           "GET /order?amount=1 HTTP/1.1\nHTTP/1.1 200 OK\nnormal order page"})
	args := `{"title":"金额篡改","category":"逻辑缺陷","target":"XX大学","vuln_urls":"https://target.test/order","proof":"GET /order HTTP/1.1\namount tamper accepted","impact":"低价购买"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("echoed request line must not become observed business-logic evidence: %+v", got)
	}
}

func TestEvidencePolicyRejectsShellEchoAsFormalVulnerabilityEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(SummarizeToolResult("execute",
		`{"cmd":"echo https://target.test/order tamper accepted"}`,
		"https://target.test/order tamper accepted"))
	args := `{"title":"金额篡改","category":"逻辑缺陷","target":"XX大学","vuln_urls":"https://target.test/order","proof":"GET /order HTTP/1.1\ntamper accepted","impact":"低价购买"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("shell echo must not become formal vulnerability evidence: %+v", got)
	}
}

func TestEvidencePolicyRejectsShellEchoContainingNetworkToolName(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(SummarizeToolResult("execute",
		`{"cmd":"echo curl https://target.test/order tamper accepted"}`,
		"curl https://target.test/order tamper accepted"))
	args := `{"title":"金额篡改","category":"逻辑缺陷","target":"XX大学","vuln_urls":"https://target.test/order","proof":"GET /order HTTP/1.1\ntamper accepted","impact":"低价购买"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("echo mentioning a network tool must not become formal evidence: %+v", got)
	}
}

func TestEvidencePolicyRejectsCommentedNetworkCommandAsEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(SummarizeToolResult("execute",
		`{"cmd":"true; echo https://target.test/order tamper accepted; # curl https://target.test/order"}`,
		"https://target.test/order tamper accepted"))
	args := `{"title":"金额篡改","category":"逻辑缺陷","target":"XX大学","vuln_urls":"https://target.test/order","proof":"GET /order HTTP/1.1\ntamper accepted","impact":"低价购买"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("commented network command must not become formal evidence: %+v", got)
	}
}

func TestEvidencePolicyRejectsChainedNetworkCommandAsEvidence(t *testing.T) {
	for _, command := range []string{
		"curl --version|echo https://target.test/order tamper accepted",
		"curl --version&echo https://target.test/order tamper accepted",
	} {
		state := newPolicyTestState()
		state.RecordTool(SummarizeToolResult("execute", `{"cmd":"`+command+`"}`,
			"https://target.test/order tamper accepted"))
		args := `{"title":"金额篡改","category":"逻辑缺陷","target":"XX大学","vuln_urls":"https://target.test/order","proof":"GET /order HTTP/1.1\ntamper accepted","impact":"低价购买"}`
		if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
			t.Fatalf("chained command %q must not become formal evidence: %+v", command, got)
		}
	}
}

func TestEvidencePolicyRejectsPythonPrintAsFormalVulnerabilityEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(SummarizeToolResult("execute-python-script",
		`{"code":"print('https://target.test/order tamper accepted')"}`,
		"https://target.test/order tamper accepted"))
	args := `{"title":"金额篡改","category":"逻辑缺陷","target":"XX大学","vuln_urls":"https://target.test/order","proof":"GET /order HTTP/1.1\ntamper accepted","impact":"低价购买"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("python print must not become formal vulnerability evidence: %+v", got)
	}
}

func TestEvidencePolicyRejectsPythonCommentedRequestAsEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(SummarizeToolResult("execute-python-script",
		`{"code":"print('https://target.test/order tamper accepted')\n# requests.get('https://target.test/order')"}`,
		"https://target.test/order tamper accepted"))
	args := `{"title":"金额篡改","category":"逻辑缺陷","target":"XX大学","vuln_urls":"https://target.test/order","proof":"GET /order HTTP/1.1\ntamper accepted","impact":"低价购买"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("commented Python request must not become formal evidence: %+v", got)
	}
}

func TestEvidencePolicyAllowsTargetFacingShellHTTPEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(SummarizeToolResult("execute",
		`{"cmd":"curl -i https://target.test/order?amount=1"}`,
		"HTTP/1.1 200 OK\namount tamper accepted; invariant violated"))
	args := `{"title":"金额篡改","category":"逻辑缺陷","target":"XX大学","vuln_urls":"https://target.test/order","proof":"GET /order HTTP/1.1\ntamper accepted","impact":"低价购买"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); !got.Allowed {
		t.Fatalf("target-facing shell HTTP evidence should remain usable: %+v", got)
	}
}

func TestEvidencePolicyAllowsObservedAuthorizationBypassForIDOR(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(ToolEvidenceEntry{ToolName: "http-framework-test", StatusHint: "interesting", Length: 100,
		InterestingParams: "url=https://target.test/orders/2",
		Summary:           "https://target.test/orders/2 auth_b accessed owner auth_a object; authorization bypass confirmed"})
	args := `{"title":"越权读取订单","category":"越权访问/IDOR","target":"XX大学","vuln_urls":"https://target.test/orders/2","proof":"GET /orders/2 HTTP/1.1\nauth_b accessed owner auth_a object","impact":"读取他人订单"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); !got.Allowed {
		t.Fatalf("observed authorization bypass must allow formal IDOR: %+v", got)
	}
}

func TestEvidencePolicyDoesNotUseEchoedAuthLabelAsIDOREvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(ToolEvidenceEntry{ToolName: "http-framework-test", StatusHint: "ok", Length: 100,
		InterestingParams: "url=https://target.test/orders/2",
		Summary:           "GET /orders/2 auth_b\nHTTP/1.1 403 Forbidden"})
	args := `{"title":"越权读取订单","category":"越权访问/IDOR","target":"XX大学","vuln_urls":"https://target.test/orders/2","proof":"GET /orders/2 HTTP/1.1\nauth_b accessed owner auth_a object","impact":"读取他人订单"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("echoed auth label must not become observed IDOR evidence: %+v", got)
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

func TestEvidencePolicyKeepsJSONPReflectionAsCandidate(t *testing.T) {
	args := `{
		"title":"【XSS候选】target+JSONP callback 反射",
		"category":"XSS",
		"vulnerability_type":"XSS",
		"target":"https://target.test",
		"signal":"GET /jsonp?callback=alert(1) 返回 alert(1)({\"ok\":true})"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability_candidate", args, newPolicyTestState())
	if !decision.Allowed {
		t.Fatalf("JSONP reflection must remain recordable as an L1 candidate: %+v", decision)
	}
}

func TestFormalEvidenceRejectionDoesNotBlockCandidateDowngrade(t *testing.T) {
	state := newPolicyTestState()
	formalArgs := `{
		"title":"【XSS】target+JSONP callback 反射",
		"category":"XSS",
		"vulnerability_type":"XSS",
		"target":"https://target.test",
		"proof":"GET /jsonp?callback=alert(1) 返回 alert(1)({\"ok\":true})"
	}`
	rejected := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", formalArgs, state)
	if rejected.Allowed {
		t.Fatal("setup formal record must be rejected")
	}
	state.RememberEvidenceRejection(rejected.Fingerprint, rejected.Code)

	candidateArgs := `{
		"title":"【XSS候选】target+JSONP callback 反射",
		"category":"XSS",
		"vulnerability_type":"XSS",
		"target":"https://target.test",
		"signal":"GET /jsonp?callback=alert(1) 返回 alert(1)({\"ok\":true})"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability_candidate", candidateArgs, state)
	if !decision.Allowed {
		t.Fatalf("formal rejection memory must not prevent an L1 downgrade: %+v", decision)
	}
}

func TestEvidencePolicyDoesNotTrustSelfAssertedBrowserProof(t *testing.T) {
	args := `{
		"title":"【XSS】target+JSONP callback 反射",
		"category":"XSS",
		"vulnerability_type":"XSS",
		"target":"https://target.test",
		"proof":"使用 Playwright 在目标源执行，document.origin=https://target.test",
		"impact":"可执行脚本"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, newPolicyTestState())
	if decision.Allowed || decision.Code != "jsonp_origin_unproven" {
		t.Fatalf("model-authored proof text must not replace observed browser evidence: %+v", decision)
	}
}

func TestEvidencePolicyAcceptsObservedBrowserOriginEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(ToolEvidenceEntry{
		ToolName:          "playwright_browser",
		StatusHint:        "ok",
		Length:            240,
		InterestingParams: "cmd=playwright test xss",
		Summary:           "executed in target origin; location.origin=https://target.test",
	})
	args := `{
		"title":"【XSS】target+JSONP callback 反射",
		"category":"XSS",
		"vulnerability_type":"XSS",
		"target":"https://target.test",
		"proof":"浏览器验证 callback 在目标源脚本上下文执行",
		"impact":"可执行脚本"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state)
	if !decision.Allowed {
		t.Fatalf("observed browser-origin evidence must release the formal XSS gate: %+v", decision)
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
	state.MarkSuccessfulDualAuthProbe("https://target.test/orders/2")
	if allowed := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); !allowed.Allowed {
		t.Fatalf("dual identity evidence must release the IDOR gate: %+v", allowed)
	}
}

func TestEvidencePolicyDoesNotTrustSelfAssertedDualIdentityProof(t *testing.T) {
	args := `{
		"title":"【越权】target+对象读取",
		"category":"越权访问/IDOR",
		"vulnerability_type":"idor_horizontal",
		"target":"https://target.test",
		"proof":"auth_a 读取对象后，auth_b 也读取成功",
		"impact":"可读取其他用户订单"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, newPolicyTestState())
	if decision.Allowed || decision.Code != "idor_dual_identity_missing" {
		t.Fatalf("model-authored identity labels must not replace an observed dual-auth probe: %+v", decision)
	}
}

func TestEvidencePolicyScopesDualIdentityEvidenceToTarget(t *testing.T) {
	state := newPolicyTestState()
	state.MarkSuccessfulDualAuthProbe("https://target-a.test/orders/1")
	args := `{
		"title":"【越权】target-b+对象读取",
		"category":"越权访问/IDOR",
		"vulnerability_type":"idor_horizontal",
		"target":"https://target-b.test",
		"proof":"两个身份返回相同对象",
		"impact":"可读取其他用户订单"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state)
	if decision.Allowed || decision.Code != "idor_dual_identity_missing" {
		t.Fatalf("dual-auth evidence from another target must not unlock this IDOR: %+v", decision)
	}
}

func TestEvidencePolicyRequiresObservedEvidenceForFormalFindings(t *testing.T) {
	args := `{
		"title":"【SQL注入】target+id 参数",
		"category":"SQL注入",
		"vulnerability_type":"sqli",
		"target":"https://target.test",
		"proof":"GET /item?id=1' 返回数据库错误并可提取数据",
		"impact":"可读取数据库"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, newPolicyTestState())
	if decision.Allowed || decision.Code != "observed_evidence_missing" {
		t.Fatalf("self-authored formal proof without a matching tool result must be rejected: %+v", decision)
	}
}

func TestEvidencePolicyAllowsFormalFindingWithMatchingObservedEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(ToolEvidenceEntry{
		ToolName:          "http-framework-test",
		StatusHint:        "interesting",
		Length:            480,
		InterestingParams: "url=https://target.test/item?id=1%27",
		Summary:           "HTTP/1.1 500 Internal Server Error | SQL syntax error near quote",
	})
	args := `{
		"title":"【SQL注入】target+id 参数",
		"category":"SQL注入",
		"vulnerability_type":"sqli",
		"target":"https://target.test",
		"proof":"GET /item?id=1' 返回 SQL syntax error",
		"impact":"可能读取数据库"
	}`
	decision := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state)
	if !decision.Allowed {
		t.Fatalf("matching observed tool evidence must allow formal policy evaluation: %+v", decision)
	}
}

func TestEvidencePolicyRejectsFailedOrUnrelatedObservedEvidence(t *testing.T) {
	args := `{"title":"SQL注入","category":"SQL注入","vulnerability_type":"sqli","target":"https://target.test","proof":"SQL syntax error","impact":"读取数据库"}`
	for _, entry := range []ToolEvidenceEntry{
		{ToolName: "http-framework-test", StatusHint: "error_or_reject", ErrorSig: "name resolution failed", Length: 80, InterestingParams: "url=https://target.test", Summary: "name resolution failed"},
		{ToolName: "http-framework-test", StatusHint: "ok", Length: 80, InterestingParams: "url=https://target.test", Summary: "HTTP/1.1 200 OK normal page"},
		{ToolName: "http-framework-test", StatusHint: "404", Length: 80, InterestingParams: "url=https://target.test", Summary: "HTTP/1.1 404 Not Found"},
	} {
		state := newPolicyTestState()
		state.RecordTool(entry)
		if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
			t.Fatalf("failed or unrelated observation must not unlock a formal finding: %+v", entry)
		}
	}
}

func TestEvidencePolicyRejectsFailedBrowserObservation(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(ToolEvidenceEntry{
		ToolName: "execute", StatusHint: "error_or_reject", ErrorSig: "playwright failed",
		Length: 100, InterestingParams: "cmd=playwright", Summary: "failed before location.origin=https://target.test",
	})
	args := `{"title":"JSONP XSS","category":"XSS","vulnerability_type":"XSS","target":"https://target.test","proof":"callback executes","impact":"script execution"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed || got.Code != "jsonp_origin_unproven" {
		t.Fatalf("failed browser execution must not unlock JSONP XSS: %+v", got)
	}
}

func TestEvidencePolicyRequiresMatchingVulnerabilityClass(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(ToolEvidenceEntry{
		ToolName: "http-framework-test", StatusHint: "interesting", Length: 100,
		InterestingParams: "url=https://target.test/item?id=1",
		Summary:           "https://target.test missing security header; target vulnerable",
	})
	args := `{"title":"SQL注入","category":"SQL注入","vulnerability_type":"sqli","target":"https://target.test","proof":"GET /item?id=1 HTTP/1.1\nSQL syntax error","impact":"读取数据库"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("another vulnerability on the same target must not unlock SQLi: %+v", got)
	}
}

func TestEvidencePolicyRejectsShellEchoAsBrowserEvidence(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(ToolEvidenceEntry{
		ToolName: "execute", StatusHint: "ok", Length: 100,
		InterestingParams: `cmd=echo "playwright location.origin=https://target.test"`,
		Summary:           "playwright location.origin=https://target.test",
	})
	args := `{"title":"JSONP XSS","category":"XSS","vulnerability_type":"XSS","target":"https://target.test","proof":"callback executes","impact":"script execution"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); got.Allowed {
		t.Fatalf("shell echo must not unlock browser-origin evidence: %+v", got)
	}
}

func TestEvidencePolicyAcceptsSummarizedTargetSQLError(t *testing.T) {
	state := newPolicyTestState()
	state.RecordTool(SummarizeToolResult(
		"http-framework-test",
		`{"url":"https://target.test/item?id=1%27"}`,
		"HTTP/1.1 500 Internal Server Error\nSQL syntax error near quote",
	))
	args := `{"title":"SQL注入","category":"SQL注入","vulnerability_type":"sqli","target":"https://target.test","proof":"GET /item?id=1 HTTP/1.1\nSQL syntax error","impact":"读取数据库"}`
	if got := EvaluateVulnerabilityEvidencePolicy("record_vulnerability", args, state); !got.Allowed {
		t.Fatalf("target SQL error from the production summarizer must remain usable: %+v", got)
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
