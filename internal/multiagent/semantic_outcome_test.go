package multiagent

import "testing"

func TestClassifySemanticOutcome(t *testing.T) {
	tests := []struct {
		name       string
		tool       string
		result     string
		isError    bool
		wantKind   SemanticOutcomeKind
		wantCode   string
		wantGrowth bool
	}{
		{
			name:       "successful state write is evidence progress",
			tool:       "upsert_project_fact",
			result:     `{"status":"success","fact_id":"fact-1"}`,
			wantKind:   SemanticOutcomeCompleted,
			wantCode:   "completed",
			wantGrowth: true,
		},
		{
			name:     "stable not found is target negative",
			tool:     "http-framework-test",
			result:   "HTTP/1.1 404 Not Found\ncontent-type: text/html",
			wantKind: SemanticOutcomeTargetNegative,
			wantCode: "http_404",
		},
		{
			name:     "connection refusal is target negative",
			tool:     "http-framework-test",
			result:   "dial tcp 192.0.2.1:7776: connect: connection refused",
			isError:  true,
			wantKind: SemanticOutcomeTargetNegative,
			wantCode: "target_unreachable",
		},
		{
			name:     "network reset is transient",
			tool:     "http-framework-test",
			result:   "read tcp 192.0.2.10:443: connection reset by peer",
			isError:  true,
			wantKind: SemanticOutcomeExternalTransient,
			wantCode: "connection_reset",
		},
		{
			name:     "schema error is invocation error",
			tool:     "upsert_project_fact",
			result:   `invalid arguments: links 须为数组`,
			isError:  true,
			wantKind: SemanticOutcomeInvocationError,
			wantCode: "invalid_arguments",
		},
		{
			name:     "policy rejection is distinct from invocation failure",
			tool:     "record_vulnerability",
			result:   "policy rejected: evidence is insufficient for a formal vulnerability",
			isError:  true,
			wantKind: SemanticOutcomePolicyRejected,
			wantCode: "policy_rejected",
		},
		{
			name:     "framework drop is not an external failure",
			tool:     "http-framework-test",
			result:   "[framework_tool_outcome] code=batch_rewritten retryable=false",
			isError:  true,
			wantKind: SemanticOutcomeFrameworkDropped,
			wantCode: "batch_rewritten",
		},
		{
			name:     "http 401 is auth rejected",
			tool:     "http-framework-test",
			result:   "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic",
			wantKind: SemanticOutcomeAuthRejected,
			wantCode: "http_401",
		},
		{
			name:     "http 403 is auth rejected",
			tool:     "http-framework-test",
			result:   "HTTP/1.1 403 Forbidden\ncontent-type: text/html",
			wantKind: SemanticOutcomeAuthRejected,
			wantCode: "http_403",
		},
		{
			name:     "chinese login-failed body is auth rejected even on 200",
			tool:     "http-framework-test",
			result:   "HTTP/1.1 200 OK\n\n<script>alert('密码错误，剩余 4 次尝试机会');</script>",
			wantKind: SemanticOutcomeAuthRejected,
			wantCode: "auth_rejected",
		},
		{
			name:     "english invalid credentials is auth rejected",
			tool:     "http-framework-test",
			result:   "HTTP/1.1 200 OK\n\nLogin failed: invalid credentials.",
			wantKind: SemanticOutcomeAuthRejected,
			wantCode: "auth_rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifySemanticOutcome(tt.tool, `{}`, tt.result, tt.isError)
			if got.Kind != tt.wantKind || got.Code != tt.wantCode || got.EvidenceProgress != tt.wantGrowth {
				t.Fatalf("unexpected outcome: got=%+v want kind=%s code=%s growth=%v", got, tt.wantKind, tt.wantCode, tt.wantGrowth)
			}
			if got.Fingerprint == "" {
				t.Fatal("semantic outcome must have a stable fingerprint")
			}
		})
	}
}

func TestSemanticOutcomePreservesTargetSQLErrorAsEvidence(t *testing.T) {
	got := ClassifySemanticOutcome("http-framework-test", `{"url":"https://target.test/item"}`,
		"HTTP/1.1 500 Internal Server Error\nSQL syntax error near quote", false)
	if got.Kind == SemanticOutcomeInvocationError {
		t.Fatalf("target SQL error must not consume invocation budget: %+v", got)
	}
}

func TestSemanticOutcomeBranchExtractsURL(t *testing.T) {
	// http-framework-test passes the endpoint as "url"; the branch must reflect
	// the target host so per-URL dedup works instead of all calls sharing one
	// empty branch slot.
	got := ClassifySemanticOutcome("http-framework-test",
		`{"url":"http://example.com/admin/login.php","method":"POST"}`,
		"HTTP/1.1 200 OK\n\n密码错误", false)
	if got.Branch == "" {
		t.Fatal("branch must be extracted from url field for http-framework-test")
	}
	if got.Kind != SemanticOutcomeAuthRejected {
		t.Fatalf("login failure must classify as auth rejected, got %s", got.Kind)
	}
}

func TestSemanticOutcomeBranchExtractsURLFromExecCommand(t *testing.T) {
	// exec tools embed the target inside a shell command string; the branch
	// must still resolve to the host so repeated probes of the same host dedup.
	got := ClassifySemanticOutcome("exec",
		`{"command":"curl -s http://example.com:9090/mlecms/upload/admin/login.php"}`,
		"HTTP/1.1 200 OK\n\nok", false)
	if got.Branch == "" {
		t.Fatal("branch must be extracted from command text for exec tools")
	}
}

func TestSemanticOutcomeKeepsToolSideSQLErrorAsInvocationError(t *testing.T) {
	got := ClassifySemanticOutcome("database-tool", `{}`, "SQL syntax error in tool query", true)
	if got.Kind != SemanticOutcomeInvocationError {
		t.Fatalf("tool-side SQL error must remain invocation error: %+v", got)
	}
}

func TestClassifySemanticOutcomeCollapsesEquivalentLowValueResults(t *testing.T) {
	first := ClassifySemanticOutcome(
		"http-framework-test",
		`{"url":"https://target.test/a"}`,
		"HTTP/1.1 200 OK\ncontent-type: text/html\n<html><div id=\"app\"></div><script src=\"/assets/app.123.js\"></script></html>",
		false,
	)
	second := ClassifySemanticOutcome(
		"http-framework-test",
		`{"url":"https://target.test/b"}`,
		"HTTP/1.1 200 OK\ncontent-type: text/html\n<html><div id=\"app\"></div><script src=\"/assets/app.456.js\"></script></html>",
		false,
	)
	if first.Kind != SemanticOutcomeTargetNegative || second.Kind != SemanticOutcomeTargetNegative {
		t.Fatalf("SPA shell must be classified as target-negative: first=%+v second=%+v", first, second)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("equivalent SPA shells must collapse: %q != %q", first.Fingerprint, second.Fingerprint)
	}
}

func TestExecutionControllerSemanticBudget(t *testing.T) {
	t.Run("one correction for the same invocation error", func(t *testing.T) {
		controller := NewExecutionController("target.test")
		first := ClassifySemanticOutcome("upsert_project_fact", `{"links":"bad"}`, "invalid arguments: links 须为数组", true)
		second := ClassifySemanticOutcome("upsert_project_fact", `{"links":{"bad":true}}`, "invalid arguments: links 须为数组", true)

		controller.RecordSemanticOutcome("call-1", "upsert_project_fact", CallSignature("upsert_project_fact", `{"links":"bad"}`), first)
		if allowed, reason := controller.CheckToolCallAllowed("upsert_project_fact", `{"links":{"bad":true}}`); !allowed {
			t.Fatalf("one corrected invocation must be allowed, reason=%q", reason)
		}
		controller.RecordSemanticOutcome("call-2", "upsert_project_fact", CallSignature("upsert_project_fact", `{"links":{"bad":true}}`), second)
		if allowed, reason := controller.CheckToolCallAllowed("upsert_project_fact", `{"links":[]}`); allowed || reason != "invocation_error_exhausted" {
			t.Fatalf("same invocation error must stop after one correction, got allowed=%v reason=%q", allowed, reason)
		}
	})

	t.Run("volatile received values do not reset invocation budget", func(t *testing.T) {
		controller := NewExecutionController("target.test")
		firstArgs := `{"links":"bad"}`
		secondArgs := `{"links":{"bad":true}}`
		first := ClassifySemanticOutcome(
			"upsert_project_fact",
			firstArgs,
			`invalid arguments: field "links" must be an array, got "bad"`,
			true,
		)
		second := ClassifySemanticOutcome(
			"upsert_project_fact",
			secondArgs,
			`invalid arguments: field "links" must be an array, got {"bad":true}`,
			true,
		)
		controller.RecordSemanticOutcome("call-1", "upsert_project_fact", CallSignature("upsert_project_fact", firstArgs), first)
		controller.RecordSemanticOutcome("call-2", "upsert_project_fact", CallSignature("upsert_project_fact", secondArgs), second)

		if allowed, reason := controller.CheckToolCallAllowed("upsert_project_fact", `{"links":[]}`); allowed || reason != "invocation_error_exhausted" {
			t.Fatalf("changing echoed invalid values must not reset the correction budget, allowed=%v reason=%q", allowed, reason)
		}
	})

	t.Run("external transient retries are bounded", func(t *testing.T) {
		controller := NewExecutionController("target.test")
		args := `{"url":"https://target.test"}`
		outcome := ClassifySemanticOutcome("http-framework-test", args, "connection reset by peer", true)
		controller.RecordSemanticOutcome("call-1", "http-framework-test", "sig-1", outcome)
		if allowed, _ := controller.CheckToolCallAllowed("http-framework-test", args); !allowed {
			t.Fatal("first transient result must allow one retry")
		}
		controller.RecordSemanticOutcome("call-2", "http-framework-test", "sig-2", outcome)
		if allowed, reason := controller.CheckToolCallAllowed("http-framework-test", args); allowed || reason != "external_transient_exhausted" {
			t.Fatalf("transient retry budget must be exhausted, got allowed=%v reason=%q", allowed, reason)
		}
	})

	t.Run("transient exhaustion is isolated by target branch", func(t *testing.T) {
		controller := NewExecutionController("target-a.test")
		argsA := `{"url":"https://target-a.test/api"}`
		outcomeA := ClassifySemanticOutcome("http-framework-test", argsA, "connection reset by peer", true)
		controller.RecordSemanticOutcome("call-a1", "http-framework-test", "sig-a1", outcomeA)
		controller.RecordSemanticOutcome("call-a2", "http-framework-test", "sig-a2", outcomeA)

		if allowed, reason := controller.CheckToolCallAllowed("http-framework-test", `{"url":"https://target-b.test/api"}`); !allowed {
			t.Fatalf("exhaustion on target A must not block target B, reason=%q", reason)
		}

		argsB := `{"url":"https://target-b.test/api"}`
		outcomeB := ClassifySemanticOutcome("http-framework-test", argsB, "connection reset by peer", true)
		controller.RecordSemanticOutcome("call-b1", "http-framework-test", "sig-b1", outcomeB)
		if allowed, reason := controller.CheckToolCallAllowed("http-framework-test", argsA); allowed || reason != "external_transient_exhausted" {
			t.Fatalf("switching branches must not forget target A exhaustion, allowed=%v reason=%q", allowed, reason)
		}
	})

	t.Run("explicit coverage branches isolate the same target", func(t *testing.T) {
		controller := NewExecutionController("target.test")
		argsA := `{"url":"https://target.test/api","coverage_path":"auth.login"}`
		outcomeA := ClassifySemanticOutcome("http-framework-test", argsA, "connection reset by peer", true)
		controller.RecordSemanticOutcome("call-a1", "http-framework-test", "sig-a1", outcomeA)
		controller.RecordSemanticOutcome("call-a2", "http-framework-test", "sig-a2", outcomeA)

		argsB := `{"url":"https://target.test/api","coverage_path":"auth.reset"}`
		if allowed, reason := controller.CheckToolCallAllowed("http-framework-test", argsB); !allowed {
			t.Fatalf("one coverage branch must not exhaust another on the same host, reason=%q", reason)
		}
	})
}

func TestSemanticOutcomeNormalizesCannotUnmarshalActualType(t *testing.T) {
	a := ClassifySemanticOutcome("upsert_project_fact", `{"target":"target.test"}`,
		"json: cannot unmarshal string into Go struct field input.links of type []string", true)
	b := ClassifySemanticOutcome("upsert_project_fact", `{"target":"target.test"}`,
		"json: cannot unmarshal object into Go struct field input.links of type []string", true)
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("actual JSON value type must not refresh invocation budget: %s != %s", a.Fingerprint, b.Fingerprint)
	}
}
