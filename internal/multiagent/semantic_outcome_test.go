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

	t.Run("external transient retries are bounded", func(t *testing.T) {
		controller := NewExecutionController("target.test")
		outcome := ClassifySemanticOutcome("http-framework-test", `{}`, "connection reset by peer", true)
		controller.RecordSemanticOutcome("call-1", "http-framework-test", "sig-1", outcome)
		if allowed, _ := controller.CheckToolCallAllowed("http-framework-test", `{"url":"https://target.test"}`); !allowed {
			t.Fatal("first transient result must allow one retry")
		}
		controller.RecordSemanticOutcome("call-2", "http-framework-test", "sig-2", outcome)
		if allowed, reason := controller.CheckToolCallAllowed("http-framework-test", `{"url":"https://target.test"}`); allowed || reason != "external_transient_exhausted" {
			t.Fatalf("transient retry budget must be exhausted, got allowed=%v reason=%q", allowed, reason)
		}
	})
}
