package multiagent

import (
	"fmt"
	"testing"
)

func TestResultFingerprintCollapsesEquivalentHTTPClientErrors(t *testing.T) {
	for _, status := range []string{"404 Not Found", "412 Precondition Failed"} {
		t.Run(status, func(t *testing.T) {
			first := ResultFingerprint("http-framework-test", "GET https://target.test/missing-a\nHTTP/1.1 "+status+"\n{\"path\":\"/missing-a\"}")
			second := ResultFingerprint("http-framework-test", "GET https://target.test/missing-b\nHTTP/1.1 "+status+"\n{\"path\":\"/missing-b\"}")

			if first != second {
				t.Fatalf("equivalent HTTP outcomes must share a fingerprint: %q != %q", first, second)
			}
		})
	}
}

func TestExecutionControllerBlocksNewProbeAfterStagnation(t *testing.T) {
	controller := NewExecutionController("target.test")
	const fingerprint = "equivalent-http-404"

	for i := 0; i < 4; i++ {
		callID := fmt.Sprintf("call-%d", i)
		signature := fmt.Sprintf("signature-%d", i)
		controller.StartProbeBatch([]string{callID})
		controller.RecordProbeResult(callID, signature, fingerprint, "http_404")
		controller.CompleteProbeBatch()
	}

	if !controller.PivotRequired() {
		t.Fatal("expected repeated equivalent outcomes to require closing the probe branch")
	}
	if allowed, reason := controller.CheckProbeCallAllowed("unseen-signature"); allowed || reason != "stagnation_blocked" {
		t.Fatalf("new probe must be blocked after stagnation, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestExecutionControllerBlocksDuplicateProvenCall(t *testing.T) {
	// An identical probe call that already completed successfully must be blocked
	// on the 2nd attempt (duplicate_proven), not allowed to repeat indefinitely.
	controller := NewExecutionController("target.test")
	args := `{"command":"curl -s http://target.test/ -o /dev/null -w %{http_code}"}`
	// First call: allowed (no prior record yet), then record its success.
	if allowed, _ := controller.CheckToolCallAllowed("exec", args); !allowed {
		t.Fatal("first successful call must be allowed")
	}
	outcome := SemanticOutcome{
		Kind:             SemanticOutcomeCompleted,
		Code:             "completed",
		Fingerprint:      "fp-1",
		Branch:           "target.test",
		EvidenceProgress: true,
	}
	controller.RecordSemanticOutcome("call-1", "exec", CallSignature("exec", args), outcome)
	// Second identical call: must be blocked as duplicate_proven.
	allowed, reason := controller.CheckToolCallAllowed("exec", args)
	if allowed || reason != "duplicate_proven" {
		t.Fatalf("duplicate successful exec must be blocked, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestExecutionControllerDoesNotBlockIdempotentMutationDuplicate(t *testing.T) {
	// record/update/upsert tools are idempotent writes — they must NOT be blocked
	// by duplicate_proven even when the signature repeats.
	controller := NewExecutionController("target.test")
	args := `{"fact":"asset","value":"1.2.3.4"}`
	outcome := SemanticOutcome{
		Kind:             SemanticOutcomeCompleted,
		Code:             "completed",
		Fingerprint:      "fp-fact",
		Branch:           "target.test",
		EvidenceProgress: true,
	}
	controller.RecordSemanticOutcome("call-1", "upsert_project_fact", CallSignature("upsert_project_fact", args), outcome)
	allowed, reason := controller.CheckToolCallAllowed("upsert_project_fact", args)
	if !allowed {
		t.Fatalf("idempotent mutation tool must not be blocked as duplicate, reason=%q", reason)
	}
}

func TestExecutionControllerBlocksAuthRejectedAfterOneAttempt(t *testing.T) {
	// Online credential guessing risks account lockout; allow at most one
	// auth-rejected attempt per (tool, branch).
	controller := NewExecutionController("target.test")
	args := `{"url":"http://target.test/admin/login.php","method":"POST","data":"username=admin&password=admin"}`
	branch := semanticOutcomeBranch(args)
	outcome := SemanticOutcome{
		Kind:             SemanticOutcomeAuthRejected,
		Code:             "auth_rejected",
		Fingerprint:      "fp-auth",
		Branch:           branch,
		EvidenceProgress: false,
	}
	controller.RecordSemanticOutcome("call-1", "http-framework-test", CallSignature("http-framework-test", args), outcome)
	// A different payload to the same branch must still be blocked (lockout guard).
	allowed, reason := controller.CheckToolCallAllowed("http-framework-test",
		`{"url":"http://target.test/admin/login.php","method":"POST","data":"username=admin&password=123456"}`)
	if allowed || reason != "auth_rejected_exhausted" {
		t.Fatalf("second auth attempt to same branch must be blocked, got allowed=%v reason=%q", allowed, reason)
	}
}
