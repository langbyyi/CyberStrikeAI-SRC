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
