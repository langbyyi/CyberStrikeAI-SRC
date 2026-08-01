package multiagent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type logicProbeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f logicProbeRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestLogicProbeRecordsDualAuthOnlyAfterComparableResponses(t *testing.T) {
	result := RunLogicProbeDiff(context.Background(), LogicProbeRequest{
		URL:   "https://target.test/orders/1",
		Mode:  LogicProbeModeIdentityDiff,
		AuthA: "Bearer account-a",
		AuthB: "Bearer account-b",
		Client: &http.Client{Transport: logicProbeRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})},
	})

	if result.DualAuthRecorded {
		t.Fatalf("failed HTTP requests must not become observed dual-auth evidence: %+v", result)
	}
}

func TestLogicProbeKeepsDualRejectionAsComparisonOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()
	result := RunLogicProbeDiff(context.Background(), LogicProbeRequest{
		URL: server.URL + "/objects/1", Mode: LogicProbeModeIdentityDiff,
		AuthA: "Bearer a", AuthB: "Bearer b", Client: server.Client(),
	})
	if !result.DualAuthRecorded || result.SuggestedInvariantBreak != "no_identity_divergence: continue payment/workflow tests with param_tamper/step_skip on same account" {
		t.Fatalf("two comparable 403 responses should remain a negative comparison, not a confirmed bypass: %+v", result)
	}
}
