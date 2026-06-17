package multiagent

import "testing"

func TestShouldEinoEmptyResponseContinue(t *testing.T) {
	t.Parallel()
	hint := "(empty hint)"
	out := &RunResult{Response: hint}
	if !shouldEinoEmptyResponseContinue(out, hint, 3, 1) {
		t.Fatal("expected continue when response is empty hint and trace grew")
	}
	if shouldEinoEmptyResponseContinue(out, hint, 1, 1) {
		t.Fatal("expected no continue when trace did not grow")
	}
	if shouldEinoEmptyResponseContinue(&RunResult{Response: "hello"}, hint, 3, 1) {
		t.Fatal("expected no continue when response has content")
	}
	if shouldEinoEmptyResponseContinue(nil, hint, 3, 1) {
		t.Fatal("expected no continue for nil result")
	}
}
