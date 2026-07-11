package multiagent

import (
	"strings"
	"testing"
)

func TestAutoUpsertCoverageFromCandidate(t *testing.T) {
	t.Parallel()
	conv := "test-cov-from-cand"
	ResetConversationExecutionStateForTest(conv)
	item := AutoUpsertCoverageFromCandidate(
		conv,
		"https://example.test/login",
		"id",
		"SQL注入",
		"SQL注入",
		"high",
		"quote error differential",
	)
	if item.Path == "" {
		t.Fatal("path empty")
	}
	if !strings.Contains(item.Path, "param:id") && !strings.Contains(item.Path, "id") {
		t.Fatalf("path should include param: %s", item.Path)
	}
	if item.Status != "open" {
		t.Fatalf("status=%s", item.Status)
	}
	if item.Priority != "P0" {
		t.Fatalf("priority=%s want P0 for high/sqli", item.Priority)
	}
	items := GetConversationExecutionState(conv).ListCoverage()
	if len(items) != 1 {
		t.Fatalf("coverage count=%d", len(items))
	}
}

func TestMarkCoverageDoneForVuln(t *testing.T) {
	t.Parallel()
	conv := "test-cov-l2-done"
	ResetConversationExecutionStateForTest(conv)
	AutoUpsertCoverageFromCandidate(conv, "https://t/app", "id", "sqli", "", "high", "signal")
	// ensure open
	cont, _, open := GetConversationExecutionState(conv).ShouldContinue()
	if !cont || len(open) == 0 {
		t.Fatal("expected open coverage")
	}
	marked := MarkCoverageDoneForVuln(conv, "【SQL注入】app+id time blind", "https://t/app")
	if len(marked) == 0 {
		t.Fatal("expected at least one coverage marked done")
	}
	_, _, open2 := GetConversationExecutionState(conv).ShouldContinue()
	if len(open2) != 0 {
		t.Fatalf("still open: %+v", open2)
	}
}

func TestCoveragePathFromCandidate(t *testing.T) {
	t.Parallel()
	p := CoveragePathFromCandidate("https://a", "file", "lfi", "")
	if !strings.Contains(p, "file") {
		t.Fatalf("%s", p)
	}
	p2 := CoveragePathFromCandidate("https://a", "", "xss", "")
	if !strings.Contains(p2, "xss") {
		t.Fatalf("%s", p2)
	}
}

func TestEstimateCoveragePriorityFromVuln(t *testing.T) {
	t.Parallel()
	if got := EstimateCoveragePriorityFromVuln("SQL Injection", "critical"); got != "P0" {
		t.Fatalf("%s", got)
	}
	if got := EstimateCoveragePriorityFromVuln("reflected xss", "medium"); got != "P1" {
		t.Fatalf("%s", got)
	}
	// info severity → P3 (contract allows P2/P3 for info-class)
	if got := EstimateCoveragePriorityFromVuln("info disclosure", "info"); got != "P3" && got != "P2" {
		t.Fatalf("info severity want P2/P3 got %s", got)
	}
}
