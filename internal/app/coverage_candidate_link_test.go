package app

import (
	"os"
	"strings"
	"testing"

	"cyberstrike-ai/internal/multiagent"
)

// TestCandidateCoverageAutoUpsertHelper drives the pure helper used by
// registerRecordVulnerabilityCandidateTool (shipped path dependency).
func TestCandidateCoverageAutoUpsertHelper(t *testing.T) {
	t.Parallel()
	conv := "app-cand-cov-link"
	multiagent.ResetConversationExecutionStateForTest(conv)
	item := multiagent.AutoUpsertCoverageFromCandidate(
		conv,
		"https://shop.example/item",
		"id",
		"sqli",
		"SQL注入",
		"high",
		"单引号 SQL syntax error 差分",
	)
	if item.Status != "open" {
		t.Fatalf("status=%s", item.Status)
	}
	if item.Priority != "P0" {
		t.Fatalf("priority=%s", item.Priority)
	}
	if !strings.Contains(item.Path, "id") {
		t.Fatalf("path=%s", item.Path)
	}
	items := multiagent.GetConversationExecutionState(conv).ListCoverage()
	if len(items) == 0 {
		t.Fatal("coverage map empty after candidate upsert")
	}
	// L2 mark done
	marked := multiagent.MarkCoverageDoneForVuln(conv, "【SQL注入】item+id", "https://shop.example/item")
	if len(marked) == 0 {
		t.Fatal("L2 should mark coverage done")
	}
	_, _, open := multiagent.GetConversationExecutionState(conv).ShouldContinue()
	if len(open) != 0 {
		t.Fatalf("still open after L2: %+v", open)
	}
}

func TestCandidateToolSourceWiresCoverageHelpers(t *testing.T) {
	// Structural: shipped vulnerability_tools.go must call AutoUpsertCoverageFromCandidate
	// and MarkCoverageDoneForVuln (prevents drift if handler is refactored away from helpers).
	t.Parallel()
	src, err := os.ReadFile("vulnerability_tools.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, "AutoUpsertCoverageFromCandidate") {
		t.Fatal("candidate path must call AutoUpsertCoverageFromCandidate")
	}
	if !strings.Contains(text, "coverage_auto_from_candidate") {
		t.Fatal("must log coverage_auto_from_candidate")
	}
	if !strings.Contains(text, "MarkCoverageDoneForVuln") {
		t.Fatal("L2 path must call MarkCoverageDoneForVuln")
	}
}
