package multiagent

import (
	"strings"
	"testing"
	"time"
)

func TestCompactCoverageDigestListsOpenPaths(t *testing.T) {
	state := &ConversationExecutionState{
		Coverage:       map[string]CoverageItem{},
		InjectedSkills: map[string]struct{}{},
		controller:     NewExecutionController("target.test"),
		maxEvidence:    defaultMaxEvidence,
		maxCoverage:    defaultMaxCoverage,
	}
	// An open P0 path and an open P1 surface resource.
	state.UpsertCoverage(CoverageItem{
		Path: "sqli.param:id.t:target.test", Status: "open", Priority: "P0", Note: "单引号触发差异",
	})
	state.UpsertCoverage(CoverageItem{
		Path: "surface.resource:/admin.t:target.test", Status: "open", Priority: "P1", Note: "后台入口",
	})
	// A blocked path — must appear as a count, not expand the open list.
	state.UpsertCoverage(CoverageItem{
		Path: "auth.login.t:target.test", Status: "blocked", Priority: "P1", Note: "验证码",
	})
	// A tool.* artifact — must be excluded.
	state.UpsertCoverage(CoverageItem{
		Path: "tool.get_execution_coverage", Status: "open", Priority: "P0",
	})

	got := state.CompactCoverageDigest(500)
	if got == "" {
		t.Fatal("digest must be non-empty when open coverage exists")
	}
	if !strings.Contains(got, "sqli.param:id.t:target.test") {
		t.Fatalf("digest must list the open P0 path: %q", got)
	}
	if !strings.Contains(got, "surface.resource:/admin.t:target.test") {
		t.Fatalf("digest must list the open P1 surface: %q", got)
	}
	if !strings.Contains(got, "已阻断: 1") {
		t.Fatalf("digest must report blocked count: %q", got)
	}
	if strings.Contains(got, "tool.get_execution_coverage") {
		t.Fatalf("digest must exclude tool.* artifacts: %q", got)
	}
}

func TestCompactCoverageDigestEmptyWhenNoOpenPaths(t *testing.T) {
	state := &ConversationExecutionState{
		Coverage:       map[string]CoverageItem{},
		InjectedSkills: map[string]struct{}{},
		controller:     NewExecutionController("target.test"),
		maxEvidence:    defaultMaxEvidence,
		maxCoverage:    defaultMaxCoverage,
	}
	// Only closed items — digest must be empty (no injection noise).
	state.UpsertCoverage(CoverageItem{Path: "xss.reflected.t:target.test", Status: "done", Priority: "P1"})
	if got := state.CompactCoverageDigest(500); got != "" {
		t.Fatalf("digest must be empty when no open/blocked items, got %q", got)
	}
}

func TestNextOpenPathsReturnsOldestFirst(t *testing.T) {
	state := &ConversationExecutionState{
		Coverage:       map[string]CoverageItem{},
		InjectedSkills: map[string]struct{}{},
		controller:     NewExecutionController("target.test"),
		maxEvidence:    defaultMaxEvidence,
		maxCoverage:    defaultMaxCoverage,
	}
	old := time.Now().Add(-10 * time.Minute)
	newer := time.Now()
	state.UpsertCoverage(CoverageItem{Path: "newer.path", Status: "open", Priority: "P1", UpdatedAt: newer})
	state.UpsertCoverage(CoverageItem{Path: "older.path", Status: "open", Priority: "P1", UpdatedAt: old})

	got := state.NextOpenPaths(2)
	if len(got) != 2 {
		t.Fatalf("expected 2 open paths, got %d: %v", len(got), got)
	}
	if got[0] != "older.path" {
		t.Fatalf("oldest path must come first for pivot suggestion, got %v", got)
	}
}
