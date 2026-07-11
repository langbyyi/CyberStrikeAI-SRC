package multiagent

import (
	"fmt"
	"sync"
	"testing"
)

func TestConversationExecutionState_ConcurrentRecordAndCoverage(t *testing.T) {
	t.Parallel()
	conv := "test-exec-state-race"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st.RecordTool(ToolEvidenceEntry{ToolName: fmt.Sprintf("t%d", i), Summary: "x", Length: i})
			st.UpsertCoverage(CoverageItem{
				Path:     fmt.Sprintf("path.%d", i%10),
				Status:   "open",
				Priority: "P1",
				Note:     fmt.Sprintf("n%d", i),
			})
			_ = st.LastK(5)
			_ = st.ListCoverage()
			_, _, _ = st.ShouldContinue()
			st.MarkSkillsInjected([]string{fmt.Sprintf("skill-%d", i%3)})
			_ = st.InjectedSkillsCopy()
		}(i)
	}
	wg.Wait()

	if len(st.LastK(100)) == 0 {
		t.Fatal("expected evidence after concurrent records")
	}
	if len(st.ListCoverage()) == 0 {
		t.Fatal("expected coverage after concurrent upserts")
	}
}

func TestConversationExecutionState_MaxCoverageEviction(t *testing.T) {
	t.Parallel()
	conv := "test-exec-max-cov"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.mu.Lock()
	st.maxCoverage = 5
	st.mu.Unlock()
	for i := 0; i < 20; i++ {
		st.UpsertCoverage(CoverageItem{
			Path:     fmt.Sprintf("evict.%d", i),
			Status:   "open",
			Priority: "P2",
		})
	}
	n := len(st.ListCoverage())
	if n > 5 {
		t.Fatalf("coverage map not capped: %d", n)
	}
	if n == 0 {
		t.Fatal("expected some coverage retained")
	}
}

func TestConversationExecutionState_MaxConversationsEviction(t *testing.T) {
	// Not parallel: mutates global cap.
	ClearAllConversationExecutionStatesForTest()
	defer func() {
		ClearAllConversationExecutionStatesForTest()
		SetMaxConversationsForTest(0)
	}()
	SetMaxConversationsForTest(3)
	for i := 0; i < 6; i++ {
		_ = GetConversationExecutionState(fmt.Sprintf("sess-%d", i))
	}
	if n := ConversationExecutionStateCount(); n > 3 {
		t.Fatalf("session map not capped: %d", n)
	}
}

func TestShouldContinue_StatusSemantics(t *testing.T) {
	t.Parallel()
	conv := "test-should-continue-sem"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)

	// empty → soft continue, no open list
	cont, _, open := st.ShouldContinue()
	if !cont || len(open) != 0 {
		t.Fatalf("empty: cont=%v open=%d", cont, len(open))
	}

	st.UpsertCoverage(CoverageItem{Path: "a", Status: "open", Priority: "P0"})
	st.UpsertCoverage(CoverageItem{Path: "b", Status: "in_progress", Priority: "P1"})
	st.UpsertCoverage(CoverageItem{Path: "c", Status: "done", Priority: "P0"})
	st.UpsertCoverage(CoverageItem{Path: "d", Status: "blocked", Priority: "P1"})
	st.UpsertCoverage(CoverageItem{Path: "e", Status: "open", Priority: "P2"})

	var reason string
	cont, reason, open = st.ShouldContinue()
	if !cont {
		t.Fatal("open P0/P1 should continue")
	}
	if len(open) != 2 {
		t.Fatalf("open count=%d want 2 (open P0 + in_progress P1), got %+v", len(open), open)
	}
	if reason == "" {
		t.Fatal("reason required")
	}

	// close remaining
	st.UpsertCoverage(CoverageItem{Path: "a", Status: "done", Priority: "P0"})
	st.UpsertCoverage(CoverageItem{Path: "b", Status: "blocked", Priority: "P1"})
	cont, _, open = st.ShouldContinue()
	if cont || len(open) != 0 {
		t.Fatalf("after close: cont=%v open=%+v", cont, open)
	}
}

func TestShouldContinue_ExcludesToolPaths(t *testing.T) {
	t.Parallel()
	conv := "test-should-continue-tool-exclude"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)

	// Only tool.* paths open — should NOT block finalize.
	st.UpsertCoverage(CoverageItem{Path: "tool.list_vulnerabilities", Status: "open", Priority: "P0"})
	st.UpsertCoverage(CoverageItem{Path: "tool.get_execution_coverage", Status: "in_progress", Priority: "P1"})
	st.UpsertCoverage(CoverageItem{Path: "tool.skill", Status: "open", Priority: "P1"})
	cont, _, open := st.ShouldContinue()
	if cont {
		t.Fatalf("tool.* only open should not continue: open=%+v", open)
	}
	if len(open) != 0 {
		t.Fatalf("tool.* should be excluded: open=%d", len(open))
	}

	// Mix of tool.* and real logic paths — only logic paths should appear.
	st.UpsertCoverage(CoverageItem{Path: "logic.race.target:example.com", Status: "open", Priority: "P1"})
	cont2, _, open2 := st.ShouldContinue()
	if !cont2 {
		t.Fatal("real logic path should trigger continue")
	}
	if len(open2) != 1 || open2[0].Path != "logic.race.target:example.com" {
		t.Fatalf("only logic path should be open: %+v", open2)
	}
}

func TestDeleteConversationExecutionState(t *testing.T) {
	t.Parallel()
	conv := "test-delete-sess"
	ResetConversationExecutionStateForTest(conv)
	_ = GetConversationExecutionState(conv)
	DeleteConversationExecutionState(conv)
	// new state should be empty
	st := GetConversationExecutionState(conv)
	if len(st.ListCoverage()) != 0 {
		t.Fatal("deleted session should re-create empty")
	}
}

func TestRecentUpsertCount_Window(t *testing.T) {
	t.Parallel()
	conv := "test-recent-upsert-window"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)

	// Record non-upsert tool → count stays 0.
	st.RecordTool(ToolEvidenceEntry{ToolName: "exec", StatusHint: "ok"})
	if n := st.RecentUpsertCount(); n != 0 {
		t.Fatalf("after non-upsert: count=%d", n)
	}

	// Record upsert calls → counter increments up to window size.
	for i := 1; i <= UpsertBreakerWindow+2; i++ {
		st.RecordTool(ToolEvidenceEntry{ToolName: "upsert_execution_coverage", StatusHint: "ok"})
		want := i
		if want > UpsertBreakerWindow {
			want = UpsertBreakerWindow
		}
		if n := st.RecentUpsertCount(); n != want {
			t.Fatalf("call %d: got count=%d want %d", i, n, want)
		}
	}
}

func TestRecentUpsertCount_DoesNotResetOnManagementTools(t *testing.T) {
	t.Parallel()
	conv := "test-recent-upsert-mgmt"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)

	// Interleaving upserts with management/read-only tools still accumulates
	// in the window, preventing the breaker from being bypassed.
	st.RecordTool(ToolEvidenceEntry{ToolName: "upsert_execution_coverage"})
	if n := st.RecentUpsertCount(); n != 1 {
		t.Fatalf("count=%d", n)
	}
	st.RecordTool(ToolEvidenceEntry{ToolName: "list_vulnerabilities"})
	if n := st.RecentUpsertCount(); n != 1 {
		t.Fatalf("after list_vulns: count=%d", n)
	}
	st.RecordTool(ToolEvidenceEntry{ToolName: "upsert_execution_coverage"})
	if n := st.RecentUpsertCount(); n != 2 {
		t.Fatalf("count=%d", n)
	}
	st.RecordTool(ToolEvidenceEntry{ToolName: "get_execution_coverage"})
	if n := st.RecentUpsertCount(); n != 2 {
		t.Fatalf("after get_coverage: count=%d", n)
	}
	st.RecordTool(ToolEvidenceEntry{ToolName: "upsert_execution_coverage"})
	if n := st.RecentUpsertCount(); n != 3 {
		t.Fatalf("count=%d", n)
	}
}

func TestRecentUpsertCount_ProgressToolsSlideWindow(t *testing.T) {
	t.Parallel()
	conv := "test-recent-upsert-progress"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)

	// Real testing tools slide the window forward, evicting old upserts.
	for i := 0; i < UpsertBreakerWindow; i++ {
		st.RecordTool(ToolEvidenceEntry{ToolName: "upsert_execution_coverage"})
	}
	if n := st.RecentUpsertCount(); n != UpsertBreakerWindow {
		t.Fatalf("expected window full of upserts, got %d", n)
	}
	for i := 0; i < UpsertBreakerWindow; i++ {
		st.RecordTool(ToolEvidenceEntry{ToolName: "exec"})
	}
	if n := st.RecentUpsertCount(); n != 0 {
		t.Fatalf("expected 0 upserts after window of exec, got %d", n)
	}
}

func TestRecentUpsertCount_NilSafe(t *testing.T) {
	t.Parallel()
	var s *ConversationExecutionState
	s.RecordTool(ToolEvidenceEntry{ToolName: "x"})
	if c := s.RecentUpsertCount(); c != 0 {
		t.Fatal("nil RecentUpsertCount should return 0")
	}
}

func TestUpsertBreakerConstants(t *testing.T) {
	t.Parallel()
	if UpsertBreakerWindow < MaxRecentUpsertsBeforeWarn || UpsertBreakerWindow > 10 {
		t.Fatalf("window=%d", UpsertBreakerWindow)
	}
	if MaxRecentUpsertsBeforeWarn < 2 || MaxRecentUpsertsBeforeWarn > UpsertBreakerWindow {
		t.Fatalf("threshold=%d", MaxRecentUpsertsBeforeWarn)
	}
}

func TestCheckAndRecordFinalizeAttempt_ForceStop(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-force-stop"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.UpsertCoverage(CoverageItem{Path: "x", Status: "open", Priority: "P0"})

	// First finalize attempt: cont=true, count=1, no override.
	cont, _, open := st.ShouldContinue()
	if !cont || len(open) == 0 {
		t.Fatal("should continue with open P0")
	}
	overridden, count := st.CheckAndRecordFinalizeAttempt("finalize", true)
	if !overridden || count != 1 {
		t.Fatalf("attempt 1: overridden=%v count=%d", overridden, count)
	}

	// Second: cont=true, count=2, no override.
	overridden, count = st.CheckAndRecordFinalizeAttempt("finalize", true)
	if !overridden || count != 2 {
		t.Fatalf("attempt 2: overridden=%v count=%d", overridden, count)
	}

	// Third (threshold): cont forced to false.
	overridden, count = st.CheckAndRecordFinalizeAttempt("finalize", true)
	if overridden || count != 3 {
		t.Fatalf("attempt 3: overridden=%v count=%d (should force stop)", overridden, count)
	}
}

func TestCheckAndRecordFinalizeAttempt_ResetsOnNonFinalize(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-reset"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.UpsertCoverage(CoverageItem{Path: "x", Status: "open", Priority: "P0"})

	for i := 0; i < 2; i++ {
		st.CheckAndRecordFinalizeAttempt("finalize", true)
	}
	if st.FinalizeAttempts() != 2 {
		t.Fatalf("expected 2 attempts, got %d", st.FinalizeAttempts())
	}
	// Non-finalize intent resets.
	st.CheckAndRecordFinalizeAttempt("continue", true)
	if st.FinalizeAttempts() != 0 {
		t.Fatalf("after non-finalize: attempts=%d", st.FinalizeAttempts())
	}
}

func TestCheckAndRecordFinalizeAttempt_ResetsOnContFalse(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-cont-false"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.UpsertCoverage(CoverageItem{Path: "x", Status: "open", Priority: "P0"})

	for i := 0; i < 2; i++ {
		st.CheckAndRecordFinalizeAttempt("finalize", true)
	}
	// cont=false resets.
	st.CheckAndRecordFinalizeAttempt("finalize", false)
	if st.FinalizeAttempts() != 0 {
		t.Fatalf("after cont=false: attempts=%d", st.FinalizeAttempts())
	}
}

func TestMaxFinalizeAttemptsBeforeForceStop_Constant(t *testing.T) {
	t.Parallel()
	if MaxFinalizeAttemptsBeforeForceStop < 2 || MaxFinalizeAttemptsBeforeForceStop > 10 {
		t.Fatalf("threshold=%d, expected 2-10", MaxFinalizeAttemptsBeforeForceStop)
	}
}
