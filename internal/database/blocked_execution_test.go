package database

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/mcp"
	"go.uber.org/zap"
)

func TestBlockedExecutionPersistenceStatsAndReconciliation(t *testing.T) {
	db, conversationID, _ := setupProcessDetailsSummaryTest(t)
	now := time.Now()
	for _, status := range []string{"completed", "failed", "blocked", "cancelled"} {
		result := &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "policy message"}}, IsError: status != "completed", Blocked: status == "blocked"}
		if err := db.SaveToolExecution(&mcp.ToolExecution{ID: status, ToolName: "test", Status: status, Result: result, StartTime: now.Add(-time.Minute), EndTime: &now, ConversationID: conversationID}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpdateToolStats("test", 4, 1, 1, &now); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateToolExecutionResult("blocked", &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "reduced output"}}}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := db.GetToolExecution("blocked")
	if err != nil || reloaded.Status != "blocked" || !reloaded.Result.Blocked || !reloaded.Result.IsError || reloaded.Result.Content[0].Text != "reduced output" {
		t.Fatalf("reduction/storage lost blocked classification: %#v err=%v", reloaded, err)
	}
	count, err := db.CancelOrphanedRunningToolExecutions(now, "restart")
	if err != nil || count != 0 {
		t.Fatalf("terminal blocks reclassified as orphaned: count=%d err=%v", count, err)
	}
	page, err := db.LoadToolExecutionListPage(0, 10, "blocked", "")
	if err != nil || len(page) != 1 || page[0].ID != "blocked" {
		t.Fatalf("blocked status filter failed: %#v err=%v", page, err)
	}
	summary, err := db.LoadToolStatsSummary(1)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Summary.TotalCalls != 4 || summary.Summary.SuccessCalls != 1 || summary.Summary.FailedCalls != 1 || summary.Summary.BlockedCalls != 1 || summary.TopTools[0].BlockedCalls != 1 {
		t.Fatalf("incorrect summary: %#v top=%#v", summary.Summary, summary.TopTools)
	}
	stats, err := db.LoadToolStats()
	if err != nil || stats["test"].BlockedCalls != 1 || stats["test"].FailedCalls != 1 {
		t.Fatalf("incorrect legacy stats: %#v err=%v", stats, err)
	}
	for _, daily := range []bool{false, true} {
		buckets, err := db.LoadCallsTimeline(now.Add(-time.Hour), daily)
		if err != nil || len(buckets) != 1 || buckets[0].Total != 4 || buckets[0].Failed != 1 || buckets[0].Blocked != 1 {
			t.Fatalf("incorrect timeline daily=%v: %#v err=%v", daily, buckets, err)
		}
	}
}

func TestLegacyToolGuardBlockMigrationIsStrictAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-guard.db")
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	refusal := "工具调用已被安全规则拦截：识别到 example.gov，禁止操作。\n规则: 政府网站保护 (government-domains)\n匹配内容: \"example.gov\""
	for i, reason := range []string{
		refusal,
		"upstream returned: " + refusal,
		"工具调用已被安全规则拦截：regular error without the envelope",
		"工具调用已被安全规则拦截：malformed match\n规则: Rule (id)\n匹配内容: unquoted",
	} {
		if err := db.SaveToolExecution(&mcp.ToolExecution{ID: fmt.Sprint(i), ToolName: "test", Status: "failed", Error: reason, StartTime: now, EndTime: &now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpdateToolStats("test", 4, 0, 4, &now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 2; run++ {
		db, err = NewDB(path, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		exec, err := db.GetToolExecution("0")
		if err != nil || exec.Status != "blocked" || !exec.Result.Blocked || !exec.Result.IsError || exec.Result.Content[0].Text != refusal {
			t.Fatalf("migration did not retain refusal: %#v err=%v", exec, err)
		}
		stats, err := db.LoadToolStats()
		if err != nil || stats["test"].TotalCalls != 4 || stats["test"].FailedCalls != 3 || stats["test"].BlockedCalls != 1 {
			t.Fatalf("migration run=%d stats=%#v err=%v", run, stats, err)
		}
		count, err := db.CountToolExecutions("failed", "")
		if err != nil || count != 3 {
			t.Fatalf("migration changed unrelated failures: count=%d err=%v", count, err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestToolResultStatusFromPayloadDistinguishesBlocked(t *testing.T) {
	for _, tc := range []struct {
		payload map[string]interface{}
		want    string
	}{
		{map[string]interface{}{"blocked": true, "success": false, "isError": true}, "blocked"},
		{map[string]interface{}{"status": "blocked", "success": false}, "blocked"},
		{map[string]interface{}{"success": false, "isError": true, "result": "工具调用已被安全规则拦截"}, "failed"},
		{map[string]interface{}{"success": true}, "completed"},
	} {
		if got := toolResultStatusFromPayload(tc.payload, "tool_result"); got != tc.want {
			t.Fatalf("payload=%#v status=%s want=%s", tc.payload, got, tc.want)
		}
	}
}
