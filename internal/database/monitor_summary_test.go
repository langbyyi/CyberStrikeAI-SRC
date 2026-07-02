package database

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

func TestLoadToolStatsSummaryAndListPage(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "monitor-summary.db")
	db, err := NewDB(dbPath, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now()
	tools := []struct {
		name   string
		calls  int
		ok     int
		fail   int
		result string
	}{
		{"alpha::run", 10, 9, 1, `{"content":[{"type":"text","text":"` + string(make([]byte, 64*1024)) + `"}]}`},
		{"beta::scan", 5, 5, 0, `{"content":[{"type":"text","text":"ok"}]}`},
		{"gamma::ping", 1, 1, 0, `{"content":[{"type":"text","text":"pong"}]}`},
	}

	for _, tool := range tools {
		if err := db.UpdateToolStats(tool.name, tool.calls, tool.ok, tool.fail, &now); err != nil {
			t.Fatalf("UpdateToolStats(%s): %v", tool.name, err)
		}
		for j := 0; j < tool.calls; j++ {
			exec := &mcp.ToolExecution{
				ID:        fmt.Sprintf("%s-exec-%d", tool.name, j),
				ToolName:  tool.name,
				Arguments: map[string]interface{}{"n": j},
				Status:    "completed",
				StartTime: now.Add(-time.Duration(j) * time.Minute),
				Result:    &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: tool.result}}},
			}
			end := exec.StartTime.Add(time.Second)
			exec.EndTime = &end
			exec.Duration = time.Second
			if err := db.SaveToolExecution(exec); err != nil {
				t.Fatalf("SaveToolExecution: %v", err)
			}
		}
	}

	summary, err := db.LoadToolStatsSummary(2)
	if err != nil {
		t.Fatalf("LoadToolStatsSummary: %v", err)
	}
	if summary.Summary.ToolCount != 3 {
		t.Fatalf("toolCount = %d, want 3", summary.Summary.ToolCount)
	}
	if summary.Summary.TotalCalls != 16 {
		t.Fatalf("totalCalls = %d, want 16", summary.Summary.TotalCalls)
	}
	if len(summary.TopTools) != 2 {
		t.Fatalf("top tools = %d, want 2", len(summary.TopTools))
	}
	if summary.TopTools[0].ToolName != "alpha::run" {
		t.Fatalf("top tool = %q, want alpha::run", summary.TopTools[0].ToolName)
	}

	list, err := db.LoadToolExecutionListPage(0, 5, "", "")
	if err != nil {
		t.Fatalf("LoadToolExecutionListPage: %v", err)
	}
	if len(list) != 5 {
		t.Fatalf("list len = %d, want 5", len(list))
	}
	for _, exec := range list {
		if exec.Arguments != nil || exec.Result != nil || exec.Error != "" {
			t.Fatalf("expected lite execution row, got args/result/error on %s", exec.ID)
		}
	}
}
