//go:build cgo

package database

import (
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

func TestToolExecutionSemanticOutcomePersistsAndAggregates(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "monitor.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	now := time.Now()
	exec := &mcp.ToolExecution{
		ID:             "exec-negative",
		ToolName:       "http-framework-test",
		Arguments:      map[string]interface{}{"url": "https://example.test/missing"},
		Status:         "completed",
		Result:         &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "HTTP/1.1 404 Not Found"}}},
		StartTime:      now,
		EndTime:        &now,
		ConversationID: "conversation-1",
	}
	if err := db.SaveToolExecution(exec); err != nil {
		t.Fatalf("SaveToolExecution: %v", err)
	}

	got, err := db.GetToolExecution(exec.ID)
	if err != nil {
		t.Fatalf("GetToolExecution: %v", err)
	}
	if got.ConversationID != exec.ConversationID {
		t.Fatalf("conversationId=%q want=%q", got.ConversationID, exec.ConversationID)
	}
	if got.SemanticOutcome != mcp.SemanticOutcomeTargetNegative {
		t.Fatalf("semanticOutcome=%q want=%q", got.SemanticOutcome, mcp.SemanticOutcomeTargetNegative)
	}

	counts, err := db.LoadToolSemanticOutcomeCounts()
	if err != nil {
		t.Fatalf("LoadToolSemanticOutcomeCounts: %v", err)
	}
	if counts[mcp.SemanticOutcomeTargetNegative] != 1 {
		t.Fatalf("target_negative count=%d want=1", counts[mcp.SemanticOutcomeTargetNegative])
	}
}
