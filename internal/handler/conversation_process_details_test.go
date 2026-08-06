package handler

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestProcessDetailsPageIncludesTerminalToolStatusAcrossPageBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "process-details-page.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("page boundary", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	message, err := db.AddMessage(conversation.ID, "assistant", "done", nil)
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}
	for i := 1; i <= 4; i++ {
		id := fmt.Sprintf("call-%d", i)
		if err := db.AddProcessDetail(message.ID, conversation.ID, "tool_call", "call", map[string]interface{}{
			"toolName": "http-framework-test", "toolCallId": id, "index": i, "total": 4,
		}); err != nil {
			t.Fatalf("AddProcessDetail(tool_call): %v", err)
		}
	}
	for i := 1; i <= 4; i++ {
		id := fmt.Sprintf("call-%d", i)
		if err := db.AddProcessDetail(message.ID, conversation.ID, "tool_result", "result", map[string]interface{}{
			"toolName": "http-framework-test", "toolCallId": id, "success": true,
		}); err != nil {
			t.Fatalf("AddProcessDetail(tool_result): %v", err)
		}
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/messages/"+message.ID+"/process-details?limit=6&offset=0", nil)
	c.Params = gin.Params{{Key: "id", Value: message.ID}}
	NewConversationHandler(db, zap.NewNop()).GetMessageProcessDetails(c)
	if w.Code != 200 {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var response struct {
		HasMore        bool                                   `json:"hasMore"`
		ProcessDetails []map[string]interface{}               `json:"processDetails"`
		ToolExecutions []database.ProcessDetailsToolExecution `json:"toolExecutions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.HasMore || len(response.ProcessDetails) != 6 {
		t.Fatalf("page hasMore=%v details=%d, want true/6", response.HasMore, len(response.ProcessDetails))
	}
	if len(response.ToolExecutions) != 4 {
		t.Fatalf("tool executions = %d, want 4", len(response.ToolExecutions))
	}
	for i, execution := range response.ToolExecutions {
		if execution.Status != "completed" {
			t.Fatalf("execution %d status = %q, want completed", i, execution.Status)
		}
	}
}
