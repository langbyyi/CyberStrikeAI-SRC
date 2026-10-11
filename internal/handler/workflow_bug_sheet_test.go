package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	agentpkg "cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	workflowrunner "cyberstrike-ai/internal/workflow"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const bugSheetLinearGraph = `{"nodes":[{"id":"start-1","type":"start","config":{}},{"id":"out","type":"output","config":{"output_key":"result","source_binding":{"from":"inputs","field":"message"}}}],"edges":[{"source":"start-1","target":"out"}],"config":{"schema_version":1}}`

func workflowBugDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "workflow.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	workflowrunner.SetCheckpointDir(filepath.Join(t.TempDir(), "checkpoints"))
	return db
}

func TestWorkflowCreateValidatesIDAndNeverReplacesExisting(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := workflowBugDB(t)
	h := NewWorkflowHandler(db, zap.NewNop())
	r := gin.New()
	r.POST("/workflows", h.Create)
	r.PUT("/workflows/:id", h.Update)
	call := func(method, url, id, name string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"id": id, "name": name, "graph": json.RawMessage(bugSheetLinearGraph)})
		req := httptest.NewRequest(method, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	for _, id := range []string{"../wf", "a/b", "a\\b", "a b", "_wf", strings.Repeat("w", 129)} {
		rec := call(http.MethodPost, "/workflows", id, "name")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("accepted id %q: %d %s", id, rec.Code, rec.Body)
		}
	}
	rec := call(http.MethodPost, "/workflows", "wf-test", "original")
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	rec = call(http.MethodPost, "/workflows", "wf-test", "replacement")
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d %s", rec.Code, rec.Body)
	}
	saved, _ := db.GetWorkflowDefinition("wf-test")
	if saved.Name != "original" || saved.Version != 1 {
		t.Fatalf("duplicate replaced: %#v", saved)
	}
	rec = call(http.MethodPut, "/workflows/missing", "missing", "new")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing update: %d %s", rec.Code, rec.Body)
	}
	rec = call(http.MethodPut, "/workflows/wf-test", "wf-test", "updated")
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	rec = call(http.MethodPut, "/workflows/wf-test", "other-id", "renamed")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ID change accepted: %d %s", rec.Code, rec.Body)
	}
	// Existing IDs from older saves/imports can still be edited in place.
	if err := db.UpsertWorkflowDefinition(&database.WorkflowDefinition{ID: "legacy.id", Name: "legacy", GraphJSON: bugSheetLinearGraph}); err != nil {
		t.Fatal(err)
	}
	rec = call(http.MethodPut, "/workflows/legacy.id", "legacy.id", "updated legacy")
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy edit rejected: %d %s", rec.Code, rec.Body)
	}
}

func TestWorkflowListAndDetailExposeValidationFailure(t *testing.T) {
	db := workflowBugDB(t)
	for _, wf := range []*database.WorkflowDefinition{
		{ID: "valid", Name: "valid", GraphJSON: bugSheetLinearGraph, Enabled: true},
		{ID: "invalid", Name: "invalid", GraphJSON: `{"nodes":[],"edges":[]}`, Enabled: true},
	} {
		if err := db.UpsertWorkflowDefinition(wf); err != nil {
			t.Fatal(err)
		}
	}
	h := NewWorkflowHandler(db, zap.NewNop())
	r := gin.New()
	r.GET("/workflows", h.List)
	r.GET("/workflows/:id", h.Get)
	for _, url := range []string{"/workflows", "/workflows/invalid"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"validation_error"`) {
			t.Fatalf("validation missing: %d %s", rec.Code, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/workflows/valid", nil))
	if strings.Contains(rec.Body.String(), `"validation_error"`) {
		t.Fatalf("valid graph mislabeled: %s", rec.Body)
	}
}

func TestWorkflowDeliveryHandlesTextOnlyAndRejectedRuns(t *testing.T) {
	db := workflowBugDB(t)
	conv, err := db.CreateConversation("workflow", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := db.AddMessage(conv.ID, "assistant", "pending", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	wf := &database.WorkflowDefinition{ID: "wf-delivery", Name: "text", GraphJSON: bugSheetLinearGraph, Enabled: true}
	if err := db.UpsertWorkflowDefinition(wf); err != nil {
		t.Fatal(err)
	}
	args := workflowrunner.RunArgs{DB: db, Logger: zap.NewNop(), Role: config.RoleConfig{Name: "test", Enabled: true, WorkflowID: wf.ID, WorkflowPolicy: "auto"}, UserMessage: "OK", ConversationID: conv.ID}
	result, err := workflowrunner.RunRoleBoundWorkflow(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	decision := h.finalizeWorkflowRunForDelivery(conv.ID, message.ID, result)
	if !decision.Finalized || decision.Status != agentfinalizer.StatusCompleted {
		t.Fatalf("text-only run rejected: %+v", decision)
	}
	// A real approval node pauses, then rejection remains cancellation rather than
	// becoming a successful answer or a missing-evidence error.
	wf.GraphJSON = `{"nodes":[{"id":"start-1","type":"start","config":{}},{"id":"review","type":"hitl","config":{"prompt":"approve?"}},{"id":"out","type":"output","config":{"output_key":"result"}}],"edges":[{"source":"start-1","target":"review"},{"source":"review","target":"out"}],"config":{"schema_version":1}}`
	if err := db.UpsertWorkflowDefinition(wf); err != nil {
		t.Fatal(err)
	}
	workflowrunner.InvalidateCompiledCache(wf.ID)
	paused, err := workflowrunner.RunRoleBoundWorkflow(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	decision = h.finalizeWorkflowRunForDelivery(conv.ID, message.ID, paused)
	if decision.Status != agentfinalizer.StatusAwaitingHITL || decision.Finalized {
		t.Fatalf("pause finalized: %+v", decision)
	}
	rejected, err := workflowrunner.ResumeWorkflowRun(context.Background(), args, paused.RunID, false, "test refusal")
	if err != nil {
		t.Fatal(err)
	}
	decision = h.finalizeWorkflowRunForDelivery(conv.ID, message.ID, rejected)
	if decision.Status != agentfinalizer.StatusCancelled || decision.CompletionReason != "workflow_rejected" || decision.Finalized {
		t.Fatalf("rejection status lost: %+v", decision)
	}
	var text string
	if err := db.QueryRow("SELECT content FROM messages WHERE id=?", message.ID).Scan(&text); err != nil {
		t.Fatal(err)
	}
	if text != rejected.Response || strings.Contains(text, "missing_execution_evidence") {
		t.Fatalf("rejection reason lost: %s", text)
	}
}

func TestWorkflowToolReceivesExpandedParameters(t *testing.T) {
	db := workflowBugDB(t)
	var received string
	server := mcp.NewServerWithStorage(zap.NewNop(), db)
	server.RegisterTool(mcp.Tool{Name: "test_echo", InputSchema: map[string]interface{}{"type": "object"}}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		received, _ = args["target"].(string)
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "received " + received}}}, nil
	})
	agent := agentpkg.NewAgent(&config.OpenAIConfig{}, &config.AgentConfig{}, server, nil, zap.NewNop(), 10)
	graph := `{"nodes":[{"id":"start-1","type":"start","config":{}},{"id":"tool-1","type":"tool","config":{"tool_name":"test_echo","arguments":"{\"target\":\"{{inputs.message}}\"}"}},{"id":"out-1","type":"output","config":{"output_key":"result"}}],"edges":[{"source":"start-1","target":"tool-1"},{"source":"tool-1","target":"out-1"}],"config":{"schema_version":1}}`
	wf := &database.WorkflowDefinition{ID: "wf-params", Name: "parameters", GraphJSON: graph, Enabled: true}
	if err := db.UpsertWorkflowDefinition(wf); err != nil {
		t.Fatal(err)
	}
	message := "test-only-target \"quoted\""
	result, err := workflowrunner.RunRoleBoundWorkflow(context.Background(), workflowrunner.RunArgs{DB: db, Agent: agent, AppCfg: &config.Config{}, Logger: zap.NewNop(), Role: config.RoleConfig{Name: "test", Enabled: true, WorkflowID: wf.ID, WorkflowPolicy: "auto"}, UserMessage: message})
	if err != nil || result.Status != "completed" {
		t.Fatalf("workflow failed: %#v %v", result, err)
	}
	if received != message {
		t.Fatalf("tool received %q, want %q", received, message)
	}
}
