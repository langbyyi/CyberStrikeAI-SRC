package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestProjectTestingSpecificationAPIAndContext(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "spec.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := NewProjectHandler(db, zap.NewNop())
	r := gin.New()
	r.POST("/projects", h.CreateProject)
	r.PUT("/projects/:id", h.UpdateProject)
	body := `{"name":"Synthetic","testing_specification":{"name":"rules.md","content":"SPEC_ONLY_THIS_PROJECT"}}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/projects", bytes.NewBufferString(body)))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var p database.Project
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.TestingSpecification == nil || p.TestingSpecification.Content != "SPEC_ONLY_THIS_PROJECT" {
		t.Fatal("project API dropped specification")
	}
	conv, err := db.CreateConversation("task", database.ConversationCreateMeta{ProjectID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	agentHandler := &AgentHandler{db: db, config: &config.Config{}, logger: zap.NewNop()}
	block := agentHandler.agentSessionContextBlock(conv.ID)
	if !strings.Contains(block, "SPEC_ONLY_THIS_PROJECT") {
		t.Fatal("execution context is missing specification")
	}
	other, err := db.CreateConversation("unbound", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(agentHandler.agentSessionContextBlock(other.ID), "SPEC_ONLY_THIS_PROJECT") {
		t.Fatal("specification leaked to unrelated task")
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/projects/"+p.ID, bytes.NewBufferString(`{"description":"metadata only"}`)))
	p, err = readSpecificationProject(db, p.ID)
	if err != nil || p.TestingSpecification == nil {
		t.Fatal("partial update cleared specification")
	}
}

func readSpecificationProject(db *database.DB, id string) (database.Project, error) {
	p, err := db.GetProject(id)
	if err != nil {
		return database.Project{}, err
	}
	return *p, nil
}

func TestBatchSpecificationResolvesDefaultAndChecksProjectPermission(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "batch.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&database.Project{Name: "Synthetic default", TestingSpecification: &database.TestingSpecification{Content: "PROJECT_DEFAULT_RULES"}})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewBatchTaskManager(zap.NewNop())
	manager.SetDB(db)
	h := &AgentHandler{db: db, config: &config.Config{Project: config.ProjectConfig{DefaultProjectID: p.ID}}, batchTaskManager: manager, logger: zap.NewNop()}
	session := security.Session{UserID: "synthetic-user", Scope: database.RBACScopeAll, Permissions: map[string]bool{"tasks:write": true}}
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(security.ContextSessionKey, session); c.Next() })
	r.POST("/api/batch-tasks", h.CreateBatchQueue)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/batch-tasks", bytes.NewBufferString(`{"tasks":["verify headers"]}`)))
	if w.Code != 403 {
		t.Fatalf("task permission must not reveal project specification: %d", w.Code)
	}
	session.Permissions["project:read"] = true
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/batch-tasks", bytes.NewBufferString(`{"tasks":["verify headers"]}`)))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var data struct {
		Queue *BatchTaskQueue `json:"queue"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data.Queue.ProjectID != p.ID {
		t.Fatal("effective default project was not frozen")
	}
	snapshot, err := db.GetBatchTaskTestingSpecification(data.Queue.ID, data.Queue.Tasks[0].ID)
	if err != nil || snapshot.Content != "PROJECT_DEFAULT_RULES" {
		t.Fatalf("default specification omitted: %#v %v", snapshot, err)
	}
	session.PermissionScopes = map[string]string{"project:read": database.RBACScopeOwn}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/batch-tasks", bytes.NewBufferString(`{"tasks":["verify headers"]}`)))
	if w.Code != 403 {
		t.Fatal("unrelated broad task scope widened project access")
	}
}

func TestPreparedTaskSpecificationPersistsAcrossFollowup(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "chat.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &AgentHandler{db: db, config: &config.Config{}, logger: zap.NewNop()}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/eino-agent", nil)
	c.Set(security.ContextSessionKey, security.Session{UserID: "synthetic-user", Scope: database.RBACScopeAll, Permissions: map[string]bool{"chat:write": true}})
	prep, err := h.prepareMultiAgentSession(&ChatRequest{Message: "first", TestingSpecification: &database.TestingSpecification{Name: "task.md", Content: "TASK_RULES"}}, c, "eino_single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.prepareMultiAgentSession(&ChatRequest{Message: "followup", ConversationID: prep.ConversationID}, c, "eino_single"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.GetConversationTestingSpecification(prep.ConversationID)
	if err != nil || !snapshot.Frozen || snapshot.Content != "TASK_RULES" {
		t.Fatalf("snapshot: %#v %v", snapshot, err)
	}
}

func TestSpecificationCannotWidenProjectReadScope(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "scopes.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&database.Project{Name: "Foreign synthetic", TestingSpecification: &database.TestingSpecification{Content: "PRIVATE_SYNTHETIC_RULES"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("project", p.ID, "another-synthetic-user"); err != nil {
		t.Fatal(err)
	}
	session := security.Session{UserID: "synthetic-user", Scope: database.RBACScopeAll, Permissions: map[string]bool{"chat:write": true, "project:read": true}, PermissionScopes: map[string]string{"project:read": database.RBACScopeOwn}}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/eino-agent", nil)
	c.Set(security.ContextSessionKey, session)
	h := &AgentHandler{db: db, config: &config.Config{}, logger: zap.NewNop()}
	if _, err := h.prepareMultiAgentSession(&ChatRequest{Message: "verify", ProjectID: p.ID}, c, "eino_single"); err == nil {
		t.Fatal("agent scope widened project read")
	}
	conversationHandler := NewConversationHandler(db, zap.NewNop())
	if conversationHandler.conversationProjectAllowed(c, p.ID) {
		t.Fatal("chat scope widened project read")
	}
}
