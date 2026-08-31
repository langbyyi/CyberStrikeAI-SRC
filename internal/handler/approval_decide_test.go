package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type orphanApprovalStore struct {
	request *approval.Request
}

type approvalSettingsSaverStub struct {
	config approval.Config
}

type promptLeakingApprovalSaver struct{ approvalSettingsSaverStub }

func (s *promptLeakingApprovalSaver) GlobalApprovalAuditAgentPrompt() string {
	return "must stay in system settings"
}

func (s *approvalSettingsSaverStub) SaveGlobalApprovalConfig(input approval.Config) error {
	s.config = input
	return nil
}

func TestApprovalConfigDoesNotExposeAuditAgentPrompt(t *testing.T) {
	runtime, err := approval.NewGlobalRuntime(approval.Config{Reviewer: approval.ReviewerAgent}, nil)
	if err != nil {
		t.Fatal(err)
	}
	saver := &promptLeakingApprovalSaver{}
	h := NewApprovalHandler(&orphanApprovalStore{}, approval.NewHumanReviewBroker(), zap.NewNop())
	h.SetGlobalRuntime(runtime, saver)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(security.ContextSessionKey, security.Session{Permissions: map[string]bool{"approval:read": true}})
	h.GetGlobalConfig(c)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, exists := body["auditAgentPrompt"]; exists {
		t.Fatal("approval config must not expose auditAgentPrompt")
	}
}

func TestApprovalConfigIgnoresAuditAgentPromptAndUpdatesPolicy(t *testing.T) {
	runtime, err := approval.NewGlobalRuntime(approval.Config{Reviewer: approval.ReviewerHuman}, nil)
	if err != nil {
		t.Fatal(err)
	}
	saver := &approvalSettingsSaverStub{}
	h := NewApprovalHandler(&orphanApprovalStore{}, approval.NewHumanReviewBroker(), zap.NewNop())
	h.SetGlobalRuntime(runtime, saver)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/approval-config", bytes.NewBufferString(`{
		"reviewer":"agent","timeoutSeconds":300,
		"toolApproval":{"enabled":false},"dangerousAction":{"enabled":true},
		"auditAgentPrompt":"approve only when impact is reversible"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(security.ContextSessionKey, security.Session{Permissions: map[string]bool{"approval:policy:write": true}})
	h.UpdateGlobalConfig(c)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if got := runtime.Config().Reviewer; got != approval.ReviewerAgent {
		t.Fatalf("reviewer = %q, want agent", got)
	}
}

func TestApprovalConfigRequiresPolicyWritePermission(t *testing.T) {
	runtime, err := approval.NewGlobalRuntime(approval.Config{Reviewer: approval.ReviewerHuman}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewApprovalHandler(&orphanApprovalStore{}, approval.NewHumanReviewBroker(), zap.NewNop())
	h.SetGlobalRuntime(runtime, &approvalSettingsSaverStub{})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/approval-config", bytes.NewBufferString(`{"reviewer":"agent"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.UpdateGlobalConfig(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", w.Code, w.Body.String())
	}
}

func TestSaveGlobalApprovalConfigRollsBackMemoryWhenPersistenceFails(t *testing.T) {
	toolEnabled := false
	dangerEnabled := true
	cfg := &config.Config{Approval: config.ApprovalConfig{
		Reviewer: "human", TimeoutSeconds: 300,
		ToolApproval:    config.ApprovalTriggerConfig{Enabled: &toolEnabled, ToolWhitelist: []string{"read_file"}},
		DangerousAction: config.ApprovalTriggerConfig{Enabled: &dangerEnabled},
	}}
	handler := NewConfigHandler(filepath.Join(t.TempDir(), "missing", "config.yaml"), cfg, nil, nil, nil, nil, nil, zap.NewNop())
	err := handler.SaveGlobalApprovalConfig(approval.Config{
		Reviewer: approval.ReviewerAgent, TimeoutSeconds: 30,
		ToolApproval: approval.TriggerConfig{Enabled: true}, DangerousAction: approval.TriggerConfig{Enabled: false},
	})
	if err == nil {
		t.Fatal("save unexpectedly succeeded")
	}
	if cfg.Approval.Reviewer != "human" || cfg.Approval.TimeoutSeconds != 300 || cfg.Approval.ToolApproval.EnabledEffective(true) {
		t.Fatalf("in-memory approval config changed after failed persistence: %+v", cfg.Approval)
	}
}

func (s *orphanApprovalStore) GetRequest(context.Context, string) (*approval.Request, error) {
	return s.request, nil
}
func (s *orphanApprovalStore) List(context.Context, approval.ListFilter) ([]*approval.Request, error) {
	return nil, nil
}
func (s *orphanApprovalStore) Count(context.Context, approval.ListFilter) (int, error) { return 0, nil }
func (s *orphanApprovalStore) RecordDecision(context.Context, approval.DecisionRecord, string, string, string) error {
	return nil
}
func (s *orphanApprovalStore) Append(context.Context, approval.LedgerEvent) error { return nil }
func (s *orphanApprovalStore) ListByInvocation(context.Context, string) ([]approval.LedgerEvent, error) {
	return nil, nil
}
func (s *orphanApprovalStore) ListRecent(context.Context, int) ([]approval.LedgerEvent, error) {
	return nil, nil
}
func (s *orphanApprovalStore) ListFiltered(context.Context, approval.LedgerFilter) ([]approval.LedgerEvent, error) {
	return nil, nil
}

func TestApprovalReaderCanListLedger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewApprovalHandler(&orphanApprovalStore{}, approval.NewHumanReviewBroker(), zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{
			UserID: "auditor-1", Scope: database.RBACScopeAll,
			Permissions: map[string]bool{"approval:read": true},
		})
		c.Next()
	})
	router.GET("/approvals/ledger", handler.ListLedger)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/approvals/ledger", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}

func TestDecideDoesNotApproveRequestWithoutLiveReviewer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &orphanApprovalStore{request: &approval.Request{
		ID: "approval-1", RequesterUserID: "user-1", Reviewer: approval.ReviewerHuman,
		Status: approval.StatusPendingHuman, Stage: approval.StageHumanReview, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}}
	handler := NewApprovalHandler(store, approval.NewHumanReviewBroker(), zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) {
		session := security.Session{UserID: "user-1", Scope: database.RBACScopeAll, Permissions: map[string]bool{"approval:decide": true}}
		c.Set(security.ContextSessionKey, session)
		principal := authctx.NewPrincipalWithScopes("user-1", "user", session.Scope, session.Permissions, nil)
		c.Request = c.Request.WithContext(authctx.WithPrincipal(c.Request.Context(), principal))
		c.Next()
	})
	router.POST("/approvals/:id/decision", handler.Decide)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/approvals/approval-1/decision", bytes.NewBufferString(`{"decision":"approve"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", recorder.Code, recorder.Body.String())
	}
}

func TestDecideRequiresApprovalPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &orphanApprovalStore{request: &approval.Request{
		ID: "approval-1", RequesterUserID: "user-1", Reviewer: approval.ReviewerHuman,
		Status: approval.StatusPendingHuman, Stage: approval.StageHumanReview, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}}
	handler := NewApprovalHandler(store, approval.NewHumanReviewBroker(), zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) {
		session := security.Session{UserID: "user-1", Scope: database.RBACScopeAll}
		c.Set(security.ContextSessionKey, session)
		principal := authctx.NewPrincipalWithScopes("user-1", "user", session.Scope, session.Permissions, nil)
		c.Request = c.Request.WithContext(authctx.WithPrincipal(c.Request.Context(), principal))
		c.Next()
	})
	router.POST("/approvals/:id/decision", handler.Decide)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/approvals/approval-1/decision", bytes.NewBufferString(`{"decision":"approve"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
	}
}
