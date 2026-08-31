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
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestNotificationReadStateIsPerUser(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "notification-rbac.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h := NewNotificationHandler(db, nil, zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "u1", Scope: database.RBACScopeAssigned})
		c.Next()
	})
	router.POST("/notifications/read", h.MarkRead)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/notifications/read", bytes.NewBufferString(`{"eventIds":["vuln:v1"]}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("mark read status = %d: %s", w.Code, w.Body.String())
	}
	u1, err := h.readStatesByIDs("u1", []string{"vuln:v1"})
	if err != nil || !u1["vuln:v1"] {
		t.Fatalf("u1 read state = %#v, err=%v", u1, err)
	}
	u2, err := h.readStatesByIDs("u2", []string{"vuln:v1"})
	if err != nil || u2["vuln:v1"] {
		t.Fatalf("u2 inherited u1 read state = %#v, err=%v", u2, err)
	}
}

func TestNotificationSummaryLoadsPendingUnifiedApprovalOnFreshDatabase(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "notification-approval.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := approval.NewSQLiteStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.CreateRequest(context.Background(), &approval.Request{
		ID: "approval-1", InvocationID: "invocation-1", InvocationHash: "hash-1",
		Source: "eino_middleware", ConversationID: "conversation-1", RequesterUserID: "user-1",
		ToolName: "shell", Arguments: map[string]any{"command": "whoami"}, RiskLevel: approval.RiskHigh,
		TriggerSources: []string{"dangerous_action"}, Reviewer: approval.ReviewerHuman,
		Stage: approval.StageHumanReview, Status: approval.StatusPendingHuman,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	h := NewNotificationHandler(db, nil, zap.NewNop())
	items, err := h.loadPendingApprovalItems(10, false, database.RBACListAccess{Scope: database.RBACScopeAll})
	if err != nil {
		t.Fatalf("load pending unified approvals: %v", err)
	}
	if len(items) != 1 || items[0].InterruptID != "approval-1" || items[0].ConversationID != "conversation-1" {
		t.Fatalf("unexpected pending approval notifications: %#v", items)
	}
}

func TestNotificationSummaryUsesUnifiedApprovalReadPermission(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "notification-approval-permission.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := approval.NewSQLiteStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.CreateRequest(context.Background(), &approval.Request{
		ID: "approval-2", InvocationID: "invocation-2", InvocationHash: "hash-2",
		Source: "eino_middleware", RequesterUserID: "user-1", ToolName: "shell",
		Arguments: map[string]any{"command": "whoami"}, RiskLevel: approval.RiskHigh,
		TriggerSources: []string{"dangerous_action"}, Reviewer: approval.ReviewerHuman,
		Stage: approval.StageHumanReview, Status: approval.StatusPendingHuman,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	h := NewNotificationHandler(db, nil, zap.NewNop())
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{
			UserID: "user-1", Scope: database.RBACScopeAll,
			Permissions: map[string]bool{"approval:read": true},
		})
		c.Next()
	})
	router.GET("/notifications/summary", h.GetSummary)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/notifications/summary?limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("summary status = %d: %s", w.Code, w.Body.String())
	}
	var summary NotificationSummaryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Counts["hitlPending"] != 1 || len(summary.Items) != 1 {
		t.Fatalf("unified approval notification missing: %#v", summary)
	}
}
