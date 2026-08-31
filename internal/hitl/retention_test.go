package hitl

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/approval"
	appconfig "cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestServicePurgeExpired_respectsZeroRetention(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hitl.db")
	db, err := database.NewDB(dbPath, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	store := approval.NewSQLiteStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -100).UTC()
	if err := store.CreateRequest(context.Background(), &approval.Request{
		ID: "approval-kept", InvocationID: "invocation-kept", InvocationHash: "hash-kept",
		Source: "test", RequesterUserID: "user-1", ToolName: "shell", Arguments: map[string]any{},
		RiskLevel: approval.RiskHigh, TriggerSources: []string{"dangerous_action"},
		Reviewer: approval.ReviewerHuman, Stage: approval.StageTerminal, Status: approval.StatusSucceeded,
		CreatedAt: old, UpdatedAt: old,
	}); err != nil {
		t.Fatal(err)
	}

	zero := 0
	svc := NewService(db, &appconfig.Config{
		Hitl: appconfig.HitlConfig{RetentionDays: &zero},
	}, zap.NewNop())
	svc.PurgeExpired()

	if _, err := store.GetRequest(context.Background(), "approval-kept"); err != nil {
		t.Fatalf("record should remain when retention_days=0: %v", err)
	}
}

func TestServicePurgeExpiredUsesUnifiedApprovalStoreOnFreshDatabase(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "approval-retention.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	store := approval.NewSQLiteStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -100).UTC()
	if err := store.CreateRequest(context.Background(), &approval.Request{
		ID: "approval-old", InvocationID: "invocation-old", InvocationHash: "hash-old",
		Source: "test", RequesterUserID: "user-1", ToolName: "shell", Arguments: map[string]any{},
		RiskLevel: approval.RiskHigh, TriggerSources: []string{"dangerous_action"},
		Reviewer: approval.ReviewerHuman, Stage: approval.StageTerminal, Status: approval.StatusSucceeded,
		CreatedAt: old, UpdatedAt: old,
	}); err != nil {
		t.Fatal(err)
	}
	days := 90
	NewService(db, &appconfig.Config{Hitl: appconfig.HitlConfig{RetentionDays: &days}}, zap.NewNop()).PurgeExpired()
	if _, err := store.GetRequest(context.Background(), "approval-old"); err == nil {
		t.Fatal("expired unified approval should be purged on a fresh database")
	}
}
