package handler

import (
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

func TestBatchHITLPolicyPersistence(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "batch.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewBatchTaskManager(zap.NewNop())
	m.SetDB(db)
	q, err := m.CreateBatchQueue("approval", "", "eino_single", "manual", "", "", nil, 1, []string{"test"}, "audit_agent")
	if err != nil {
		t.Fatal(err)
	}
	reloaded := NewBatchTaskManager(zap.NewNop())
	reloaded.SetDB(db)
	if err := reloaded.LoadFromDB(); err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.GetBatchQueue(q.ID)
	if !ok || got.HITLPolicy != "audit_agent" {
		t.Fatalf("reload: %+v", got)
	}
	if err := reloaded.UpdateQueueMetadata(q.ID, "renamed", "", "", nil); err != nil {
		t.Fatal(err)
	}
	row, err := db.GetBatchQueue(q.ID)
	if err != nil || row.HITLPolicy != "audit_agent" {
		t.Fatalf("unrelated edit lost policy: %+v, %v", row, err)
	}
	if err := reloaded.UpdateQueueMetadata(q.ID, "renamed", "", "", nil, ""); err != nil {
		t.Fatal(err)
	}
	row, err = db.GetBatchQueue(q.ID)
	if err != nil || row.HITLPolicy != "" {
		t.Fatalf("reset failed: %+v, %v", row, err)
	}
	if err := reloaded.UpdateQueueMetadata(q.ID, "renamed", "", "", nil, "invalid"); err == nil {
		t.Fatal("accepted invalid policy")
	}
	reloaded.UpdateTaskStatus(q.ID, got.Tasks[0].ID, BatchTaskStatusRunning, "", "")
	if err := reloaded.UpdateQueueMetadata(q.ID, "renamed", "", "", nil, "off"); err == nil {
		t.Fatal("changed policy during single-task execution")
	}
}

func TestBatchHITLActivation(t *testing.T) {
	for _, tc := range []struct {
		policy       string
		wantOverride bool
		wantDisabled bool
		wantReviewer string
	}{
		{"", false, false, ""},
		{"off", true, true, ""},
		{"human", true, false, approval.ReviewerHuman},
		{"audit_agent", true, false, approval.ReviewerAgent},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			override, ok := batchTaskPolicyOverride(tc.policy)
			if ok != tc.wantOverride {
				t.Fatalf("batchTaskPolicyOverride(%q) ok = %v, want %v", tc.policy, ok, tc.wantOverride)
			}
			if !tc.wantOverride {
				return
			}
			if override.Disabled != tc.wantDisabled || override.Reviewer != tc.wantReviewer {
				t.Fatalf("bad override: %+v", override)
			}
		})
	}
	if err := validateBatchHITLPolicy("review_edit"); err == nil {
		t.Fatal("review_edit is not part of the unified approval architecture")
	}
}

func TestBatchHITLPersistenceFailure(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "closed.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	m := NewBatchTaskManager(zap.NewNop())
	m.SetDB(db)
	q, err := m.CreateBatchQueue("test", "", "eino_single", "manual", "", "", nil, 1, []string{"test"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := m.UpdateQueueMetadata(q.ID, "changed", "", "", nil, "off"); err == nil {
		t.Fatal("save failure hidden")
	}
	if q.HITLPolicy != "human" || q.Title != "test" {
		t.Fatal("failed write changed in-memory policy")
	}
	if _, err := m.CreateBatchQueue("test", "", "eino_single", "manual", "", "", nil, 1, []string{"test"}, "audit_agent"); err == nil {
		t.Fatal("create failure hidden")
	}
}
