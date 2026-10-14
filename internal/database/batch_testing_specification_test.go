package database

import (
	"go.uber.org/zap"
	"path/filepath"
	"testing"
)

func TestBatchTestingSpecificationsFreezeBeforeExecution(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "batch-spec.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&Project{Name: "Synthetic", TestingSpecification: &TestingSpecification{Content: "original"}})
	if err != nil {
		t.Fatal(err)
	}
	tasks := []map[string]interface{}{{"id": "first", "message": "one"}, {"id": "second", "message": "two"}}
	if err := db.CreateBatchQueueWithTestingSpecifications("queue", "", "", "eino_single", "manual", "", nil, p.ID, 1, tasks, nil, map[int]*TestingSpecification{1: {Content: "override"}}); err != nil {
		t.Fatal(err)
	}
	p.TestingSpecification.Content = "changed"
	if err := db.UpdateProject(p); err != nil {
		t.Fatal(err)
	}
	first, err := db.GetBatchTaskTestingSpecification("queue", "first")
	if err != nil || first.Content != "original" || first.Source != "project" {
		t.Fatalf("first: %#v %v", first, err)
	}
	second, err := db.GetBatchTaskTestingSpecification("queue", "second")
	if err != nil || second.Content != "override" || second.Source != "task" {
		t.Fatalf("second: %#v %v", second, err)
	}
	if err := db.AddBatchTask("queue", "third", "three"); err != nil {
		t.Fatal(err)
	}
	third, err := db.GetBatchTaskTestingSpecification("queue", "third")
	if err != nil || third.Content != "original" {
		t.Fatalf("added task: %#v %v", third, err)
	}
}

func TestLegacyBatchTestingSpecificationFreezesEffectiveProject(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "legacy-batch-spec.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&Project{Name: "Synthetic default", TestingSpecification: &TestingSpecification{Content: "default project rules"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, queueID := range []string{"legacy", "new-unbound"} {
		if err := db.CreateBatchQueue(queueID, "", "", "eino_single", "manual", "", nil, "", 1, []map[string]interface{}{{"id": queueID + "-task", "message": "verify headers"}}); err != nil {
			t.Fatal(err)
		}
	}
	// Old versions did not create a queue specification row.
	if _, err := db.Exec("DELETE FROM batch_testing_specifications WHERE queue_id=?", "legacy"); err != nil {
		t.Fatal(err)
	}
	projectID, err := db.GetBatchQueueTestingSpecificationProjectID("legacy", p.ID)
	if err != nil || projectID != p.ID {
		t.Fatalf("legacy default: %q %v", projectID, err)
	}
	got, err := db.GetBatchTaskTestingSpecification("legacy", "legacy-task", projectID)
	if err != nil || got == nil || got.Content != "default project rules" {
		t.Fatalf("legacy snapshot: %#v %v", got, err)
	}
	row, err := db.GetBatchQueue("legacy")
	if err != nil || row.ProjectID.String != p.ID {
		t.Fatalf("legacy project was not persisted: %#v %v", row, err)
	}
	projectID, err = db.GetBatchQueueTestingSpecificationProjectID("legacy", "changed-default")
	if err != nil || projectID != p.ID {
		t.Fatalf("legacy binding drifted: %q %v", projectID, err)
	}
	projectID, err = db.GetBatchQueueTestingSpecificationProjectID("new-unbound", p.ID)
	if err != nil || projectID != "" {
		t.Fatalf("existing empty snapshot must remain unbound: %q %v", projectID, err)
	}
	got, err = db.GetBatchTaskTestingSpecification("new-unbound", "new-unbound-task", p.ID)
	if err != nil || got == nil || got.Content != "" {
		t.Fatalf("existing empty snapshot changed: %#v %v", got, err)
	}
}
