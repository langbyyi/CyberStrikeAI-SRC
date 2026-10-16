package database

import (
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestTestingSpecificationSnapshot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "spec.db")
	db, err := NewDB(dbPath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&Project{Name: "Synthetic project", TestingSpecification: &TestingSpecification{Name: "rules.md", Content: "Only app.example.test; maximum 2 requests/s."}})
	if err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("test", ConversationCreateMeta{ProjectID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.GetConversationTestingSpecification(conv.ID)
	if err != nil || snapshot.Source != "project" || snapshot.Content != p.TestingSpecification.Content || snapshot.Hash == "" {
		t.Fatalf("snapshot: %#v, %v", snapshot, err)
	}
	p.TestingSpecification.Content = "Changed project rules"
	if err := db.UpdateProject(p); err != nil {
		t.Fatal(err)
	}
	old, err := db.GetConversationTestingSpecification(conv.ID)
	if err != nil || old.Hash != snapshot.Hash || old.Content != snapshot.Content {
		t.Fatalf("snapshot changed: %#v, %v", old, err)
	}
	override, err := db.CreateConversation("override", ConversationCreateMeta{ProjectID: p.ID, TestingSpecification: &TestingSpecification{Name: "task.txt", Content: "Task-specific reporting requirements"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GetConversationTestingSpecification(override.ID)
	if err != nil || got.Source != "task" || got.Name != "task.txt" || got.Content != "Task-specific reporting requirements" {
		t.Fatalf("override: %#v, %v", got, err)
	}
	message, err := db.AddMessage(override.ID, "user", "execute", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationTestingSpecification(override.ID, &TestingSpecification{Content: "replace after start"}); err == nil {
		t.Fatal("started task specification must be immutable")
	}
	if _, err := db.DeleteConversationTurn(override.ID, message.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationTestingSpecification(override.ID, &TestingSpecification{Content: "replace after deleting messages"}); err == nil {
		t.Fatal("deleting messages must not unfreeze snapshot")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = NewDB(dbPath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err = db.GetConversationTestingSpecification(override.ID)
	if err != nil || got.Hash == "" || got.Content != "Task-specific reporting requirements" {
		t.Fatalf("reopened snapshot: %#v, %v", got, err)
	}
}

func TestTestingSpecificationEmptySnapshotAndValidation(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "spec.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&Project{Name: "Empty"})
	if err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("empty", ConversationCreateMeta{ProjectID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	p.TestingSpecification = &TestingSpecification{Content: "Added later"}
	if err := db.UpdateProject(p); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetConversationTestingSpecification(conv.ID)
	if err != nil || got.Source != "none" || got.Content != "" {
		t.Fatalf("empty snapshot must remain empty: %#v, %v", got, err)
	}
	for _, content := range []string{strings.Repeat("x", MaxTestingSpecificationBytes+1), "invalid\x00text", string([]byte{0xff})} {
		if _, err := NormalizeTestingSpecification(&TestingSpecification{Content: content}); err == nil {
			t.Fatal("invalid content accepted")
		}
	}
}

func TestTestingSpecificationEmptyOverrideSurvivesProjectChange(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "empty-override.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&Project{Name: "Synthetic", TestingSpecification: &TestingSpecification{Content: "project rules"}})
	if err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("explicitly empty", ConversationCreateMeta{TestingSpecification: &TestingSpecification{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationProjectID(conv.ID, p.ID); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetConversationTestingSpecification(conv.ID)
	if err != nil || got == nil || got.Source != "task" || got.Content != "" || got.Hash != "" {
		t.Fatalf("explicit empty override was replaced: %#v %v", got, err)
	}
	block, err := db.ConversationTestingSpecificationBlock(conv.ID)
	if err != nil || block != "" {
		t.Fatalf("empty override injected rules: %q %v", block, err)
	}
}

// 执行侧规范块不得再让 Agent 停下来征求用户意见：那会把每一次规范冲突变成一次等待，
// 与「授权范围内直接执行」相冲突。摘掉的只是包装句，规范原文仍须原样带入。
func TestTestingSpecificationBlockDoesNotInterruptForUserConsent(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "spec-no-interrupt.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conv, err := db.CreateConversation("spec no interrupt", ConversationCreateMeta{
		TestingSpecification: &TestingSpecification{Name: "task.md", Content: "禁止对删除类接口做真实触发。"},
	})
	if err != nil {
		t.Fatal(err)
	}
	block, err := db.ConversationTestingSpecificationBlock(conv.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"先向用户说明", "如存在冲突或歧义"} {
		if strings.Contains(block, forbidden) {
			t.Errorf("规范块不得让执行 Agent 停下来问用户，命中 %q: %s", forbidden, block)
		}
	}
	if !strings.Contains(block, "禁止对删除类接口做真实触发。") {
		t.Errorf("规范原文丢失: %s", block)
	}
}
