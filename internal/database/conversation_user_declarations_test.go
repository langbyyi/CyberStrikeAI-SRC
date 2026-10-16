package database

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func newDeclarationTestConversation(t *testing.T) (*DB, string) {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "declarations.sqlite"), zap.NewNop())
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conv, err := db.CreateConversation("declarations", ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("conv: %v", err)
	}
	return db, conv.ID
}

// 跨轮授权必须在审批上下文里可见：用户在第 1 轮说过"我授权测试该接口"，
// 第 2 轮同类调用仍应看得到，否则审计 Agent 每轮都要求重新声明。
func TestConversationUserDeclarationsSpansEarlierTurns(t *testing.T) {
	db, conv := newDeclarationTestConversation(t)

	if _, err := db.AddMessage(conv, "user", "挖高危漏洞", nil); err != nil {
		t.Fatal(err)
	}
	firstAssistant, err := db.AddMessage(conv, "assistant", "第一轮结论", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMessage(conv, "user", "我授权你测试该重置密码接口", nil); err != nil {
		t.Fatal(err)
	}
	secondAssistant, err := db.AddMessage(conv, "assistant", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	all, err := db.ConversationUserDeclarations(conv, secondAssistant.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0] != "挖高危漏洞" || all[1] != "我授权你测试该重置密码接口" {
		t.Fatalf("declarations=%#v, want both user messages in chronological order", all)
	}

	// 锚点之前的轮次不得包含锚点之后的用户消息。
	earlier, err := db.ConversationUserDeclarations(conv, firstAssistant.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(earlier) != 1 || earlier[0] != "挖高危漏洞" {
		t.Fatalf("declarations before anchor=%#v, want only the first user message", earlier)
	}

	// limit 保留最近的声明。
	recent, err := db.ConversationUserDeclarations(conv, secondAssistant.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 1 || recent[0] != "我授权你测试该重置密码接口" {
		t.Fatalf("limited declarations=%#v, want the most recent one", recent)
	}
}

func TestConversationUserDeclarationsIgnoresAssistantAndBlankMessages(t *testing.T) {
	db, conv := newDeclarationTestConversation(t)
	if _, err := db.AddMessage(conv, "user", "   ", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMessage(conv, "assistant", "助手推理不应进入授权基线", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMessage(conv, "user", "只测该入口", nil); err != nil {
		t.Fatal(err)
	}

	declarations, err := db.ConversationUserDeclarations(conv, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(declarations) != 1 || declarations[0] != "只测该入口" {
		t.Fatalf("declarations=%#v, want only the non-blank user message", declarations)
	}
}
