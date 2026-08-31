package handler

import (
	"context"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestEnrichHitlApprovalPayloadCarriesOnlyTurnUserDeclaration(t *testing.T) {
	tmp := t.TempDir()
	db, err := database.NewDB(filepath.Join(tmp, "test.sqlite"), zap.NewNop())
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	// Close 必须先于 TempDir 清理执行，否则 Windows 上 sqlite 文件被占用导致清理失败。
	t.Cleanup(func() { _ = db.Close() })

	conv, err := db.CreateConversation("hitl ctx", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("conv: %v", err)
	}
	if _, err := db.AddMessage(conv.ID, "user", "scan 10.0.0.1 please", nil); err != nil {
		t.Fatalf("user msg: %v", err)
	}
	asst, err := db.AddMessage(conv.ID, "assistant", "", nil)
	if err != nil {
		t.Fatalf("asst msg: %v", err)
	}
	if err := db.AddProcessDetail(asst.ID, conv.ID, "thinking", "need port scan first", nil); err != nil {
		t.Fatalf("detail: %v", err)
	}

	h := &AgentHandler{db: db, tasks: NewAgentTaskManager()}
	payload := map[string]interface{}{"toolName": "nmap", "arguments": "{}"}
	h.enrichHitlApprovalPayload(conv.ID, asst.ID, payload)

	if got := payload["userMessage"]; got != "scan 10.0.0.1 please" {
		t.Fatalf("userMessage=%v", got)
	}
	for _, forbidden := range []string{"thinking", "reasoningChain", "planning"} {
		if _, exists := payload[forbidden]; exists {
			t.Fatalf("approval payload must not carry %s", forbidden)
		}
	}
}

func TestEnrichHitlApprovalPayloadCarriesInterruptContinueDeclaration(t *testing.T) {
	h := &AgentHandler{tasks: NewAgentTaskManager()}
	if _, err := h.tasks.StartTask("conversation-1", "测试删除会话接口", func(error) {}); err != nil {
		t.Fatal(err)
	}
	h.tasks.SetInterruptContinueNote("conversation-1", "确认继续执行该删除接口测试")
	payload := map[string]interface{}{}

	h.enrichHitlApprovalPayload("conversation-1", "", payload)

	if got, want := payload["userMessage"], "测试删除会话接口\n\n确认继续执行该删除接口测试"; got != want {
		t.Fatalf("userMessage=%#v, want %q", got, want)
	}
}

func TestEnrichHitlApprovalPayloadCarriesActiveToolInterruptDeclaration(t *testing.T) {
	tasks := NewAgentTaskManager()
	if _, err := tasks.StartTask("conversation-1", "测试删除会话接口", func(error) {}); err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(context.Background())
	tasks.RegisterActiveEinoExecute("conversation-1", cancel)
	if !tasks.AbortActiveEinoExecute("conversation-1", "确认继续执行该删除接口测试") {
		t.Fatal("active execute abort should succeed")
	}
	h := &AgentHandler{tasks: tasks}
	payload := map[string]interface{}{}

	h.enrichHitlApprovalPayload("conversation-1", "", payload)

	if got, want := payload["userMessage"], "测试删除会话接口\n\n确认继续执行该删除接口测试"; got != want {
		t.Fatalf("userMessage=%#v, want %q", got, want)
	}
}
