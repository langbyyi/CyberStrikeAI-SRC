package handler

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestEnrichHitlApprovalPayloadCarriesUserDeclarationsWithoutAssistantCognition(t *testing.T) {
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

// 用户在第 1 轮给出的授权必须活到第 2 轮：否则审计 Agent 每轮都只看到
// 当轮那句泛化指令，同类操作会被无限次拒绝。
func TestEnrichHitlApprovalPayloadCarriesConsentFromEarlierTurn(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "test.sqlite"), zap.NewNop())
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	conv, err := db.CreateConversation("hitl consent", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("conv: %v", err)
	}
	if _, err := db.AddMessage(conv.ID, "user", "挖高危漏洞", nil); err != nil {
		t.Fatalf("user msg: %v", err)
	}
	if _, err := db.AddMessage(conv.ID, "assistant", "第一轮结论", nil); err != nil {
		t.Fatalf("asst msg: %v", err)
	}
	if _, err := db.AddMessage(conv.ID, "user", "我授权你测试该重置密码接口", nil); err != nil {
		t.Fatalf("consent msg: %v", err)
	}
	asst, err := db.AddMessage(conv.ID, "assistant", "", nil)
	if err != nil {
		t.Fatalf("asst msg: %v", err)
	}

	h := &AgentHandler{db: db, tasks: NewAgentTaskManager()}
	payload := map[string]interface{}{}
	h.enrichHitlApprovalPayload(conv.ID, asst.ID, payload)

	got, _ := payload["userMessage"].(string)
	for _, want := range []string{"挖高危漏洞", "我授权你测试该重置密码接口"} {
		if !strings.Contains(got, want) {
			t.Fatalf("userMessage=%q must carry %q", got, want)
		}
	}
	if strings.Contains(got, "第一轮结论") {
		t.Fatalf("userMessage=%q must not carry assistant text", got)
	}
}

// 测试规范是授权基线的一部分：审计 Agent 必须拿到它的原文，
// 且不能把执行侧"规范不授予额外权限"那段免责文案一起带过去。
func TestEnrichHitlApprovalPayloadCarriesTestingSpecification(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "test.sqlite"), zap.NewNop())
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const specContent = "范围：http://target/。允许对自建测试账号执行一次改密验证。"
	conv, err := db.CreateConversation("hitl spec", database.ConversationCreateMeta{
		TestingSpecification: &database.TestingSpecification{Name: "task.md", Content: specContent},
	})
	if err != nil {
		t.Fatalf("conv: %v", err)
	}
	asst, err := db.AddMessage(conv.ID, "assistant", "", nil)
	if err != nil {
		t.Fatalf("asst msg: %v", err)
	}

	h := &AgentHandler{db: db, tasks: NewAgentTaskManager()}
	payload := map[string]interface{}{}
	h.enrichHitlApprovalPayload(conv.ID, asst.ID, payload)

	spec, _ := payload["testingSpecification"].(string)
	if !strings.Contains(spec, specContent) {
		t.Fatalf("testingSpecification=%q must carry the spec content", spec)
	}
	if strings.Contains(spec, "规范不授予额外权限") {
		t.Fatalf("testingSpecification=%q must not carry the execution-side disclaimer", spec)
	}
	review := buildAuditAgentReviewInput("http-framework-test", payload)
	if !strings.Contains(review, specContent) {
		t.Fatalf("audit agent input must carry the testing specification, got %q", review)
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

// 注入审计 Agent 的用户声明必须有界：既丢最早的（保留最新表态），
// 也不允许单条超长消息突破上限——否则一次大段粘贴就能撑爆审计请求。
func TestJoinHitlUserDeclarationsEnforcesByteBudget(t *testing.T) {
	filler := strings.Repeat("a", 40)
	joined := joinHitlUserDeclarations(
		[]string{"最早的声明", filler, filler + "x", "最新的同意"},
		100,
	)
	if len(joined) > 100 {
		t.Fatalf("拼接结果必须受字节上限约束，实际 %d", len(joined))
	}
	if !strings.Contains(joined, "最新的同意") {
		t.Fatalf("超限时应优先保留最新表态，实际 %q", joined)
	}
	if strings.Contains(joined, "最早的声明") {
		t.Fatalf("超限时应丢弃最早的声明，实际 %q", joined)
	}

	// 单条消息本身超过上限：丢弃循环失效，必须走截断兜底。
	huge := strings.Repeat("改", 200) // 中文 3 字节/字，共 600 字节
	single := joinHitlUserDeclarations([]string{huge}, 100)
	if len(single) > 100+len("…（已截断）") {
		t.Fatalf("单条超长消息未被截断，实际 %d 字节", len(single))
	}
	if !strings.HasSuffix(single, "…（已截断）") {
		t.Fatalf("截断后应带标记，实际 %q", single)
	}
	if !utf8.ValidString(single) {
		t.Fatalf("截断不得切断 UTF-8 字符，实际 %q", single)
	}
}
