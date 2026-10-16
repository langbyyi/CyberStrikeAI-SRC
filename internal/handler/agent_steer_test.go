package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func steerHandlerFixture(t *testing.T) (*AgentHandler, *database.RBACUser, string) {
	t.Helper()
	db, user := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("steer-target", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(user.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	return &AgentHandler{db: db, tasks: NewAgentTaskManager(), logger: zap.NewNop()}, user, conversation.ID
}

func steerBody(conversationID, message string) map[string]string {
	return map[string]string{"conversationId": conversationID, "message": message}
}

// TestSteerAgentLoopRejectsForeignConversation 引导与取消同权限边界：不得跨会话注入指令。
func TestSteerAgentLoopRejectsForeignConversation(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	hidden, _ := db.CreateConversation("hidden", database.ConversationCreateMeta{})
	h := &AgentHandler{db: db, tasks: NewAgentTaskManager(), logger: zap.NewNop()}

	w := performAssignedHandler(user, http.MethodPost, "/api/agent-loop/steer",
		steerBody(hidden.ID, "补充指示"), h.SteerAgentLoop)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestSteerAgentLoopRequiresNonEmptyMessage(t *testing.T) {
	h, user, conversationID := steerHandlerFixture(t)

	w := performAssignedHandler(user, http.MethodPost, "/api/agent-loop/steer",
		steerBody(conversationID, "   "), h.SteerAgentLoop)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
}

// TestSteerAgentLoopNoActiveTask 会话空闲时不属于引导场景：前端据此按普通发送处理。
func TestSteerAgentLoopNoActiveTask(t *testing.T) {
	h, user, conversationID := steerHandlerFixture(t)

	w := performAssignedHandler(user, http.MethodPost, "/api/agent-loop/steer",
		steerBody(conversationID, "补充指示"), h.SteerAgentLoop)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Status != "no_active_task" {
		t.Fatalf("body = %s, want no_active_task", w.Body.String())
	}
}

// TestSteerAgentLoopUnsupportedWithoutTurnLoop workflow/批量等无 TurnLoop 安全点的运行时
// 不允许引导：必须明确拒绝，而不是静默中断正在跑的任务。
func TestSteerAgentLoopUnsupportedWithoutTurnLoop(t *testing.T) {
	h, user, conversationID := steerHandlerFixture(t)
	if _, err := h.tasks.StartTask(conversationID, "运行中", func(error) {}); err != nil {
		t.Fatal(err)
	}

	w := performAssignedHandler(user, http.MethodPost, "/api/agent-loop/steer",
		steerBody(conversationID, "补充指示"), h.SteerAgentLoop)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Status != "steer_unsupported" {
		t.Fatalf("body = %s, want steer_unsupported", w.Body.String())
	}
	if msgs := h.tasks.GetHitlUserMessages(conversationID); len(msgs) != 1 {
		t.Fatalf("hitl declarations = %#v, want only the task's own message", msgs)
	}
}

// TestSteerAgentLoopAcceptsAndExtendsApprovalScope 引导被受理后：
// 指示进入运行任务的 TurnLoop 入队 hook，并作为用户声明扩展审批授权范围。
func TestSteerAgentLoopAcceptsAndExtendsApprovalScope(t *testing.T) {
	h, user, conversationID := steerHandlerFixture(t)
	if _, err := h.tasks.StartTask(conversationID, "运行中", func(error) {}); err != nil {
		t.Fatal(err)
	}
	var pushed []string
	unregister := h.tasks.BindAgentTurnLoopSteer(conversationID, func(message string) bool {
		pushed = append(pushed, message)
		return true
	})
	t.Cleanup(unregister)

	w := performAssignedHandler(user, http.MethodPost, "/api/agent-loop/steer",
		steerBody(conversationID, "  只测 10.0.160.98 的 8080  "), h.SteerAgentLoop)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Status != "steer_accepted" {
		t.Fatalf("body = %s, want steer_accepted", w.Body.String())
	}
	if len(pushed) != 1 || pushed[0] != "只测 10.0.160.98 的 8080" {
		t.Fatalf("pushed = %#v, want trimmed steer message", pushed)
	}
	msgs := h.tasks.GetHitlUserMessages(conversationID)
	if len(msgs) != 2 || msgs[1] != "只测 10.0.160.98 的 8080" {
		t.Fatalf("hitl declarations = %#v, want steer appended", msgs)
	}
}
