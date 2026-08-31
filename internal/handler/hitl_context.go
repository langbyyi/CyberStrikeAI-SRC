package handler

import (
	"strings"
)

const (
	hitlPayloadUserMessage = "userMessage"
)

func (h *AgentHandler) enrichHitlApprovalPayload(conversationID, assistantMessageID string, payload map[string]interface{}) {
	if h == nil || payload == nil {
		return
	}
	if h.tasks != nil {
		if messages := h.tasks.GetHitlUserMessages(conversationID); len(messages) > 0 {
			payload[hitlPayloadUserMessage] = strings.Join(messages, "\n\n")
			return
		}
	}
	if h.db == nil {
		return
	}
	userMessage, err := h.db.GetTurnUserMessage(conversationID, assistantMessageID)
	if err == nil {
		if s := strings.TrimSpace(userMessage); s != "" {
			payload[hitlPayloadUserMessage] = s
		}
	}
}
