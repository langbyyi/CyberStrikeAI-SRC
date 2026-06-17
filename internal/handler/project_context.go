package handler

import (
	"strings"

	"cyberstrike-ai/internal/project"
	"go.uber.org/zap"
)

// projectBlackboardBlock 根据对话 ID 构建项目事实索引块（用于注入 system prompt）。
func (h *AgentHandler) projectBlackboardBlock(conversationID string) string {
	if h == nil || h.db == nil || h.config == nil {
		return ""
	}
	if !h.config.Project.Enabled {
		return ""
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ""
	}
	projectID, err := h.db.GetConversationProjectID(conversationID)
	if err != nil || projectID == "" {
		return ""
	}
	block, err := project.BuildProjectBlackboardBlock(h.db, projectID, h.config.Project)
	if err != nil {
		h.logger.Warn("构建项目黑板索引失败", zap.String("conversationId", conversationID), zap.Error(err))
		return ""
	}
	return strings.TrimSpace(block)
}
