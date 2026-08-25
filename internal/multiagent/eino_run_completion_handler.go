package multiagent

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

type einoRunCompletionHandler struct {
	conversationID string
	orchMode       string
	progress       func(eventType, message string, data interface{})
	logger         *zap.Logger

	pending      *einoPendingToolCalls
	cpStore      *fileCheckPointStore
	checkPointID string

	deliveredToolResults func() map[string]string
}

type einoRunCompletionHandlerConfig struct {
	ConversationID string
	OrchMode       string
	Progress       func(eventType, message string, data interface{})
	Logger         *zap.Logger
	Pending        *einoPendingToolCalls
	Checkpoint     *fileCheckPointStore
	CheckpointID   string
	// DeliveredToolResults 返回「已送入模型」的工具结果（ToolCallID → 正文，来自模型侧轨迹）。
	// 用于在 run 结束时对账 pending：未知工具（UnknownToolsHandler）路径的结果不会产生
	// ADK 工具事件，只进模型输入；这类 pending 应按真实结果补发，而不是误报强制关闭。
	DeliveredToolResults func() map[string]string
}

func newEinoRunCompletionHandler(cfg einoRunCompletionHandlerConfig) *einoRunCompletionHandler {
	return &einoRunCompletionHandler{
		conversationID:       cfg.ConversationID,
		orchMode:             cfg.OrchMode,
		progress:             cfg.Progress,
		logger:               cfg.Logger,
		pending:              cfg.Pending,
		cpStore:              cfg.Checkpoint,
		checkPointID:         cfg.CheckpointID,
		deliveredToolResults: cfg.DeliveredToolResults,
	}
}

func (h *einoRunCompletionHandler) Complete() {
	if h == nil {
		return
	}
	h.ReconcileDeliveredPending()
	h.flushOrphanedPending()
	h.cleanupCheckpoint()
}

// ReconcileDeliveredPending 将结果已送达模型但未被事件观测到的 pending 项按真实结果补发。
// 错误/取消路径在 FlushAsFailed 前也应调用，避免幽灵 pending 误报为工具失败。
func (h *einoRunCompletionHandler) ReconcileDeliveredPending() {
	if h.pending == nil || h.deliveredToolResults == nil {
		return
	}
	delivered := h.deliveredToolResults()
	reconciled := h.pending.ExtractDelivered(delivered)
	if len(reconciled) == 0 {
		return
	}
	if h.logger != nil {
		h.logger.Info("eino pending tool calls reconciled from model-facing trace",
			zap.String("conversationId", h.conversationID),
			zap.String("orchestration", h.orchMode),
			zap.Int("reconciledCount", len(reconciled)),
		)
	}
	if h.progress == nil {
		return
	}
	for _, tc := range reconciled {
		content := strings.TrimSpace(delivered[tc.ToolCallID])
		toolName := tc.ToolName
		if strings.TrimSpace(toolName) == "" {
			toolName = "unknown"
		}
		isErr := einoToolResultIsError(toolName, content)
		preview := content
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		h.progress("tool_result", fmt.Sprintf("工具结果 (%s)", toolName), map[string]interface{}{
			"toolName":                 toolName,
			"success":                  !isErr,
			"isError":                  isErr,
			"result":                   content,
			"resultPreview":            preview,
			"toolCallId":               tc.ToolCallID,
			"conversationId":           h.conversationID,
			"einoAgent":                tc.EinoAgent,
			"einoRole":                 tc.EinoRole,
			"source":                   "eino",
			"reconciledFromModelTrace": true,
		})
	}
}

func (h *einoRunCompletionHandler) flushOrphanedPending() {
	if h.pending == nil {
		return
	}
	orphanCount := h.pending.Count()
	if orphanCount <= 0 {
		return
	}
	h.pending.FlushAsFailed(errors.New("pending tool call missing result before run completion"))
	if h.progress != nil {
		h.progress("eino_pending_orphaned", "pending tool calls were force-closed at run end", map[string]interface{}{
			"conversationId": h.conversationID,
			"source":         "eino",
			"orchestration":  h.orchMode,
			"pendingCount":   orphanCount,
		})
	}
}

// deliveredToolResultsFromMessages 从模型侧消息轨迹提取 ToolCallID → 正文 映射。
func deliveredToolResultsFromMessages(msgs []adk.Message) map[string]string {
	if len(msgs) == 0 {
		return nil
	}
	out := make(map[string]string)
	for _, m := range msgs {
		if m == nil || m.Role != schema.Tool {
			continue
		}
		id := strings.TrimSpace(m.ToolCallID)
		if id == "" {
			continue
		}
		out[id] = m.Content
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (h *einoRunCompletionHandler) cleanupCheckpoint() {
	if h.cpStore == nil || h.checkPointID == "" {
		return
	}
	p, err := h.cpStore.path(h.checkPointID)
	if err != nil {
		return
	}
	if rmErr := os.Remove(p); rmErr != nil && !os.IsNotExist(rmErr) && h.logger != nil {
		h.logger.Warn("eino checkpoint cleanup failed", zap.String("path", p), zap.Error(rmErr))
	}
}
