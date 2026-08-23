package handler

import (
	"context"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

const finalizationAutoContinueMaxAttempts = 2

func accumulateEinoRunMCPExecutionIDs(ids []string, result *multiagent.RunResult) []string {
	if result == nil {
		return ids
	}
	return mergeMCPExecutionIDLists(ids, result.MCPExecutionIDs)
}

func shouldAutoContinueAfterFinalization(d agentfinalizer.Decision, attempt int) bool {
	if d.Finalizable || d.Finalized {
		return false
	}
	if attempt >= finalizationAutoContinueMaxAttempts {
		return false
	}
	return d.CompletionReason == agentfinalizer.ReasonMissingEvidence
}

func (h *AgentHandler) tryAutoContinueAfterFinalization(
	taskCtx context.Context,
	conversationID string,
	result *multiagent.RunResult,
	decision agentfinalizer.Decision,
	attempt *int,
	curHistory *[]agent.ChatMessage,
	curFinalMessage *string,
	progressCallback func(eventType, message string, data interface{}),
) bool {
	if !shouldAutoContinueAfterFinalization(decision, *attempt) || result == nil || !multiagent.HasEinoResumeTrace(result) {
		return false
	}
	*attempt++
	h.persistEinoAgentTraceForResume(conversationID, result)
	if hist, err := h.loadHistoryFromAgentTrace(conversationID); err == nil && len(hist) > 0 {
		*curHistory = hist
	} else if h.logger != nil {
		h.logger.Warn("finalization auto-continue could not restore trace",
			zap.String("conversationId", conversationID),
			zap.Error(err))
		return false
	}
	// 仅注入当前 Runner，不写入用户消息表；明确反馈缺失的结束条件，避免模型再次停在计划正文。
	*curFinalMessage = finalizationAutoContinuePrompt(decision)
	if progressCallback != nil {
		progressCallback("finalization_auto_continue", "最终回复检查尚未收敛，正在基于已有轨迹继续执行…", map[string]interface{}{
			"conversationId":       conversationID,
			"source":               "finalizer",
			"attempt":              *attempt,
			"maxAttempts":          finalizationAutoContinueMaxAttempts,
			"status":               decision.Status,
			"completionReason":     decision.CompletionReason,
			"missingChecks":        decision.MissingChecks,
			"pendingExecutionIds":  decision.PendingExecutionIDs,
			"contextInjection":     true,
			"persistedUserMessage": false,
		})
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(finalizationAutoContinueBackoff(*attempt)):
		return true
	}
}

func finalizationAutoContinuePrompt(d agentfinalizer.Decision) string {
	return "[内部续跑指令] 当前任务尚未满足最终交付条件（" + d.CompletionReason + "）。" +
		"请基于已有轨迹继续执行未完成步骤，不得重做已完成的工具调用；" +
		"只有用户目标真正完成时才调用 exit，并在 final_result 中给出完整最终答复。"
}

func finalizationAutoContinueBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 500 * time.Millisecond
	}
	return time.Duration(attempt) * time.Second
}
