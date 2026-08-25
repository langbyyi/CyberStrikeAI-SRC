package handler

import (
	"context"
	"strings"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

const finalizationAutoContinueMaxAttempts = 2
const finalizationMissingSignalAutoContinueMaxAttempts = 1
const finalizationPendingToolCancelWait = 2 * time.Second
const finalizationPendingToolCancelPoll = 50 * time.Millisecond
const finalizationPendingToolCancelNote = "Agent 迭代已结束，最终回复前自动终止未完成的工具执行"

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
	switch d.CompletionReason {
	case agentfinalizer.ReasonMissingEvidence:
		return attempt < finalizationAutoContinueMaxAttempts
	case agentfinalizer.ReasonMissingCompletionSignal:
		return d.CandidateResponseLen > 0 && attempt < finalizationMissingSignalAutoContinueMaxAttempts
	default:
		return false
	}
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
		maxAttempts := finalizationAutoContinueMaxAttempts
		if decision.CompletionReason == agentfinalizer.ReasonMissingCompletionSignal {
			maxAttempts = finalizationMissingSignalAutoContinueMaxAttempts
		}
		progressCallback("finalization_auto_continue", "最终回复检查尚未收敛，正在基于已有轨迹继续执行…", map[string]interface{}{
			"conversationId":       conversationID,
			"source":               "finalizer",
			"attempt":              *attempt,
			"maxAttempts":          maxAttempts,
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
	if d.CompletionReason == agentfinalizer.ReasonMissingCompletionSignal {
		return "[内部终态修复指令] 上一段已形成候选最终答复，但未提交显式完成信号。" +
			"请基于已有轨迹复核并整理候选答复，不得调用除 exit 外的任何工具；" +
			"直接调用 exit，并在 final_result 中提交完整最终答复。"
	}
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

func (h *AgentHandler) cleanupPendingToolExecutionsAfterIteration(
	taskCtx context.Context,
	conversationID string,
	decision agentfinalizer.Decision,
	progressCallback func(eventType, message string, data interface{}),
) []string {
	if h == nil || h.agent == nil || decision.CompletionReason != agentfinalizer.ReasonPendingTools {
		return nil
	}
	pending := uniqueNonEmptyStrings(decision.PendingExecutionIDs)
	if len(pending) == 0 {
		return nil
	}
	cancelled := make([]string, 0, len(pending))
	for _, executionID := range pending {
		if h.agent.CancelMCPToolExecutionWithNote(executionID, finalizationPendingToolCancelNote) {
			cancelled = append(cancelled, executionID)
		} else if h.logger != nil {
			h.logger.Warn("finalization pending tool cleanup could not cancel execution",
				zap.String("conversationId", conversationID),
				zap.String("executionId", executionID))
		}
	}
	if len(cancelled) == 0 {
		return nil
	}
	if progressCallback != nil {
		progressCallback("finalization_pending_tools_cancelled", "迭代结束，已自动终止仍在运行的工具执行。", map[string]interface{}{
			"conversationId":                   conversationID,
			"source":                           "finalizer",
			"autoCancelledPendingExecutionIds": cancelled,
			"pendingExecutionIds":              pending,
			"reason":                           agentfinalizer.ReasonPendingTools,
		})
	}
	h.waitForToolExecutionsToLeavePending(taskCtx, cancelled, finalizationPendingToolCancelWait)
	return cancelled
}

func (h *AgentHandler) waitForToolExecutionsToLeavePending(ctx context.Context, executionIDs []string, wait time.Duration) {
	if h == nil || h.db == nil || len(executionIDs) == 0 || wait <= 0 {
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(finalizationPendingToolCancelPoll)
	defer ticker.Stop()
	for {
		if !h.hasPendingToolExecutions(executionIDs) {
			return
		}
		select {
		case <-contextDone(ctx):
			return
		case <-timer.C:
			return
		case <-ticker.C:
		}
	}
}

func (h *AgentHandler) hasPendingToolExecutions(executionIDs []string) bool {
	if h == nil || h.db == nil {
		return false
	}
	for _, executionID := range uniqueNonEmptyStrings(executionIDs) {
		exec, err := h.db.GetToolExecution(executionID)
		if err != nil || exec == nil {
			continue
		}
		switch strings.TrimSpace(exec.Status) {
		case mcp.ToolExecutionStatusQueued, mcp.ToolExecutionStatusRunning:
			return true
		}
	}
	return false
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func contextDone(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}
