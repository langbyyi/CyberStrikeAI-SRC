package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// EinoSingleAgentLoopStream Eino ADK 单代理（ChatModelAgent + Runner）流式对话；不依赖 multi_agent.enabled。
func (h *AgentHandler) EinoSingleAgentLoopStream(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ev := StreamEvent{Type: "error", Message: "请求参数错误: " + err.Error()}
		b, _ := json.Marshal(ev)
		fmt.Fprintf(c.Writer, "data: %s\n\n", b)
		done := StreamEvent{Type: "done", Message: ""}
		db, _ := json.Marshal(done)
		fmt.Fprintf(c.Writer, "data: %s\n\n", db)
		if flusher, ok := c.Writer.(http.Flusher); ok {
			flusher.Flush()
		}
		return
	}

	c.Header("X-Accel-Buffering", "no")

	var baseCtx context.Context
	stream := newAgentSSEStream(c, h.taskEventBus, func() context.Context {
		return baseCtx
	})
	sendEvent := stream.Send

	h.logger.Info("收到 Eino ADK 单代理流式请求",
		zap.String("conversationId", req.ConversationID),
	)

	prep, err := h.prepareMultiAgentSession(&req, c, "eino_agent_stream")
	if err != nil {
		sendEvent("error", err.Error(), nil)
		sendEvent("done", "", nil)
		return
	}
	stream.SetConversationID(prep.ConversationID)
	if prep.CreatedNew {
		sendEvent("conversation", "会话已创建", map[string]interface{}{
			"conversationId": prep.ConversationID,
		})
	}

	conversationID := prep.ConversationID
	assistantMessageID := prep.AssistantMessageID
	h.activateHITLForConversation(conversationID, req.Hitl)
	if h.hitlManager != nil {
		defer h.hitlManager.DeactivateConversation(conversationID)
	}

	if prep.UserMessageID != "" {
		sendEvent("message_saved", "", map[string]interface{}{
			"conversationId": conversationID,
			"userMessageId":  prep.UserMessageID,
		})
	}

	var cancelWithCause context.CancelCauseFunc
	curFinalMessage := prep.FinalMessage
	curHistory := prep.History
	roleTools := prep.RoleTools

	sendEvent("progress", "正在启动 Eino ADK 单代理（ChatModelAgent）...", map[string]interface{}{
		"conversationId": conversationID,
	})

	stopKeepalive := make(chan struct{})
	go sseKeepalive(c, stopKeepalive, stream.WriteMutex())
	defer close(stopKeepalive)

	if h.config == nil {
		sendEvent("error", "服务器配置未加载", nil)
		sendEvent("done", "", map[string]interface{}{"conversationId": conversationID})
		return
	}

	var result *multiagent.RunResult
	var runErr error

	runDeadline := time.Now().Add(einoExecutionTimeout(h.config, "eino_single"))
	baseCtx, cancelWithCause, taskCtx, timeoutCancel := newEinoSingleSegmentContexts(runDeadline)

	managedTask, err := beginManagedAgentTask(h.tasks, conversationID, req.Message, cancelWithCause)
	if err != nil {
		var errorMsg string
		if errors.Is(err, ErrTaskAlreadyRunning) {
			errorMsg = "⚠️ 当前会话已有任务正在执行中，请等待当前任务完成或点击「停止任务」后再尝试。"
			sendEvent("error", errorMsg, map[string]interface{}{
				"conversationId": conversationID,
				"errorType":      "task_already_running",
			})
		} else {
			errorMsg = "❌ 无法启动任务: " + err.Error()
			sendEvent("error", errorMsg, nil)
		}
		if assistantMessageID != "" {
			_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", errorMsg, time.Now(), assistantMessageID)
		}
		sendEvent("done", "", map[string]interface{}{"conversationId": conversationID})
		timeoutCancel()
		return
	}
	defer managedTask.Finish()

	var cumulativeMCPExecutionIDs []string
	// 同一请求内分段续跑时，主代理 iteration 事件按偏移累计，避免 UI 出现「第3轮 → 第1轮」回跳。
	var mainIterationOffset int
	var emptyResponseContinueAttempt int

	for {
		segmentMainIterationMax := 0
		rawProgressCallback := h.createProgressCallback(taskCtx, cancelWithCause, conversationID, assistantMessageID, sendEvent)
		progressCallback := func(eventType, message string, data interface{}) {
			if eventType == "iteration" {
				if m, ok := data.(map[string]interface{}); ok {
					if scope, _ := m["einoScope"].(string); scope == "main" {
						raw := 0
						switch v := m["iteration"].(type) {
						case int:
							raw = v
						case int32:
							raw = int(v)
						case int64:
							raw = int(v)
						case float64:
							raw = int(v)
						case float32:
							raw = int(v)
						}
						if raw > 0 {
							if raw > segmentMainIterationMax {
								segmentMainIterationMax = raw
							}
							m["iteration"] = raw + mainIterationOffset
						}
					}
				}
			}
			rawProgressCallback(eventType, message, data)
		}
		taskCtxLoop := mcp.WithMCPConversationID(taskCtx, conversationID)
		taskCtxLoop = mcp.WithToolRunRegistry(taskCtxLoop, h.tasks)
		taskCtxLoop = mcp.WithEinoExecuteRunRegistry(taskCtxLoop, h.tasks)
		taskCtxLoop = multiagent.WithHITLToolInterceptor(taskCtxLoop, func(ctx context.Context, toolName, arguments string) (string, error) {
			return h.interceptHITLForEinoTool(ctx, cancelWithCause, conversationID, assistantMessageID, sendEvent, toolName, arguments)
		})

		result, runErr = multiagent.RunEinoSingleChatModelAgent(
			taskCtxLoop,
			h.config,
			&h.config.MultiAgent,
			h.agent,
			h.db,
			h.logger,
			conversationID,
			h.conversationProjectID(conversationID),
			curFinalMessage,
			curHistory,
			roleTools,
			progressCallback,
			chatReasoningToClientIntent(req.Reasoning),
			h.agentSessionContextBlock(conversationID),
		)

		if result != nil && len(result.MCPExecutionIDs) > 0 {
			cumulativeMCPExecutionIDs = mergeMCPExecutionIDLists(cumulativeMCPExecutionIDs, result.MCPExecutionIDs)
		}

		if runErr == nil {
			mw := &h.config.MultiAgent.EinoMiddleware
			if h.tryContinueOnEinoEmptyResponse(taskCtx, mw, conversationID, result, &emptyResponseContinueAttempt, &curHistory, &curFinalMessage, progressCallback) {
				mainIterationOffset += segmentMainIterationMax
				timeoutCancel()
				baseCtx, cancelWithCause, taskCtx, timeoutCancel = h.rebindEinoSingleRunningTask(conversationID, timeoutCancel, runDeadline)
				continue
			}
			timeoutCancel()
			break
		}

		cause := context.Cause(baseCtx)
		if errors.Is(cause, multiagent.ErrInterruptContinue) {
			if shouldPersistEinoAgentTraceAfterRunError(baseCtx) {
				h.persistEinoAgentTraceForResume(conversationID, result)
			}
			note := h.tasks.TakeInterruptContinueNote(conversationID)
			icSummary := interruptContinueTimelineSummary(note)
			progressCallback("user_interrupt_continue", icSummary, map[string]interface{}{
				"conversationId": conversationID,
				"rawReason":      strings.TrimSpace(note),
				"emptyReason":    strings.TrimSpace(note) == "",
				"kind":           "no_active_mcp_tool",
			})
			inject := formatInterruptContinueUserMessage(note)
			// 不写入 messages 表为 user 气泡：避免主对话流出现大段模板；说明已由 user_interrupt_continue 记入助手 process_details（迭代详情）。
			if hist, err := h.loadHistoryFromAgentTrace(conversationID); err == nil && len(hist) > 0 {
				curHistory = hist
			}
			curFinalMessage = inject
			sendEvent("progress", "已合并用户补充与最新轨迹，正在继续推理…", map[string]interface{}{
				"conversationId": conversationID,
				"source":         "interrupt_continue",
			})
			mainIterationOffset += segmentMainIterationMax
			timeoutCancel()
			baseCtx, cancelWithCause, taskCtx, timeoutCancel = h.rebindEinoSingleRunningTask(conversationID, timeoutCancel, runDeadline)
			continue
		}

		if shouldPersistEinoAgentTraceAfterRunError(baseCtx) {
			h.persistEinoAgentTraceForResume(conversationID, result)
		}
		if errors.Is(cause, ErrTaskCancelled) {
			managedTask.SetStatus("cancelled")
			cancelMsg := "任务已被用户取消，后续操作已停止。"
			if assistantMessageID != "" {
				if result != nil {
					if err := h.mergeAssistantMessagePartialOnCancel(assistantMessageID, result.Response); err != nil {
						h.logger.Warn("合并取消前的部分回复失败", zap.Error(err))
					}
				}
				if err := h.appendAssistantMessageNotice(assistantMessageID, cancelMsg); err != nil {
					h.logger.Warn("更新取消后的助手消息失败", zap.Error(err))
				}
				_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "cancelled", cancelMsg, nil)
			}
			sendEvent("cancelled", cancelMsg, map[string]interface{}{
				"conversationId": conversationID,
				"messageId":      assistantMessageID,
			})
			sendEvent("done", "", map[string]interface{}{"conversationId": conversationID})
			timeoutCancel()
			return
		}

		if errors.Is(runErr, context.DeadlineExceeded) || errors.Is(context.Cause(taskCtx), context.DeadlineExceeded) {
			managedTask.SetStatus("timeout")
			timeoutMsg := "任务执行超时，已自动终止。"
			if assistantMessageID != "" {
				_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", timeoutMsg, time.Now(), assistantMessageID)
				_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "timeout", timeoutMsg, nil)
			}
			sendEvent("error", timeoutMsg, map[string]interface{}{
				"conversationId": conversationID,
				"messageId":      assistantMessageID,
				"errorType":      "timeout",
			})
			sendEvent("done", "", map[string]interface{}{"conversationId": conversationID})
			timeoutCancel()
			return
		}

		h.logger.Error("Eino ADK 单代理执行失败", zap.Error(runErr))
		managedTask.SetStatus("failed")
		errMsg := "执行失败: " + runErr.Error()
		if assistantMessageID != "" {
			_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", errMsg, time.Now(), assistantMessageID)
			_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "error", errMsg, nil)
		}
		sendEvent("error", errMsg, map[string]interface{}{
			"conversationId": conversationID,
			"messageId":      assistantMessageID,
		})
		sendEvent("done", "", map[string]interface{}{"conversationId": conversationID})
		timeoutCancel()
		return
	}

	timeoutCancel()

	if err := persistAssistantFinal(h.db.UpdateAssistantMessageFinalize, assistantMessageID, result.Response, cumulativeMCPExecutionIDs, multiagent.AggregatedReasoningFromTraceJSON(result.LastAgentTraceInput)); err != nil {
		h.logger.Error("更新最终助手消息失败", zap.Error(err))
		managedTask.SetStatus("failed")
		sendEvent("error", "保存最终回复失败", map[string]interface{}{
			"conversationId": conversationID,
			"messageId":      assistantMessageID,
		})
		sendEvent("done", "", map[string]interface{}{"conversationId": conversationID})
		return
	}

	if result.LastAgentTraceInput != "" || result.LastAgentTraceOutput != "" {
		if err := h.db.SaveAgentTrace(conversationID, result.LastAgentTraceInput, result.LastAgentTraceOutput); err != nil {
			h.logger.Warn("保存代理轨迹失败", zap.Error(err))
		}
	}

	sendEvent("response", result.Response, map[string]interface{}{
		"mcpExecutionIds": cumulativeMCPExecutionIDs,
		"conversationId":  conversationID,
		"messageId":       assistantMessageID,
		"agentMode":       "eino_single",
	})
	sendEvent("done", "", map[string]interface{}{"conversationId": conversationID})
}

func newEinoSingleSegmentContexts(deadline time.Time) (context.Context, context.CancelCauseFunc, context.Context, context.CancelFunc) {
	baseCtx, cancelWithCause := context.WithCancelCause(context.Background())
	taskCtx, timeoutCancel := context.WithDeadline(baseCtx, deadline)
	return baseCtx, cancelWithCause, taskCtx, timeoutCancel
}

func (h *AgentHandler) rebindEinoSingleRunningTask(conversationID string, timeoutCancel context.CancelFunc, deadline time.Time) (context.Context, context.CancelCauseFunc, context.Context, context.CancelFunc) {
	if timeoutCancel != nil {
		timeoutCancel()
	}
	baseCtx, cancelWithCause, taskCtx, newTimeoutCancel := newEinoSingleSegmentContexts(deadline)
	h.tasks.BindTaskCancel(conversationID, cancelWithCause)
	h.tasks.UpdateTaskStatus(conversationID, "running")
	return baseCtx, cancelWithCause, taskCtx, newTimeoutCancel
}

// EinoSingleAgentLoop Eino ADK 单代理非流式对话。
func (h *AgentHandler) EinoSingleAgentLoop(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.config == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器配置未加载"})
		return
	}

	h.logger.Info("收到 Eino ADK 单代理非流式请求", zap.String("conversationId", req.ConversationID))

	prep, err := h.prepareMultiAgentSession(&req, c, "eino_agent")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.activateHITLForConversation(prep.ConversationID, req.Hitl)
	if h.hitlManager != nil {
		defer h.hitlManager.DeactivateConversation(prep.ConversationID)
	}

	var progressBuf strings.Builder
	progressCallbackRaw := func(eventType, message string, data interface{}) {
		progressBuf.WriteString(eventType)
		progressBuf.WriteByte('\n')
	}
	baseCtx, cancelWithCause := context.WithCancelCause(c.Request.Context())
	defer cancelWithCause(nil)
	managedTask, err := beginManagedAgentTask(h.tasks, prep.ConversationID, req.Message, cancelWithCause)
	if err != nil {
		status := http.StatusInternalServerError
		errorMsg := "无法启动任务: " + err.Error()
		if errors.Is(err, ErrTaskAlreadyRunning) {
			status = http.StatusConflict
			errorMsg = "当前会话已有任务正在执行中"
		}
		if prep.AssistantMessageID != "" {
			_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", errorMsg, time.Now(), prep.AssistantMessageID)
		}
		c.JSON(status, gin.H{"error": errorMsg})
		return
	}
	defer managedTask.Finish()
	taskCtx, timeoutCancel := context.WithTimeout(baseCtx, einoExecutionTimeout(h.config, "eino_single"))
	defer timeoutCancel()
	progressCallback := h.createProgressCallback(taskCtx, cancelWithCause, prep.ConversationID, prep.AssistantMessageID, progressCallbackRaw)
	taskCtx = multiagent.WithHITLToolInterceptor(taskCtx, func(ctx context.Context, toolName, arguments string) (string, error) {
		return h.interceptHITLForEinoTool(ctx, cancelWithCause, prep.ConversationID, prep.AssistantMessageID, nil, toolName, arguments)
	})

	curHist := prep.History
	curMsg := prep.FinalMessage
	var result *multiagent.RunResult
	var runErr error
	for {
		result, runErr = multiagent.RunEinoSingleChatModelAgent(
			taskCtx,
			h.config,
			&h.config.MultiAgent,
			h.agent,
			h.db,
			h.logger,
			prep.ConversationID,
			h.conversationProjectID(prep.ConversationID),
			curMsg,
			curHist,
			prep.RoleTools,
			progressCallback,
			chatReasoningToClientIntent(req.Reasoning),
			h.agentSessionContextBlock(prep.ConversationID),
		)
		if runErr == nil {
			break
		}
		if shouldPersistEinoAgentTraceAfterRunError(baseCtx) {
			h.persistEinoAgentTraceForResume(prep.ConversationID, result)
		}
		managedTask.SetStatus(agentTaskTerminalStatus(taskCtx, runErr))
		errMsg := "执行失败: " + runErr.Error()
		if prep.AssistantMessageID != "" {
			_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", errMsg, time.Now(), prep.AssistantMessageID)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMsg})
		return
	}

	if err := persistAssistantFinal(h.db.UpdateAssistantMessageFinalize, prep.AssistantMessageID, result.Response, result.MCPExecutionIDs, multiagent.AggregatedReasoningFromTraceJSON(result.LastAgentTraceInput)); err != nil {
		h.logger.Error("更新最终助手消息失败", zap.Error(err))
		managedTask.SetStatus("failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存最终回复失败"})
		return
	}
	if result.LastAgentTraceInput != "" || result.LastAgentTraceOutput != "" {
		if err := h.db.SaveAgentTrace(prep.ConversationID, result.LastAgentTraceInput, result.LastAgentTraceOutput); err != nil {
			h.logger.Warn("保存代理轨迹失败", zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"response":           result.Response,
		"conversationId":     prep.ConversationID,
		"mcpExecutionIds":    result.MCPExecutionIDs,
		"assistantMessageId": prep.AssistantMessageID,
		"agentMode":          "eino_single",
	})
}
