package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

// ExecutionCoverageToolNames is the set registered by registerExecutionCoverageTools
// (startup + ApplyConfig re-register after ClearTools).
var ExecutionCoverageToolNames = []string{
	builtin.ToolUpsertExecutionCoverage,
	builtin.ToolGetExecutionCoverage,
	builtin.ToolShouldContinueExecution,
}

// registerExecutionCoverageTools 注册会话级 coverage / should_continue 门闩工具。
// 必须在 New 启动路径与 ApplyConfig vulnerabilityRegistrar 中同时调用，否则 ClearTools 后门闩会消失。
func registerExecutionCoverageTools(mcpServer *mcp.Server, logger *zap.Logger) {
	registerUpsertExecutionCoverageTool(mcpServer, logger)
	registerGetExecutionCoverageTool(mcpServer, logger)
	registerShouldContinueExecutionTool(mcpServer, logger)
	if logger != nil {
		logger.Info("execution coverage MCP 工具注册成功", zap.Strings("tools", ExecutionCoverageToolNames))
	}
}

func registerUpsertExecutionCoverageTool(mcpServer *mcp.Server, logger *zap.Logger) {
	tool := mcp.Tool{
		Name: builtin.ToolUpsertExecutionCoverage,
		Description: "仅在用 exec/curl/nuclei/sqlmap/http-framework-test/logic_probe_diff 等工具完成真实漏洞验证后，" +
			"写入/更新本会话执行覆盖项（path/status/priority）。" +
			"path 如 auth.login、sqli.param:id、recon.ports；priority 为 P0/P1/P2；status 为 open|in_progress|done|blocked。" +
			"P0/P1 未闭环时 should_continue_execution 会阻止过早收工。" +
			"禁止：不做测试直接 upsert、把 upsert 当状态管理工具空转。",
		ShortDescription: "更新执行 coverage",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "覆盖路径键，如 auth.login / sqli.param:id",
				},
				"status": map[string]interface{}{
					"type":        "string",
					"description": "open | in_progress | done | blocked",
					"enum":        []string{"open", "in_progress", "done", "blocked"},
				},
				"priority": map[string]interface{}{
					"type":        "string",
					"description": "P0 | P1 | P2",
					"enum":        []string{"P0", "P1", "P2"},
				},
				"note": map[string]interface{}{
					"type":        "string",
					"description": "备注（差分、死路原因等）",
				},
			},
			"required": []string{"path"},
		},
	}
	mcpServer.RegisterTool(tool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		convID := strings.TrimSpace(conversationIDFromToolCtx(ctx))
		if convID == "" {
			// Do not fall through to shared "default" session state.
			return textResult("错误: conversation_id 未设置。这是系统错误，请重试。", true), nil
		}
		path := strings.TrimSpace(strArg(args, "path"))
		if path == "" {
			return textResult("错误: path 必填", true), nil
		}
		status := strings.TrimSpace(strArg(args, "status"))
		if status == "" {
			status = "open"
		}
		priority := strings.TrimSpace(strArg(args, "priority"))
		if priority == "" {
			priority = "P1"
		}
		note := strings.TrimSpace(strArg(args, "note"))
		state := multiagent.GetConversationExecutionState(convID)
		// Reject redundant upsert on terminal items: if the path is already done/blocked
		// and the new status is also done/blocked, refuse and redirect to should_continue.
		existing := state.ListCoverage()
		for _, e := range existing {
			if e.Path == path {
				oldTerminal := e.Status == "blocked" || e.Status == "done"
				newTerminal := status == "blocked" || status == "done"
				if oldTerminal && newTerminal {
					cont, reason, open := state.ShouldContinue()
					errMsg := fmt.Sprintf(
						"[框架拦截] path=%s 已是终态(%s)，重复 upsert 无意义。\n"+
							"should_continue=%v reason=%s open_p0_p1=%d\n"+
							"你必须立即调用：should_continue_execution(intent=\"finalize\")",
						path, e.Status, cont, reason, len(open))
					return textResult(errMsg, true), nil
				}
				break
			}
		}
		// Record the tool evidence first; this updates the sliding-window upsert
		// count. The breaker is checked BEFORE writing coverage so rejected calls
		// do not pollute state. Terminal upserts (done/blocked) are real closure
		// and do not count toward the breaker.
		isTerminal := status == "done" || status == "blocked"
		state.RecordTool(multiagent.ToolEvidenceEntry{
			ToolName:    "upsert_execution_coverage",
			StatusHint:  "ok",
			SkipBreaker: isTerminal,
		})
		count := state.RecentUpsertCount()
		if count >= multiagent.MaxRecentUpsertsBeforeWarn {
			cont, reason, open := state.ShouldContinue()
			errMsg := fmt.Sprintf(
				"[框架硬断路器] 最近 %d 次工具调用中有 %d 次 upsert_execution_coverage，已拒绝执行。\n"+
					"should_continue=%v reason=%s open_p0_p1=%d\n"+
					"**本次调用被拦截，coverage 未写入。禁止继续 upsert。**\n"+
					"你必须立即调用：should_continue_execution(intent=\"finalize\")\n"+
					"注意：intent 参数必须为 finalize，不可省略。",
				multiagent.UpsertBreakerWindow, count, cont, reason, len(open))
			if logger != nil {
				logger.Warn("upsert_circuit_breaker",
					zap.String("conversation_id", convID),
					zap.Int("recent_upsert_count", count),
					zap.Bool("should_continue", cont),
					zap.Int("open_p0_p1", len(open)),
				)
			}
			return textResult(errMsg, true), nil
		}
		state.UpsertCoverage(multiagent.CoverageItem{
			Path:      path,
			Status:    status,
			Priority:  priority,
			Note:      note,
			UpdatedAt: time.Now(),
		})
		if logger != nil {
			logger.Info("execution coverage upsert",
				zap.String("conversation_id", convID),
				zap.String("path", path),
				zap.String("status", status),
				zap.String("priority", priority),
			)
		}
		resp := fmt.Sprintf("coverage 已更新: path=%s status=%s priority=%s", path, status, priority)
		return textResult(resp, false), nil
	})
}

func registerGetExecutionCoverageTool(mcpServer *mcp.Server, logger *zap.Logger) {
	tool := mcp.Tool{
		Name:             builtin.ToolGetExecutionCoverage,
		Description:      "列出本会话全部执行 coverage 项及 P0/P1 未闭环摘要。",
		ShortDescription: "读取执行 coverage",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	}
	mcpServer.RegisterTool(tool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		convID := strings.TrimSpace(conversationIDFromToolCtx(ctx))
		if convID == "" {
			return textResult("错误: conversation_id 未设置。这是系统错误，请重试。", true), nil
		}
		state := multiagent.GetConversationExecutionState(convID)
		state.RecordTool(multiagent.ToolEvidenceEntry{
			ToolName:   "get_execution_coverage",
			StatusHint: "ok",
		})
		items := state.ListCoverage()
		var b strings.Builder
		b.WriteString(fmt.Sprintf("conversation=%s coverage_count=%d\n", convID, len(items)))
		if len(items) == 0 {
			b.WriteString("（暂无 coverage，建议在关键探测路径上 upsert_execution_coverage）\n")
			return textResult(b.String(), false), nil
		}
		for _, it := range items {
			b.WriteString(fmt.Sprintf("- path=%s status=%s priority=%s note=%s\n",
				it.Path, it.Status, it.Priority, truncateRunes(it.Note, 120)))
		}
		cont, reason, open := multiagent.GetConversationExecutionState(convID).ShouldContinue()
		b.WriteString(fmt.Sprintf("\nshould_continue=%v reason=%s open_p0_p1=%d\n", cont, reason, len(open)))
		return textResult(b.String(), false), nil
	})
}

func registerShouldContinueExecutionTool(mcpServer *mcp.Server, logger *zap.Logger) {
	tool := mcp.Tool{
		Name: builtin.ToolShouldContinueExecution,
		Description: "判断本会话是否应继续执行（P0/P1 coverage 未闭环则 should_continue=true）。" +
			"收工/finalize 前应调用；若返回 continue，必须用安全测试工具（exec/curl/nuclei 等）做真实验证，禁止仅做 upsert 管理。",
		ShortDescription: "是否应继续执行（门闩）",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"intent": map[string]interface{}{
					"type":        "string",
					"description": "可选：continue | finalize，仅影响文案提示",
				},
			},
		},
	}
	mcpServer.RegisterTool(tool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		convID := strings.TrimSpace(conversationIDFromToolCtx(ctx))
		if convID == "" {
			return textResult("错误: conversation_id 未设置。这是系统错误，请重试。", true), nil
		}
		intent := strings.ToLower(strings.TrimSpace(strArg(args, "intent")))
		state := multiagent.GetConversationExecutionState(convID)
		state.RecordTool(multiagent.ToolEvidenceEntry{
			ToolName:   "should_continue_execution",
			StatusHint: "ok",
		})
		cont, reason, open := state.ShouldContinue()
		// Finalize loop detection: if intent=finalize and cont has been true
		// for MaxFinalizeAttemptsBeforeForceStop consecutive calls, force cont=false.
		overriddenCont, attemptCount := state.CheckAndRecordFinalizeAttempt(intent, cont)
		if overriddenCont != cont && !overriddenCont {
			reason = fmt.Sprintf("finalize 已连续询问 %d 次仍返回继续，框架强制放行", attemptCount)
			open = nil
		}
		if logger != nil {
			logger.Info("should_continue_execution",
				zap.String("conversation_id", convID),
				zap.Bool("continue", overriddenCont),
				zap.String("reason", reason),
				zap.Int("open_count", len(open)),
				zap.String("intent", intent),
				zap.Int("finalize_attempts", attemptCount),
			)
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("should_continue=%v\nreason=%s\n", overriddenCont, reason))
		if len(open) > 0 {
			b.WriteString("open_p0_p1:\n")
			for _, it := range open {
				b.WriteString(fmt.Sprintf("- %s [%s] %s\n", it.Path, it.Priority, it.Status))
			}
			if intent == "finalize" {
				b.WriteString("\n【框架门闩】intent=finalize 但 P0/P1 未闭环：请继续验证或将项标记 done/blocked 并说明原因，禁止空结论收工。\n")
			}
		}
		if !overriddenCont && attemptCount >= multiagent.MaxFinalizeAttemptsBeforeForceStop {
			b.WriteString(fmt.Sprintf("\n【框架强制放行】finalize 已连续 %d 次返回继续，框架判定无法闭环，允许结束会话。\n", attemptCount))
		}
		return textResult(b.String(), false), nil
	})
}
