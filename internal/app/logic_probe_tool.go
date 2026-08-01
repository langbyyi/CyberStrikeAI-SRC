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

// LogicProbeToolNames registered by registerLogicProbeTools (startup + hot reload).
var LogicProbeToolNames = []string{
	builtin.ToolLogicProbeDiff,
}

// registerLogicProbeTools registers logic_probe_diff for payment/workflow/race (and optional dual-auth).
func registerLogicProbeTools(mcpServer *mcp.Server, logger *zap.Logger) {
	if mcpServer == nil {
		return
	}
	tool := mcp.Tool{
		Name:             builtin.ToolLogicProbeDiff,
		Description:      multiagent.LogicProbeToolDescription,
		ShortDescription: "业务/后端缺陷探针（支付篡改/跳步/竞态；双号可选）",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"method": map[string]interface{}{
					"type":        "string",
					"description": "HTTP 方法，默认 GET",
				},
				"url": map[string]interface{}{
					"type":        "string",
					"description": "目标 URL（必填）",
				},
				"headers": map[string]interface{}{
					"type":        "object",
					"description": "共享请求头（不含身份覆盖）",
				},
				"body": map[string]interface{}{
					"type":        "string",
					"description": "请求体（JSON 或 form）；支付场景建议含 amount/price",
				},
				"auth_a": map[string]interface{}{
					"type":        "string",
					"description": "可选单身份 Cookie/Authorization（支付/篡改/竞态足够）",
				},
				"auth_b": map[string]interface{}{
					"type":        "string",
					"description": "可选第二账号，仅 identity_diff 需要；非必填",
				},
				"auth_header": map[string]interface{}{
					"type":        "string",
					"description": "身份头名，默认自动（Cookie 或 Authorization）",
				},
				"mode": map[string]interface{}{
					"type":        "string",
					"description": "推荐 param_tamper（默认）→ step_skip → parallel → identity_diff（可选）",
					"enum":        []string{"param_tamper", "step_skip", "parallel", "identity_diff"},
				},
				"mutations": map[string]interface{}{
					"type":        "object",
					"description": "param_tamper/step_skip：字段→值数组；空则用支付默认 price/amount/total_fee/quantity",
				},
				"parallel_n": map[string]interface{}{
					"type":        "integer",
					"description": "parallel 模式并发数，上限 10",
				},
			},
			"required": []string{"url"},
		},
	}
	mcpServer.RegisterTool(tool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		convID := strings.TrimSpace(conversationIDFromToolCtx(ctx))
		if convID == "" {
			return textResult("错误: conversation_id 未设置。逻辑探针需要会话上下文，请重试。", true), nil
		}
		url := strings.TrimSpace(strArg(args, "url"))
		if url == "" {
			return textResult("错误: url 必填", true), nil
		}
		mode := multiagent.NormalizeLogicProbeMode(strArg(args, "mode"))
		req := multiagent.LogicProbeRequest{
			Method:     strArg(args, "method"),
			URL:        url,
			Body:       strArg(args, "body"),
			AuthA:      strArg(args, "auth_a"),
			AuthB:      strArg(args, "auth_b"),
			AuthHeader: strArg(args, "auth_header"),
			Mode:       mode,
			ParallelN:  intArg(args, "parallel_n", 0),
			Timeout:    15 * time.Second,
		}
		if h := args["headers"]; h != nil {
			req.Headers = stringMapArg(h)
		}
		if m := args["mutations"]; m != nil {
			req.Mutations = mutationsArg(m)
		}
		if errMsg := multiagent.ValidateLogicProbeRequest(req); errMsg != "" {
			return textResult(errMsg, true), nil
		}
		result := multiagent.RunLogicProbeDiff(ctx, req)
		if result.Error != "" {
			return textResult(result.Error, true), nil
		}
		// Auto open idor_horizontal when identity_diff used with dual auth
		if mode == multiagent.LogicProbeModeIdentityDiff {
			item := multiagent.CoverageItem{
				Path:     multiagent.CoveragePathFromLogic(url, multiagent.LogicClassIDORHoriz, ""),
				Status:   "in_progress",
				Priority: multiagent.EstimateLogicCoveragePriority(multiagent.LogicClassIDORHoriz),
				Note:     "logic_probe_diff identity_diff",
			}
			if result.SuggestedInvariantBreak != "" && strings.Contains(result.SuggestedInvariantBreak, "divergence") {
				item.Status = "open"
				item.Note = result.SuggestedInvariantBreak
			}
			multiagent.GetConversationExecutionState(convID).UpsertCoverage(item)
		}
		if mode == multiagent.LogicProbeModeParamTamper || mode == multiagent.LogicProbeModeStepSkip {
			cls := multiagent.LogicClassParamTamper
			if mode == multiagent.LogicProbeModeStepSkip {
				cls = multiagent.LogicClassWorkflowSkip
			}
			multiagent.GetConversationExecutionState(convID).UpsertCoverage(multiagent.CoverageItem{
				Path:     multiagent.CoveragePathFromLogic(url, cls, ""),
				Status:   "in_progress",
				Priority: multiagent.EstimateLogicCoveragePriority(cls),
				Note:     "logic_probe_diff " + mode,
			})
		}
		if mode == multiagent.LogicProbeModeParallel {
			multiagent.GetConversationExecutionState(convID).UpsertCoverage(multiagent.CoverageItem{
				Path:     multiagent.CoveragePathFromLogic(url, multiagent.LogicClassRace, ""),
				Status:   "in_progress",
				Priority: multiagent.EstimateLogicCoveragePriority(multiagent.LogicClassRace),
				Note:     "logic_probe_diff parallel",
			})
		}
		if logger != nil {
			logger.Info("logic_probe_diff",
				zap.String("conversation_id", convID),
				zap.String("mode", mode),
				zap.String("url", url),
				zap.Bool("dual_auth", result.DualAuthRecorded),
			)
		}
		text := multiagent.FormatLogicProbeResult(result)
		return textResult(text, false), nil
	})
	if logger != nil {
		logger.Info("logic probe MCP 工具注册成功", zap.Strings("tools", LogicProbeToolNames))
	}
}

func stringMapArg(v interface{}) map[string]string {
	out := map[string]string{}
	switch m := v.(type) {
	case map[string]string:
		return m
	case map[string]interface{}:
		for k, val := range m {
			out[k] = fmt.Sprint(val)
		}
	}
	return out
}

func mutationsArg(v interface{}) map[string][]string {
	out := map[string][]string{}
	m, ok := v.(map[string]interface{})
	if !ok {
		if ms, ok2 := v.(map[string][]string); ok2 {
			return ms
		}
		return out
	}
	for k, val := range m {
		switch arr := val.(type) {
		case []interface{}:
			var ss []string
			for _, x := range arr {
				ss = append(ss, fmt.Sprint(x))
			}
			out[k] = ss
		case []string:
			out[k] = arr
		default:
			out[k] = []string{fmt.Sprint(val)}
		}
	}
	return out
}
