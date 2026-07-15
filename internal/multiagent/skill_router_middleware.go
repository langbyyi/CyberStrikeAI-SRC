package multiagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/einomcp"

	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// executionToolMiddlewareConfig wires skill router + evidence capture on tool results.
type executionToolMiddlewareConfig struct {
	MW                 *config.MultiAgentEinoMiddlewareConfig
	SkillsRoot         string
	ConversationID     string
	Logger             *zap.Logger
	DecisionController bool
	Progress           func(string, string, interface{})
}

// buildExecutionToolMiddlewares returns HITL + soft recovery + governance + optional execution-boost post-process.
// 中间件洋葱顺序（外→内）：hitl → softRecovery → [并发上限 → per-call 超时] → executionBoost → 实际工具。
func buildExecutionToolMiddlewares(cfg executionToolMiddlewareConfig) []compose.ToolMiddleware {
	mws := []compose.ToolMiddleware{
		hitlToolCallMiddleware(),
		softRecoveryToolMiddleware(),
	}
	if gov := toolExecGovernorMiddlewares(cfg); len(gov) > 0 {
		mws = append(mws, gov...)
	}
	if cfg.MW != nil && cfg.MW.ExecutionBoostEffective() {
		mws = append(mws, executionBoostToolMiddleware(cfg))
	}
	return mws
}

// executionBoostToolMiddleware records evidence, auto-upserts coverage, and injects skill tips.
func executionBoostToolMiddleware(cfg executionToolMiddlewareConfig) compose.ToolMiddleware {
	return compose.ToolMiddleware{
		Invokable:  executionBoostInvokable(cfg),
		Streamable: executionBoostStreamable(cfg),
	}
}

func executionBoostInvokable(cfg executionToolMiddlewareConfig) compose.InvokableToolMiddleware {
	return func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
			toolName, args, callID := "", "", ""
			if input != nil {
				toolName = input.Name
				args = input.Arguments
				callID = input.CallID
			}
			// PRE-invoke: do not call the real tool if it was hard-failed this session.
			if msg := deadToolPrecheck(cfg, toolName); msg != "" {
				return &compose.ToolOutput{Result: msg}, nil
			}
			if cfg.DecisionController {
				if msg := executionDecisionPrecheck(cfg.ConversationID, toolName, callID, args); msg != "" {
					if cfg.Progress != nil {
						cfg.Progress("tool_call_blocked", "执行控制器阻断工具调用", map[string]interface{}{
							"tool": toolName, "callId": callID,
						})
					}
					return &compose.ToolOutput{Result: msg}, nil
				}
				ctx = WithExecutionToolCallID(ctx, callID)
			}
			output, err := next(ctx, input)
			if output == nil {
				return output, err
			}
			result := output.Result
			result = applyExecutionBoostPostProcess(cfg, toolName, callID, args, result)
			output.Result = result
			return output, err
		}
	}
}

func executionBoostStreamable(cfg executionToolMiddlewareConfig) compose.StreamableToolMiddleware {
	return func(next compose.StreamableToolEndpoint) compose.StreamableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.StreamToolOutput, error) {
			toolName, args, callID := "", "", ""
			if input != nil {
				toolName = input.Name
				args = input.Arguments
				callID = input.CallID
			}
			if msg := deadToolPrecheck(cfg, toolName); msg != "" {
				return &compose.StreamToolOutput{
					Result: schema.StreamReaderFromArray([]string{msg}),
				}, nil
			}
			if cfg.DecisionController {
				if msg := executionDecisionPrecheck(cfg.ConversationID, toolName, callID, args); msg != "" {
					if cfg.Progress != nil {
						cfg.Progress("tool_call_blocked", "执行控制器阻断工具调用", map[string]interface{}{
							"tool": toolName, "callId": callID,
						})
					}
					return &compose.StreamToolOutput{Result: schema.StreamReaderFromArray([]string{msg})}, nil
				}
				ctx = WithExecutionToolCallID(ctx, callID)
			}
			out, err := next(ctx, input)
			if err != nil || out == nil || out.Result == nil {
				return out, err
			}
			// Collect stream then re-emit with post-process (best-effort for non-huge outputs).
			var chunks []string
			for {
				chunk, rerr := out.Result.Recv()
				if rerr != nil {
					break
				}
				chunks = append(chunks, chunk)
			}
			out.Result.Close()
			combined := strings.Join(chunks, "")
			combined = applyExecutionBoostPostProcess(cfg, toolName, callID, args, combined)
			return &compose.StreamToolOutput{
				Result: schema.StreamReaderFromArray([]string{combined}),
			}, err
		}
	}
}

// deadToolPrecheck returns a framework message if the tool must not run again this session.
func deadToolPrecheck(cfg executionToolMiddlewareConfig, toolName string) string {
	if cfg.MW == nil || !cfg.MW.ExecutionBoostEffective() {
		return ""
	}
	state := GetConversationExecutionState(cfg.ConversationID)
	dead, reason := state.IsToolDead(toolName)
	if !dead {
		return ""
	}
	return fmt.Sprintf(
		"[framework_tool_dead] 工具 %s 本会话已判定不可用（%s），已跳过真实执行。\n请改用当前角色已加载的其他工具完成等价目标。\n",
		toolName, reason)
}

// applyExecutionBoostPostProcess order (stable, tested):
//  1. structured summary prepend (scanners only)
//  2. original tool body
//  3. skill router block appended last
//
// Never: skill block before summary.
func applyExecutionBoostPostProcess(cfg executionToolMiddlewareConfig, toolName, callID, args, result string) string {
	mw := cfg.MW
	if mw == nil || !mw.ExecutionBoostEffective() {
		return result
	}
	state := GetConversationExecutionState(cfg.ConversationID)
	obligationsBefore := state.Controller().Summary().ObligationsCreated
	if normalizedExecutionToolName(toolName) == "skill" {
		recordManualSkillLoad(cfg.ConversationID, args, result)
	}
	if cfg.DecisionController {
		class := classifyExecutionTool(toolName)
		if class != executionToolDecision && class != executionToolStateMutation {
			code, _ := classifyToolError(result)
			if code == "" {
				code = "ok"
			}
			state.Controller().RecordProbeResult(callID, CallSignature(toolName, args), ResultFingerprint(toolName, result), code)
		}
	}
	// Note: invoke-time dead-tool block is in deadToolPrecheck (PRE next).
	// Here we only mark new hard failures after a real execution.

	entry := SummarizeToolResult(toolName, args, result)
	state.RecordTool(entry)

	// Mark hard failures (templates_missing / executable not found / config_error).
	if code, _ := classifyToolError(result); code == "templates_missing" || code == "config_error" {
		state.MarkToolDead(toolName, code)
	}
	lowRes := strings.ToLower(result)
	if strings.Contains(lowRes, "executable file not found") || strings.Contains(lowRes, "not found in $path") ||
		strings.Contains(lowRes, "exec: \"") && strings.Contains(lowRes, "executable file not found") {
		state.MarkToolDead(toolName, "executable_not_found")
	}

	body := result
	summaryBlock := ""
	// Structured summary prepend for scanners (budget-configurable).
	maxRunes := DefaultStructuredSummaryMaxRunes
	if n := mw.StructuredSummaryMaxRunesEffective(); n > 0 {
		maxRunes = n
	}
	if prepended, ok := PrependStructuredToolSummary(toolName, args, body, maxRunes); ok {
		// Prepend returns summary+body; split at marker so skill can append after body.
		if idx := strings.Index(prepended, "---\n"); idx >= 0 {
			summaryBlock = prepended[:idx+4]
		} else {
			body = prepended
		}
		if cfg.Logger != nil {
			cfg.Logger.Info("tool_structured_summary",
				zap.String("tool", toolName),
				zap.String("conversation_id", cfg.ConversationID),
				zap.Int("result_len", len(prepended)),
			)
		}
	}

	// Auto coverage upsert for key tools (use original body signals).
	if path := AutoCoveragePathFromTool(toolName, result); path != "" {
		pr := "P2"
		low := strings.ToLower(toolName + " " + result)
		if strings.Contains(low, "sql") || strings.Contains(low, "rce") || strings.Contains(low, "auth") {
			pr = "P1"
		}
		st := "in_progress"
		if entry.StatusHint == "interesting" || HasHighValueSurfaceSignal(result) {
			st = "open"
			pr = "P0"
		}
		state.UpsertCoverage(CoverageItem{Path: path, Status: st, Priority: pr, Note: entry.Summary})
	}
	// Attack-surface inventory (API/schema list, endpoints, stack) → open surface.* coverage.
	if surfaceItems := AutoUpsertSurfaceCoverageFromTool(cfg.ConversationID, toolName, args, result); len(surfaceItems) > 0 {
		entry.StatusHint = MarkInterestingIfSurface(entry.StatusHint, result)
		if cfg.Logger != nil {
			paths := make([]string, 0, len(surfaceItems))
			for _, it := range surfaceItems {
				paths = append(paths, it.Path)
			}
			cfg.Logger.Info("coverage_auto_from_surface",
				zap.String("tool", toolName),
				zap.String("conversation_id", cfg.ConversationID),
				zap.Strings("paths", paths),
			)
		}
	}
	if cfg.DecisionController && cfg.Progress != nil {
		after := state.Controller().Summary().ObligationsCreated
		if after > obligationsBefore {
			cfg.Progress("execution_obligation_created", "强证据已创建记录义务", map[string]interface{}{
				"created": after - obligationsBefore, "tool": toolName, "callId": callID,
			})
		}
		if isRecordTool(toolName) && state.Controller().PendingObligation() == nil && !strings.Contains(result, einomcp.ToolErrorPrefix) {
			cfg.Progress("execution_obligation_resolved", "L1/L2 已满足记录义务", map[string]interface{}{
				"tool": toolName, "callId": callID,
			})
		}
	}
	// Logic Track: business entry/params → open logic coverage (P0/P1) so finalize gate blocks CVE-only wrap-up.
	if logicItems := AutoUpsertLogicCoverageFromToolSignals(cfg.ConversationID, toolName, args, result); len(logicItems) > 0 {
		if cfg.Logger != nil {
			paths := make([]string, 0, len(logicItems))
			for _, it := range logicItems {
				paths = append(paths, it.Path)
			}
			cfg.Logger.Info("coverage_auto_from_logic",
				zap.String("tool", toolName),
				zap.String("conversation_id", cfg.ConversationID),
				zap.Strings("paths", paths),
			)
		}
	}

	skillBlock := ""
	if mw.SkillRouterEffective() {
		tn := strings.ToLower(strings.TrimSpace(toolName))
		if tn != "tool_search" && tn != "skill" && tn != "task" && tn != "transfer_to_agent" {
			topK, maxSkillRunes := executionSkillRouterLimits(cfg)
			routed := RouteSkills(SkillRouterInput{
				ToolName:        toolName,
				Arguments:       args,
				Output:          result,
				TopK:            topK,
				MaxRunes:        maxSkillRunes,
				SkillsRoot:      cfg.SkillsRoot,
				AlreadyInjected: state.InjectedSkillsCopy(),
			})
			if routed.Block != "" {
				skillBlock = routed.Block
				state.MarkSkillsInjected(routed.Injected)
				if cfg.Logger != nil {
					cfg.Logger.Info("skill_router injected",
						zap.String("tool", toolName),
						zap.Strings("skills", routed.Injected),
						zap.String("conversation_id", cfg.ConversationID),
					)
				}
			}
		}
	}

	// 强制深挖：interesting 状态或结果正文强信号 → 追加 depth_force_next
	// Surface inventory also upgrades hint so record/L1 is not skipped after confirmed inventory hits.
	statusForForce := MarkInterestingIfSurface(entry.StatusHint, result)
	body = AppendDepthForceNextHint(body, statusForForce)
	body = AppendDepthForceNextHintFromBody(body)

	if summaryBlock == "" && skillBlock == "" {
		return body
	}
	return ComposeToolResultWithBoostOrder(summaryBlock, body, skillBlock)
}

func executionSkillRouterLimits(cfg executionToolMiddlewareConfig) (int, int) {
	if cfg.DecisionController {
		return 1, 4000
	}
	if cfg.MW == nil {
		return 1, 4000
	}
	return cfg.MW.SkillRouterTopKEffective(), cfg.MW.SkillRouterMaxRunesEffective()
}

func recordManualSkillLoad(conversationID, arguments, result string) {
	lowResult := strings.ToLower(result)
	if strings.Contains(lowResult, "error") || strings.Contains(lowResult, "failed") || strings.Contains(lowResult, "拒绝") {
		return
	}
	var args map[string]interface{}
	if json.Unmarshal([]byte(arguments), &args) != nil {
		return
	}
	for _, key := range []string{"skill", "skill_name", "name"} {
		name := strings.TrimSpace(fmt.Sprint(args[key]))
		if name != "" && name != "<nil>" {
			GetConversationExecutionState(conversationID).MarkSkillsInjected([]string{name})
			return
		}
	}
}
