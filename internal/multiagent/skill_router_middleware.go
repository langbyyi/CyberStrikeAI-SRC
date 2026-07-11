package multiagent

import (
	"context"
	"strings"

	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// executionToolMiddlewareConfig wires skill router + evidence capture on tool results.
type executionToolMiddlewareConfig struct {
	MW             *config.MultiAgentEinoMiddlewareConfig
	SkillsRoot     string
	ConversationID string
	Logger         *zap.Logger
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
			output, err := next(ctx, input)
			if output == nil {
				return output, err
			}
			toolName, args := "", ""
			if input != nil {
				toolName = input.Name
				args = input.Arguments
			}
			result := output.Result
			result = applyExecutionBoostPostProcess(cfg, toolName, args, result)
			output.Result = result
			return output, err
		}
	}
}

func executionBoostStreamable(cfg executionToolMiddlewareConfig) compose.StreamableToolMiddleware {
	return func(next compose.StreamableToolEndpoint) compose.StreamableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.StreamToolOutput, error) {
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
			toolName, args := "", ""
			if input != nil {
				toolName = input.Name
				args = input.Arguments
			}
			combined = applyExecutionBoostPostProcess(cfg, toolName, args, combined)
			return &compose.StreamToolOutput{
				Result: schema.StreamReaderFromArray([]string{combined}),
			}, err
		}
	}
}

// applyExecutionBoostPostProcess order (stable, tested):
//  1. structured summary prepend (scanners only)
//  2. original tool body
//  3. skill router block appended last
// Never: skill block before summary.
func applyExecutionBoostPostProcess(cfg executionToolMiddlewareConfig, toolName, args, result string) string {
	mw := cfg.MW
	if mw == nil || !mw.ExecutionBoostEffective() {
		return result
	}
	state := GetConversationExecutionState(cfg.ConversationID)
	entry := SummarizeToolResult(toolName, args, result)
	state.RecordTool(entry)

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
		if entry.StatusHint == "interesting" {
			st = "open"
			pr = "P0"
		}
		state.UpsertCoverage(CoverageItem{Path: path, Status: st, Priority: pr, Note: entry.Summary})
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
			routed := RouteSkills(SkillRouterInput{
				ToolName:        toolName,
				Arguments:       args,
				Output:          result,
				TopK:            mw.SkillRouterTopKEffective(),
				MaxRunes:        mw.SkillRouterMaxRunesEffective(),
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

	if summaryBlock == "" && skillBlock == "" {
		return body
	}
	return ComposeToolResultWithBoostOrder(summaryBlock, body, skillBlock)
}
