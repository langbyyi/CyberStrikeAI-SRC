package multiagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"go.uber.org/zap"
)

const userContextSupplementHeader = "\n\n## 用户历史输入（原文，子代理必读）\n"

// taskContextEnrichMiddleware intercepts "task" tool calls on the orchestrator
// and appends the user's original conversation messages to the task description.
// This ensures sub-agents always receive the full user intent (target URLs,
// scope, etc.) even when the orchestrator forgets to include them.
//
// Design: user context is injected into the task description (per-task), NOT
// into the sub-agent's Instruction (system prompt). This keeps sub-agent
// Instructions clean as pure role definitions while attaching context to the
// specific delegation — aligned with Claude Code's agent design philosophy.
type taskContextEnrichMiddleware struct {
	adk.BaseChatModelAgentMiddleware
	supplement     string // pre-built user context block
	factBodies     string // optional project fact bodies
	conversationID string
	mwCfg          *config.MultiAgentEinoMiddlewareConfig
	logger         *zap.Logger
}

// taskEnrichOptions optional fields for execution-boost task handoff.
type taskEnrichOptions struct {
	FactBodies     string
	ConversationID string
	MW             *config.MultiAgentEinoMiddlewareConfig
	Logger         *zap.Logger
}

// newTaskContextEnrichMiddleware returns a middleware that enriches task
// descriptions with user conversation context. Returns nil if disabled
// (maxRunes < 0) or no user messages exist and no boost evidence path.
// projectBlackboard 仅传项目黑板索引块（BuildFactIndexBlock）；勿传完整 systemPromptExtra。
func newTaskContextEnrichMiddleware(userMessage string, history []agent.ChatMessage, maxRunes int, projectBlackboard string) adk.ChatModelAgentMiddleware {
	return newTaskContextEnrichMiddlewareExt(userMessage, history, maxRunes, projectBlackboard, taskEnrichOptions{})
}

func newTaskContextEnrichMiddlewareExt(userMessage string, history []agent.ChatMessage, maxRunes int, projectBlackboard string, opt taskEnrichOptions) adk.ChatModelAgentMiddleware {
	supplement := buildUserContextSupplement(userMessage, history, maxRunes)
	if bb := strings.TrimSpace(projectBlackboard); bb != "" {
		if supplement != "" {
			supplement += "\n\n" + bb
		} else {
			supplement = "\n\n" + bb
		}
	}
	factBodies := strings.TrimSpace(opt.FactBodies)
	boost := opt.MW != nil && opt.MW.ExecutionBoostEffective()
	if supplement == "" && factBodies == "" && !boost {
		return nil
	}
	return &taskContextEnrichMiddleware{
		supplement:     supplement,
		factBodies:     factBodies,
		conversationID: opt.ConversationID,
		mwCfg:          opt.MW,
		logger:         opt.Logger,
	}
}

func (m *taskContextEnrichMiddleware) WrapInvokableToolCall(
	ctx context.Context,
	endpoint adk.InvokableToolCallEndpoint,
	tCtx *adk.ToolContext,
) (adk.InvokableToolCallEndpoint, error) {
	if tCtx == nil || !strings.EqualFold(strings.TrimSpace(tCtx.Name), "task") {
		return endpoint, nil
	}
	return func(ctx context.Context, argumentsInJSON string, opts ...tool.Option) (string, error) {
		enriched, reject := m.enrichTaskArguments(argumentsInJSON)
		if reject != "" {
			if m.logger != nil {
				m.logger.Info("task handoff rejected by framework",
					zap.String("reason", reject),
					zap.String("conversation_id", m.conversationID),
				)
			}
			// Soft-reject: return error text to model without calling sub-agent.
			return reject, nil
		}
		return endpoint(ctx, enriched, opts...)
	}, nil
}

// enrichTaskDescription parses the task JSON arguments, appends user context
// to the "description" field, and re-serializes. Falls back to the original
// JSON if parsing fails or no description field exists.
func (m *taskContextEnrichMiddleware) enrichTaskDescription(argsJSON string) string {
	enriched, _ := m.enrichTaskArguments(argsJSON)
	return enriched
}

// EnrichTaskArguments is the testable pure-ish core for task handoff.
// rejectMsg non-empty means the framework should not dispatch the sub-agent.
func EnrichTaskArguments(
	argsJSON string,
	supplement string,
	factBodies string,
	conversationID string,
	mwCfg *config.MultiAgentEinoMiddlewareConfig,
) (enrichedJSON string, rejectMsg string) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(argsJSON), &raw); err != nil {
		return argsJSON, ""
	}
	desc, _ := raw["description"].(string)
	subagent, _ := raw["subagent_type"].(string)
	if subagent == "" {
		if s, ok := raw["subagent"].(string); ok {
			subagent = s
		}
	}

	// verify/exploit routing correction
	if corrected, changed := CorrectSubagentRouting(desc, subagent); changed {
		raw["subagent_type"] = corrected
		desc = desc + fmt.Sprintf("\n\n[框架路由纠正] subagent_type %q → %q（verify/exploit 类任务）", subagent, corrected)
		subagent = corrected
	}

	// Target/scope require or backfill
	requireTarget := mwCfg != nil && mwCfg.TaskRequireTargetEffective()
	target := ExtractTargetFromText(desc)
	if target == "" {
		target = ExtractTargetFromText(supplement)
	}
	if target == "" && requireTarget {
		return argsJSON, "【框架拒绝·task 缺 target/scope】description 与用户上下文中均未解析到 URL/主机目标。" +
			"请在 description 中写明完整目标（如 https://example.com/path）及授权范围后重试 task。"
	}
	if target != "" && !strings.Contains(desc, target) {
		desc = desc + "\n\n[框架回填目标] target/scope: " + target
	}

	// Attach user context + facts + evidence
	if strings.TrimSpace(supplement) != "" {
		desc = desc + supplement
	}
	if strings.TrimSpace(factBodies) != "" {
		desc = desc + "\n\n## 相关项目事实正文（框架附加）\n" + factBodies
	}
	k := 0
	if mwCfg != nil {
		k = mwCfg.TaskEvidenceKEffective()
	}
	if k > 0 {
		entries := GetConversationExecutionState(conversationID).LastK(k)
		if block := FormatToolEvidenceBlock(entries); block != "" {
			desc = desc + block
		}
	}

	raw["description"] = desc
	out, err := json.Marshal(raw)
	if err != nil {
		return argsJSON, ""
	}
	return string(out), ""
}

func (m *taskContextEnrichMiddleware) enrichTaskArguments(argsJSON string) (string, string) {
	enriched, reject := EnrichTaskArguments(argsJSON, m.supplement, m.factBodies, m.conversationID, m.mwCfg)
	if reject == "" && m.logger != nil && m.mwCfg != nil && m.mwCfg.ExecutionBoostEffective() {
		// Log evidence attachment volume
		k := m.mwCfg.TaskEvidenceKEffective()
		n := 0
		if k > 0 {
			n = len(GetConversationExecutionState(m.conversationID).LastK(k))
		}
		m.logger.Info("task handoff enriched",
			zap.String("conversation_id", m.conversationID),
			zap.Int("evidence_k", k),
			zap.Int("evidence_attached", n),
			zap.Bool("has_user_context", strings.TrimSpace(m.supplement) != ""),
			zap.Bool("has_fact_bodies", strings.TrimSpace(m.factBodies) != ""),
		)
	}
	return enriched, reject
}

// buildUserContextSupplement collects user messages from conversation history
// and the current message, returning a formatted block to append to task
// descriptions. Returns "" if disabled or no user messages exist.
func buildUserContextSupplement(userMessage string, history []agent.ChatMessage, maxRunes int) string {
	if maxRunes < 0 {
		return ""
	}

	var userMsgs []string
	for _, h := range history {
		if h.Role == "user" {
			if m := strings.TrimSpace(h.Content); m != "" {
				userMsgs = append(userMsgs, m)
			}
		}
	}
	if um := strings.TrimSpace(userMessage); um != "" {
		if len(userMsgs) == 0 || userMsgs[len(userMsgs)-1] != um {
			userMsgs = append(userMsgs, um)
		}
	}
	if len(userMsgs) == 0 {
		return ""
	}

	lines := make([]string, 0, len(userMsgs))
	for i, msg := range userMsgs {
		lines = append(lines, fmt.Sprintf("[第%d轮] %s", i+1, msg))
	}
	joined := strings.Join(lines, "\n")
	if maxRunes > 0 && len([]rune(joined)) > maxRunes {
		joined = truncateKeepFirstLast(userMsgs, maxRunes)
	}

	return userContextSupplementHeader + joined
}

// truncateKeepFirstLast keeps the first and last user messages, giving each
// half the rune budget. The first message typically contains target info;
// the last contains the current instruction.
func truncateKeepFirstLast(msgs []string, maxRunes int) string {
	if len(msgs) == 1 {
		return truncateRunes(msgs[0], maxRunes)
	}

	first := msgs[0]
	last := msgs[len(msgs)-1]
	sep := "\n---\n...(中间对话省略)...\n---\n"
	sepLen := len([]rune(sep))

	budget := maxRunes - sepLen
	if budget <= 0 {
		return truncateRunes(first+"\n---\n"+last, maxRunes)
	}

	halfBudget := budget / 2
	firstTrunc := truncateRunes(first, halfBudget)
	lastTrunc := truncateRunes(last, budget-len([]rune(firstTrunc)))

	return firstTrunc + sep + lastTrunc
}

func truncateRunes(s string, max int) string {
	rs := []rune(s)
	if len(rs) <= max {
		return s
	}
	if max <= 0 {
		return ""
	}
	return string(rs[:max])
}
