package multiagent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

const repairedMissingToolResult = `{"status":"cancelled","error":"tool result missing; repaired before model call"}`

// orphanToolPrunerMiddleware 在每次 ChatModel 调用前规范化 assistant(tool_calls) / tool 消息回合。
//
// 背景：
//   - eino 的 summarization 中间件在触发摘要后，默认把所有非 system 消息替换为 1 条 summary 消息；
//     本项目通过自定义 Finalize（summarizeFinalizeWithRecentAssistantToolTrail）在 summary 后回填
//     最近的 assistant/tool 轨迹。若 Finalize 的保留策略按"条数"截断而未按 round 对齐，可能保留
//     了 tool 结果却把对应的 assistant(tool_calls) 落在了 summary 前面，形成孤儿 tool 消息。
//   - 同样，reduction / tool_search / 自定义断点恢复等任一改写历史的逻辑，都可能破坏
//     tool_call ↔ tool_result 配对。
//
// 一旦孤儿 tool 消息进入 ChatModel，OpenAI 兼容 API（含 DashScope / 各类中转）会返回
// 400 "No tool call found for function call output with call_id ..."，并被 Eino 包装成
// [NodeRunError] 抛出，终止整轮编排。
//
// 设计取舍：
//   - 不向历史里注入虚构 assistant(tool_calls)；孤儿结果直接删除。
//   - 对真实 assistant(tool_calls) 缺少结果的情况补取消占位，确保每个调用在发给模型前都有结果，
//     同时不会重新执行可能具有副作用的工具。
//   - 位置建议：挂在 summarization / reduction / skill / plantask / system 合并 / 续聊 dedup /
//     tool_search 之后，靠近 ChatModel 调用的那一端。
type orphanToolPrunerMiddleware struct {
	adk.BaseChatModelAgentMiddleware
	logger *zap.Logger
	phase  string
}

// newOrphanToolPrunerMiddleware 构造中间件。phase 仅用于日志区分 deep / supervisor /
// plan_execute_executor / sub_agent，不影响运行时行为。
func newOrphanToolPrunerMiddleware(logger *zap.Logger, phase string) adk.ChatModelAgentMiddleware {
	return &orphanToolPrunerMiddleware{
		logger: logger,
		phase:  phase,
	}
}

// BeforeModelRewriteState 顺序扫描消息列表，只接受紧随 assistant(tool_calls) 的匹配 tool 结果。
// 空 ID、孤儿、跨轮和重复结果会被删除，缺失结果会补结构化占位。
//
// 复杂度：O(N)。未发生修复时返回原 state。
func (m *orphanToolPrunerMiddleware) BeforeModelRewriteState(
	ctx context.Context,
	state *adk.ChatModelAgentState,
	mc *adk.ModelContext,
) (context.Context, *adk.ChatModelAgentState, error) {
	_ = mc
	if m == nil || state == nil || len(state.Messages) == 0 {
		return ctx, state, nil
	}

	normalized := make([]adk.Message, 0, len(state.Messages))
	droppedIDs := make([]string, 0, 2)
	droppedNames := make([]string, 0, 2)
	patchedIDs := make([]string, 0, 2)
	changed := false

	for i := 0; i < len(state.Messages); {
		msg := state.Messages[i]
		if msg == nil {
			changed = true
			i++
			continue
		}
		if msg.Role == schema.Tool {
			droppedIDs = append(droppedIDs, msg.ToolCallID)
			droppedNames = append(droppedNames, msg.ToolName)
			changed = true
			i++
			continue
		}
		if msg.Role != schema.Assistant || len(msg.ToolCalls) == 0 {
			normalized = append(normalized, msg)
			i++
			continue
		}

		validCalls := make([]schema.ToolCall, 0, len(msg.ToolCalls))
		expected := make(map[string]struct{}, len(msg.ToolCalls))
		assistantChanged := false
		for _, call := range msg.ToolCalls {
			id := strings.TrimSpace(call.ID)
			name := strings.TrimSpace(call.Function.Name)
			arguments := strings.TrimSpace(call.Function.Arguments)
			if id == "" || name == "" || (arguments != "" && !json.Valid([]byte(arguments))) {
				droppedIDs = append(droppedIDs, call.ID)
				droppedNames = append(droppedNames, call.Function.Name)
				changed = true
				assistantChanged = true
				continue
			}
			if _, duplicate := expected[id]; duplicate {
				droppedIDs = append(droppedIDs, id)
				droppedNames = append(droppedNames, call.Function.Name)
				changed = true
				assistantChanged = true
				continue
			}
			if id != call.ID {
				call.ID = id
				changed = true
				assistantChanged = true
			}
			if name != call.Function.Name {
				call.Function.Name = name
				changed = true
				assistantChanged = true
			}
			if arguments == "" {
				call.Function.Arguments = "{}"
				changed = true
				assistantChanged = true
			} else if arguments != call.Function.Arguments {
				call.Function.Arguments = arguments
				changed = true
				assistantChanged = true
			}
			expected[id] = struct{}{}
			validCalls = append(validCalls, call)
		}

		assistant := msg
		if assistantChanged {
			cloned := *msg
			cloned.ToolCalls = validCalls
			assistant = &cloned
		}
		if len(validCalls) > 0 || strings.TrimSpace(assistant.Content) != "" {
			normalized = append(normalized, assistant)
		} else {
			changed = true
		}
		i++

		seenResults := make(map[string]struct{}, len(validCalls))
		for i < len(state.Messages) {
			result := state.Messages[i]
			if result == nil {
				changed = true
				i++
				continue
			}
			if result.Role != schema.Tool {
				break
			}
			id := strings.TrimSpace(result.ToolCallID)
			_, expectedResult := expected[id]
			_, duplicate := seenResults[id]
			if id == "" || !expectedResult || duplicate {
				droppedIDs = append(droppedIDs, result.ToolCallID)
				droppedNames = append(droppedNames, result.ToolName)
				changed = true
				i++
				continue
			}
			if id != result.ToolCallID {
				cloned := *result
				cloned.ToolCallID = id
				result = &cloned
				changed = true
			}
			normalized = append(normalized, result)
			seenResults[id] = struct{}{}
			i++
		}
		for _, call := range validCalls {
			if _, ok := seenResults[call.ID]; ok {
				continue
			}
			normalized = append(normalized, schema.ToolMessage(
				repairedMissingToolResult,
				call.ID,
				schema.WithToolName(call.Function.Name),
			))
			patchedIDs = append(patchedIDs, call.ID)
			changed = true
		}
	}

	if !changed {
		return ctx, state, nil
	}
	if m.logger != nil {
		m.logger.Warn("eino tool message sequence normalized before model call",
			zap.String("phase", m.phase),
			zap.Int("dropped_count", len(droppedIDs)),
			zap.Strings("dropped_tool_call_ids", droppedIDs),
			zap.Strings("dropped_tool_names", droppedNames),
			zap.Int("patched_count", len(patchedIDs)),
			zap.Strings("patched_tool_call_ids", patchedIDs),
			zap.Int("messages_before", len(state.Messages)),
			zap.Int("messages_after", len(normalized)),
		)
	}

	ns := *state
	ns.Messages = normalized
	return ctx, &ns, nil
}
