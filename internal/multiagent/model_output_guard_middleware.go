package multiagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

const (
	modelOutputRecoveryKey          = "_cyberstrike_model_output_recovery"
	modelOutputRejectedResultPrefix = "[Model Output Rejected]"
	modelOutputRepairInstruction    = "The previous model output reached its output limit and was rejected. Retry once with a concise response. For long scripts or payloads, call write_file first, then run a short exec/execute command. Do not repeat the long content inside tool arguments."
)

type modelOutputRecoveryMarker struct {
	Reason           string `json:"reason"`
	ArgumentsBytes   int    `json:"arguments_bytes,omitempty"`
	FinishReason     string `json:"finish_reason,omitempty"`
	CompletionTokens int    `json:"completion_tokens,omitempty"`
	ReasoningTokens  int    `json:"reasoning_tokens,omitempty"`
	RepairAttempt    int    `json:"repair_attempt"`
}

type modelOutputGuardConfig struct {
	maxToolArgumentsBytes int
	maxShellCommandBytes  int
	maxRepairAttempts     int
}

func modelOutputGuardConfigFromMW(mw *config.MultiAgentEinoMiddlewareConfig) modelOutputGuardConfig {
	if mw == nil {
		mw = &config.MultiAgentEinoMiddlewareConfig{}
	}
	return modelOutputGuardConfig{
		maxToolArgumentsBytes: mw.MaxToolArgumentsBytesEffective(),
		maxShellCommandBytes:  mw.MaxShellCommandBytesEffective(),
		maxRepairAttempts:     mw.ModelOutputRepairMaxAttemptsEffective(),
	}
}

type modelOutputRejectedError struct {
	Reason           string
	FinishReason     string
	ToolName         string
	ToolCallID       string
	ArgumentsBytes   int
	CompletionTokens int
	ReasoningTokens  int
	RepairAttempt    int
	Repairable       bool
}

func (e *modelOutputRejectedError) Error() string {
	if e == nil {
		return "model output rejected"
	}
	return fmt.Sprintf("model output rejected: reason=%s finish_reason=%s tool=%s arguments_bytes=%d repair_attempt=%d",
		e.Reason, e.FinishReason, e.ToolName, e.ArgumentsBytes, e.RepairAttempt)
}

type modelOutputGuardMiddleware struct {
	adk.BaseChatModelAgentMiddleware
	cfg    modelOutputGuardConfig
	logger *zap.Logger
	phase  string
}

func newModelOutputGuardMiddleware(mw *config.MultiAgentEinoMiddlewareConfig, logger *zap.Logger, phase string) adk.ChatModelAgentMiddleware {
	return &modelOutputGuardMiddleware{cfg: modelOutputGuardConfigFromMW(mw), logger: logger, phase: phase}
}

func (m *modelOutputGuardMiddleware) AfterModelRewriteState(
	ctx context.Context,
	state *adk.ChatModelAgentState,
	mc *adk.ModelContext,
) (context.Context, *adk.ChatModelAgentState, error) {
	_ = mc
	if m == nil || state == nil || len(state.Messages) == 0 {
		return ctx, state, nil
	}
	last := state.Messages[len(state.Messages)-1]
	if last == nil || last.Role != schema.Assistant {
		return ctx, state, nil
	}

	finishReason, completionTokens, reasoningTokens := responseDiagnostics(last)
	reason := ""
	badIndex := -1
	argumentBytes := 0
	if strings.EqualFold(strings.TrimSpace(finishReason), "length") {
		if len(last.ToolCalls) == 0 {
			reason = "output_limit"
		} else {
			for i, tc := range last.ToolCalls {
				r, n := validateGeneratedToolCall(tc, m.cfg)
				if r != "" {
					reason, badIndex, argumentBytes = "output_limit", i, n
					break
				}
			}
		}
	} else {
		for i, tc := range last.ToolCalls {
			r, n := validateGeneratedToolCall(tc, m.cfg)
			if r != "" {
				reason, badIndex, argumentBytes = r, i, n
				break
			}
		}
	}
	if reason == "" {
		return ctx, state, nil
	}

	priorRepairs := consecutiveModelOutputRepairRounds(state.Messages[:len(state.Messages)-1])
	attempt := priorRepairs + 1
	rejected := &modelOutputRejectedError{
		Reason: reason, FinishReason: finishReason, ArgumentsBytes: argumentBytes,
		CompletionTokens: completionTokens, ReasoningTokens: reasoningTokens,
		RepairAttempt: attempt, Repairable: attempt <= m.cfg.maxRepairAttempts,
	}
	if badIndex >= 0 {
		rejected.ToolName = last.ToolCalls[badIndex].Function.Name
		rejected.ToolCallID = last.ToolCalls[badIndex].ID
	} else if len(last.ToolCalls) > 0 {
		rejected.ToolName = last.ToolCalls[0].Function.Name
		rejected.ToolCallID = last.ToolCalls[0].ID
		rejected.ArgumentsBytes = len(last.ToolCalls[0].Function.Arguments)
		argumentBytes = rejected.ArgumentsBytes
	}
	if m.logger != nil {
		m.logger.Warn("eino model output rejected before tool execution",
			zap.String("phase", m.phase), zap.String("reason", reason),
			zap.String("finish_reason", finishReason), zap.String("tool_name", rejected.ToolName),
			zap.String("tool_call_id", rejected.ToolCallID), zap.Int("arguments_bytes", argumentBytes),
			zap.Int("completion_tokens", completionTokens), zap.Int("reasoning_tokens", reasoningTokens),
			zap.Int("repair_attempt", attempt), zap.Bool("repairable", rejected.Repairable),
		)
	}
	if !rejected.Repairable || len(last.ToolCalls) == 0 {
		return ctx, state, rejected
	}

	marker := modelOutputRecoveryMarker{
		Reason: reason, ArgumentsBytes: argumentBytes, FinishReason: finishReason,
		CompletionTokens: completionTokens, ReasoningTokens: reasoningTokens, RepairAttempt: attempt,
	}
	markerJSON, _ := json.Marshal(map[string]modelOutputRecoveryMarker{modelOutputRecoveryKey: marker})
	calls := append([]schema.ToolCall(nil), last.ToolCalls...)
	for i := range calls {
		calls[i].Function.Arguments = string(markerJSON)
	}
	cloned := *last
	cloned.Content = ""
	cloned.ReasoningContent = ""
	cloned.ToolCalls = calls
	out := append([]adk.Message(nil), state.Messages...)
	out[len(out)-1] = &cloned
	ns := *state
	ns.Messages = out
	return ctx, &ns, nil
}

func responseDiagnostics(msg adk.Message) (finishReason string, completionTokens, reasoningTokens int) {
	if msg == nil || msg.ResponseMeta == nil {
		return "", 0, 0
	}
	finishReason = strings.TrimSpace(msg.ResponseMeta.FinishReason)
	if msg.ResponseMeta.Usage != nil {
		completionTokens = msg.ResponseMeta.Usage.CompletionTokens
		reasoningTokens = msg.ResponseMeta.Usage.CompletionTokensDetails.ReasoningTokens
	}
	return
}

func validateGeneratedToolCall(tc schema.ToolCall, cfg modelOutputGuardConfig) (string, int) {
	arguments := tc.Function.Arguments
	n := len(arguments)
	if n > cfg.maxToolArgumentsBytes {
		return "tool_arguments_too_large", n
	}
	var obj map[string]any
	if strings.TrimSpace(arguments) == "" || json.Unmarshal([]byte(arguments), &obj) != nil || obj == nil {
		return "invalid_tool_arguments_json", n
	}
	name := strings.ToLower(strings.TrimSpace(tc.Function.Name))
	if name == "exec" || name == "execute" {
		command, _ := obj["command"].(string)
		if len(command) > cfg.maxShellCommandBytes {
			return "shell_command_too_large", n
		}
	}
	return "", n
}

func consecutiveModelOutputRepairRounds(messages []adk.Message) int {
	count := 0
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		if msg == nil {
			continue
		}
		if msg.Role == schema.User && strings.TrimSpace(msg.Content) == modelOutputRepairInstruction {
			count++
			continue
		}
		if msg.Role == schema.Tool && strings.HasPrefix(msg.Content, modelOutputRejectedResultPrefix) {
			count++
			for i > 0 && messages[i-1] != nil && messages[i-1].Role == schema.Tool {
				i--
			}
			continue
		}
		if msg.Role == schema.Assistant && len(msg.ToolCalls) > 0 {
			continue
		}
		break
	}
	return count
}

func modelOutputExecutionGuardMiddleware() compose.ToolMiddleware {
	messageFor := func(input *compose.ToolInput) (string, bool) {
		if input == nil {
			return "", false
		}
		var envelope map[string]json.RawMessage
		if json.Unmarshal([]byte(input.Arguments), &envelope) != nil {
			return "", false
		}
		raw, ok := envelope[modelOutputRecoveryKey]
		if !ok {
			return "", false
		}
		var marker modelOutputRecoveryMarker
		_ = json.Unmarshal(raw, &marker)
		return fmt.Sprintf("%s Tool call '%s' was not executed because the model output was unsafe (%s). Repair attempt %d. Use write_file for long scripts or payloads, then call exec/execute with a short command.",
			modelOutputRejectedResultPrefix, input.Name, marker.Reason, marker.RepairAttempt), true
	}
	return compose.ToolMiddleware{
		Invokable: func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
				if msg, reject := messageFor(input); reject {
					return &compose.ToolOutput{Result: msg}, nil
				}
				return next(ctx, input)
			}
		},
		Streamable: func(next compose.StreamableToolEndpoint) compose.StreamableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.StreamToolOutput, error) {
				if msg, reject := messageFor(input); reject {
					return &compose.StreamToolOutput{Result: schema.StreamReaderFromArray([]string{msg})}, nil
				}
				return next(ctx, input)
			}
		},
	}
}

func modelOutputRecoveryFromToolCall(tc schema.ToolCall) (modelOutputRecoveryMarker, bool) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal([]byte(tc.Function.Arguments), &envelope) != nil {
		return modelOutputRecoveryMarker{}, false
	}
	raw, ok := envelope[modelOutputRecoveryKey]
	if !ok {
		return modelOutputRecoveryMarker{}, false
	}
	var marker modelOutputRecoveryMarker
	if json.Unmarshal(raw, &marker) != nil {
		return modelOutputRecoveryMarker{}, false
	}
	return marker, true
}
