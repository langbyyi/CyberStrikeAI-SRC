package multiagent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

func guardedAssistant(arguments, finishReason string) adk.Message {
	msg := assistantToolCallsMsg("", "call-1")
	msg.ToolCalls[0].Function.Name = "exec"
	msg.ToolCalls[0].Function.Arguments = arguments
	msg.ResponseMeta = &schema.ResponseMeta{
		FinishReason: finishReason,
		Usage: &schema.TokenUsage{
			CompletionTokens:        99,
			CompletionTokensDetails: schema.CompletionTokensDetails{ReasoningTokens: 33},
		},
	}
	return msg
}

func runModelOutputGuard(t *testing.T, messages []adk.Message, cfg config.MultiAgentEinoMiddlewareConfig) (*adk.ChatModelAgentState, error) {
	t.Helper()
	mw := newModelOutputGuardMiddleware(&cfg, nil, "test").(*modelOutputGuardMiddleware)
	_, state, err := mw.AfterModelRewriteState(context.Background(), &adk.ChatModelAgentState{Messages: messages}, &adk.ModelContext{})
	return state, err
}

func TestModelOutputGuardRejectsTruncatedToolCallBeforeExecution(t *testing.T) {
	original := `{"command":"secret-token-should-not-survive`
	state, err := runModelOutputGuard(t, []adk.Message{schema.UserMessage("run"), guardedAssistant(original, "length")}, config.MultiAgentEinoMiddlewareConfig{})
	if err != nil {
		t.Fatal(err)
	}
	got := state.Messages[len(state.Messages)-1].ToolCalls[0].Function.Arguments
	if strings.Contains(got, "secret-token") || !strings.Contains(got, modelOutputRecoveryKey) {
		t.Fatalf("unsafe arguments were not replaced: %q", got)
	}
	marker, ok := modelOutputRecoveryFromToolCall(state.Messages[len(state.Messages)-1].ToolCalls[0])
	if !ok || marker.Reason != "output_limit" || marker.CompletionTokens != 99 || marker.ReasoningTokens != 33 {
		t.Fatalf("unexpected recovery marker: %+v ok=%v", marker, ok)
	}
}

func TestModelOutputGuardAllowsValidToolCallDespiteLengthFinish(t *testing.T) {
	original := `{"command":"echo ok"}`
	state, err := runModelOutputGuard(t, []adk.Message{schema.UserMessage("run"), guardedAssistant(original, "length")}, config.MultiAgentEinoMiddlewareConfig{})
	if err != nil {
		t.Fatal(err)
	}
	got := state.Messages[len(state.Messages)-1].ToolCalls[0].Function.Arguments
	if got != original {
		t.Fatalf("valid arguments should pass unchanged: %q", got)
	}
}

func TestModelOutputGuardRejectsInvalidJSONShapes(t *testing.T) {
	for _, arguments := range []string{"", `[]`, `{"command":`} {
		t.Run(arguments, func(t *testing.T) {
			state, err := runModelOutputGuard(t, []adk.Message{guardedAssistant(arguments, "tool_calls")}, config.MultiAgentEinoMiddlewareConfig{})
			if err != nil {
				t.Fatal(err)
			}
			marker, ok := modelOutputRecoveryFromToolCall(state.Messages[0].ToolCalls[0])
			if !ok || marker.Reason != "invalid_tool_arguments_json" {
				t.Fatalf("arguments=%q marker=%+v ok=%v", arguments, marker, ok)
			}
		})
	}
}

func TestGeneratedToolCallSizeBoundaries(t *testing.T) {
	cfg := modelOutputGuardConfig{maxToolArgumentsBytes: 128, maxShellCommandBytes: 16, maxRepairAttempts: 1}
	call := schema.ToolCall{Function: schema.FunctionCall{Name: "exec", Arguments: `{"command":"1234567890123456"}`}}
	if reason, _ := validateGeneratedToolCall(call, cfg); reason != "" {
		t.Fatalf("shell boundary should pass: %s", reason)
	}
	call.Function.Arguments = `{"command":"12345678901234567"}`
	if reason, _ := validateGeneratedToolCall(call, cfg); reason != "shell_command_too_large" {
		t.Fatalf("shell overflow reason=%q", reason)
	}
	call.Function.Name = "other"
	call.Function.Arguments = `{"value":"` + strings.Repeat("x", 116) + `"}`
	if len(call.Function.Arguments) != 128 {
		t.Fatalf("test fixture length=%d", len(call.Function.Arguments))
	}
	if reason, _ := validateGeneratedToolCall(call, cfg); reason != "" {
		t.Fatalf("generic boundary should pass: %q", reason)
	}
	call.Function.Arguments = `{"value":"` + strings.Repeat("x", 200) + `"}`
	if reason, _ := validateGeneratedToolCall(call, cfg); reason != "tool_arguments_too_large" {
		t.Fatalf("generic overflow reason=%q", reason)
	}
}

func TestModelOutputGuardAllowsOneRepairThenFails(t *testing.T) {
	first, err := runModelOutputGuard(t, []adk.Message{guardedAssistant(`{"command":`, "tool_calls")}, config.MultiAgentEinoMiddlewareConfig{})
	if err != nil {
		t.Fatal(err)
	}
	toolCall := first.Messages[0].ToolCalls[0]
	recoveryResult := schema.ToolMessage(modelOutputRejectedResultPrefix+" retry", toolCall.ID)
	secondMessages := append(first.Messages, recoveryResult, guardedAssistant(`{"command":`, "tool_calls"))
	_, err = runModelOutputGuard(t, secondMessages, config.MultiAgentEinoMiddlewareConfig{})
	var rejected *modelOutputRejectedError
	if !errors.As(err, &rejected) || rejected.Repairable || rejected.RepairAttempt != 2 {
		t.Fatalf("second rejection should be terminal: %#v", err)
	}
}

func TestModelOutputGuardNoToolLengthIsRepairableOnce(t *testing.T) {
	truncated := schema.AssistantMessage("partial", nil)
	truncated.ResponseMeta = &schema.ResponseMeta{FinishReason: "length"}
	_, err := runModelOutputGuard(t, []adk.Message{schema.UserMessage("answer"), truncated}, config.MultiAgentEinoMiddlewareConfig{})
	var rejected *modelOutputRejectedError
	if !errors.As(err, &rejected) || !rejected.Repairable {
		t.Fatalf("first no-tool length should be repairable: %#v", err)
	}
	_, err = runModelOutputGuard(t, []adk.Message{schema.UserMessage("answer"), schema.UserMessage(modelOutputRepairInstruction), truncated}, config.MultiAgentEinoMiddlewareConfig{})
	if !errors.As(err, &rejected) || rejected.Repairable || rejected.RepairAttempt != 2 {
		t.Fatalf("second no-tool length should fail: %#v", err)
	}
}

func TestModelOutputExecutionGuardNeverCallsTool(t *testing.T) {
	markerJSON := `{"` + modelOutputRecoveryKey + `":{"reason":"output_limit","repair_attempt":1}}`
	called := false
	mw := modelOutputExecutionGuardMiddleware().Invokable
	endpoint := mw(func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
		called = true
		return &compose.ToolOutput{Result: "executed"}, nil
	})
	out, err := endpoint(context.Background(), &compose.ToolInput{Name: "exec", Arguments: markerJSON})
	if err != nil || called || out == nil || !strings.HasPrefix(out.Result, modelOutputRejectedResultPrefix) {
		t.Fatalf("guard failed: called=%v out=%+v err=%v", called, out, err)
	}
}

func TestModelOutputExecutionGuardBlocksStreamableTool(t *testing.T) {
	markerJSON := `{"` + modelOutputRecoveryKey + `":{"reason":"shell_command_too_large","repair_attempt":1}}`
	called := false
	endpoint := modelOutputExecutionGuardMiddleware().Streamable(func(context.Context, *compose.ToolInput) (*compose.StreamToolOutput, error) {
		called = true
		return &compose.StreamToolOutput{Result: schema.StreamReaderFromArray([]string{"executed"})}, nil
	})
	out, err := endpoint(context.Background(), &compose.ToolInput{Name: "execute", Arguments: markerJSON})
	if err != nil || called || out == nil {
		t.Fatalf("stream guard failed: called=%v out=%+v err=%v", called, out, err)
	}
	result, recvErr := out.Result.Recv()
	if recvErr != nil || !strings.HasPrefix(result, modelOutputRejectedResultPrefix) {
		t.Fatalf("unexpected stream result=%q err=%v", result, recvErr)
	}
}

func TestModelOutputExecutionGuardAllowsNormalTool(t *testing.T) {
	called := false
	endpoint := modelOutputExecutionGuardMiddleware().Invokable(func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
		called = true
		return &compose.ToolOutput{Result: "executed"}, nil
	})
	out, err := endpoint(context.Background(), &compose.ToolInput{Name: "exec", Arguments: `{"command":"true"}`})
	if err != nil || !called || out == nil || out.Result != "executed" {
		t.Fatalf("normal tool should execute: called=%v out=%+v err=%v", called, out, err)
	}
}

func TestModelOutputRejectedErrorIsNotTransient(t *testing.T) {
	if isEinoTransientRunError(&modelOutputRejectedError{Reason: "output_limit", Repairable: true}) {
		t.Fatal("model output rejection must not use network backoff")
	}
}
