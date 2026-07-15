package multiagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type executionToolClass int

const (
	executionToolProbe executionToolClass = iota
	executionToolLongRunning
	executionToolStateMutation
	executionToolDecision
	executionToolUnknown
)

type einoSingleExecutionMiddleware struct {
	*adk.BaseChatModelAgentMiddleware
	conversationID  string
	progress        func(string, string, interface{})
	modelTimeout    time.Duration
	modelStreamIdle time.Duration
}

type einoSingleDeadlineModel struct {
	base       model.BaseModel[*schema.Message]
	callLimit  time.Duration
	streamIdle time.Duration
}

func (m *einoSingleExecutionMiddleware) WrapModel(_ context.Context, base model.BaseModel[*schema.Message], _ *adk.ModelContext) (model.BaseModel[*schema.Message], error) {
	if base == nil || (m.modelTimeout <= 0 && m.modelStreamIdle <= 0) {
		return base, nil
	}
	return &einoSingleDeadlineModel{base: base, callLimit: m.modelTimeout, streamIdle: m.modelStreamIdle}, nil
}

func (m *einoSingleDeadlineModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	child, cancel, _ := EffectiveChildTimeout(ctx, m.callLimit)
	defer cancel()
	return m.base.Generate(child, input, opts...)
}

func (m *einoSingleDeadlineModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	child, cancel, _ := EffectiveChildTimeout(ctx, m.callLimit)
	underlying, err := m.base.Stream(child, input, opts...)
	if err != nil {
		cancel()
		return nil, err
	}
	reader, writer := schema.Pipe[*schema.Message](1)
	go proxyModelStreamWithIdle(child, cancel, underlying, writer, m.streamIdle)
	return reader, nil
}

type modelStreamRecv struct {
	message *schema.Message
	err     error
}

func proxyModelStreamWithIdle(ctx context.Context, cancel context.CancelFunc, source *schema.StreamReader[*schema.Message], writer *schema.StreamWriter[*schema.Message], idle time.Duration) {
	defer cancel()
	defer source.Close()
	defer writer.Close()
	for {
		recv := make(chan modelStreamRecv, 1)
		go func() {
			message, err := source.Recv()
			recv <- modelStreamRecv{message: message, err: err}
		}()
		var idleC <-chan time.Time
		var timer *time.Timer
		if idle > 0 {
			timer = time.NewTimer(idle)
			idleC = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			writer.Send(nil, ctx.Err())
			return
		case <-idleC:
			cancel()
			writer.Send(nil, context.DeadlineExceeded)
			return
		case got := <-recv:
			if timer != nil {
				timer.Stop()
			}
			if errors.Is(got.err, io.EOF) {
				return
			}
			if got.err != nil {
				writer.Send(got.message, got.err)
				return
			}
			if writer.Send(got.message, nil) {
				return
			}
		}
	}
}

func newEinoSingleExecutionMiddleware(conversationID string, progress func(string, string, interface{}), modelTimeout, modelStreamIdle time.Duration) *einoSingleExecutionMiddleware {
	return &einoSingleExecutionMiddleware{
		BaseChatModelAgentMiddleware: &adk.BaseChatModelAgentMiddleware{},
		conversationID:               strings.TrimSpace(conversationID),
		progress:                     progress,
		modelTimeout:                 modelTimeout,
		modelStreamIdle:              modelStreamIdle,
	}
}

func (m *einoSingleExecutionMiddleware) BeforeModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, _ *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	if state == nil {
		return ctx, state, nil
	}
	controller := GetConversationExecutionState(m.conversationID).Controller()
	pending := controller.ConsumePendingDirective()
	if pending != nil {
		summary := truncateRunes(strings.TrimSpace(pending.EvidenceSummary), 200)
		state.Messages = append(state.Messages, schema.SystemMessage(fmt.Sprintf(
			"[framework_next_action]\n已有可复现强证据待记录。下一个并且唯一的工具调用必须是 record_vulnerability_candidate 或 record_vulnerability。禁止与探测、coverage、fact 或 skill 并发。\nevidence: %s",
			summary)))
		return ctx, state, nil
	}
	if directive := controller.PivotDirective(); directive != "" {
		state.Messages = append(state.Messages, schema.SystemMessage(directive))
	}
	return ctx, state, nil
}

func (m *einoSingleExecutionMiddleware) AfterModelRewriteState(ctx context.Context, state *adk.ChatModelAgentState, _ *adk.ModelContext) (context.Context, *adk.ChatModelAgentState, error) {
	if state == nil || len(state.Messages) == 0 {
		return ctx, state, nil
	}
	last := state.Messages[len(state.Messages)-1]
	if last == nil || last.Role != schema.Assistant || len(last.ToolCalls) == 0 {
		return ctx, state, nil
	}
	controller := GetConversationExecutionState(m.conversationID).Controller()
	wasPivot := controller.PivotRequired()
	controller.CompleteProbeBatch()
	if !wasPivot && controller.PivotRequired() && m.progress != nil {
		m.progress("execution_stagnation", "连续探测无新证据，下一轮必须换假设或关闭分支", map[string]interface{}{
			"conversationId": m.conversationID,
		})
	}
	plannedCalls := append([]schema.ToolCall(nil), last.ToolCalls...)
	planned := len(plannedCalls)
	kept, reason := rewriteEinoSingleToolCalls(plannedCalls, controller.PendingObligation())
	if pending := controller.PendingObligation(); pending != nil && len(kept) == 1 && isRecordTool(kept[0].Function.Name) {
		if recordCallMatchesObligation(kept[0].Function.Arguments, pending) {
			controller.BindResolutionCall(pending.ID, kept[0].ID)
		} else {
			kept = nil
			reason = "record_arguments_mismatch"
		}
	}
	if controller.PendingObligation() == nil {
		filtered := kept[:0]
		for _, call := range kept {
			class := classifyExecutionTool(call.Function.Name)
			if class == executionToolDecision || class == executionToolStateMutation {
				filtered = append(filtered, call)
				continue
			}
			if allowed, _ := controller.CheckProbeCallAllowed(CallSignature(call.Function.Name, call.Function.Arguments)); allowed {
				filtered = append(filtered, call)
			} else {
				reason = "stagnation_or_retry_budget"
			}
		}
		kept = filtered
	}
	// pending 义务存在但本批无合法 record：保留 1 个调用交给 precheck，向模型写入 dependency_blocked，
	// 避免 ToolCalls 清空导致 ADK 直接结束、UI 出现 orphan pending。
	if controller.PendingObligation() != nil && len(kept) == 0 && planned > 0 {
		kept = []schema.ToolCall{plannedCalls[0]}
		reason = "pending_record_missing"
	}
	last.ToolCalls = kept
	dropped := planned - len(kept)
	controller.RecordToolBatch(planned, dropped)
	probeCallIDs := make([]string, 0, len(kept))
	for _, call := range kept {
		class := classifyExecutionTool(call.Function.Name)
		if class != executionToolDecision && class != executionToolStateMutation {
			probeCallIDs = append(probeCallIDs, call.ID)
		}
	}
	if len(probeCallIDs) > 0 {
		controller.StartProbeBatch(probeCallIDs)
	}
	if dropped > 0 {
		emitDroppedToolCallResults(m.progress, plannedCalls, kept, reason, m.conversationID)
	}
	return ctx, state, nil
}

// emitDroppedToolCallResults closes UI/progress pending entries for calls removed by rewrite
// before ADK runs tools, preventing "pending tool call missing result before run completion".
func emitDroppedToolCallResults(progress func(string, string, interface{}), planned, kept []schema.ToolCall, reason, conversationID string) {
	if len(planned) == 0 {
		return
	}
	keptIDs := make(map[string]struct{}, len(kept))
	for _, call := range kept {
		if id := strings.TrimSpace(call.ID); id != "" {
			keptIDs[id] = struct{}{}
		}
	}
	droppedIDs := make([]string, 0)
	dropped := 0
	for _, call := range planned {
		id := strings.TrimSpace(call.ID)
		if id == "" {
			continue
		}
		if _, ok := keptIDs[id]; ok {
			continue
		}
		dropped++
		droppedIDs = append(droppedIDs, id)
		name := strings.TrimSpace(call.Function.Name)
		if name == "" {
			name = "unknown"
		}
		msg := fmt.Sprintf("[framework_tool_outcome] code=batch_rewritten retryable=false reason=%s\n本批次工具调用已被执行控制器裁剪，未真实执行。请按框架短指令在下一轮调整（强证据时仅 L1/L2；skill/state 不与 probe 并发）。", reason)
		if progress != nil {
			progress("tool_result", fmt.Sprintf("工具结果 (%s)", name), map[string]interface{}{
				"toolName":       name,
				"success":        false,
				"isError":        true,
				"result":         msg,
				"resultPreview":  msg,
				"toolCallId":     id,
				"conversationId": conversationID,
				"source":         "eino",
				"frameworkDrop":  true,
				"dropReason":     reason,
			})
		}
	}
	// Clear run-loop pending even when progress is a different function pointer than the loop wrapper.
	NotifyPendingToolCallsResolved(conversationID, droppedIDs...)
	if dropped > 0 && progress != nil {
		progress("tool_batch_rewritten", "单 Agent 工具批次已按执行义务重写", map[string]interface{}{
			"planned": len(planned), "kept": len(kept), "dropped": dropped, "reason": reason,
			"conversationId": conversationID,
		})
	}
}

func rewriteEinoSingleToolCalls(calls []schema.ToolCall, pending *DecisionObligation) ([]schema.ToolCall, string) {
	if len(calls) == 0 {
		return nil, "empty"
	}
	if pending != nil {
		for _, call := range calls {
			if isRecordTool(call.Function.Name) {
				return []schema.ToolCall{call}, "pending_record"
			}
		}
		return nil, "pending_record_missing"
	}

	bestState := -1
	bestRank := int(^uint(0) >> 1)
	for i := range calls {
		class := classifyExecutionTool(calls[i].Function.Name)
		if class != executionToolDecision && class != executionToolStateMutation {
			continue
		}
		if rank := executionStateToolRank(calls[i].Function.Name); rank < bestRank {
			bestState, bestRank = i, rank
		}
	}
	if bestState >= 0 {
		return []schema.ToolCall{calls[bestState]}, "state_tool_exclusive"
	}
	for i := range calls {
		class := classifyExecutionTool(calls[i].Function.Name)
		if class == executionToolLongRunning {
			return []schema.ToolCall{calls[i]}, "long_running_exclusive"
		}
		if class == executionToolUnknown {
			return []schema.ToolCall{calls[i]}, "unknown_exclusive"
		}
	}
	if len(calls) > 3 {
		return append([]schema.ToolCall(nil), calls[:3]...), "probe_limit"
	}
	return append([]schema.ToolCall(nil), calls...), "unchanged"
}

func classifyExecutionTool(name string) executionToolClass {
	name = normalizedExecutionToolName(name)
	switch name {
	case "record_vulnerability", "record_vulnerability_candidate", "should_continue_execution":
		return executionToolDecision
	case "upsert_execution_coverage", "upsert_project_fact", "skill",
		"update_vulnerability", "delete_vulnerability":
		return executionToolStateMutation
	case "nuclei", "ffuf", "nmap", "exec", "execute", "execute-python-script", "execute_python_script", "waybackurls":
		return executionToolLongRunning
	case "http-framework-test", "http_framework_test", "list_vulnerabilities", "get_vulnerability", "get_execution_coverage", "tool_search", "read_file", "grep", "glob":
		return executionToolProbe
	default:
		return executionToolUnknown
	}
}

func normalizedExecutionToolName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	}
	if i := strings.LastIndex(name, "::"); i >= 0 {
		name = name[i+2:]
	}
	return name
}

func isRecordTool(name string) bool {
	name = normalizedExecutionToolName(name)
	return name == "record_vulnerability" || name == "record_vulnerability_candidate"
}

func executionStateToolRank(name string) int {
	switch normalizedExecutionToolName(name) {
	case "record_vulnerability", "record_vulnerability_candidate":
		return 0
	case "should_continue_execution":
		return 1
	case "upsert_execution_coverage":
		return 2
	case "upsert_project_fact":
		return 3
	case "update_vulnerability", "delete_vulnerability":
		return 4
	case "skill":
		return 5
	default:
		return 100
	}
}

func recordCallMatchesObligation(arguments string, pending *DecisionObligation) bool {
	if pending == nil {
		return false
	}
	var args map[string]interface{}
	if json.Unmarshal([]byte(arguments), &args) != nil {
		return false
	}
	joined := strings.ToLower(arguments)
	if target := ExtractTargetFromText(arguments); target != "" && !strings.EqualFold(NormalizePrimaryTarget(target), pending.Target) {
		return false
	}
	if pending.EvidenceSummary != "" && strings.Contains(joined, strings.ToLower(pending.EvidenceSummary)) {
		return true
	}
	for _, coverage := range pending.LinkedCoverage {
		if strings.Contains(joined, strings.ToLower(coverage)) {
			return true
		}
	}
	// Record schemas differ; a matching primary target is sufficient after the batch has
	// already been forced by this obligation, while an explicit conflicting target is not.
	return strings.Contains(joined, strings.ToLower(pending.Target))
}

func executionDecisionPrecheck(conversationID, toolName, callID, arguments string) string {
	controller := GetConversationExecutionState(conversationID).Controller()
	pending := controller.PendingObligation()
	if pending == nil {
		class := classifyExecutionTool(toolName)
		if class == executionToolDecision || class == executionToolStateMutation {
			return ""
		}
		if allowed, reason := controller.CheckProbeCallAllowed(CallSignature(toolName, arguments)); !allowed {
			return fmt.Sprintf("[framework_tool_outcome] code=%s retryable=false\n当前调用签名已被执行控制器阻断，请换假设或关闭分支。", reason)
		}
		return ""
	}
	if !isRecordTool(toolName) || pending.BoundToolCallID == "" || pending.BoundToolCallID != strings.TrimSpace(callID) {
		return fmt.Sprintf("[framework_tool_outcome] code=dependency_blocked retryable=false obligation=%s\n已有强证据待记录，当前调用已跳过；只允许绑定的 L1/L2 记录调用。", pending.ID)
	}
	if !recordCallMatchesObligation(arguments, pending) {
		return fmt.Sprintf("[framework_tool_outcome] code=dependency_blocked retryable=false obligation=%s\n记录参数与主目标/待记录证据不一致，当前调用已跳过。", pending.ID)
	}
	return ""
}
