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
			"[framework_next_action]\n已有可复现强证据待记录。请用 L1/L2 落库新发现，或对同项目已有洞 update_vulnerability 写入最新复测证据。\n"+
				"- 新建：record_vulnerability_candidate（L1）/ record_vulnerability（L2）\n"+
				"- 已有洞（同项目任意会话）：update_vulnerability（id + proof 等）；误报用 delete_vulnerability\n"+
				"update/delete 为自由管理工具，不与义务互斥。勿只做无关探测。\nevidence: %s",
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
	if pending := controller.PendingObligation(); pending != nil && len(kept) > 0 {
		// L1/L2 always bind+keep when pending (strict target match was deadlocking retests
		// on a related host, e.g. primary 10.x vs retest 183.x). update/delete stay free.
		bound := false
		filtered := kept[:0]
		for _, call := range kept {
			if isFreeVulnManageTool(call.Function.Name) {
				filtered = append(filtered, call)
				continue
			}
			if isL1L2RecordTool(call.Function.Name) {
				controller.BindResolutionCall(pending.ID, call.ID)
				filtered = append(filtered, call)
				bound = true
				if !recordCallMatchesObligation(call.Function.Arguments, pending) {
					// Soft note only: still execute so the agent is not stuck unable to record.
					reason = "pending_record_soft_match"
				}
				continue
			}
			filtered = append(filtered, call)
		}
		kept = filtered
		if !bound && len(kept) == 0 && planned > 0 {
			_ = bound
		}
	}
	if controller.PendingObligation() == nil {
		filtered := kept[:0]
		for _, call := range kept {
			if isFreeVulnManageTool(call.Function.Name) {
				filtered = append(filtered, call)
				continue
			}
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
		if isFreeVulnManageTool(call.Function.Name) {
			continue
		}
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
		msg := fmt.Sprintf("[framework_tool_outcome] code=batch_rewritten retryable=false reason=%s\n本批次工具调用已被执行控制器裁剪，未真实执行。请按框架短指令调整（强证据时优先 L1/L2；update/delete 为自由工具；skill 不与 probe 并发）。", reason)
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
	// update/delete 始终可走：同项目维护工具，不与 L1/L2 义务互斥。
	freeManage := make([]schema.ToolCall, 0, len(calls))
	rest := make([]schema.ToolCall, 0, len(calls))
	for _, call := range calls {
		if isFreeVulnManageTool(call.Function.Name) {
			freeManage = append(freeManage, call)
		} else {
			rest = append(rest, call)
		}
	}
	if pending != nil {
		for _, call := range rest {
			if isL1L2RecordTool(call.Function.Name) {
				out := append([]schema.ToolCall{call}, freeManage...)
				return out, "pending_record"
			}
		}
		if len(freeManage) > 0 {
			return freeManage, "pending_vuln_manage"
		}
		return nil, "pending_record_missing"
	}

	bestState := -1
	bestRank := int(^uint(0) >> 1)
	for i := range rest {
		class := classifyExecutionTool(rest[i].Function.Name)
		if class != executionToolDecision && class != executionToolStateMutation {
			continue
		}
		if rank := executionStateToolRank(rest[i].Function.Name); rank < bestRank {
			bestState, bestRank = i, rank
		}
	}
	if bestState >= 0 {
		out := append([]schema.ToolCall{rest[bestState]}, freeManage...)
		return out, "state_tool_exclusive"
	}
	for i := range rest {
		class := classifyExecutionTool(rest[i].Function.Name)
		if class == executionToolLongRunning {
			out := append([]schema.ToolCall{rest[i]}, freeManage...)
			return out, "long_running_exclusive"
		}
		if class == executionToolUnknown {
			out := append([]schema.ToolCall{rest[i]}, freeManage...)
			return out, "unknown_exclusive"
		}
	}
	// free manage + up to 3 probes
	if len(rest) > 3 {
		out := append(append([]schema.ToolCall(nil), freeManage...), rest[:3]...)
		return out, "probe_limit"
	}
	out := append(append([]schema.ToolCall(nil), freeManage...), rest...)
	if len(freeManage) > 0 {
		return out, "unchanged_with_vuln_manage"
	}
	return out, "unchanged"
}

func classifyExecutionTool(name string) executionToolClass {
	name = normalizedExecutionToolName(name)
	switch name {
	case "record_vulnerability", "record_vulnerability_candidate", "should_continue_execution":
		return executionToolDecision
	case "upsert_execution_coverage", "upsert_project_fact", "skill":
		return executionToolStateMutation
	case "update_vulnerability", "delete_vulnerability":
		// Free project-scoped CRUD: never batch-blocked as exclusive state, never obligation-gated.
		return executionToolProbe
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

// isL1L2RecordTool is formal new-finding write (bound by record obligations).
func isL1L2RecordTool(name string) bool {
	name = normalizedExecutionToolName(name)
	return name == "record_vulnerability" || name == "record_vulnerability_candidate"
}

// isFreeVulnManageTool is always-allowed project CRUD (cross-session same project).
func isFreeVulnManageTool(name string) bool {
	name = normalizedExecutionToolName(name)
	return name == "update_vulnerability" || name == "delete_vulnerability"
}

// isRecordTool tools that may clear a pending record obligation after success.
func isRecordTool(name string) bool {
	return isL1L2RecordTool(name) || normalizedExecutionToolName(name) == "update_vulnerability"
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
	case "skill":
		return 4
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
	// Explicit target field must not conflict with the obligation primary target.
	if raw, ok := args["target"].(string); ok {
		if t := strings.TrimSpace(raw); t != "" {
			nt := NormalizePrimaryTarget(t)
			pt := pending.Target
			if nt != "" && pt != "" && !strings.EqualFold(nt, pt) &&
				!strings.Contains(strings.ToLower(pt), strings.ToLower(nt)) &&
				!strings.Contains(strings.ToLower(nt), strings.ToLower(pt)) {
				return false
			}
		}
	}
	// update_vulnerability: id + substantive retest fields fulfill the obligation.
	// Agents often omit repeating the host when only refreshing proof/description.
	if id, _ := args["id"].(string); strings.TrimSpace(id) != "" {
		for _, key := range []string{"proof", "description", "impact", "title", "status", "severity", "vuln_urls", "recommendation"} {
			if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
				return true
			}
		}
	}
	if target := ExtractTargetFromText(arguments); target != "" && !strings.EqualFold(NormalizePrimaryTarget(target), pending.Target) {
		// Soft host presence in free text (e.g. proof URL) is OK when it matches primary host.
		pt := strings.ToLower(pending.Target)
		nt := strings.ToLower(NormalizePrimaryTarget(target))
		if pt == "" || nt == "" || (!strings.Contains(pt, nt) && !strings.Contains(nt, pt)) {
			return false
		}
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
	return pending.Target != "" && strings.Contains(joined, strings.ToLower(pending.Target))
}

func executionDecisionPrecheck(conversationID, toolName, callID, arguments string) string {
	// Project-scoped update/delete are free tools: never blocked by obligations or retry budget.
	if isFreeVulnManageTool(toolName) {
		return ""
	}
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
	// L1/L2 always allowed while a record obligation is open. Bind this call id so
	// ResolveConversationObligation can close the duty after a successful write.
	// (Strict argument match previously blocked legitimate retests on a related host.)
	if isL1L2RecordTool(toolName) {
		if pending.BoundToolCallID == "" || pending.BoundToolCallID != strings.TrimSpace(callID) {
			controller.BindResolutionCall(pending.ID, callID)
		}
		return ""
	}
	return fmt.Sprintf("[framework_tool_outcome] code=dependency_blocked retryable=false obligation=%s\n已有强证据待记录，当前调用已跳过；请调用 record_vulnerability / record_vulnerability_candidate 落库，或 update_vulnerability 更新已有洞（自由工具）。", pending.ID)
}
