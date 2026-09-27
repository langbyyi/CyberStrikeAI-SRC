package multiagent

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"cyberstrike-ai/internal/einomcp"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/prebuilt/supervisor"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// productionSupervisorToolsConfig 复刻 runner.go supervisor 分支的工具中间件链
// （不含 transfer 接管，由 withEinoAgenticTransferTool 追加），
// 确保委派回归测试同时覆盖 HITL 免审批 / RBAC / 输出守卫。
func productionSupervisorToolsConfig() adk.ToolsConfig {
	return adk.ToolsConfig{
		ToolsNodeConfig: compose.ToolsNodeConfig{
			ToolCallMiddlewares: []compose.ToolMiddleware{
				modelOutputExecutionGuardMiddleware(),
				localToolRBACMiddleware(),
				hitlToolCallMiddleware(),
				softRecoveryToolMiddleware(),
			},
		},
	}
}

// newTestAgenticSupervisor 复刻 runner.go supervisor 分支的装配方式：
// typed 监督者 → 按 typed 接口注册子代理 → 包 classic 适配层 → supervisor.New。
func newTestAgenticSupervisor(
	t *testing.T,
	ctx context.Context,
	supModel *capturingAgenticChatModel,
	subModel *capturingAgenticChatModel,
) adk.ResumableAgent {
	t.Helper()
	supTyped, err := newEinoAgenticChatModelAgent(ctx, einoAgenticChatModelAgentConfig{
		Name:        "boss",
		Description: "supervisor",
		Instruction: "delegate when useful",
		Model:       supModel,
		ToolsConfig: withEinoAgenticTransferTool(productionSupervisorToolsConfig()),
		Exit:        &einoAgenticExitTool{},
	})
	if err != nil {
		t.Fatalf("supervisor agent: %v", err)
	}
	subTyped, err := newEinoAgenticChatModelAgent(ctx, einoAgenticChatModelAgentConfig{
		Name:        "expert",
		Description: "specialist",
		Instruction: "do the work",
		Model:       subModel,
		Exit:        &einoAgenticExitTool{},
	})
	if err != nil {
		t.Fatalf("sub agent: %v", err)
	}
	if err := bindAgenticSupervisorSubAgents(ctx, nil, supTyped, []adk.TypedAgent[*schema.AgenticMessage]{subTyped}); err != nil {
		t.Fatalf("bindAgenticSupervisorSubAgents: %v", err)
	}
	root, err := supervisor.New(ctx, &supervisor.Config{
		Supervisor: newEinoAgenticMessageAgentAdapter(supTyped),
		SubAgents:  []adk.Agent{newEinoAgenticMessageAgentAdapter(subTyped)},
	})
	if err != nil {
		t.Fatalf("supervisor.New: %v", err)
	}
	return root
}

func collectAgentEvents(t *testing.T, root adk.ResumableAgent, ctx context.Context, input *adk.AgentInput) []*adk.AgentEvent {
	t.Helper()
	iter := root.Run(ctx, input)
	var events []*adk.AgentEvent
	for {
		ev, ok := iter.Next()
		if !ok {
			break
		}
		if ev.Err != nil {
			t.Fatalf("agent event error: %v", ev.Err)
		}
		events = append(events, ev)
	}
	return events
}

// 回归：supervisor 主代理经 classic 适配层包装后，子代理必须真正注册进
// TypedChatModelAgent，否则 transfer_to_agent 不在 tools 索引里、委派整体失效。
func TestAgenticSupervisorDelegatesToSubAgentOnTransfer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	supModel := &capturingAgenticChatModel{outputs: []*schema.AgenticMessage{
		agenticAssistantToolCall("call-1", adk.TransferToAgentToolName, `{"agent_name":"expert"}`),
		agenticAssistantToolCall("call-2", "exit", `{"final_result":"delegated and done"}`),
	}}
	subModel := &capturingAgenticChatModel{}
	root := newTestAgenticSupervisor(t, ctx, supModel, subModel)

	result, err := runEinoADKAgentLoop(ctx, &einoADKRunLoopArgs{
		OrchMode:         "supervisor",
		OrchestratorName: "boss",
		ConversationID:   "supervisor-delegation",
		DA:               root,
	}, []*schema.Message{schema.UserMessage("go")})
	if err != nil {
		t.Fatalf("runEinoADKAgentLoop: %v", err)
	}

	if got := len(subModel.snapshotInputs()); got == 0 {
		t.Fatal("supervisor 未把任务交给子代理：子代理模型 0 次调用（transfer_to_agent 未注册）")
	}
	if result.CompletionSignal != "exit" || result.FinalResponse != "delegated and done" {
		t.Fatalf("completion result = %+v", result)
	}
}

// transfer_to_agent 动作事件必须在主代理侧可见（供前端展示移交轨迹）。
func TestAgenticSupervisorEmitsTransferActionEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	supModel := &capturingAgenticChatModel{outputs: []*schema.AgenticMessage{
		agenticAssistantToolCall("call-1", adk.TransferToAgentToolName, `{"agent_name":"expert"}`),
		agenticAssistantToolCall("call-2", "exit", `{"final_result":"done"}`),
	}}
	root := newTestAgenticSupervisor(t, ctx, supModel, &capturingAgenticChatModel{})

	iter := root.Run(ctx, &adk.AgentInput{Messages: []*schema.Message{schema.UserMessage("go")}})
	var transferTargets []string
	for {
		ev, ok := iter.Next()
		if !ok {
			break
		}
		if ev.Err != nil {
			t.Fatalf("agent event error: %v", ev.Err)
		}
		if ev.Action != nil && ev.Action.TransferToAgent != nil {
			transferTargets = append(transferTargets, ev.Action.TransferToAgent.DestAgentName)
		}
	}
	// 去程（boss → expert）与回程（expert → boss）都必须是真实动作事件。
	if len(transferTargets) == 0 || transferTargets[0] != "expert" {
		t.Fatalf("transfer 目标序列 = %v, 首跳应为 expert", transferTargets)
	}
	if !slices.Contains(transferTargets, "boss") {
		t.Fatalf("transfer 目标序列 = %v, 缺少回程 boss", transferTargets)
	}
}

// 未绑定子代理时 transfer_to_agent 不在 tools 索引里（修复前的既有形态）：
// 走生产的未知工具兜底后模型拿到提醒，但委派不会发生。
func TestAgenticSupervisorWithoutSubAgentRegistrationCannotDelegate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	subModel := &capturingAgenticChatModel{}
	supTyped, err := newEinoAgenticChatModelAgent(ctx, einoAgenticChatModelAgentConfig{
		Name:        "boss",
		Description: "supervisor",
		Instruction: "delegate when useful",
		Model: &capturingAgenticChatModel{outputs: []*schema.AgenticMessage{
			agenticAssistantToolCall("call-1", adk.TransferToAgentToolName, `{"agent_name":"expert"}`),
			agenticAssistantToolCall("call-2", "exit", `{"final_result":"gave up delegating"}`),
		}},
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{
				UnknownToolsHandler: einomcp.UnknownToolReminderHandler(),
			},
		},
		MaxIterations: 4,
		Exit:          &einoAgenticExitTool{},
	})
	if err != nil {
		t.Fatalf("supervisor agent: %v", err)
	}
	_ = subModel
	iter := supTyped.Run(ctx, &adk.TypedAgentInput[*schema.AgenticMessage]{
		Messages: EinoMessagesToAgentic([]*schema.Message{schema.UserMessage("go")}),
	})
	for {
		ev, ok := iter.Next()
		if !ok {
			break
		}
		if ev.Err != nil {
			t.Fatalf("agent event error: %v", ev.Err)
		}
	}
	if got := len(subModel.snapshotInputs()); got != 0 {
		t.Fatalf("未注册子代理时不应发生委派，子代理模型调用 %d 次", got)
	}
}

func TestBindAgenticSupervisorSubAgentsRejectsSecondRegistration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	supTyped, err := newEinoAgenticChatModelAgent(ctx, einoAgenticChatModelAgentConfig{
		Name: "boss", Description: "supervisor", Instruction: "x", Model: &capturingAgenticChatModel{},
	})
	if err != nil {
		t.Fatalf("supervisor agent: %v", err)
	}
	expert, err := newEinoAgenticChatModelAgent(ctx, einoAgenticChatModelAgentConfig{
		Name: "expert", Description: "specialist", Instruction: "x", Model: &capturingAgenticChatModel{},
	})
	if err != nil {
		t.Fatalf("sub agent: %v", err)
	}
	subs := []adk.TypedAgent[*schema.AgenticMessage]{expert}
	if err := bindAgenticSupervisorSubAgents(ctx, nil, supTyped, subs); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	if err := bindAgenticSupervisorSubAgents(ctx, nil, supTyped, subs); err == nil {
		t.Fatal("重复注册应返回错误")
	}
	// 空子代理列表是 no-op（supervisor 未配置子代理时不得报错）。
	if err := bindAgenticSupervisorSubAgents(ctx, nil, supTyped, nil); err != nil {
		t.Fatalf("empty bind: %v", err)
	}
}

func TestAgenticTransferToolMiddlewareInterceptsOfficialTransfer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	nextCalled := false
	mw := agenticTransferToolMiddleware()
	endpoint := mw.Invokable(func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
		nextCalled = true
		return nil, errors.New("官方 transfer 工具不应执行（会写经典 Message state）")
	})
	chain := compose.NewChain[string, string](compose.WithGenLocalState(func(context.Context) *agenticShapedReactState {
		return &agenticShapedReactState{}
	}))
	chain.AppendLambda(compose.InvokableLambda(func(ctx context.Context, in string) (string, error) {
		out, err := endpoint(ctx, &compose.ToolInput{
			Name:      adk.TransferToAgentToolName,
			Arguments: `{"agent_name":"expert"}`,
		})
		if err != nil {
			return "", err
		}
		if out == nil || !strings.Contains(out.Result, "expert") {
			return "", errors.New("缺少移交结果文案")
		}
		if nextCalled {
			return "", errors.New("官方 transfer 工具被执行")
		}
		return in, compose.ProcessState(ctx, func(_ context.Context, st *agenticShapedReactState) error {
			action := st.ToolGenActions[adk.TransferToAgentToolName]
			if action == nil || action.TransferToAgent == nil || action.TransferToAgent.DestAgentName != "expert" {
				return errors.New("transfer 动作未写入当前 react state")
			}
			return nil
		})
	}))
	r, err := chain.Compile(ctx)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := r.Invoke(ctx, "ok"); err != nil {
		t.Fatalf("invoke: %v", err)
	}
}

func TestAgenticTransferToolMiddlewareLeavesOtherToolsUntouched(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mw := agenticTransferToolMiddleware()
	endpoint := mw.Invokable(func(_ context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
		return &compose.ToolOutput{Result: "passthrough:" + input.Name}, nil
	})
	out, err := endpoint(ctx, &compose.ToolInput{Name: "execute", Arguments: `{"command":"id"}`})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if out.Result != "passthrough:execute" {
		t.Fatalf("result = %q", out.Result)
	}
}
