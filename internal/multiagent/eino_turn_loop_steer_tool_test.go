package multiagent

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

const steerSlowToolName = "slow_probe"

// steerToolCallingModel 第 1 次调用返回 slow_probe 工具调用，之后返回最终答案。
// 用于复现真实时序：用户补充指示落在「工具执行期间」。
type steerToolCallingModel struct {
	mu     sync.Mutex
	inputs [][]*schema.Message
}

func (m *steerToolCallingModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *steerToolCallingModel) Generate(ctx context.Context, input []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	m.mu.Lock()
	m.inputs = append(m.inputs, cloneSchemaMessages(input))
	callNo := len(m.inputs)
	m.mu.Unlock()
	if callNo == 1 {
		return schema.AssistantMessage("", []schema.ToolCall{{
			ID:   "call-1",
			Type: "function",
			Function: schema.FunctionCall{
				Name:      steerSlowToolName,
				Arguments: `{}`,
			},
		}}), nil
	}
	return schema.AssistantMessage("final answer", nil), nil
}

func (m *steerToolCallingModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func (m *steerToolCallingModel) snapshot() [][]*schema.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]*schema.Message, len(m.inputs))
	for i := range m.inputs {
		out[i] = cloneSchemaMessages(m.inputs[i])
	}
	return out
}

func (m *steerToolCallingModel) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.inputs)
}

// steerSlowTool 模拟长工具调用：release 模式阻塞到显式放行，duration 模式跑满时长。
// 记录每次调用是正常完成还是被取消，用于断言「引导不掐断正在跑的工具」。
type steerSlowTool struct {
	started  chan struct{}
	release  chan struct{}
	duration time.Duration

	mu       sync.Mutex
	outcomes []string
}

func (t *steerSlowTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name:        steerSlowToolName,
		Desc:        "slow probe",
		ParamsOneOf: schema.NewParamsOneOfByParams(map[string]*schema.ParameterInfo{}),
	}, nil
}

func (t *steerSlowTool) record(outcome string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outcomes = append(t.outcomes, outcome)
}

func (t *steerSlowTool) outcomesSnapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.outcomes...)
}

func (t *steerSlowTool) InvokableRun(ctx context.Context, _ string, _ ...tool.Option) (string, error) {
	select {
	case t.started <- struct{}{}:
	default:
	}
	if t.duration > 0 {
		select {
		case <-ctx.Done():
			t.record("aborted")
			return "", ctx.Err()
		case <-time.After(t.duration):
			t.record("completed")
			return "probe done", nil
		}
	}
	select {
	case <-ctx.Done():
		t.record("aborted")
		return "", ctx.Err()
	case <-t.release:
		t.record("completed")
		return "probe done", nil
	}
}

func newSteerToolAgent(t *testing.T, ctx context.Context, mockModel *steerToolCallingModel, slow *steerSlowTool) adk.Agent {
	t.Helper()
	agent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name:  "steer-tool-agent",
		Model: mockModel,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{
				Tools: []tool.BaseTool{slow},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewChatModelAgent: %v", err)
	}
	return agent
}

func steerInputCarriesMark(inputs [][]*schema.Message, mark string) bool {
	if len(inputs) == 0 {
		return false
	}
	for _, msg := range inputs[len(inputs)-1] {
		if msg != nil && strings.Contains(msg.Content, mark) {
			return true
		}
	}
	return false
}

// TestEinoTurnLoopUserSteerDuringToolCallStartsNextTurn 执行中引导必须落在
// 「工具轮结束」的安全点：真实场景里用户正是在长工具跑着的时候补一句。
// 若取消信号没到达工具轮安全点，引导会静默丢失（模型完全看不到该消息）。
func TestEinoTurnLoopUserSteerDuringToolCallStartsNextTurn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	mockModel := &steerToolCallingModel{}
	slow := &steerSlowTool{started: make(chan struct{}, 4), release: make(chan struct{})}
	agent := newSteerToolAgent(t, ctx, mockModel, slow)

	runtime := NewEinoTurnLoopRuntime(EinoTurnLoopRuntimeConfig{
		Agent:            agent,
		InitialMessages:  []*schema.Message{schema.UserMessage("initial task")},
		InterruptTimeout: 20 * time.Millisecond,
	})
	runtime.Run(ctx)

	select {
	case <-slow.started:
	case <-ctx.Done():
		t.Fatal("slow tool did not start")
	}

	const mark = "STEER-MARK-TOOL"
	if !runtime.PushUserSteerWithTrace(mark, nil) {
		t.Fatal("user steer push was rejected")
	}
	close(slow.release)

	deadline := time.After(5 * time.Second)
	for mockModel.callCount() < 2 {
		select {
		case <-deadline:
			t.Fatalf("引导期间工具轮安全点未触发新一轮：模型调用次数=%d", mockModel.callCount())
		case <-time.After(20 * time.Millisecond):
		}
	}
	runtime.StopWhenIdle()
	runtime.Wait()

	if !steerInputCarriesMark(mockModel.snapshot(), mark) {
		t.Fatalf("引导内容未进入下一轮模型输入：%#v", mockModel.snapshot())
	}
}

// TestEinoTurnLoopUserSteerDoesNotAbortRunningTool 引导必须让正在跑的工具自然结束，
// 而不是靠超时升级把它掐断。
// 工具耗时 4 秒 > 「中断并继续」的 3 秒抢占升级超时：若引导沿用 3 秒，这里会看到
// aborted，并在 trace 里丢掉这次工具结果。实测（Kali 真机）3 秒升级会把 30 秒的
// exec 打断重跑，因此引导使用远长于单步合法耗时的 einoTurnLoopSteerPreemptTimeout。
func TestEinoTurnLoopUserSteerDoesNotAbortRunningTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockModel := &steerToolCallingModel{}
	slow := &steerSlowTool{
		started:  make(chan struct{}, 4),
		duration: 4 * time.Second,
	}
	agent := newSteerToolAgent(t, ctx, mockModel, slow)

	runtime := NewEinoTurnLoopRuntime(EinoTurnLoopRuntimeConfig{
		Agent:            agent,
		InitialMessages:  []*schema.Message{schema.UserMessage("initial task")},
		InterruptTimeout: 20 * time.Millisecond,
	})
	runtime.Run(ctx)

	select {
	case <-slow.started:
	case <-ctx.Done():
		t.Fatal("slow tool did not start")
	}

	const mark = "STEER-MARK-NO-ABORT"
	if !runtime.PushUserSteerWithTrace(mark, nil) {
		t.Fatal("user steer push was rejected")
	}

	deadline := time.After(15 * time.Second)
	for mockModel.callCount() < 2 {
		select {
		case <-deadline:
			t.Fatalf("引导未触发下一轮：模型调用次数=%d 工具结果=%v", mockModel.callCount(), slow.outcomesSnapshot())
		case <-time.After(20 * time.Millisecond):
		}
	}
	runtime.StopWhenIdle()
	runtime.Wait()

	if got := slow.outcomesSnapshot(); len(got) != 1 || got[0] != "completed" {
		t.Fatalf("工具执行结果 = %v，want [completed]（引导不得掐断正在跑的工具）", got)
	}
	if !steerInputCarriesMark(mockModel.snapshot(), mark) {
		t.Fatalf("引导内容未进入下一轮模型输入：%#v", mockModel.snapshot())
	}
}

// TestEinoTurnLoopSteerPreemptTimeoutExceedsSingleStep 引导的升级超时必须远长于
// 单步合法耗时：退化成秒级就会在工具正常执行中把工具掐断（见上一条用例）。
func TestEinoTurnLoopSteerPreemptTimeoutExceedsSingleStep(t *testing.T) {
	if einoTurnLoopSteerPreemptTimeout < 30*time.Minute {
		t.Fatalf("引导升级超时 = %v，必须远长于任何单步合法耗时（配置 agent.tool_timeout_minutes 默认 60 分钟）",
			einoTurnLoopSteerPreemptTimeout)
	}
	if einoTurnLoopSteerPreemptTimeout <= einoTurnLoopInterruptPreemptTimeout {
		t.Fatalf("引导升级超时 = %v，不得小于「中断并继续」的 %v",
			einoTurnLoopSteerPreemptTimeout, einoTurnLoopInterruptPreemptTimeout)
	}
}

// 对照组：「中断并继续」在同样的工具执行窗口内也必须能切换轮次。
// 两条路径共用 TurnLoop 抢占通道，若此用例通过而引导用例失败，问题就在引导的取消选项。
func TestEinoTurnLoopInterruptContinueDuringToolCallStartsNextTurn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	mockModel := &steerToolCallingModel{}
	slow := &steerSlowTool{started: make(chan struct{}, 4), release: make(chan struct{})}
	agent := newSteerToolAgent(t, ctx, mockModel, slow)

	runtime := NewEinoTurnLoopRuntime(EinoTurnLoopRuntimeConfig{
		Agent:            agent,
		InitialMessages:  []*schema.Message{schema.UserMessage("initial task")},
		InterruptTimeout: 20 * time.Millisecond,
	})
	runtime.Run(ctx)

	select {
	case <-slow.started:
	case <-ctx.Done():
		t.Fatal("slow tool did not start")
	}

	const mark = "INTERRUPT-MARK-TOOL"
	if !runtime.PushInterruptContinueWithTrace(mark, nil) {
		t.Fatal("interrupt continue push was rejected")
	}
	close(slow.release)

	deadline := time.After(5 * time.Second)
	for mockModel.callCount() < 2 {
		select {
		case <-deadline:
			t.Fatalf("中断并继续期间工具轮安全点未触发新一轮：模型调用次数=%d", mockModel.callCount())
		case <-time.After(20 * time.Millisecond):
		}
	}
	runtime.StopWhenIdle()
	runtime.Wait()

	if !steerInputCarriesMark(mockModel.snapshot(), mark) {
		t.Fatalf("中断说明未进入下一轮模型输入：%#v", mockModel.snapshot())
	}
}

// agenticInputsCarryMark 报告任意一次模型输入里是否已带上该标记文本。
func agenticInputsCarryMark(inputs [][]*schema.AgenticMessage, mark string) bool {
	for _, msgs := range inputs {
		for _, msg := range msgs {
			if strings.Contains(agenticMessageText(msg), mark) {
				return true
			}
		}
	}
	return false
}

// TestEinoTurnLoopUserSteerReachesDescendantSafePoint 生产装配下的引导回归：
// eino_single / 多代理的 TurnLoop 根 agent 是 adapter 包装
// （newEinoAgenticChatModelAgentAdapter），真实 ChatModelAgent 在内层。
// 本用例是唯一按该结构跑的引导用例，锁定「在这种装配下引导确实进到了模型输入」。
// 注意：它**不能**判别 WithRecursive 的必要性——把抢占换成不带递归的 WithPreempt
// 本用例仍会通过（item 无论如何都会在轮次结束时被消费），真机上的因果未逐项隔离。
func TestEinoTurnLoopUserSteerReachesDescendantSafePoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	slow := &steerSlowTool{started: make(chan struct{}, 4), release: make(chan struct{})}
	model := &capturingAgenticChatModel{outputs: []*schema.AgenticMessage{
		agenticAssistantToolCall("call-1", steerSlowToolName, `{}`),
		agenticAssistantToolCall("call-2", adk.ToolInfoExit.Name, `{"final_result":"done"}`),
	}}
	root, err := newEinoAgenticChatModelAgentAdapter(ctx, einoAgenticChatModelAgentConfig{
		Name:  "steer-agentic-root",
		Model: model,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{
				Tools: []tool.BaseTool{slow},
			},
		},
		Exit: &einoAgenticExitTool{},
	})
	if err != nil {
		t.Fatalf("newEinoAgenticChatModelAgentAdapter: %v", err)
	}

	runtime := NewEinoTurnLoopRuntime(EinoTurnLoopRuntimeConfig{
		Agent:            root,
		InitialMessages:  []*schema.Message{schema.UserMessage("initial task")},
		InterruptTimeout: 20 * time.Millisecond,
	})
	runtime.Run(ctx)

	select {
	case <-slow.started:
	case <-ctx.Done():
		t.Fatal("slow tool did not start")
	}

	const mark = "STEER-MARK-DESCENDANT"
	if !runtime.PushUserSteerWithTrace(mark, nil) {
		t.Fatal("user steer push was rejected")
	}
	close(slow.release)

	deadline := time.After(20 * time.Second)
	for !agenticInputsCarryMark(model.snapshotInputs(), mark) {
		select {
		case <-deadline:
			t.Fatalf("引导未到达内层安全点（模型调用 %d 次）：引导没有进入内层 agent 的模型输入",
				len(model.snapshotInputs()))
		case <-time.After(25 * time.Millisecond):
		}
	}

	runtime.StopWhenIdle()
	runtime.Wait()
}
