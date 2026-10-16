package multiagent

import (
	"context"
	"strings"
	"time"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

const (
	einoTurnLoopInterruptPreemptTimeout = 3 * time.Second
	einoTurnLoopIdleStop                = 250 * time.Millisecond

	// einoTurnLoopSteerPreemptTimeout 执行中引导抢占的「升级兜底」超时。
	//
	// ADK 没有「安全点抢占 + WithRecursive + 无超时」的组合选项：递归传播只存在于
	// WithPreemptTimeout 里，而它会在超时后升级为立即中止（掐断正在跑的步骤）。
	// 取 60 分钟对齐配置默认的单次工具上限 agent.tool_timeout_minutes（默认 60）：
	// 正常情况下工具轮/模型调用一结束就命中安全点完成切换，升级只用于运行真正挂死
	// （用户另有「停止任务」）。注意该配置若被设为 0（不限）或大于 60，长时间工具仍
	// 可能在升级点被中止——需要更宽窗口时调大本常量。
	einoTurnLoopSteerPreemptTimeout = 60 * time.Minute

	// TurnLoop item 类型：中断续跑与执行中用户补充指示（引导）。
	EinoTurnLoopItemKindInterruptContinue = "interrupt_continue"
	EinoTurnLoopItemKindUserSteer         = "user_steer"
)

// EinoTurnLoopItem is the conversation-level input unit consumed by an Eino
// TurnLoop. The item is gob-friendly so it can be checkpointed by TurnLoop when
// a CheckPointStore is configured.
type EinoTurnLoopItem struct {
	Messages []*schema.Message
	Kind     string
	Note     string
}

// EinoTurnLoopRuntime wraps Eino's native TurnLoop with the semantics this
// project needs: persistent per-conversation runtime, user-supplement preempt,
// and graceful idle shutdown.
type EinoTurnLoopRuntime struct {
	loop             *adk.TurnLoop[EinoTurnLoopItem, *schema.Message]
	interruptTimeout time.Duration
}

type EinoTurnLoopRuntimeConfig struct {
	Agent            adk.Agent
	InitialMessages  []*schema.Message
	Store            adk.CheckPointStore
	CheckpointID     string
	EnableStreaming  bool
	PrepareAgent     func(context.Context, *adk.TurnLoop[EinoTurnLoopItem, *schema.Message], []EinoTurnLoopItem) (adk.Agent, error)
	OnAgentEvents    func(context.Context, *adk.TurnContext[EinoTurnLoopItem, *schema.Message], *adk.AsyncIterator[*adk.AgentEvent]) error
	InterruptTimeout time.Duration
}

func NewEinoTurnLoopRuntime(cfg EinoTurnLoopRuntimeConfig) *EinoTurnLoopRuntime {
	timeout := cfg.InterruptTimeout
	if timeout <= 0 {
		timeout = einoTurnLoopInterruptPreemptTimeout
	}
	enableStreaming := cfg.EnableStreaming
	prepareAgent := cfg.PrepareAgent
	history := &einoTurnHistory{}
	if prepareAgent == nil {
		prepareAgent = func(context.Context, *adk.TurnLoop[EinoTurnLoopItem, *schema.Message], []EinoTurnLoopItem) (adk.Agent, error) {
			return cfg.Agent, nil
		}
	}
	loop := adk.NewTurnLoop[EinoTurnLoopItem, *schema.Message](adk.TurnLoopConfig[EinoTurnLoopItem, *schema.Message]{
		Store:        cfg.Store,
		CheckpointID: cfg.CheckpointID,
		GenInput: func(ctx context.Context, _ *adk.TurnLoop[EinoTurnLoopItem, *schema.Message], items []EinoTurnLoopItem) (*adk.GenInputResult[EinoTurnLoopItem, *schema.Message], error) {
			msgs := mergeEinoTurnLoopMessages(items)
			// 二开的中断续跑（interrupt_continue）与执行中用户补充指示（user_steer）
			// 已把被中断轮的 model-facing 轨迹前置进 item 消息，此时 history 再前置
			// 会造成同一进度重复输入；仅纯提示词续跑等无轨迹场景用 history 找回跨轮记忆。
			if !einoItemsCarryModelFacingTrace(items) {
				msgs = append(history.nextInput(), msgs...)
			}
			history = &einoTurnHistory{}
			history.begin(msgs)
			return &adk.GenInputResult[EinoTurnLoopItem, *schema.Message]{
				RunCtx: context.WithValue(ctx, einoTurnHistoryKey{}, history),
				Input: &adk.AgentInput{
					Messages:        msgs,
					EnableStreaming: enableStreaming,
				},
				Consumed: items,
			}, nil
		},
		GenResume: func(ctx context.Context, _ *adk.TurnLoop[EinoTurnLoopItem, *schema.Message], interruptedItems, unhandledItems, newItems []EinoTurnLoopItem) (*adk.GenResumeResult[EinoTurnLoopItem, *schema.Message], error) {
			consumed := make([]EinoTurnLoopItem, 0, len(interruptedItems)+len(newItems))
			consumed = append(consumed, interruptedItems...)
			consumed = append(consumed, newItems...)
			remaining := append([]EinoTurnLoopItem(nil), unhandledItems...)
			return &adk.GenResumeResult[EinoTurnLoopItem, *schema.Message]{
				RunCtx:    context.WithValue(ctx, einoTurnHistoryKey{}, history),
				Consumed:  consumed,
				Remaining: remaining,
			}, nil
		},
		PrepareAgent: prepareAgent,
		OnAgentEvents: func(ctx context.Context, tc *adk.TurnContext[EinoTurnLoopItem, *schema.Message], events *adk.AsyncIterator[*adk.AgentEvent]) error {
			return history.wrapEvents(cfg.OnAgentEvents)(ctx, tc, events)
		},
	})
	if len(cfg.InitialMessages) > 0 {
		loop.Push(EinoTurnLoopItem{Kind: "initial", Messages: cloneSchemaMessages(cfg.InitialMessages)})
	}
	return &EinoTurnLoopRuntime{loop: loop, interruptTimeout: timeout}
}

func (r *EinoTurnLoopRuntime) Run(ctx context.Context) {
	if r == nil || r.loop == nil {
		return
	}
	r.loop.Run(ctx)
}

func (r *EinoTurnLoopRuntime) PushInterruptContinue(note string) bool {
	return r.PushInterruptContinueWithTrace(note, nil)
}

// PushInterruptContinueWithTrace 携带被中断轮的模型可见轨迹续跑。
// ADK TurnLoop 抢占后不延续被中断 turn 的消息状态，续跑输入若只剩中断提示词，
// 模型会丢失全部已完成步骤（官方 issue #121：中断后记忆丢失/重复执行）。
// 把轨迹作为前置消息塞进 interrupt_continue item，续跑输入即恢复为
// 「原有进度 + 用户备注」，与「中断并继续」的产品语义一致。
// prefix 为空时退化为纯提示词续跑（首次模型调用前中断等场景）。
func (r *EinoTurnLoopRuntime) PushInterruptContinueWithTrace(note string, prefix []*schema.Message) bool {
	return r.pushUserInput(
		EinoTurnLoopItemKindInterruptContinue,
		note,
		formatInterruptContinuePrompt(note),
		prefix,
		adk.WithPreemptTimeout[EinoTurnLoopItem, *schema.Message](adk.AnySafePoint, r.interruptTimeout),
	)
}

// PushUserSteerWithTrace 把用户在任务执行过程中补充的指示（引导）推入 TurnLoop。
//
// 抢占参数取 WithPreemptTimeout(AnySafePoint, einoTurnLoopSteerPreemptTimeout)：
//   - 升级超时远长于单步合法耗时，避免「中断并继续」那套 3 秒升级掐断正在跑的工具
//     （真机实测：3 秒会把 30 秒的 exec 打断重跑）。这一条有判别性回归测试。
//   - 顺带获得 WithRecursive（ADK 只在 WithPreemptTimeout 里附带递归传播）。本项目
//     TurnLoop 的根 agent 是 adapter 包装（newEinoAgenticChatModelAgentAdapter），
//     真实安全点在内层，带递归是保守选择；但递归对结果的决定作用**未逐项隔离**：
//     单测里不带递归也能送达（item 无论如何都会在轮次结束时被消费），真机差异更可能
//     来自超时升级路径。保留递归无额外副作用——升级不触发就不会有立即中止的级联。
func (r *EinoTurnLoopRuntime) PushUserSteerWithTrace(note string, prefix []*schema.Message) bool {
	return r.pushUserInput(
		EinoTurnLoopItemKindUserSteer,
		note,
		formatUserSteerPrompt(note),
		prefix,
		adk.WithPreemptTimeout[EinoTurnLoopItem, *schema.Message](adk.AnySafePoint, einoTurnLoopSteerPreemptTimeout),
	)
}

// pushUserInput 把一条用户输入作为 TurnLoop item 入队并请求安全点切换。
// 返回 false 仅当 loop 不存在或已停止；调用方据此回退到「无法引导」的提示。
func (r *EinoTurnLoopRuntime) pushUserInput(
	kind, note, prompt string,
	prefix []*schema.Message,
	opts ...adk.PushOption[EinoTurnLoopItem, *schema.Message],
) bool {
	if r == nil || r.loop == nil {
		return false
	}
	msgs := cloneSchemaMessages(prefix)
	msgs = append(msgs, schema.UserMessage(prompt))
	item := EinoTurnLoopItem{
		Kind:     kind,
		Note:     strings.TrimSpace(note),
		Messages: msgs,
	}
	ok, ack := r.loop.Push(item, opts...)
	if ack != nil {
		go func() { <-ack }()
	}
	return ok
}

func (r *EinoTurnLoopRuntime) StopImmediate(cause string) {
	if r == nil || r.loop == nil {
		return
	}
	r.loop.Stop(adk.WithImmediate(), adk.WithStopCause(cause))
}

func (r *EinoTurnLoopRuntime) StopWhenIdle() {
	if r == nil || r.loop == nil {
		return
	}
	r.loop.Stop(adk.UntilIdleFor(einoTurnLoopIdleStop))
}

func (r *EinoTurnLoopRuntime) Wait() *adk.TurnLoopExitState[EinoTurnLoopItem, *schema.Message] {
	if r == nil || r.loop == nil {
		return nil
	}
	return r.loop.Wait()
}

func mergeEinoTurnLoopMessages(items []EinoTurnLoopItem) []*schema.Message {
	var msgs []*schema.Message
	for _, item := range items {
		msgs = append(msgs, cloneSchemaMessages(item.Messages)...)
	}
	return msgs
}

// einoItemsCarryModelFacingTrace 报告 items 中是否有已携带上一轮模型可见轨迹前缀的
// 续跑消息（轨迹前置 + 提示词 > 1 条）；纯提示词续跑为 1 条。
// 中断续跑与执行中用户补充指示都走这条前缀，避免与 history 重复注入同一进度。
func einoItemsCarryModelFacingTrace(items []EinoTurnLoopItem) bool {
	for _, item := range items {
		if item.Kind != EinoTurnLoopItemKindInterruptContinue && item.Kind != EinoTurnLoopItemKindUserSteer {
			continue
		}
		if len(item.Messages) > 1 {
			return true
		}
	}
	return false
}

// interruptContinueRecoverHint 中断续跑的上下文找回引导。
// ADK TurnLoop 抢占后续跑 turn 只收到本提示词，被中断轮的消息状态不会延续；
// 引导模型先从项目黑板/漏洞库找回已完成步骤，避免"缺上下文"空转或中止。
const interruptContinueRecoverHint = "若看不到此前已完成的步骤与工具结果，先用 list_project_facts / list_vulnerabilities 查看项目已沉淀的事实与漏洞，基于其继续推进；不要重复大规模侦察，也不要因缺上下文而中止。"

func formatInterruptContinuePrompt(note string) string {
	note = strings.TrimSpace(note)
	if note == "" {
		return "用户请求中断当前推理并继续。请基于已经完成的步骤继续，不要重复已完成工具调用。" + interruptContinueRecoverHint
	}
	return "用户请求中断当前推理并补充上下文后继续：\n" + note +
		"\n\n请基于已经完成的步骤继续，不要重复已完成工具调用。" + interruptContinueRecoverHint
}

// formatUserSteerPrompt 执行中用户补充指示（引导）的注入提示词。
// 与「中断并继续」区分：用户没有要求中断，只是追加或修正方向，
// 因此在已有轨迹基础上调整后续动作即可，不做「重来一轮」的暗示。
func formatUserSteerPrompt(note string) string {
	return "用户在任务执行过程中补充了以下指示，请在继续推进时遵循，不要重复已经完成的工具调用：\n" +
		strings.TrimSpace(note)
}

func cloneSchemaMessages(in []*schema.Message) []*schema.Message {
	if len(in) == 0 {
		return nil
	}
	out := make([]*schema.Message, 0, len(in))
	for _, msg := range in {
		if msg == nil {
			continue
		}
		cp := *msg
		if len(msg.ToolCalls) > 0 {
			cp.ToolCalls = append([]schema.ToolCall(nil), msg.ToolCalls...)
		}
		if len(msg.MultiContent) > 0 {
			cp.MultiContent = append([]schema.ChatMessagePart(nil), msg.MultiContent...)
		}
		if len(msg.UserInputMultiContent) > 0 {
			cp.UserInputMultiContent = append([]schema.MessageInputPart(nil), msg.UserInputMultiContent...)
		}
		if len(msg.AssistantGenMultiContent) > 0 {
			cp.AssistantGenMultiContent = append([]schema.MessageOutputPart(nil), msg.AssistantGenMultiContent...)
		}
		cp.Extra = cloneAnyMap(msg.Extra)
		out = append(out, &cp)
	}
	return out
}
