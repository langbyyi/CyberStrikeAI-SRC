package multiagent

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type turnLoopBlockingModel struct {
	started chan struct{}
	release chan struct{}

	mu     sync.Mutex
	inputs [][]*schema.Message
}

func newTurnLoopBlockingModel() *turnLoopBlockingModel {
	return &turnLoopBlockingModel{
		started: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
}

func (m *turnLoopBlockingModel) Generate(ctx context.Context, input []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	m.mu.Lock()
	m.inputs = append(m.inputs, cloneSchemaMessages(input))
	callNo := len(m.inputs)
	m.mu.Unlock()

	select {
	case m.started <- struct{}{}:
	default:
	}
	if callNo == 1 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-m.release:
		}
	}
	return schema.AssistantMessage("done", nil), nil
}

func (m *turnLoopBlockingModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func (m *turnLoopBlockingModel) snapshotInputs() [][]*schema.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]*schema.Message, len(m.inputs))
	for i := range m.inputs {
		out[i] = cloneSchemaMessages(m.inputs[i])
	}
	return out
}

// turnLoopHangingStreamModel emits one stream chunk then blocks until the
// agent cancel scope ends. That matches production ChatModel streams that
// receive ErrStreamCanceled when TurnLoop preempt escalates to CancelImmediate.
type turnLoopHangingStreamModel struct {
	started chan struct{}
	mu      sync.Mutex
	inputs  [][]*schema.Message
}

func newTurnLoopHangingStreamModel() *turnLoopHangingStreamModel {
	return &turnLoopHangingStreamModel{started: make(chan struct{}, 8)}
}

func (m *turnLoopHangingStreamModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	sr, err := m.Stream(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	defer sr.Close()
	var last *schema.Message
	for {
		msg, rerr := sr.Recv()
		if rerr != nil {
			if last != nil {
				return last, nil
			}
			return nil, rerr
		}
		if msg != nil {
			last = msg
		}
	}
}

func (m *turnLoopHangingStreamModel) Stream(ctx context.Context, input []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	m.mu.Lock()
	m.inputs = append(m.inputs, cloneSchemaMessages(input))
	callNo := len(m.inputs)
	m.mu.Unlock()

	select {
	case m.started <- struct{}{}:
	default:
	}

	if callNo == 1 {
		reader, writer := schema.Pipe[*schema.Message](1)
		go func() {
			writer.Send(schema.AssistantMessage("partial", nil), nil)
			<-ctx.Done()
			writer.Close()
		}()
		return reader, nil
	}
	return schema.StreamReaderFromArray([]*schema.Message{schema.AssistantMessage("done", nil)}), nil
}

func (m *turnLoopHangingStreamModel) snapshotInputs() [][]*schema.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]*schema.Message, len(m.inputs))
	for i := range m.inputs {
		out[i] = cloneSchemaMessages(m.inputs[i])
	}
	return out
}

func TestEinoTurnLoopRuntimePushInterruptStartsNextTurn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mockModel := newTurnLoopBlockingModel()
	agent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name:  "turn-loop-agent",
		Model: mockModel,
	})
	if err != nil {
		t.Fatalf("NewChatModelAgent: %v", err)
	}

	runtime := NewEinoTurnLoopRuntime(EinoTurnLoopRuntimeConfig{
		Agent:            agent,
		InitialMessages:  []*schema.Message{schema.UserMessage("initial task")},
		InterruptTimeout: 20 * time.Millisecond,
	})
	runtime.Run(ctx)

	select {
	case <-mockModel.started:
	case <-ctx.Done():
		t.Fatal("first model call did not start")
	}
	if !runtime.PushInterruptContinue("focus on ssh") {
		t.Fatal("interrupt continue push was rejected")
	}
	select {
	case <-mockModel.started:
	case <-ctx.Done():
		t.Fatal("second model call did not start after interrupt push")
	}

	runtime.StopWhenIdle()
	state := runtime.Wait()
	if state == nil {
		t.Fatal("expected turn loop exit state")
	}
	if state.ExitReason != nil {
		t.Fatalf("exit reason = %v", state.ExitReason)
	}

	inputs := mockModel.snapshotInputs()
	if len(inputs) < 2 {
		t.Fatalf("model calls = %d, want at least 2", len(inputs))
	}
	if got := inputs[0][0].Content; got != "initial task" {
		t.Fatalf("first input = %q, want initial task", got)
	}
	lastInput := inputs[len(inputs)-1]
	if len(lastInput) == 0 || !strings.Contains(lastInput[len(lastInput)-1].Content, "focus on ssh") {
		t.Fatalf("last input = %#v, want interrupt note", lastInput)
	}
}

// TestEinoTurnLoopRuntimePushInterruptWithTrace 续跑输入须为「轨迹 + 中断提示词」：
// 抢占后模型仍能看到原始任务与既有进度，不再只剩备注（官方 issue #121 场景）。
func TestEinoTurnLoopRuntimePushInterruptWithTrace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mockModel := newTurnLoopBlockingModel()
	agent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name:  "turn-loop-agent",
		Model: mockModel,
	})
	if err != nil {
		t.Fatalf("NewChatModelAgent: %v", err)
	}

	runtime := NewEinoTurnLoopRuntime(EinoTurnLoopRuntimeConfig{
		Agent:            agent,
		InitialMessages:  []*schema.Message{schema.UserMessage("initial task")},
		InterruptTimeout: 20 * time.Millisecond,
	})
	runtime.Run(ctx)

	select {
	case <-mockModel.started:
	case <-ctx.Done():
		t.Fatal("first model call did not start")
	}
	trace := []*schema.Message{
		schema.UserMessage("initial task"),
		schema.AssistantMessage("已完成 a-03 侦察：10.0.160.98 开放 80 端口", nil),
	}
	if !runtime.PushInterruptContinueWithTrace("完成a-03", trace) {
		t.Fatal("interrupt continue push was rejected")
	}
	select {
	case <-mockModel.started:
	case <-ctx.Done():
		t.Fatal("second model call did not start after interrupt push")
	}

	runtime.StopWhenIdle()
	if state := runtime.Wait(); state == nil || state.ExitReason != nil {
		t.Fatalf("exit state = %+v, reason = %v", state, state.ExitReason)
	}

	inputs := mockModel.snapshotInputs()
	if len(inputs) < 2 {
		t.Fatalf("model calls = %d, want at least 2", len(inputs))
	}
	lastInput := inputs[len(inputs)-1]
	if len(lastInput) != 3 {
		t.Fatalf("resumed input len = %d, want 3 (trace×2 + interrupt)", len(lastInput))
	}
	if lastInput[0].Content != "initial task" || lastInput[1].Content != "已完成 a-03 侦察：10.0.160.98 开放 80 端口" {
		t.Fatalf("resumed input prefix = %#v, want model-facing trace", lastInput[:2])
	}
	if !strings.Contains(lastInput[2].Content, "完成a-03") {
		t.Fatalf("resumed input tail = %q, want interrupt note", lastInput[2].Content)
	}
}

func TestMergeEinoTurnLoopMessagesClonesInput(t *testing.T) {
	original := schema.UserMessage("hello")
	msgs := mergeEinoTurnLoopMessages([]EinoTurnLoopItem{{Messages: []*schema.Message{original}}})
	if len(msgs) != 1 || msgs[0].Content != "hello" {
		t.Fatalf("merged = %#v", msgs)
	}
	msgs[0].Content = "changed"
	if original.Content != "hello" {
		t.Fatalf("original message was mutated: %#v", original)
	}
}

func TestFormatInterruptContinuePrompt(t *testing.T) {
	got := formatInterruptContinuePrompt("focus ports")
	if !strings.Contains(got, "focus ports") || !strings.Contains(got, "不要重复") {
		t.Fatalf("prompt = %q", got)
	}
	empty := formatInterruptContinuePrompt(" ")
	if !strings.Contains(empty, "不要重复") {
		t.Fatalf("empty prompt = %q", empty)
	}
	// 续跑提示词须包含状态找回引导：抢占后上下文不延续，靠黑板/漏洞库兜底。
	for _, p := range []string{got, empty} {
		if !strings.Contains(p, "list_project_facts") || !strings.Contains(p, "list_vulnerabilities") {
			t.Fatalf("prompt missing recover hint: %q", p)
		}
	}
}
