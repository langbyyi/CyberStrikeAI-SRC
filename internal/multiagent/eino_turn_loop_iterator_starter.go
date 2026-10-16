package multiagent

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

type einoTurnLoopRuntimeControl interface {
	Run(context.Context)
	PushInterruptContinue(string) bool
	PushInterruptContinueWithTrace(string, []*schema.Message) bool
	PushUserSteerWithTrace(string, []*schema.Message) bool
	StopImmediate(string)
	StopWhenIdle()
	Wait() *adk.TurnLoopExitState[EinoTurnLoopItem, *schema.Message]
}

type einoTurnLoopRuntimeFactory func(EinoTurnLoopRuntimeConfig) einoTurnLoopRuntimeControl

type einoTurnLoopIteratorStarterConfig struct {
	Context                     context.Context
	Agent                       adk.Agent
	ConversationID              string
	OrchMode                    string
	Progress                    func(eventType, message string, data interface{})
	Logger                      *zap.Logger
	Store                       adk.CheckPointStore
	CheckPointID                string
	InterruptTimeout            time.Duration
	NativeCancelCause           *atomic.Value
	UnregisterAgentCancel       *func()
	UnregisterTurnLoopInterrupt *func()
	UnregisterTurnLoopSteer     *func()
	RuntimeCancelRegistrar      AgentRuntimeCancelRegistrar
	TurnLoopInterruptRegistrar  AgentTurnLoopInterruptRegistrar
	TurnLoopSteerRegistrar      AgentTurnLoopSteerRegistrar
	RuntimeFactory              einoTurnLoopRuntimeFactory
	// SnapshotModelFacingTrace 可选：返回被中断轮最近一次送入模型的消息快照。
	// 「中断并继续」时作为前置消息随中断提示词一起推入续跑 item，
	// 使续跑输入为「原有进度 + 用户备注」而非仅剩备注。
	SnapshotModelFacingTrace func() []*schema.Message
}

type einoTurnLoopIteratorStarter struct {
	cfg einoTurnLoopIteratorStarterConfig
}

func newEinoTurnLoopIteratorStarter(cfg einoTurnLoopIteratorStarterConfig) *einoTurnLoopIteratorStarter {
	if cfg.RuntimeFactory == nil {
		cfg.RuntimeFactory = func(runtimeCfg EinoTurnLoopRuntimeConfig) einoTurnLoopRuntimeControl {
			return NewEinoTurnLoopRuntime(runtimeCfg)
		}
	}
	return &einoTurnLoopIteratorStarter{cfg: cfg}
}

func (s *einoTurnLoopIteratorStarter) Start(runMsgs []adk.Message) *adk.AsyncIterator[*adk.AgentEvent] {
	if s == nil {
		return nil
	}
	callAndClearUnregister(s.cfg.UnregisterTurnLoopInterrupt)
	callAndClearUnregister(s.cfg.UnregisterTurnLoopSteer)
	callAndClearUnregister(s.cfg.UnregisterAgentCancel)

	iter, gen := adk.NewAsyncIteratorPair[*adk.AgentEvent]()
	eventsBridge := newEinoTurnLoopEventBridge(s.cfg.ConversationID, s.cfg.OrchMode, s.cfg.Progress, gen)
	runtime := s.cfg.RuntimeFactory(EinoTurnLoopRuntimeConfig{
		Agent:            s.cfg.Agent,
		InitialMessages:  runMsgs,
		Store:            s.cfg.Store,
		CheckpointID:     s.turnLoopCheckpointID(),
		EnableStreaming:  true,
		InterruptTimeout: s.cfg.InterruptTimeout,
		OnAgentEvents:    eventsBridge.OnAgentEvents,
	})
	s.bindTurnLoopInterrupt(runtime)
	s.bindTurnLoopSteer(runtime)
	s.bindRuntimeCancel(runtime)
	runtime.Run(s.cfg.Context)
	runtime.StopWhenIdle()
	go func() {
		defer gen.Close()
		state := runtime.Wait()
		if state == nil || state.ExitReason == nil || eventsBridge.ForwardedError() {
			return
		}
		gen.Send(&adk.AgentEvent{Err: state.ExitReason})
	}()
	return iter
}

func (s *einoTurnLoopIteratorStarter) turnLoopCheckpointID() string {
	if s == nil || s.cfg.CheckPointID == "" {
		return ""
	}
	return buildEinoTurnLoopCheckpointID(s.cfg.OrchMode)
}

func (s *einoTurnLoopIteratorStarter) bindTurnLoopInterrupt(runtime einoTurnLoopRuntimeControl) {
	if s == nil || runtime == nil || s.cfg.TurnLoopInterruptRegistrar == nil || s.cfg.UnregisterTurnLoopInterrupt == nil {
		return
	}
	*s.cfg.UnregisterTurnLoopInterrupt = s.cfg.TurnLoopInterruptRegistrar(func(note string) bool {
		ok := runtime.PushInterruptContinueWithTrace(note, s.snapshotModelFacingTrace())
		if ok {
			s.emitInterruptContinueProgress(note)
		}
		return ok
	})
}

// bindTurnLoopSteer 登记执行中用户补充指示（引导）的入队 hook。
// 与「中断并继续」共用同一条 TurnLoop 抢占通道，但提示词与抢占策略不同。
func (s *einoTurnLoopIteratorStarter) bindTurnLoopSteer(runtime einoTurnLoopRuntimeControl) {
	if s == nil || runtime == nil || s.cfg.TurnLoopSteerRegistrar == nil || s.cfg.UnregisterTurnLoopSteer == nil {
		return
	}
	*s.cfg.UnregisterTurnLoopSteer = s.cfg.TurnLoopSteerRegistrar(func(note string) bool {
		ok := runtime.PushUserSteerWithTrace(note, s.snapshotModelFacingTrace())
		if ok {
			s.emitUserSteerProgress(note)
		}
		return ok
	})
}

// snapshotModelFacingTrace 读取被中断轮的模型可见轨迹快照；未接线时返回 nil，
// 续跑退化为纯中断提示词（与官方行为一致，无回归）。
func (s *einoTurnLoopIteratorStarter) snapshotModelFacingTrace() []*schema.Message {
	if s == nil || s.cfg.SnapshotModelFacingTrace == nil {
		return nil
	}
	return s.cfg.SnapshotModelFacingTrace()
}

func (s *einoTurnLoopIteratorStarter) bindRuntimeCancel(runtime einoTurnLoopRuntimeControl) {
	if s == nil || runtime == nil || s.cfg.RuntimeCancelRegistrar == nil || s.cfg.UnregisterAgentCancel == nil {
		return
	}
	*s.cfg.UnregisterAgentCancel = s.cfg.RuntimeCancelRegistrar(func(cause error) bool {
		s.storeNativeCancelCause(cause)
		if errors.Is(cause, ErrInterruptContinue) {
			return runtime.PushInterruptContinueWithTrace("", s.snapshotModelFacingTrace())
		}
		runtime.StopImmediate("task_cancelled")
		if s.cfg.Logger != nil {
			s.cfg.Logger.Info("eino turn loop stop requested",
				zap.String("conversation_id", s.cfg.ConversationID),
				zap.String("orchestration", s.cfg.OrchMode),
				zap.Error(cause))
		}
		return true
	})
}

func (s *einoTurnLoopIteratorStarter) storeNativeCancelCause(cause error) {
	if s == nil || s.cfg.NativeCancelCause == nil || cause == nil {
		return
	}
	s.cfg.NativeCancelCause.Store(cause)
}

func (s *einoTurnLoopIteratorStarter) emitInterruptContinueProgress(note string) {
	if s == nil || s.cfg.Progress == nil {
		return
	}
	trimmed := strings.TrimSpace(note)
	s.cfg.Progress("user_interrupt_continue", einoTurnLoopInterruptTimelineSummary(note), map[string]interface{}{
		"conversationId": s.cfg.ConversationID,
		"rawReason":      trimmed,
		"emptyReason":    trimmed == "",
		"kind":           "turn_loop_preempt",
		"source":         "eino",
		"orchestration":  s.cfg.OrchMode,
	})
	s.cfg.Progress("progress", "已将用户补充推入 Eino TurnLoop，正在等待安全点切换…", map[string]interface{}{
		"conversationId": s.cfg.ConversationID,
		"source":         "eino",
		"orchestration":  s.cfg.OrchMode,
	})
}

// emitUserSteerProgress 把用户补充指示记为时间线事件，供对话/监控页展示「已引导」及生效时刻。
func (s *einoTurnLoopIteratorStarter) emitUserSteerProgress(note string) {
	if s == nil || s.cfg.Progress == nil {
		return
	}
	s.cfg.Progress("user_steer", einoUserSteerTimelineSummary(note), map[string]interface{}{
		"conversationId": s.cfg.ConversationID,
		"rawMessage":     strings.TrimSpace(note),
		"kind":           "turn_loop_steer",
		"source":         "eino",
		"orchestration":  s.cfg.OrchMode,
	})
}

func callAndClearUnregister(target *func()) {
	if target == nil || *target == nil {
		return
	}
	(*target)()
	*target = nil
}
