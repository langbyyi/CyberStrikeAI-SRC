package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/multiagent"

	"github.com/gin-gonic/gin"
)

const (
	defaultEinoSingleRunTimeout = 120 * time.Minute
	defaultMultiAgentRunTimeout = 600 * time.Minute
)

func einoExecutionTimeout(cfg *config.Config, agentMode string) time.Duration {
	if strings.EqualFold(strings.TrimSpace(agentMode), "eino_single") {
		if cfg == nil {
			return defaultEinoSingleRunTimeout
		}
		return time.Duration(cfg.Agent.EinoSingleExecution.RunTimeoutMinutesEffective()) * time.Minute
	}
	return defaultMultiAgentRunTimeout
}

type sseConnectionState struct {
	disconnected atomic.Bool
}

func (s *sseConnectionState) isDisconnected() bool {
	return s != nil && s.disconnected.Load()
}

func (s *sseConnectionState) markDisconnected() {
	if s != nil {
		s.disconnected.Store(true)
	}
}

type agentSSEStream struct {
	context        *gin.Context
	eventBus       *TaskEventBus
	baseContext    func() context.Context
	connection     sseConnectionState
	writeMu        sync.Mutex
	conversationMu sync.RWMutex
	conversationID string
}

func newAgentSSEStream(c *gin.Context, eventBus *TaskEventBus, baseContext func() context.Context) *agentSSEStream {
	return &agentSSEStream{
		context:     c,
		eventBus:    eventBus,
		baseContext: baseContext,
	}
}

func (s *agentSSEStream) SetConversationID(conversationID string) {
	if s == nil {
		return
	}
	s.conversationMu.Lock()
	s.conversationID = strings.TrimSpace(conversationID)
	s.conversationMu.Unlock()
}

func (s *agentSSEStream) WriteMutex() *sync.Mutex {
	if s == nil {
		return nil
	}
	return &s.writeMu
}

func (s *agentSSEStream) Send(eventType, message string, data interface{}) {
	if s == nil || s.context == nil {
		return
	}
	if eventType == "error" && s.baseContext != nil {
		if baseCtx := s.baseContext(); baseCtx != nil {
			cause := context.Cause(baseCtx)
			if errors.Is(cause, ErrTaskCancelled) || errors.Is(cause, multiagent.ErrInterruptContinue) {
				return
			}
		}
	}
	event := StreamEvent{Type: eventType, Message: message, Data: data}
	payload, err := json.Marshal(event)
	if err != nil {
		payload = []byte(`{"type":"error","message":"marshal failed"}`)
	}
	line := make([]byte, 0, len(payload)+8)
	line = append(line, []byte("data: ")...)
	line = append(line, payload...)
	line = append(line, '\n', '\n')

	s.conversationMu.RLock()
	conversationID := s.conversationID
	s.conversationMu.RUnlock()
	if conversationID != "" && s.eventBus != nil {
		s.eventBus.Publish(conversationID, line)
	}
	if s.connection.isDisconnected() {
		return
	}
	if request := s.context.Request; request != nil {
		select {
		case <-request.Context().Done():
			s.connection.markDisconnected()
			return
		default:
		}
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.connection.isDisconnected() {
		return
	}
	if _, err := s.context.Writer.Write(line); err != nil {
		s.connection.markDisconnected()
		return
	}
	if flusher, ok := s.context.Writer.(http.Flusher); ok {
		flusher.Flush()
	} else {
		s.context.Writer.Flush()
	}
}

type assistantMessageFinalizer func(messageID, content string, executionIDs []string, reasoning string) error

func persistAssistantFinal(
	finalize assistantMessageFinalizer,
	messageID, content string,
	executionIDs []string,
	reasoning string,
) error {
	if strings.TrimSpace(messageID) == "" || finalize == nil {
		return nil
	}
	return finalize(messageID, content, executionIDs, reasoning)
}

func agentTaskTerminalStatus(ctx context.Context, runErr error) string {
	if errors.Is(runErr, context.DeadlineExceeded) ||
		(ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return "timeout"
	}
	if errors.Is(runErr, context.Canceled) ||
		(ctx != nil && errors.Is(ctx.Err(), context.Canceled)) {
		return "cancelled"
	}
	if runErr != nil {
		return "failed"
	}
	return "completed"
}

type managedAgentTask struct {
	manager        *AgentTaskManager
	conversationID string
	finished       atomic.Bool
	statusMu       sync.Mutex
	status         string
}

func beginManagedAgentTask(
	manager *AgentTaskManager,
	conversationID, message string,
	cancel context.CancelCauseFunc,
) (*managedAgentTask, error) {
	if manager == nil {
		return nil, errors.New("agent task manager is nil")
	}
	if _, err := manager.StartTask(conversationID, message, cancel); err != nil {
		return nil, err
	}
	return &managedAgentTask{
		manager:        manager,
		conversationID: conversationID,
		status:         "completed",
	}, nil
}

func (t *managedAgentTask) SetStatus(status string) {
	if t == nil || t.manager == nil {
		return
	}
	status = strings.TrimSpace(status)
	if status == "" {
		return
	}
	t.statusMu.Lock()
	t.status = status
	t.statusMu.Unlock()
	t.manager.UpdateTaskStatus(t.conversationID, status)
}

func (t *managedAgentTask) Finish() {
	if t == nil || t.manager == nil || !t.finished.CompareAndSwap(false, true) {
		return
	}
	t.statusMu.Lock()
	status := t.status
	t.statusMu.Unlock()
	t.manager.FinishTask(t.conversationID, status)
}
