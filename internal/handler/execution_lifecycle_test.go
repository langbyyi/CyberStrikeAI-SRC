package handler

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"

	"github.com/gin-gonic/gin"
)

func TestEinoExecutionTimeout(t *testing.T) {
	cfg := &config.Config{}
	cfg.Agent.EinoSingleExecution.RunTimeoutMinutes = 37

	tests := []struct {
		name string
		cfg  *config.Config
		mode string
		want time.Duration
	}{
		{name: "single explicit", cfg: cfg, mode: "eino_single", want: 37 * time.Minute},
		{name: "single default", cfg: &config.Config{}, mode: "eino_single", want: 120 * time.Minute},
		{name: "single nil config", mode: "eino_single", want: 120 * time.Minute},
		{name: "multi compatibility", cfg: cfg, mode: "deep", want: 600 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := einoExecutionTimeout(tt.cfg, tt.mode); got != tt.want {
				t.Fatalf("einoExecutionTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSEConnectionStateConcurrentMarkAndRead(t *testing.T) {
	var state sseConnectionState
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			state.markDisconnected()
		}()
		go func() {
			defer wg.Done()
			_ = state.isDisconnected()
		}()
	}
	wg.Wait()

	if !state.isDisconnected() {
		t.Fatal("connection should remain disconnected after being marked")
	}
}

func TestPersistAssistantFinalPropagatesError(t *testing.T) {
	wantErr := errors.New("write failed")
	called := false
	err := persistAssistantFinal(
		func(messageID, content string, executionIDs []string, reasoning string) error {
			called = true
			return wantErr
		},
		"message-1",
		"response",
		[]string{"execution-1"},
		"reasoning",
	)
	if !called {
		t.Fatal("finalizer was not called")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("persistAssistantFinal() error = %v, want %v", err, wantErr)
	}
}

func TestPersistAssistantFinalSkipsEmptyMessageID(t *testing.T) {
	called := false
	err := persistAssistantFinal(
		func(messageID, content string, executionIDs []string, reasoning string) error {
			called = true
			return nil
		},
		"",
		"response",
		nil,
		"",
	)
	if err != nil {
		t.Fatalf("persistAssistantFinal() error = %v, want nil", err)
	}
	if called {
		t.Fatal("finalizer should not be called for an empty message id")
	}
}

func TestConversationExecutionStateCleaner(t *testing.T) {
	var cleaned string
	h := &ConversationHandler{}
	h.SetExecutionStateCleaner(func(conversationID string) {
		cleaned = conversationID
	})

	h.cleanupExecutionState("conversation-1")

	if cleaned != "conversation-1" {
		t.Fatalf("cleaned conversation = %q, want %q", cleaned, "conversation-1")
	}
}

func TestAgentTaskTerminalStatus(t *testing.T) {
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer deadlineCancel()
	<-deadlineCtx.Done()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want string
	}{
		{name: "success", ctx: context.Background(), want: "completed"},
		{name: "request cancelled", ctx: cancelledCtx, err: context.Canceled, want: "cancelled"},
		{name: "deadline", ctx: deadlineCtx, err: context.DeadlineExceeded, want: "timeout"},
		{name: "run failure", ctx: context.Background(), err: errors.New("model failed"), want: "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := agentTaskTerminalStatus(tt.ctx, tt.err); got != tt.want {
				t.Fatalf("agentTaskTerminalStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAgentSSEStreamSend(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/", nil)
	eventBus := NewTaskEventBus()
	sub, events := eventBus.Subscribe("conversation-a")
	defer eventBus.Unsubscribe("conversation-a", sub)

	stream := newAgentSSEStream(c, eventBus, func() context.Context {
		return context.Background()
	})
	stream.SetConversationID("conversation-a")
	stream.Send("progress", "running", map[string]interface{}{"step": 1})

	body := recorder.Body.String()
	if !strings.Contains(body, `"type":"progress"`) ||
		!strings.Contains(body, `"message":"running"`) {
		t.Fatalf("SSE body = %q, want progress event", body)
	}
	select {
	case mirrored := <-events:
		if string(mirrored) != body {
			t.Fatalf("mirrored event = %q, want %q", mirrored, body)
		}
	default:
		t.Fatal("event was not mirrored to TaskEventBus")
	}
}

func TestAgentSSEStreamSuppressesCancellationError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/", nil)
	baseCtx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrTaskCancelled)

	stream := newAgentSSEStream(c, nil, func() context.Context {
		return baseCtx
	})
	stream.Send("error", "cancelled", nil)

	if recorder.Body.Len() != 0 {
		t.Fatalf("cancellation error should be suppressed, got %q", recorder.Body.String())
	}
}

func TestManagedAgentTaskOwnsLifecycle(t *testing.T) {
	manager := NewAgentTaskManager()
	task, err := beginManagedAgentTask(manager, "conversation-a", "run", func(error) {})
	if err != nil {
		t.Fatalf("beginManagedAgentTask() error = %v", err)
	}
	if _, err := beginManagedAgentTask(manager, "conversation-a", "duplicate", func(error) {}); !errors.Is(err, ErrTaskAlreadyRunning) {
		t.Fatalf("duplicate begin error = %v, want ErrTaskAlreadyRunning", err)
	}

	task.SetStatus("failed")
	task.Finish()
	task.Finish()

	if active := manager.GetTask("conversation-a"); active != nil {
		t.Fatalf("task remains active after Finish(): %#v", active)
	}
	completed := manager.GetCompletedTasks()
	if len(completed) != 1 || completed[0].Status != "failed" {
		t.Fatalf("completed tasks = %#v, want one failed task", completed)
	}
}
