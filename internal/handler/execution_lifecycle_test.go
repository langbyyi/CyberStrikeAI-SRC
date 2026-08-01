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
	"cyberstrike-ai/internal/multiagent"

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

func TestIsUserCancelledRunDistinguishesCancellationFromTimeout(t *testing.T) {
	cancelledCtx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrTaskCancelled)
	if !isUserCancelledRun(cancelledCtx, context.Canceled) {
		t.Fatal("explicit user cancellation must bypass formal failure finalization")
	}

	timeoutCtx, timeoutCancel := context.WithCancelCause(context.Background())
	timeoutCancel(context.DeadlineExceeded)
	if isUserCancelledRun(timeoutCtx, context.DeadlineExceeded) {
		t.Fatal("deadline must still produce a deterministic failure report")
	}
	if isUserCancelledRun(context.Background(), context.Canceled) {
		t.Fatal("a bare downstream context.Canceled is not an explicit user cancellation")
	}
}

func TestEinoRunFailurePresentationPreservesPartialWorkAndHidesRawError(t *testing.T) {
	rawErr := errors.New(`transient retry exhausted after 3 attempts: Post "https://model.internal/v1/chat": connection reset by peer`)
	result := &multiagent.RunResult{
		MCPExecutionIDs:     []string{"execution-1"},
		LastAgentTraceInput: `{"messages":[{"role":"tool"}]}`,
	}

	message, errorType := einoRunFailurePresentation(rawErr, result)

	if errorType != "model_service_unavailable" {
		t.Fatalf("errorType = %q, want model_service_unavailable", errorType)
	}
	if !strings.Contains(message, "已保留") || !strings.Contains(message, "继续") {
		t.Fatalf("message must explain partial-work preservation, got %q", message)
	}
	for _, leaked := range []string{"model.internal", "connection reset", "transient retry"} {
		if strings.Contains(strings.ToLower(message), leaked) {
			t.Fatalf("message leaks raw infrastructure error %q: %q", leaked, message)
		}
	}
}

// TestEinoRunFailurePresentationClassifiesHttp2HeaderStallAsTransient 验证 StepFun 网关
// 「accepts TCP but never sends headers」的 http2 超时被归类为模型服务暂时不可用，
// 而非硬性执行失败——这样它会走退避重试，并向用户展示友好的模型服务不可用提示。
func TestEinoRunFailurePresentationClassifiesHttp2HeaderStallAsTransient(t *testing.T) {
	rawErr := errors.New(`Post "https://api.stepfun.com/step_plan/v1/chat/completions": http2: timeout awaiting response headers`)

	message, errorType := einoRunFailurePresentation(rawErr, nil)

	if errorType != "model_service_unavailable" {
		t.Fatalf("errorType = %q, want model_service_unavailable (http2 header stall is transient)", errorType)
	}
	if !strings.Contains(message, "模型服务暂时不可用") {
		t.Fatalf("message must indicate model-service-unavailable, got %q", message)
	}
	for _, leaked := range []string{"api.stepfun.com", "http2", "awaiting"} {
		if strings.Contains(strings.ToLower(message), leaked) {
			t.Fatalf("message leaks raw infrastructure error %q: %q", leaked, message)
		}
	}
}

func TestEinoRunFailureFinalContentPreservesEvidenceReport(t *testing.T) {
	conversationID := "failure-final-report"
	state := multiagent.GetConversationExecutionState(conversationID)
	state.RecordTool(multiagent.ToolEvidenceEntry{
		ToolName:   "http-framework-test",
		StatusHint: "404",
		Summary:    "GET /api/admin returned stable 404",
	})
	result := &multiagent.RunResult{Response: "下一步计划：继续扫描更多路径。", MCPExecutionIDs: []string{"run-tool-1"}}

	got := einoRunFailureFinalContentForRun(conversationID, result.MCPExecutionIDs, 0, 0, "任务执行超时，已自动终止。")

	for _, required := range []string{"已验证事实", "/api/admin", "任务执行超时"} {
		if !strings.Contains(got, required) {
			t.Fatalf("failure final content missing %q: %q", required, got)
		}
	}
	if strings.Contains(got, "继续扫描更多路径") {
		t.Fatalf("planning-only partial response leaked into failure report: %q", got)
	}
}

func TestEinoRunFailureWithoutPartialWorkDoesNotReuseOldEvidence(t *testing.T) {
	conversationID := "failure-without-partial-work"
	multiagent.GetConversationExecutionState(conversationID).RecordTool(multiagent.ToolEvidenceEntry{
		ToolName:   "http-framework-test",
		StatusHint: "200",
		Length:     100,
		Summary:    "historical result from an earlier run",
	})
	notice := "模型服务暂时不可用，本次执行已中断。"

	if got := einoRunFailureFinalContentForRun(conversationID, nil, 0, 0, notice); got != notice {
		t.Fatalf("failure before any partial work must not reuse historical evidence: %q", got)
	}
	traceOnly := &multiagent.RunResult{LastAgentTraceInput: `{"messages":[]}`, LastAgentTraceOutput: "model failed"}
	if got := einoRunFailureFinalContentForRun(conversationID, traceOnly.MCPExecutionIDs, 0, 0, notice); got != notice {
		t.Fatalf("trace-only failure must not reuse historical evidence: %q", got)
	}
	responseOnly := &multiagent.RunResult{Response: "下一步计划：先枚举路径"}
	if got := einoRunFailureFinalContentForRun(conversationID, responseOnly.MCPExecutionIDs, 0, 0, notice); got != notice {
		t.Fatalf("planning-only failure must not reuse historical evidence: %q", got)
	}
}

func TestEinoRunFailureUsesCumulativeExecutionIDs(t *testing.T) {
	conversationID := "failure-cumulative-ids"
	multiagent.GetConversationExecutionState(conversationID).RecordTool(multiagent.ToolEvidenceEntry{
		ToolName: "http-framework-test", StatusHint: "interesting", Length: 10, Summary: "current tool evidence",
	})
	got := einoRunFailureFinalContentForRun(conversationID, []string{"earlier-segment-id"}, 0, 0, "failed")
	if !strings.Contains(got, "已验证事实") {
		t.Fatalf("cumulative execution IDs must preserve current-run evidence: %q", got)
	}
}

func TestEinoRunFailureDoesNotTrustPartialModelClaim(t *testing.T) {
	conversationID := "failure-untrusted-partial"
	multiagent.GetConversationExecutionState(conversationID).RecordTool(multiagent.ToolEvidenceEntry{
		ToolName: "http-framework-test", StatusHint: "404", Length: 10, Summary: "GET /missing returned 404",
	})
	result := &multiagent.RunResult{Response: "已确认存在远程代码执行漏洞", MCPExecutionIDs: []string{"tool-1"}}
	got := einoRunFailureFinalContentForRun(conversationID, result.MCPExecutionIDs, 0, 0, "failed")
	if strings.Contains(got, "已确认存在远程代码执行漏洞") {
		t.Fatalf("failure finalization must not trust partial model claims: %q", got)
	}
}

func TestEinoRunFailureReportIsScopedToCurrentRunEvidence(t *testing.T) {
	conversationID := "failure-run-scope"
	state := multiagent.GetConversationExecutionState(conversationID)
	state.RecordTool(multiagent.ToolEvidenceEntry{ToolName: "old-tool", Length: 10, Summary: "historical-secret"})
	cursor := state.EvidenceCursor()
	state.RecordTool(multiagent.ToolEvidenceEntry{ToolName: "new-tool", Length: 10, Summary: "current-result"})
	got := einoRunFailureFinalContentForRun(conversationID, []string{"tool-1"}, cursor, 0, "failed")
	if strings.Contains(got, "historical-secret") || !strings.Contains(got, "current-result") {
		t.Fatalf("failure report must contain only current-run evidence: %q", got)
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
