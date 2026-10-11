package handler

import (
	"context"
	"cyberstrike-ai/internal/multiagent"
	"testing"
)

func TestCancelledAgentTaskCannotFinishSuccessfully(t *testing.T) {
	for _, lateStatus := range []string{"running", "completed", "failed"} {
		m := NewAgentTaskManager()
		ctx, cancel := context.WithCancelCause(context.Background())
		task, err := m.StartTask("conversation", "test", cancel)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := m.CancelTask("conversation", ErrTaskCancelled); err != nil || !ok {
			t.Fatalf("cancel: %v %v", ok, err)
		}
		if context.Cause(ctx) != ErrTaskCancelled {
			t.Fatal("cancellation not delivered")
		}
		m.UpdateTaskStatus("conversation", lateStatus)
		if err := m.FinishTaskRun("conversation", task.RunID, "completed"); err != nil {
			t.Fatal(err)
		}
		done := m.GetCompletedTasks()
		if len(done) != 1 || done[0].Status != "cancelled" {
			t.Fatalf("cancelled task became successful: %#v", done)
		}
		if len(m.GetActiveTasks()) != 0 {
			t.Fatal("cancelled task remains active")
		}
	}
}
func TestInterruptContinueDoesNotBecomeTaskCancellation(t *testing.T) {
	m := NewAgentTaskManager()
	_, cancel := context.WithCancelCause(context.Background())
	task, err := m.StartTask("conversation", "test", cancel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CancelTask("conversation", multiagent.ErrInterruptContinue); err != nil {
		t.Fatal(err)
	}
	m.UpdateTaskStatus("conversation", "running")
	if err := m.FinishTaskRun("conversation", task.RunID, "completed"); err != nil {
		t.Fatal(err)
	}
	if done := m.GetCompletedTasks(); len(done) != 1 || done[0].Status != "completed" {
		t.Fatal("continue run lost success")
	}
}

func TestDoneEventCarriesTheSavedCancellationStatus(t *testing.T) {
	m := NewAgentTaskManager()
	task, err := m.StartTask("conversation", "test", func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CancelTask("conversation", ErrTaskCancelled); err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{tasks: m}
	var result map[string]interface{}
	send := h.taskFinishingEventSender(func(kind, message string, data interface{}) {
		if kind == "done" {
			result = data.(map[string]interface{})
		}
	}, "conversation", task.RunID, func() string { return "completed" })
	original := map[string]interface{}{"messageId": "message"}
	send("done", "", original)
	if result["status"] != "cancelled" || result["messageId"] != "message" {
		t.Fatalf("incorrect done payload: %#v", result)
	}
	if _, exists := original["status"]; exists {
		t.Fatal("caller payload mutated")
	}
}
