package handler

import (
	"context"
	"errors"
	"testing"

	"cyberstrike-ai/internal/multiagent"
)

func TestCancelTaskInvokesToolCancelerOnFullStop(t *testing.T) {
	tm := NewAgentTaskManager()
	called := false
	tm.SetToolCanceler(func(conversationID string) {
		if conversationID == "conv-1" {
			called = true
		}
	})

	_, cancel := context.WithCancelCause(context.Background())
	_, err := tm.StartTask("conv-1", "hello", cancel)
	if err != nil {
		t.Fatalf("StartTask: %v", err)
	}

	ok, err := tm.CancelTask("conv-1", ErrTaskCancelled)
	if err != nil || !ok {
		t.Fatalf("CancelTask: ok=%v err=%v", ok, err)
	}
	if !called {
		t.Fatal("expected tool canceler to be invoked on full task cancel")
	}
}

func TestCancelTaskSkipsToolCancelerOnInterruptContinue(t *testing.T) {
	tm := NewAgentTaskManager()
	called := false
	tm.SetToolCanceler(func(conversationID string) {
		called = true
	})

	_, cancel := context.WithCancelCause(context.Background())
	_, err := tm.StartTask("conv-1", "hello", cancel)
	if err != nil {
		t.Fatalf("StartTask: %v", err)
	}

	ok, err := tm.CancelTask("conv-1", multiagent.ErrInterruptContinue)
	if err != nil || !ok {
		t.Fatalf("CancelTask: ok=%v err=%v", ok, err)
	}
	if called {
		t.Fatal("tool canceler must not run for interrupt-continue")
	}
}

func TestCancelTaskDefaultCauseIsTaskCancelled(t *testing.T) {
	tm := NewAgentTaskManager()
	var gotCause error
	tm.SetToolCanceler(func(conversationID string) {
		if conversationID == "conv-2" {
			gotCause = ErrTaskCancelled
		}
	})

	ctx, cancel := context.WithCancelCause(context.Background())
	if _, err := tm.StartTask("conv-2", "hello", cancel); err != nil {
		t.Fatalf("StartTask: %v", err)
	}

	if _, err := tm.CancelTask("conv-2", nil); err != nil {
		t.Fatalf("CancelTask: %v", err)
	}
	if !errors.Is(context.Cause(ctx), ErrTaskCancelled) {
		t.Fatalf("expected ErrTaskCancelled cause, got %v", context.Cause(ctx))
	}
	if gotCause != ErrTaskCancelled {
		t.Fatalf("expected tool canceler path for default cancel cause")
	}
}
