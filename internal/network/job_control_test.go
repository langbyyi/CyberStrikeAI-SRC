package network

import (
	"context"
	"testing"
	"time"
)

func TestJobPauseDrainsInflightAndResumeContinues(t *testing.T) {
	c := NewJobControl()
	ctx, cancel := context.WithCancel(WithJobControl(context.Background(), c))
	defer cancel()
	finish, err := beginJobUnit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.Pause()
	if state, _ := c.Snapshot(); state != "pausing" {
		t.Fatal(state)
	}
	c.Advance(JobProgress{Completed: 1})
	finish()
	if state, progress := c.Snapshot(); state != "paused" || progress.Completed != 1 {
		t.Fatalf("%s %+v", state, progress)
	}
	started := make(chan struct{})
	go func() {
		done, err := beginJobUnit(ctx)
		if err == nil {
			close(started)
			done()
		}
	}()
	select {
	case <-started:
		t.Fatal("new work started while paused")
	case <-time.After(20 * time.Millisecond):
	}
	c.Resume()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("resume did not release waiting work")
	}
}

func TestPausedJobCancelsAndDoesNotConsumeWorkBudget(t *testing.T) {
	c := NewJobControl()
	c.Pause()
	ctx, cancel := context.WithCancel(WithJobControl(context.Background(), c))
	defer cancel()
	go c.WatchBudget(ctx, 30*time.Millisecond, cancel)
	time.Sleep(50 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("pause consumed work budget")
	}
	c.Resume()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("active timeout was not enforced")
	}
	if _, err := beginJobUnit(ctx); err == nil {
		t.Fatal("canceled pause accepted new work")
	}
}
