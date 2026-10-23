package network

import (
	"context"
	"sync"
	"time"
)

type JobProgress struct {
	Kind      string `json:"kind,omitempty"`
	Stage     string `json:"stage,omitempty"`
	Total     int    `json:"total,omitempty"`
	Completed int    `json:"completed"`
	Imported  int    `json:"imported"`
	Skipped   int    `json:"skipped"`
	Pages     int    `json:"pages"`
	Passed    int    `json:"passed"`
	Failed    int    `json:"failed"`
	Revision  uint64 `json:"revision"`
}

// JobControl pauses at committed work-unit boundaries, never by discarding a response.
type JobControl struct {
	mu       sync.Mutex
	paused   bool
	active   int
	changed  chan struct{}
	progress JobProgress
}

type jobControlKey struct{}

func NewJobControl() *JobControl { return &JobControl{changed: make(chan struct{})} }
func WithJobControl(ctx context.Context, c *JobControl) context.Context {
	return context.WithValue(ctx, jobControlKey{}, c)
}
func jobControl(ctx context.Context) *JobControl {
	c, _ := ctx.Value(jobControlKey{}).(*JobControl)
	return c
}
func (c *JobControl) signalLocked() { close(c.changed); c.changed = make(chan struct{}) }
func (c *JobControl) Pause()        { c.mu.Lock(); defer c.mu.Unlock(); c.paused = true; c.signalLocked() }
func (c *JobControl) Resume()       { c.mu.Lock(); defer c.mu.Unlock(); c.paused = false; c.signalLocked() }
func (c *JobControl) Snapshot() (string, JobProgress) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := "running"
	if c.paused {
		state = "paused"
		if c.active > 0 {
			state = "pausing"
		}
	}
	return state, c.progress
}
func (c *JobControl) Advance(p JobProgress) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.Kind != "" {
		c.progress.Kind = p.Kind
	}
	if p.Stage != "" {
		c.progress.Stage = p.Stage
	}
	if p.Total > 0 {
		c.progress.Total = p.Total
	}
	c.progress.Completed += p.Completed
	c.progress.Imported += p.Imported
	c.progress.Skipped += p.Skipped
	c.progress.Pages += p.Pages
	c.progress.Passed += p.Passed
	c.progress.Failed += p.Failed
	c.progress.Revision++
}
func reportJobProgress(ctx context.Context, p JobProgress) {
	if c := jobControl(ctx); c != nil {
		c.Advance(p)
	}
}
func beginJobUnit(ctx context.Context) (func(), error) {
	c := jobControl(ctx)
	if c == nil {
		return func() {}, ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		if !c.paused {
			c.active++
			c.signalLocked()
			c.mu.Unlock()
			var once sync.Once
			return func() { once.Do(func() { c.mu.Lock(); c.active--; c.signalLocked(); c.mu.Unlock() }) }, nil
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

// WatchBudget excludes fully paused time; cancellation still wakes every waiter.
func (c *JobControl) WatchBudget(ctx context.Context, remaining time.Duration, cancel context.CancelFunc) {
	for {
		c.mu.Lock()
		paused := c.paused && c.active == 0
		changed := c.changed
		c.mu.Unlock()
		if paused {
			select {
			case <-ctx.Done():
				return
			case <-changed:
				continue
			}
		}
		if remaining <= 0 {
			cancel()
			return
		}
		started := time.Now()
		timer := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			cancel()
			return
		case <-changed:
			timer.Stop()
			remaining -= time.Since(started)
		}
	}
}

// BeginJobUnit lets inline imports share the same pause boundary as fetched pages.
func BeginJobUnit(ctx context.Context) (func(), error)     { return beginJobUnit(ctx) }
func ReportJobProgress(ctx context.Context, p JobProgress) { reportJobProgress(ctx, p) }
