package multiagent

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// ToolOutcome is the execution layer's stable result contract.
type ToolOutcome struct {
	Code          string        `json:"code"`
	TimeoutLayer  string        `json:"timeoutLayer,omitempty"`
	Retryable     bool          `json:"retryable"`
	RetryLeft     int           `json:"retryLeft"`
	PartialOutput string        `json:"-"`
	Duration      time.Duration `json:"durationMs"`
}

// EffectiveChildTimeout derives a child context without extending an existing deadline.
func EffectiveChildTimeout(ctx context.Context, requested time.Duration) (context.Context, context.CancelFunc, time.Duration) {
	if ctx == nil {
		ctx = context.Background()
	}
	effective := requested
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		}
		if effective <= 0 || remaining < effective {
			effective = remaining
		}
	}
	if effective <= 0 {
		child, cancel := context.WithCancel(ctx)
		return child, cancel, effective
	}
	child, cancel := context.WithTimeout(ctx, effective)
	return child, cancel, effective
}

func timeoutLayerFor(ctx context.Context, requested time.Duration) string {
	if deadline, ok := ctx.Deadline(); ok && requested > 0 && time.Until(deadline) <= requested {
		return "run"
	}
	return "tool"
}

// RenderToolOutcome keeps useful partial output before a machine-readable terminal block.
func RenderToolOutcome(outcome ToolOutcome) string {
	wire := struct {
		Code         string `json:"code"`
		TimeoutLayer string `json:"timeoutLayer,omitempty"`
		Retryable    bool   `json:"retryable"`
		RetryLeft    int    `json:"retryLeft"`
		DurationMs   int64  `json:"durationMs"`
	}{
		Code: outcome.Code, TimeoutLayer: outcome.TimeoutLayer, Retryable: outcome.Retryable,
		RetryLeft: outcome.RetryLeft, DurationMs: outcome.Duration.Milliseconds(),
	}
	encoded, _ := json.Marshal(wire)
	partial := strings.TrimSpace(outcome.PartialOutput)
	if partial == "" {
		return "[tool_outcome] " + string(encoded)
	}
	return partial + "\n\n[tool_outcome] " + string(encoded)
}
