package multiagent

import (
	"errors"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
)

func TestIsEinoTransientRunError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "rate limited", err: errors.New("unexpected status code: 429"), want: true},
		{name: "server error", err: errors.New("HTTP status 502 Bad Gateway"), want: true},
		{name: "network reset", err: errors.New("read tcp: connection reset by peer"), want: true},
		{name: "http2 header stall", err: errors.New(`Post "https://api.stepfun.com/step_plan/v1/chat/completions": http2: timeout awaiting response headers`), want: true},
		{name: "not acceptable", err: errors.New("unexpected status code: 406"), want: false},
		{name: "quota exhausted", err: errors.New("quota exceeded for this project"), want: false},
		{name: "token limit", err: errors.New("request token count 15000 exceeds limit"), want: false},
		{name: "ordinary number", err: errors.New("processed 500 records before validation failed"), want: false},
		{name: "authentication", err: errors.New("HTTP status 401 unauthorized"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEinoTransientRunError(tt.err); got != tt.want {
				t.Fatalf("isEinoTransientRunError(%q) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestEinoTransientRetryDefaultsAreBounded(t *testing.T) {
	policy := einoTransientRunRetryPolicyFromMW(nil)
	if policy.maxAttempts != 3 {
		t.Fatalf("default max attempts = %d, want 3", policy.maxAttempts)
	}
	if policy.maxBackoff != 10*time.Second {
		t.Fatalf("default max backoff = %v, want %v", policy.maxBackoff, 10*time.Second)
	}
}

func TestEinoTransientRetryExplicitConfigWins(t *testing.T) {
	policy := einoTransientRunRetryPolicyFromMW(&config.MultiAgentEinoMiddlewareConfig{
		RunRetryMaxAttempts:   7,
		RunRetryMaxBackoffSec: 23,
	})
	if policy.maxAttempts != 7 {
		t.Fatalf("configured max attempts = %d, want 7", policy.maxAttempts)
	}
	if policy.maxBackoff != 23*time.Second {
		t.Fatalf("configured max backoff = %v, want %v", policy.maxBackoff, 23*time.Second)
	}
}
