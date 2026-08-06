package einoobserve

import (
	"context"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestAttachAgentRunCallbacks_Disabled(t *testing.T) {
	ctx := context.Background()
	cfg := &config.MultiAgentEinoCallbacksConfig{Enabled: false}
	out := AttachAgentRunCallbacks(ctx, cfg, Params{})
	if out != ctx {
		t.Fatalf("expected same ctx when disabled")
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("abc", 10); got != "abc" {
		t.Fatalf("got %q", got)
	}
	if got := truncateRunes("abcdefghij", 4); got != "abcd…" {
		t.Fatalf("got %q", got)
	}
}
