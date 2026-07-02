package multiagent

import "testing"

func TestMCPExecutionBinder(t *testing.T) {
	b := NewMCPExecutionBinder()
	b.Bind("call-1", "exec-1")
	if got := b.ExecutionID("call-1"); got != "exec-1" {
		t.Fatalf("expected exec-1, got %q", got)
	}
	if got := b.ExecutionID("missing"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}
