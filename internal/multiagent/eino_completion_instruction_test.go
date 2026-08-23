package multiagent

import (
	"context"
	"testing"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
)

func TestWithEinoExitToolPreservesToolsAndReturnsExitDirectly(t *testing.T) {
	original := adk.ToolsConfig{}
	original.Tools = []tool.BaseTool{nil}

	got := withEinoExitTool(original)
	if len(original.Tools) != 1 || len(got.Tools) != 2 || got.Tools[0] != nil {
		t.Fatalf("tool lists changed unexpectedly: original=%d configured=%d", len(original.Tools), len(got.Tools))
	}
	info, err := got.Tools[1].Info(context.Background())
	if err != nil || info == nil || info.Name != adk.ToolInfoExit.Name {
		t.Fatalf("exit tool info = %#v err=%v", info, err)
	}
	if !got.ReturnDirectly[adk.ToolInfoExit.Name] {
		t.Fatalf("exit must return directly: %#v", got.ReturnDirectly)
	}
}

func TestEinoExplicitCompletionInstructionSkipsPlanExecute(t *testing.T) {
	if got := einoExplicitCompletionInstruction("plan_execute"); got != "" {
		t.Fatalf("plan_execute uses framework completion and must not require exit: %q", got)
	}
	if got := einoExplicitCompletionInstruction("eino_single"); got == "" {
		t.Fatal("single-agent completion instruction is empty")
	}
}
