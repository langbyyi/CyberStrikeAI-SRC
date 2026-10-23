package multiagent

import (
	"context"
	"slices"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp/builtin"
	"github.com/cloudwego/eino/components/tool"
)

func TestNetworkResidentDefaultsAreVisibleButCanBecomeDynamic(t *testing.T) {
	configured := config.Default().MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools
	var tools []tool.BaseTool
	for _, name := range append(append([]string{}, configured...), builtin.ToolRecordVulnerability, "ordinary-tool") {
		tools = append(tools, stubTool{name: name})
	}
	static, dynamic, ok := splitToolsForToolSearchByNames(tools, mergeAlwaysVisibleToolNames(configured), 1)
	if !ok || len(dynamic) != 1 {
		t.Fatalf("default tool search split failed: static=%d dynamic=%d", len(static), len(dynamic))
	}
	visible := false
	for _, item := range static {
		info, _ := item.Info(context.Background())
		if info.Name == builtin.ToolNetworkAcquire {
			visible = true
		}
	}
	if !visible {
		t.Fatal("default checked network tool was hidden")
	}
	configured = slices.DeleteFunc(append([]string{}, configured...), func(name string) bool { return name == builtin.ToolNetworkAcquire })
	_, dynamic, ok = splitToolsForToolSearchByNames(tools, mergeAlwaysVisibleToolNames(configured), 1)
	if !ok {
		t.Fatal("tool search was disabled after unchecking one tool")
	}
	for _, item := range dynamic {
		info, _ := item.Info(context.Background())
		if info.Name == builtin.ToolNetworkAcquire {
			return
		}
	}
	t.Fatal("unchecked network tool was still forced to stay resident")
}
