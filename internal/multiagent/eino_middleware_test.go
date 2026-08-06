package multiagent

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

func TestReductionCacheRootDir(t *testing.T) {
	got := reductionCacheRootDir("", "proj-1", "conv-1")
	want := filepath.Join("tmp", "reduction", "projects", "proj-1")
	if got != want {
		t.Fatalf("project scope: got %q want %q", got, want)
	}
	got = reductionCacheRootDir("", "", "conv-abc")
	want = filepath.Join("tmp", "reduction", "conversations", "conv-abc")
	if got != want {
		t.Fatalf("conversation scope: got %q want %q", got, want)
	}
	custom := reductionCacheRootDir("/data/cache", "p1", "c1")
	if !strings.HasSuffix(custom, filepath.Join("projects", "p1")) {
		t.Fatalf("custom base should still scope by project, got %q", custom)
	}
}

type stubTool struct{ name string }

func (s stubTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: s.name}, nil
}

func TestSplitToolsForToolSearch(t *testing.T) {
	mk := func(n int) []tool.BaseTool {
		out := make([]tool.BaseTool, n)
		for i := 0; i < n; i++ {
			out[i] = stubTool{name: fmt.Sprintf("t%d", i)}
		}
		return out
	}
	static, dynamic, ok := splitToolsForToolSearch(mk(4), 3)
	if ok || len(static) != 4 || dynamic != nil {
		t.Fatalf("expected no split when len<=alwaysVisible+1, got ok=%v static=%d dynamic=%v", ok, len(static), dynamic)
	}
	static, dynamic, ok = splitToolsForToolSearch(mk(20), 5)
	if !ok || len(static) != 5 || len(dynamic) != 15 {
		t.Fatalf("expected split 5+15, got ok=%v static=%d dynamic=%d", ok, len(static), len(dynamic))
	}
}
