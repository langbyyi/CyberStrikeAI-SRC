package multiagent

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"
)

func TestInjectToolNamesOnlyInstruction_ToolSearchSplit(t *testing.T) {
	t.Parallel()
	all := []tool.BaseTool{
		stubTool{name: "fofa_search"},
		stubTool{name: "read_file"},
		stubTool{name: "mcp__ext__nuclei"},
	}
	mounted := []tool.BaseTool{all[0], all[1]} // fofa_search 常驻,nuclei 非常驻

	out := injectToolNamesOnlyInstruction(context.Background(), "你是CyberStrikeAI", all, mounted, true)

	if !strings.Contains(out, transcriptToolIndexStartMarker) {
		t.Fatalf("missing tool index header: %q", out)
	}
	staticIdx := strings.Index(out, "【常驻工具】")
	dynamicIdx := strings.Index(out, "【非常驻工具】")
	if staticIdx < 0 || dynamicIdx < 0 || staticIdx > dynamicIdx {
		t.Fatalf("static/dynamic sections missing or out of order: %q", out)
	}
	staticSection, dynamicSection := out[staticIdx:dynamicIdx], out[dynamicIdx:]
	if !strings.Contains(staticSection, "fofa_search") || !strings.Contains(staticSection, "read_file") {
		t.Fatalf("static section missing always-visible tools: %q", staticSection)
	}
	if strings.Contains(staticSection, "mcp__ext__nuclei") {
		t.Fatalf("dynamic tool leaked into static section: %q", staticSection)
	}
	if !strings.Contains(dynamicSection, "mcp__ext__nuclei") {
		t.Fatalf("dynamic section missing deferred tool: %q", dynamicSection)
	}
	if !strings.Contains(out, "query") || !strings.Contains(out, "select:") {
		t.Fatalf("tool_search query/select: guidance missing: %q", out)
	}
	if strings.Contains(out, "regex_pattern：") || strings.Contains(out, "参数 regex_pattern") {
		t.Fatalf("stale regex_pattern guidance survived: %q", out)
	}
	if !strings.Contains(out, "matches:null") {
		t.Fatalf("matches:null expectation note missing: %q", out)
	}
}

func TestInjectToolNamesOnlyInstruction_NoToolSearchKeepsSingleList(t *testing.T) {
	t.Parallel()
	all := []tool.BaseTool{stubTool{name: "fofa_search"}}
	out := injectToolNamesOnlyInstruction(context.Background(), "你是CyberStrikeAI", all, all, false)
	if strings.Contains(out, "【常驻工具】") || strings.Contains(out, "【非常驻工具】") {
		t.Fatalf("unexpected split sections without tool_search: %q", out)
	}
	if !strings.Contains(out, "fofa_search") {
		t.Fatalf("tool name missing: %q", out)
	}
	if strings.Contains(out, "regex_pattern") {
		t.Fatalf("regex_pattern should not appear without tool_search: %q", out)
	}
}
