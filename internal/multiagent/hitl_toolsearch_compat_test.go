package multiagent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHitlRejectToolResult_toolSearchIsJSON(t *testing.T) {
	raw := HitlRejectToolResult("tool_search", "rejected by user: timeout")
	var payload toolSearchHitlRejectPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.SelectedTools) != 0 {
		t.Fatalf("expected empty selectedTools, got %v", payload.SelectedTools)
	}
	if !payload.HitlRejected {
		t.Fatal("expected _hitlRejected true")
	}
	if !strings.Contains(payload.Reason, "timeout") {
		t.Fatalf("reason=%q", payload.Reason)
	}
}

func TestHitlRejectToolResult_otherToolKeepsLegacyText(t *testing.T) {
	raw := HitlRejectToolResult("nmap", "too risky")
	if strings.HasPrefix(raw, "{") {
		t.Fatalf("expected legacy text, got %q", raw)
	}
	if !strings.HasPrefix(raw, "[HITL Reject]") {
		t.Fatalf("expected [HITL Reject] prefix, got %q", raw)
	}
}

func TestHitlRejectToolResult_rejectsCallNotTool(t *testing.T) {
	raw := HitlRejectToolResult("exec", "rejected by user: 删除业务数据属于破坏性操作")
	// 措辞必须传达"仅否决本次调用、工具未被禁用"，避免模型把单次拒绝泛化成工具不可用。
	for _, want := range []string{"本次调用未通过审批", "工具本身未被禁用", "重新发起", "删除业务数据属于破坏性操作"} {
		if !strings.Contains(raw, want) {
			t.Errorf("reject result missing %q: %s", want, raw)
		}
	}
	if strings.Contains(raw, "continue without") {
		t.Errorf("reject result must not instruct the model to avoid the tool: %s", raw)
	}
	if strings.Contains(raw, "rejected by user:") {
		t.Errorf("inner prefix should be stripped to avoid duplication: %s", raw)
	}
}

func TestMergeHitlExemptMetaTools_includesBuiltInExemptTools(t *testing.T) {
	merged := MergeHitlExemptMetaTools([]string{"read_file"})
	foundToolSearch := false
	for _, name := range merged {
		if IsToolSearchTool(name) {
			foundToolSearch = true
			break
		}
	}
	if !foundToolSearch {
		t.Fatalf("tool_search missing from %v", merged)
	}
	foundBuiltInTools := map[string]bool{
		"exit":                false,
		"write_file":          false,
		"upsert_project_fact": false,
		"get_project_fact":    false,
	}
	for _, name := range merged {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if _, ok := foundBuiltInTools[normalized]; ok {
			foundBuiltInTools[normalized] = true
		}
	}
	for name, found := range foundBuiltInTools {
		if !found {
			t.Fatalf("%s missing from %v", name, merged)
		}
	}
}
