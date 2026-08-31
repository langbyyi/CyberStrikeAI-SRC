package multiagent

import (
	"encoding/json"
	"fmt"
	"strings"
)

const toolSearchToolName = "tool_search"

// HitlExemptMetaTools 为 HITL 内置免审批工具：包括编排/元工具，以及模型输出修复链路依赖的 write_file。
// tool_search 必须免审批，否则其 HITL 拒绝结果与 Eino toolsearch 中间件不兼容（会硬崩 ChatModel）；
// write_file 必须免审批，否则长脚本或请求体无法先安全落盘，模型输出修复链路会被再次阻塞。
var HitlExemptMetaTools = []string{
	toolSearchToolName,
	"skill",
	"task",
	"write_todos",
	"write_file",
	"transfer_to_agent",
	"exit",
	"TaskCreate",
	"TaskGet",
	"TaskUpdate",
	"TaskList",
	"upsert_project_fact",
	"get_project_fact",
}

// IsToolSearchTool reports whether name is the Eino dynamictool tool_search meta-tool.
func IsToolSearchTool(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), toolSearchToolName)
}

// MergeHitlExemptMetaTools unions configured whitelist with built-in meta-tool exemptions.
func MergeHitlExemptMetaTools(configured []string) []string {
	merged := make([]string, 0, len(configured)+len(HitlExemptMetaTools))
	seen := make(map[string]struct{}, len(configured)+len(HitlExemptMetaTools))
	add := func(name string) {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		merged = append(merged, strings.TrimSpace(name))
	}
	for _, t := range configured {
		add(t)
	}
	for _, t := range HitlExemptMetaTools {
		add(t)
	}
	return merged
}

type toolSearchHitlRejectPayload struct {
	SelectedTools []string `json:"selectedTools"`
	HitlRejected  bool     `json:"_hitlRejected"`
	Reason        string   `json:"reason"`
}

// HitlRejectToolResult returns a tool result body safe for downstream consumers.
// tool_search must stay JSON-shaped so toolsearch.extractSelectedTools does not terminate the graph.
func HitlRejectToolResult(toolName, reason string) string {
	reason = strings.TrimSpace(reason)
	reason = strings.TrimPrefix(reason, "rejected by user: ")
	reason = strings.TrimPrefix(reason, "rejected by user")
	if !IsToolSearchTool(toolName) {
		if reason == "" {
			reason = "审批人未给出具体理由"
		}
		// 措辞必须明确"仅否决本次调用、工具未被禁用"：
		// 若只写 "Tool was rejected"，模型会把单次拒绝泛化成工具不可用，
		// 后续整个任务都不再尝试该工具。
		// 询问用户是可选项：是否转达授权问题、绕开重试还是跳过，由主 Agent 按任务目标自行判断。
		return fmt.Sprintf("[HITL Reject] 工具 '%s' 的本次调用未通过审批（审批人否决的只是这一次调用，工具本身未被禁用）。审批意见：%s\n请根据审批意见处理：若审批意见表明需要用户授权，可停止该类操作并向用户说明、询问是否授权，获得同意后重新发起调用即可通过；若该操作对任务目标非必需，也可调整参数或方式绕开，或直接跳过该操作并在结论中说明。不要因为这一次未通过就放弃使用该工具。",
			strings.TrimSpace(toolName), reason)
	}
	payload := toolSearchHitlRejectPayload{
		SelectedTools: []string{},
		HitlRejected:  true,
		Reason:        reason,
	}
	if payload.Reason == "" {
		payload.Reason = "tool_search rejected by reviewer; no dynamic tools unlocked"
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return `{"selectedTools":[],"_hitlRejected":true,"reason":"tool_search rejected by reviewer"}`
	}
	return string(out)
}
