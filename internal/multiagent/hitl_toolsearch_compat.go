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
		// 解封路径（授权 / 补理由 / 跳过）只在被拒时下发，不占执行 Agent 的常驻系统提示词。
		// 三条都要写死：首次被拒不是终态（可重发）、重发是可选项（不必攻克它）、
		// 重发要带同意或理由而非原样重复。少写"可选"那句，模型可能把解封当成新目标而跑偏。
		return fmt.Sprintf("[HITL Reject] 工具 '%s' 的本次调用未通过审批（审批人否决的只是这一次调用，工具本身未被禁用）。审批意见：%s\n处理方式（可选，不要因为这一次被拒就偏离主线任务）：需要重发时带上同意或理由即可通过——若需用户授权，停止该类操作并向用户说明、询问是否授权（用户对某类操作的明确同意在本会话长期有效，不必每次再问）；若确有可检验的理由，重新发起时随调用说明：证明什么、依据本会话哪次实测、操作哪个对象、如何回滚，对象优先取自建或不存在的、保持单次有界。不要原样重复提交同一调用，也不要换工具（例如改用 exec+curl 打同一接口）变相绕过。该操作对任务目标非必需时，调整参数或方式绕开、或直接跳过并在结论中说明即可，继续推进主线；不要因为这一次未通过就放弃使用该工具，也不要为解封它而停下主要工作。",
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
