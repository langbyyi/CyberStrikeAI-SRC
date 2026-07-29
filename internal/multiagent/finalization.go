package multiagent

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

type NoToolFinalizer func(context.Context, string) (string, error)

var internalFinalMarkers = []string{
	"identity_gap",
	"framework_next_action",
	"framework_tool_outcome",
	"framework_tool_dead",
	"execution_stagnation",
	"stagnation_blocked",
	"eino_pending_orphaned",
	"pending tool calls were force-closed",
}

func SanitizeFinalResponse(response string) string {
	paragraphs := strings.Split(strings.ReplaceAll(response, "\r\n", "\n"), "\n\n")
	kept := make([]string, 0, len(paragraphs))
	for _, paragraph := range paragraphs {
		low := strings.ToLower(paragraph)
		internal := false
		for _, marker := range internalFinalMarkers {
			if strings.Contains(low, marker) {
				internal = true
				break
			}
		}
		if !internal {
			if paragraph = strings.TrimSpace(paragraph); paragraph != "" {
				kept = append(kept, paragraph)
			}
		}
	}
	return strings.TrimSpace(strings.Join(kept, "\n\n"))
}

func IsPlanningOnlyFinalResponse(response string) bool {
	cleaned := SanitizeFinalResponse(response)
	if cleaned == "" {
		return true
	}
	low := strings.ToLower(cleaned)
	evidenceCues := []string{
		"已验证", "确认", "返回", "状态码", "http/", "未发现", "未确认", "证据",
		"漏洞", "限制", "blocked", "verified", "confirmed", "status", "result",
	}
	for _, cue := range evidenceCues {
		if strings.Contains(low, cue) {
			return false
		}
	}
	planningCues := []string{
		"下一步", "接下来", "我将", "我会", "继续扫描", "继续请求", "计划",
		"next step", "i will", "i'll", "continue scanning",
	}
	for _, cue := range planningCues {
		if strings.Contains(low, cue) {
			return true
		}
	}
	return false
}

func FinalizeRunResponse(ctx context.Context, state *ConversationExecutionState, candidate string, finalizer NoToolFinalizer) string {
	cleaned := SanitizeFinalResponse(candidate)
	forceFinalizer := state != nil && state.Controller().FinalizationRequired()
	if !forceFinalizer && !IsPlanningOnlyFinalResponse(cleaned) {
		return cleaned
	}
	prompt := buildFinalizerPrompt(state, cleaned)
	if finalizer != nil {
		if response, err := finalizer(ctx, prompt); err == nil {
			response = SanitizeFinalResponse(response)
			if !IsPlanningOnlyFinalResponse(response) {
				return response
			}
		}
	}
	return BuildDeterministicFinalReport(state)
}

func buildFinalizerPrompt(state *ConversationExecutionState, candidate string) string {
	return "请基于以下执行事实直接生成最终报告，不调用工具，不描述计划，不输出框架标记。" +
		"报告须区分已验证事实、未确认候选、限制与下一步；不得把未验证候选写成正式漏洞。\n\n" +
		"原始候选回复：\n" + candidate + "\n\n执行状态：\n" + BuildDeterministicFinalReport(state)
}

func BuildDeterministicFinalReport(state *ConversationExecutionState) string {
	var out strings.Builder
	out.WriteString("## 已验证事实\n")
	evidence := state.LastK(8)
	if len(evidence) == 0 {
		out.WriteString("- 本次执行未保留足够的结构化工具事实，不能据此确认漏洞。\n")
	} else {
		for _, entry := range evidence {
			summary := strings.TrimSpace(entry.Summary)
			if summary == "" {
				summary = "工具已执行，但没有可安全归纳的结果摘要"
			}
			status := strings.TrimSpace(entry.StatusHint)
			if status != "" {
				summary = "status=" + status + "；" + summary
			}
			out.WriteString("- ")
			out.WriteString(strings.TrimSpace(entry.ToolName))
			out.WriteString("：")
			out.WriteString(truncateSummaryText(summary, 500))
			out.WriteByte('\n')
		}
	}

	coverage := state.ListCoverage()
	sort.SliceStable(coverage, func(i, j int) bool {
		return coverage[i].Path < coverage[j].Path
	})
	out.WriteString("\n## 未确认候选\n")
	openCount := 0
	for _, item := range coverage {
		status := strings.ToLower(strings.TrimSpace(item.Status))
		if status != "" && status != "open" && status != "in_progress" {
			continue
		}
		openCount++
		out.WriteString(fmt.Sprintf("- %s（%s）：%s\n", item.Path, item.Priority, strings.TrimSpace(item.Note)))
	}
	if openCount == 0 {
		out.WriteString("- 无可由当前结构化证据支持的未确认候选。\n")
	}

	out.WriteString("\n## 限制与下一步\n")
	limitations := 0
	for _, item := range coverage {
		if strings.EqualFold(strings.TrimSpace(item.Status), "blocked") {
			limitations++
			out.WriteString(fmt.Sprintf("- %s：%s\n", item.Path, strings.TrimSpace(item.Note)))
		}
	}
	if limitations == 0 {
		out.WriteString("- 若需继续，应围绕仍开放的高优先级覆盖项补充差异化证据，避免重复无差异探测。\n")
	}
	return strings.TrimSpace(out.String())
}
