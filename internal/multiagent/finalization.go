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
	// Strong evidence cues: these substring pairs only co-occur in real finding
	// summaries, not in planning fragments. A single generic word like "漏洞"
	// was too broad — a planning sentence ("尝试 5vshop 已知漏洞") matched it and
	// masqueraded as a finished report, suppressing the deterministic fallback.
	strongEvidence := [][]string{
		{"已验证", "事实"},
		{"已验证", "exec"},
		{"status=", "http"},
		{"status_hint", "http"},
		{"http_status", ":"},
		{"未确认候选"},
		{"限制与下一步"},
	}
	for _, pair := range strongEvidence {
		if strings.Contains(low, pair[0]) && strings.Contains(low, pair[1]) {
			return false
		}
	}
	// Single-word cues that are reliable on their own (rare in planning text).
	strongSingles := []string{
		"http/", "verified", "confirmed",
	}
	for _, cue := range strongSingles {
		if strings.Contains(low, cue) {
			return false
		}
	}
	planningCues := []string{
		"下一步", "接下来", "我将", "我会", "继续扫描", "继续请求", "计划",
		"尝试", "让我", "转向", "换", "搜索",
		"next step", "i will", "i'll", "continue scanning", "let me", "try",
	}
	for _, cue := range planningCues {
		if strings.Contains(low, cue) {
			return true
		}
	}
	return false
}

// shortCandidateThreshold is the rune length below which a post-stagnation
// candidate is treated as a planning fragment rather than a real report, so the
// deterministic fallback report is forced. Stagnation cuts off tool calls, and
// the model often emits a one-line plan ("尝试已知漏洞…") as its final message.
const shortCandidateThreshold = 400

func FinalizeRunResponse(ctx context.Context, state *ConversationExecutionState, candidate string, finalizer NoToolFinalizer) string {
	if state != nil {
		defer state.Controller().CompleteFinalization()
	}
	cleaned := SanitizeFinalResponse(candidate)
	forceFinalizer := state != nil && state.Controller().FinalizationRequired()
	// Stagnation path: pivot-driven ends never enter the Finalizing phase, so
	// FinalizationRequired() is false. If stagnation fired at least once AND the
	// candidate is a short fragment (typical "let me try…" plan), force the
	// deterministic report so the user always sees a real summary.
	if !forceFinalizer && state != nil {
		if gates := state.Controller().StagnationGates(); gates > 0 {
			if IsPlanningOnlyFinalResponse(cleaned) || len([]rune(cleaned)) <= shortCandidateThreshold {
				forceFinalizer = true
			}
		}
	}
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
	return buildDeterministicFinalReport(state, state.LastK(8))
}

func BuildDeterministicFinalReportSince(state *ConversationExecutionState, cursor uint64) string {
	return buildDeterministicFinalReport(state, state.EvidenceSince(cursor))
}

func BuildDeterministicFinalReportForRun(state *ConversationExecutionState, evidenceCursor, coverageCursor uint64) string {
	return buildDeterministicFinalReportParts(state.EvidenceSince(evidenceCursor), state.CoverageSince(coverageCursor))
}

func buildDeterministicFinalReport(state *ConversationExecutionState, evidence []ToolEvidenceEntry) string {
	return buildDeterministicFinalReportParts(evidence, state.ListCoverage())
}

func buildDeterministicFinalReportParts(evidence []ToolEvidenceEntry, coverage []CoverageItem) string {
	var out strings.Builder
	out.WriteString("## 已验证事实\n")
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
