package multiagent

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// Wrap-up phrases that look like shallow "no vuln / testing complete" conclusions.
// Matched case-insensitively against assistant final text.
var finalizeWrapUpPhrases = []string{
	"未发现漏洞",
	"未发现安全漏洞",
	"没有发现漏洞",
	"无漏洞",
	"测试完成",
	"扫描完成",
	"渗透测试完成",
	"测试已完成",
	"未发现明显",
	"未发现高危",
	"暂无漏洞",
	"暂未发现",
	"没有发现安全问题",
	"未发现安全问题",
	"本次测试未发现",
	"本次扫描未发现",
	"可以结束",
	"建议收工",
	"建议结束",
	"先到这里",
	"暂时没有发现",
	"目前没有发现",
	"整体较为安全",
	"风险较低",
	"安全状况良好",
	"无需进一步",
	"未发现可利用",
	"未发现有效漏洞",
	"信息收集完成",
	"侦察完成",
	"no vulnerabilities found",
	"no vulnerability found",
	"testing complete",
	"scan complete",
	"nothing found",
	"looks secure",
	"no issues found",
	"no security issues",
}

// FinalizeGateInstruction is appended/rewritten when open P0/P1 + wrap-up phrasing.
const FinalizeGateInstruction = "\n\n## [finalize_gate_blocked] 框架门闩（非用户消息）\n" +
	"本会话仍有 **P0/P1 coverage 未闭环**，但助手回复呈现「无漏洞/测试完成」类收工话术。\n" +
	"**禁止以此结论交付。** 请立即做以下其中一项（不可跳步）：\n" +
	"1. **继续安全测试**：对下列 open 项，用 exec/curl/http-framework-test/sqlmap/nuclei 等工具做一次真实漏洞验证（不是 upsert），验证后自然会得到结论；\n" +
	"2. **确认死路**：将对应 path 标为 `blocked`（note 写明具体原因，如「需认证无法绕过」「WAF 拦截」），然后调用 should_continue_execution(intent=finalize)。\n" +
	"**禁止：不做测试直接 upsert、连续调用 upsert 不做验证。**\n" +
	"open_p0_p1:\n"

// IsFinalizeWrapUpText reports whether text matches shallow wrap-up phrasing.
func IsFinalizeWrapUpText(text string) bool {
	t := strings.TrimSpace(text)
	if t == "" {
		return false
	}
	// Skip if already gated
	if strings.Contains(t, "finalize_gate_blocked") {
		return false
	}
	low := strings.ToLower(t)
	for _, p := range finalizeWrapUpPhrases {
		if strings.Contains(low, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// CoverageShouldBlockFinalize is the shared pure decision for finalize gate and tests.
// Blocks only when response is wrap-up phrasing AND state has open/in_progress P0/P1 items.
// Empty coverage map does not block (exploration phase soft-hint only).
func CoverageShouldBlockFinalize(state *ConversationExecutionState, responseText string) (bool, string) {
	resp := strings.TrimSpace(responseText)
	if resp == "" || !IsFinalizeWrapUpText(resp) {
		return false, ""
	}
	if state == nil {
		return false, ""
	}
	cont, reason, open := state.ShouldContinue()
	if !cont || len(open) == 0 {
		return false, ""
	}
	return true, reason
}

// SurfaceRecordGateInstruction is appended when high-value surface was seen but no L1/L2 recorded.
// Scenario-agnostic (Web/API/cloud/config/info-leak).
const SurfaceRecordGateInstruction = "\n\n## [surface_record_blocked] 框架门闩（非用户消息）\n" +
	"本会话已检测到**高价值攻击面**（API/服务清单、调试入口、源码/密钥/云元数据、目录列表或强信息泄露等），但尚未调用 " +
	"`record_vulnerability_candidate`（L1）或 `record_vulnerability`（L2）落库。\n" +
	"**禁止直接交付总结报告。** 请立即：\n" +
	"1. 对可复现暴露调用 `record_vulnerability_candidate` 或 `record_vulnerability`(severity=info/low/对应等级)，target=用户指定目标；\n" +
	"2. 再 `should_continue_execution(intent=finalize)` 收工。\n" +
	"证明须含真实目标标识、状态码/输出摘要；禁止套用无关历史案例标题。\n"

// SurfaceRecordShouldBlockFinalize blocks wrap-up when surface was seen but no vuln recorded.
// Also treats long "渗透测试报告" style delivery as wrap-up for this gate only.
func SurfaceRecordShouldBlockFinalize(state *ConversationExecutionState, responseText string) (bool, string) {
	resp := strings.TrimSpace(responseText)
	if resp == "" || state == nil {
		return false, ""
	}
	if strings.Contains(resp, "surface_record_blocked") {
		return false, ""
	}
	if !state.SurfaceNeedsRecord() {
		return false, ""
	}
	// Broaden wrap-up detection: final report headers count as delivery.
	if IsFinalizeWrapUpText(resp) || isDeliveryReportText(resp) {
		return true, "surface_seen_without_vulnerability_record"
	}
	return false, ""
}

func isDeliveryReportText(text string) bool {
	low := strings.ToLower(text)
	markers := []string{
		"渗透测试报告",
		"漏洞记录情况",
		"风险与修复建议",
		"# 渗透测试",
		"## 已确认攻击面",
		"executive summary",
	}
	for _, m := range markers {
		if strings.Contains(low, strings.ToLower(m)) {
			return true
		}
	}
	// Long structured markdown conclusion
	if strings.Count(text, "## ") >= 3 && (strings.Contains(text, "修复") || strings.Contains(low, "finding")) {
		return true
	}
	return false
}

// ApplyFinalizeGate is the pure post-process for assistant final text.
// When coverage has open P0/P1 and response is wrap-up phrasing, rewrites/appends a continue instruction.
// Also appends identity-gap hint when idor_horizontal is open without dual-auth probe (even if not blocked).
// Returns (newText, blocked).
func ApplyFinalizeGate(conversationID, response string) (string, bool) {
	resp := strings.TrimSpace(response)
	if resp == "" {
		return response, false
	}
	state := GetConversationExecutionState(conversationID)
	block, reason := CoverageShouldBlockFinalize(state, resp)
	out := response
	if block {
		_, _, open := state.ShouldContinue()
		var b strings.Builder
		b.WriteString(resp)
		b.WriteString(FinalizeGateInstruction)
		b.WriteString(fmt.Sprintf("reason=%s\n", reason))
		for _, it := range open {
			b.WriteString(fmt.Sprintf("- path=%s priority=%s status=%s note=%s\n",
				it.Path, it.Priority, it.Status, truncateRunes(it.Note, 80)))
		}
		out = b.String()
	}
	// Surface without L1/L2: block report-style delivery after confirmed inventory/disclosure.
	if sBlock, sReason := SurfaceRecordShouldBlockFinalize(state, out); sBlock {
		var b strings.Builder
		b.WriteString(out)
		b.WriteString(SurfaceRecordGateInstruction)
		b.WriteString(fmt.Sprintf("reason=%s\n", sReason))
		out = b.String()
		block = true
	}
	// Identity gap: honest degradation for horizontal tests without dual accounts.
	out = AppendIdentityGapIfNeeded(state, out)
	// blocked flag: true if gate rewrote wrap-up; identity gap alone does not count as "blocked"
	// unless wrap-up was also gated (preserves existing tests). If only identity gap appended
	// on wrap-up with open IDOR, still report blocked when gate fired.
	return out, block
}

// ApplyFinalizeGateToRunResult mutates RunResult.Response whenever ApplyFinalizeGate
// changes the text — wrap-up gate (blocked=true) and/or identity_gap (blocked may be false).
// Must not early-return on !blocked, or identity_gap would be discarded on the production path.
// Logs finalize_gate_blocked only when the wrap-up gate fired.
// 随后叠加 depth_force：无 open coverage 的浅扫收工也会被拦截。
func ApplyFinalizeGateToRunResult(out *RunResult, conversationID string, logger *zap.Logger) *RunResult {
	if out == nil {
		return out
	}
	orig := out.Response
	newResp, blocked := ApplyFinalizeGate(conversationID, orig)
	if newResp != orig {
		out.Response = newResp
		// Keep trace aligned when user-visible text gained gate or identity_gap markers.
		if blocked {
			if out.LastAgentTraceOutput == "" || !strings.Contains(out.LastAgentTraceOutput, "finalize_gate_blocked") {
				out.LastAgentTraceOutput = newResp
			}
		} else if strings.Contains(newResp, "identity_gap") {
			if out.LastAgentTraceOutput == "" || !strings.Contains(out.LastAgentTraceOutput, "identity_gap") {
				out.LastAgentTraceOutput = newResp
			}
		}
	}
	if blocked && logger != nil {
		logger.Info("finalize_gate_blocked",
			zap.String("conversation_id", conversationID),
			zap.Int("response_runes", len([]rune(newResp))),
		)
	}
	// 深度门闩：coverage 未开但工具过少时仍拦截「无洞收工」
	return ApplyDepthForceGateToRunResult(out, conversationID, logger)
}
