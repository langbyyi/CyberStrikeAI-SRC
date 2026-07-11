package multiagent

import "strings"

// Identity gap finalize hint (R5): ONLY about horizontal/cross-account access control.
// MUST NOT claim "logic track cannot run" or "all business logic skipped without dual accounts".
// Single-identity payment/workflow/race testing remains fully valid.
const IdentityGapFinalizeHint = "\n\n## [identity_gap] 框架提示（非用户消息）\n" +
	"**仅影响跨账号/水平越权（idor_horizontal）类项**：本会话有相关 open/in_progress，但未记录双身份探针（auth_a + auth_b）。\n" +
	"- 水平越权/对象级授权：建议补第二账号后用 `logic_probe_diff` mode=`identity_diff` 对比；或将对应 path 标 `blocked` 并注明「无第二账号」。\n" +
	"- **支付金额篡改、流程跳步、优惠券/竞态、状态机等业务/后端缺陷不依赖双账号**，请继续用 param_tamper / step_skip / parallel 推进，禁止因无双号宣称「逻辑漏洞无法测」或整轨跳过。\n"

// HasOpenIDORHorizontal reports whether any open|in_progress coverage is horizontal IDOR-like.
func HasOpenIDORHorizontal(state *ConversationExecutionState) bool {
	if state == nil {
		return false
	}
	for _, it := range state.ListCoverage() {
		st := strings.ToLower(strings.TrimSpace(it.Status))
		if st != "open" && st != "in_progress" && st != "" {
			continue
		}
		path := strings.ToLower(it.Path + " " + it.Note)
		// Prefer explicit class segment; avoid matching "order" alone.
		if strings.Contains(path, LogicClassIDORHoriz) ||
			strings.Contains(path, "idor_horizontal") ||
			strings.Contains(path, "logic.idor") ||
			(strings.Contains(path, "idor") && !strings.Contains(path, "param_tamper")) {
			return true
		}
	}
	return false
}

// BuildIdentityGapHint returns the identity-gap block when IDOR open and no dual-auth probe.
// Pure function: never implies whole Logic Track is blocked without dual accounts.
func BuildIdentityGapHint(state *ConversationExecutionState) string {
	if state == nil {
		return ""
	}
	if !HasOpenIDORHorizontal(state) {
		return ""
	}
	if state.HasDualAuthProbe() {
		return ""
	}
	return IdentityGapFinalizeHint
}

// AppendIdentityGapIfNeeded appends identity gap text when applicable (idempotent).
func AppendIdentityGapIfNeeded(state *ConversationExecutionState, response string) string {
	hint := BuildIdentityGapHint(state)
	if hint == "" {
		return response
	}
	if strings.Contains(response, "identity_gap") {
		return response
	}
	// Never rewrite response into "logic fully skipped"
	return response + hint
}

// IdentityGapImpliesWholeTrackSkip detects R5-forbidden *affirmative* claims that
// dual-account absence cancels the whole business/backend track.
// Mentions inside "禁止宣称…" educational disclaimers do NOT count.
func IdentityGapImpliesWholeTrackSkip(text string) bool {
	// Strip educational "do not claim X" clauses so they are not false positives.
	cleaned := text
	for _, neg := range []string{"禁止因无双号宣称", "禁止宣称", "不得宣称", "不要宣称", "勿宣称"} {
		if i := strings.Index(cleaned, neg); i >= 0 {
			// drop rest of that sentence/clause roughly
			rest := cleaned[i:]
			if end := strings.IndexAny(rest, "。\n"); end > 0 {
				cleaned = cleaned[:i] + cleaned[i+end:]
			} else {
				cleaned = cleaned[:i]
			}
		}
	}
	// Affirmative over-broad claims (after stripping negations)
	forbidden := []string{
		"无法测逻辑漏洞",
		"逻辑漏洞无法测",
		"逻辑轨无法推进",
		"逻辑全跳过",
		"整轨跳过",
		"无双号无法测逻辑",
		"cannot test logic without dual",
		"logic track disabled",
		"skip all logic",
	}
	low := strings.ToLower(cleaned)
	for _, f := range forbidden {
		if strings.Contains(cleaned, f) || strings.Contains(low, strings.ToLower(f)) {
			return true
		}
	}
	return false
}
