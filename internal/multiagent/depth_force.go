package multiagent

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// MinVerificationToolsBeforeWrapUp：收工前至少需要的「验证类」工具调用次数。
// 低于此数且话术像收工 → 深度门闩拦截，逼模型继续实锤。
const MinVerificationToolsBeforeWrapUp = 3

// MinTotalToolsBeforeWrapUp：收工前总工具调用下限（含 skill/coverage 等）。
const MinTotalToolsBeforeWrapUp = 5

// DepthForceInstruction 浅扫收工时追加的强制续测块。
const DepthForceInstruction = "\n\n## [depth_force_blocked] 框架深度门闩（非用户消息）\n" +
	"当前会话验证深度不足（工具调用过少或几乎只有元工具/信息收集），但回复呈现收工/无洞话术。\n" +
	"**禁止交付。** 立即执行至少一项真实验证（不可只 upsert/只 skill）：\n" +
	"1. **参数级验证**：对已发现入口用 `http-framework-test` / `exec`(curl) 或角色已挂载的扫描/利用工具做差分或 payload 确认；\n" +
	"2. **攻击面补强**：用角色 tools 内可用的枚举/测试能力补入口，再对手测 1 个高信号点；\n" +
	"3. **业务轨**：支付/流程入口优先 `logic_probe_diff`（param_tamper / step_skip / parallel）；\n" +
	"4. 有信号 → `record_vulnerability_candidate`；死路 → coverage `blocked` + 原因；再 `should_continue_execution`。\n" +
	"**禁止：未验证就写「未发现漏洞」。扫描器是否可用以当前角色 tools 为准，框架不强制挂载扫描器。**\n"

// DepthForceNextHint 工具结果出现 interesting 信号时强制追加的下一步。
const DepthForceNextHint = "\n\n## [depth_force_next] 框架强制深挖（非用户消息）\n" +
	"上一步输出含高信号，**禁止只总结**。下一动作必须是：\n" +
	"1. 对同一 target/param 再做一次确认性验证（换 payload / 换工具 / 对比正常基线）；\n" +
	"2. 确认可复现 → `record_vulnerability_candidate`（L1）或 `record_vulnerability`（完整 PoC）；\n" +
	"3. 不可复现 → `upsert_execution_coverage` 标 `blocked` 并写原因，换相邻攻击面。\n" +
	"然后调用 `should_continue_execution` 决定是否还有 open P0/P1。\n"

// metaOrShallowTools 不计入「验证深度」的工具（元调度 / 记账 / 纯列表）。
var metaOrShallowTools = map[string]struct{}{
	"skill": {}, "tool_search": {}, "task": {}, "transfer_to_agent": {}, "exit": {},
	"write_todos": {}, "taskcreate": {}, "taskget": {}, "taskupdate": {}, "tasklist": {},
	"list_vulnerabilities": {}, "get_vulnerability": {}, "update_vulnerability": {}, "delete_vulnerability": {}, "list_project_facts": {},
	"get_project_fact": {}, "search_project_facts": {}, "get_execution_coverage": {},
	"should_continue_execution": {}, "upsert_execution_coverage": {}, "upsert_project_fact": {},
}

// verificationTools 计入验证深度的工具名（小写）。
var verificationTools = map[string]struct{}{
	"exec": {}, "execute": {}, "execute-python-script": {},
	"http-framework-test": {}, "sqlmap": {}, "nuclei": {}, "ffuf": {}, "katana": {},
	"arjun": {}, "dalfox": {}, "jwt-analyzer": {}, "dnslog": {},
	"logic_probe_diff": {}, "nmap": {}, "gobuster": {}, "feroxbuster": {},
	"wpscan": {}, "nikto": {}, "hydra": {}, "x8": {}, "paramspider": {},
	"record_vulnerability": {}, "record_vulnerability_candidate": {},
}

// TotalToolCount 返回会话已记录工具次数。
func (s *ConversationExecutionState) TotalToolCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.RecentTools)
}

// VerificationToolCount 返回验证类工具调用次数。
func (s *ConversationExecutionState) VerificationToolCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.RecentTools {
		if isVerificationToolName(e.ToolName) {
			n++
		}
	}
	return n
}

func isVerificationToolName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if _, shallow := metaOrShallowTools[n]; shallow {
		return false
	}
	if _, ok := verificationTools[n]; ok {
		return true
	}
	// 外部 MCP：名称含 exec/scan 等启发式
	if strings.Contains(n, "sqlmap") || strings.Contains(n, "nuclei") ||
		strings.Contains(n, "ffuf") || strings.Contains(n, "scan") {
		return true
	}
	return false
}

// IsInterestingStatusHint 是否应对工具结果强制深挖提示。
func IsInterestingStatusHint(hint string) bool {
	h := strings.ToLower(strings.TrimSpace(hint))
	return h == "interesting" || h == "vuln" || h == "vulnerable" || h == "confirmed"
}

// AppendDepthForceNextHint 在 interesting 工具结果后追加强制下一步（已含标记则跳过）。
func AppendDepthForceNextHint(result, statusHint string) string {
	if !IsInterestingStatusHint(statusHint) {
		return result
	}
	if strings.Contains(result, "depth_force_next") {
		return result
	}
	// 结果正文也强信号时同样追加（status 可能未标 interesting）
	return result + DepthForceNextHint
}

// AppendDepthForceNextHintFromBody 基于结果正文启发式追加（SQL 报错、反射、401 绕过等）。
func AppendDepthForceNextHintFromBody(result string) string {
	if strings.Contains(result, "depth_force_next") {
		return result
	}
	low := strings.ToLower(result)
	signals := []string{
		"sql syntax", "mysql", "sqlite", "ora-", "postgresql", "odbc",
		"you have an error in your sql",
		"root:x:", "uid=0", "www-data",
		"stack trace", "traceback (most recent",
		"<script>alert", "onerror=",
		"internal server error", " monolog ",
		"jwt", "eyj", // weak: only with other signals
		"permission denied", "access denied",
		"\"code\":0", "\"success\":true", // business success after tamper often appears with logic track
	}
	hits := 0
	for _, s := range signals {
		if strings.Contains(low, s) {
			hits++
		}
	}
	// 需要至少 1 个强信号；jwt 单独不算
	strong := []string{
		"sql syntax", "you have an error in your sql", "root:x:", "uid=0",
		"<script>alert", "stack trace", "traceback (most recent",
		// High-value surfaces across scenarios (API inventory / disclosure / cloud / VCS).
		"service list", "openapi", "swagger", "__schema", "wsdl",
		"exception report", "phpinfo()", "index of /", ".git/head",
		"169.254.169.254", "begin rsa private key", "akia",
	}
	for _, s := range strong {
		if strings.Contains(low, s) {
			return result + DepthForceNextHint
		}
	}
	if hits >= 2 {
		return result + DepthForceNextHint
	}
	return result
}

// DepthShouldBlockFinalize：浅验证 + 收工话术 → 拦截。
// 即使没有 open coverage（模型从未 upsert），也要挡「一两个 skill 就无洞收工」。
func DepthShouldBlockFinalize(state *ConversationExecutionState, responseText string) (bool, string) {
	if !IsFinalizeWrapUpText(responseText) {
		return false, ""
	}
	if state == nil {
		// 无状态仍视为过浅
		return true, "no_execution_state"
	}
	total := state.TotalToolCount()
	verify := state.VerificationToolCount()
	if verify < MinVerificationToolsBeforeWrapUp {
		return true, fmt.Sprintf("verification_tools=%d<%d", verify, MinVerificationToolsBeforeWrapUp)
	}
	if total < MinTotalToolsBeforeWrapUp {
		return true, fmt.Sprintf("total_tools=%d<%d", total, MinTotalToolsBeforeWrapUp)
	}
	return false, ""
}

// ApplyDepthForceGate 在 finalize 之后再跑：补浅扫拦截。
func ApplyDepthForceGate(conversationID, response string) (string, bool) {
	resp := strings.TrimSpace(response)
	if resp == "" || strings.Contains(resp, "depth_force_blocked") {
		return response, false
	}
	// 已被 coverage finalize 拦住时，不再叠加强制块（避免双重噪音）；仍可在无 coverage 时单独挡
	if strings.Contains(resp, "finalize_gate_blocked") {
		return response, false
	}
	state := GetConversationExecutionState(conversationID)
	block, reason := DepthShouldBlockFinalize(state, resp)
	if !block {
		return response, false
	}
	var b strings.Builder
	b.WriteString(resp)
	b.WriteString(DepthForceInstruction)
	b.WriteString(fmt.Sprintf("reason=%s total_tools=%d verification_tools=%d\n",
		reason, state.TotalToolCount(), state.VerificationToolCount()))
	return b.String(), true
}

// ApplyDepthForceGateToRunResult 写入 RunResult 并打日志。
func ApplyDepthForceGateToRunResult(out *RunResult, conversationID string, logger *zap.Logger) *RunResult {
	if out == nil {
		return out
	}
	orig := out.Response
	newResp, blocked := ApplyDepthForceGate(conversationID, orig)
	if newResp != orig {
		out.Response = newResp
		if blocked && (out.LastAgentTraceOutput == "" || !strings.Contains(out.LastAgentTraceOutput, "depth_force_blocked")) {
			out.LastAgentTraceOutput = newResp
		}
	}
	if blocked && logger != nil {
		logger.Info("depth_force_blocked",
			zap.String("conversation_id", conversationID),
			zap.Int("response_runes", len([]rune(newResp))),
		)
	}
	return out
}
