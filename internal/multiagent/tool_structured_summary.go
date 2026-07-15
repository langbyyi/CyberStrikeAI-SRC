package multiagent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// DefaultStructuredSummaryMaxRunes is the default budget for the prepended summary block (800–1500).
const DefaultStructuredSummaryMaxRunes = 1200

// StructuredSummaryTools tools that get a fixed-structure summary prepended to results.
var StructuredSummaryTools = map[string]struct{}{
	"sqlmap":                 {},
	"nuclei":                 {},
	"ffuf":                   {},
	"http-framework-test":    {},
	"dalfox":                 {},
	"execute-python-script":  {},
	"katana":                 {},
	"arjun":                  {},
	"jwt-analyzer":           {},
	"exec":                   {},
	"execute":                {},
}

// ShouldStructureToolResult reports whether toolName should get a structured summary prepend.
func ShouldStructureToolResult(toolName string) bool {
	tn := normalizeToolBaseName(toolName)
	_, ok := StructuredSummaryTools[tn]
	return ok
}

func normalizeToolBaseName(toolName string) string {
	tn := strings.ToLower(strings.TrimSpace(toolName))
	if idx := strings.LastIndex(tn, "__"); idx >= 0 {
		tn = tn[idx+2:]
	}
	if idx := strings.LastIndex(tn, "::"); idx >= 0 {
		tn = tn[idx+2:]
	}
	return tn
}

// StructuredToolSummary is the fixed field set prepended to scanner tool results.
type StructuredToolSummary struct {
	StatusHint        string `json:"status_hint"`
	HTTPStatus        string `json:"http_status,omitempty"`
	Length            int    `json:"length"`
	TimeMs            int64  `json:"time_ms,omitempty"`
	ErrorSig          string `json:"error_sig,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"` // ok/templates_missing/target_unreachable/timeout/config_error
	Retryable         bool   `json:"retryable,omitempty"`
	InterestingParams string `json:"interesting_params,omitempty"`
	MatchedPayload    string `json:"matched_payload,omitempty"`
	NextHint          string `json:"next_hint,omitempty"`
}

var (
	reHTTPStatus   = regexp.MustCompile(`(?i)\b(?:HTTP/\d(?:\.\d)?\s+|status(?:\s*code)?[:\s=]+)(\d{3})\b`)
	reTimeMs       = regexp.MustCompile(`(?i)\b(\d+(?:\.\d+)?)\s*(?:ms|milliseconds)\b`)
	reTimeSec      = regexp.MustCompile(`(?i)\b(\d+(?:\.\d+)?)\s*(?:s|sec|seconds)\b`)
	rePayloadHint  = regexp.MustCompile(`(?i)(?:payload|inject(?:ion)?|parameter)\s*[:=]\s*([^\n]{3,120})`)
	// Include payment/business keys so backend-logic signals surface in structured summaries.
	reInteresting = regexp.MustCompile(`(?i)\b((?:id|user_id|uid|file|path|url|redirect|q|search|token|jwt|page|order|sort|price|amount|quantity|total_fee|coupon|discount|balance|checkout|payment)[=:][^\s&"'<>]{1,80})`)
)

// BuildStructuredToolSummary extracts fields from tool I/O (pure helper for tests + middleware).
func BuildStructuredToolSummary(toolName, arguments, output string) StructuredToolSummary {
	s := StructuredToolSummary{
		Length: len(output),
	}
	low := strings.ToLower(output)
	entry := SummarizeToolResult(toolName, arguments, output)
	s.StatusHint = entry.StatusHint
	s.ErrorSig = entry.ErrorSig
	s.InterestingParams = entry.InterestingParams
	s.MatchedPayload = entry.PayloadHint

	if m := reHTTPStatus.FindStringSubmatch(output); len(m) > 1 {
		s.HTTPStatus = m[1]
	}
	if m := reTimeMs.FindStringSubmatch(output); len(m) > 1 {
		var f float64
		fmt.Sscanf(m[1], "%f", &f)
		s.TimeMs = int64(f)
	} else if m := reTimeSec.FindStringSubmatch(output); len(m) > 1 {
		var f float64
		fmt.Sscanf(m[1], "%f", &f)
		s.TimeMs = int64(f * 1000)
	}
	if s.MatchedPayload == "" {
		if m := rePayloadHint.FindStringSubmatch(output); len(m) > 1 {
			s.MatchedPayload = truncateRunes(strings.TrimSpace(m[1]), 120)
		}
	}
	if s.InterestingParams == "" {
		if ms := reInteresting.FindAllString(output, 6); len(ms) > 0 {
			s.InterestingParams = strings.Join(ms, "; ")
		}
	}
	// args JSON enrichment
	if strings.TrimSpace(arguments) != "" {
		var raw map[string]interface{}
		if json.Unmarshal([]byte(arguments), &raw) == nil {
			keys := make([]string, 0, 8)
			for k, v := range raw {
				ks := strings.ToLower(k)
				if strings.Contains(ks, "url") || strings.Contains(ks, "param") || strings.Contains(ks, "payload") ||
					strings.Contains(ks, "data") || strings.Contains(ks, "target") || strings.Contains(ks, "cmd") ||
					strings.Contains(ks, "price") || strings.Contains(ks, "amount") || strings.Contains(ks, "coupon") ||
					strings.Contains(ks, "payment") || strings.Contains(ks, "checkout") || strings.Contains(ks, "quantity") ||
					ks == "id" || ks == "file" || ks == "path" || ks == "q" || ks == "token" || ks == "jwt" ||
					ks == "total_fee" || ks == "discount" || ks == "balance" {
					keys = append(keys, fmt.Sprintf("%s=%v", k, truncateRunes(fmt.Sprint(v), 80)))
				}
			}
			if len(keys) > 0 && s.InterestingParams == "" {
				s.InterestingParams = strings.Join(keys, "; ")
			}
			if s.MatchedPayload == "" {
				if p, ok := raw["payload"]; ok {
					s.MatchedPayload = truncateRunes(fmt.Sprint(p), 120)
				}
			}
		}
	}
	// status_hint refinement for scanners + attack-surface inventory
	tn := normalizeToolBaseName(toolName)
	switch {
	case strings.Contains(low, "vulnerable") || strings.Contains(low, "injection found") ||
		strings.Contains(low, "is vulnerable") || strings.Contains(low, "[critical]") ||
		strings.Contains(low, "[high]") && strings.Contains(low, "matched"):
		s.StatusHint = "interesting"
	case HasHighValueSurfaceSignal(output):
		// API/schema inventory or high-value disclosure: not a soft "ok" 200.
		s.StatusHint = "interesting"
	case strings.Contains(low, "error") || strings.Contains(low, "failed") || strings.Contains(low, "traceback"):
		if s.StatusHint == "ok" {
			s.StatusHint = "error_or_reject"
		}
	}
	s.ErrorCode, s.Retryable = classifyToolError(output)
	s.NextHint = nextHintForTool(tn, s)
	if HasHighValueSurfaceSignal(output) && (s.NextHint == "" || strings.Contains(s.NextHint, "对照框架版本")) {
		s.NextHint = "高价值攻击面已暴露：先 L1/L2 落库，再用已加载工具钉住入口/资源验证；勿只总结或跳无关横向"
	}
	return s
}

// classifyToolError 将工具输出按模式匹配分类为可操作的 error_code（取代裸首行 error_sig 启发式）。
// 返回 (code, retryable)；code 为空表示无明显错误分类，交由 status_hint 处理。
// 枚举：templates_missing / target_unreachable / timeout / config_error。
func classifyToolError(output string) (string, bool) {
	if output == "" {
		return "", false
	}
	low := strings.ToLower(output)
	switch {
	case strings.Contains(low, "[preflight]"):
		return "config_error", false
	case strings.Contains(low, "could not find templates") || strings.Contains(low, "no templates") ||
		strings.Contains(low, "templates directory") || strings.Contains(low, "templates-dir") ||
		strings.Contains(low, "template path"):
		return "templates_missing", false
	case strings.Contains(low, "connection refused") || strings.Contains(low, "no route to host") ||
		strings.Contains(low, "network is unreachable") || strings.Contains(low, "host is unreachable") ||
		strings.Contains(low, "could not resolve") || strings.Contains(low, "name resolution") ||
		strings.Contains(low, "name or service not known"):
		return "target_unreachable", false
	case strings.Contains(low, "deadline exceeded") || strings.Contains(low, "context deadline") ||
		strings.Contains(low, "timed out") || strings.Contains(low, "timeout expired") ||
		strings.Contains(low, "no new output") || strings.Contains(low, "命令已终止") || strings.Contains(low, "已超过"):
		return "timeout", true
	}
	return "", false
}

func nextHintForTool(toolName string, s StructuredToolSummary) string {
	// 优先按 error_code 给可操作的换路指引（取代静态首行启发式）。
	switch s.ErrorCode {
	case "templates_missing":
		return "模板库缺失：运行 nuclei -update-templates 安装模板，或改用 http-framework-test 等不依赖模板库的工具"
	case "target_unreachable":
		return "目标不可达：核对目标/端口可达性与 DNS，换可达资产；勿在此目标重复同类请求"
	case "timeout":
		return "超时：收窄范围/调限速参数（-rate-limit/-timeout），或对慢资产后台运行后查结果；本类可重试"
	case "config_error":
		return "配置缺失：按 [preflight] 提示补齐字典/模板等前置依赖后再重试"
	}
	// 无明确错误分类时回退到按工具语义的静态提示。
	switch toolName {
	case "sqlmap":
		if s.StatusHint == "interesting" {
			return "对命中参数做手工验证；record_vulnerability_candidate 记 L1，闭环后 L2"
		}
		return "检查 DBMS 指纹/参数可注性；失败则换技巧(--technique)或手工布尔/时间盲注"
	case "nuclei":
		if s.StatusHint == "interesting" {
			return "对 matched template 做手工复现；排除误报后记 candidate/L2"
		}
		return "收窄 severity/tags 重扫；对关键路径改 http-framework-test 深挖"
	case "ffuf", "katana", "arjun":
		return "对发现路径/参数做差异探测；高价值点 upsert_execution_coverage 并深测"
	case "dalfox":
		return "确认反射上下文；用 fetch 到受控地址证危害，禁 alert"
	case "http-framework-test":
		if s.StatusHint == "interesting" {
			return "高信号响应：落库 candidate/info，钉住路径做 method/参数验证；勿只总结"
		}
		return "对照框架版本与已知 CVE；服务清单/堆栈类信号写 candidate 并深挖业务入口"
	case "execute-python-script", "exec", "execute":
		return "保留关键 stdout/stderr；成功 PoC 写入 proof 再 L2"
	default:
		if s.StatusHint == "interesting" {
			return "保留差分证据并继续验证闭环"
		}
		return "结合参数/状态码差异决定是否深挖或标记 blocked"
	}
}

// FormatStructuredSummaryBlock renders the fixed-field block for prepending (rune budget).
func FormatStructuredSummaryBlock(s StructuredToolSummary, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = DefaultStructuredSummaryMaxRunes
	}
	var b strings.Builder
	b.WriteString("## [tool_structured_summary]\n")
	b.WriteString(fmt.Sprintf("status_hint: %s\n", emptyDash(s.StatusHint)))
	b.WriteString(fmt.Sprintf("http_status: %s\n", emptyDash(s.HTTPStatus)))
	b.WriteString(fmt.Sprintf("length: %d\n", s.Length))
	if s.TimeMs > 0 {
		b.WriteString(fmt.Sprintf("time_ms: %d\n", s.TimeMs))
	} else {
		b.WriteString("time_ms: -\n")
	}
	b.WriteString(fmt.Sprintf("error_sig: %s\n", emptyDash(s.ErrorSig)))
	b.WriteString(fmt.Sprintf("error_code: %s\n", emptyDash(s.ErrorCode)))
	if s.ErrorCode != "" {
		b.WriteString(fmt.Sprintf("retryable: %v\n", s.Retryable))
	}
	b.WriteString(fmt.Sprintf("interesting_params: %s\n", emptyDash(s.InterestingParams)))
	b.WriteString(fmt.Sprintf("matched_payload: %s\n", emptyDash(s.MatchedPayload)))
	b.WriteString(fmt.Sprintf("next_hint: %s\n", emptyDash(s.NextHint)))
	b.WriteString("---\n")
	out := b.String()
	if len([]rune(out)) > maxRunes {
		return truncateRunes(out, maxRunes-1) + "\n"
	}
	return out
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return strings.TrimSpace(s)
}

// PrependStructuredToolSummary if applicable, prepends summary to result (does not strip body).
// Safe for non-UTF8, oversized, and empty inputs (no panic). Does not strip original body.
func PrependStructuredToolSummary(toolName, arguments, result string, maxRunes int) (string, bool) {
	if !ShouldStructureToolResult(toolName) {
		return result, false
	}
	// Bound pathological inputs for regex / rune walks (body still attached, possibly truncated).
	const maxScanBytes = 2 << 20 // 2 MiB scan window
	scanBody := result
	if len(scanBody) > maxScanBytes {
		scanBody = scanBody[:maxScanBytes]
	}
	sum := BuildStructuredToolSummary(toolName, arguments, scanBody)
	// Preserve original length for observability.
	sum.Length = len(result)
	block := FormatStructuredSummaryBlock(sum, maxRunes)
	return block + result, true
}

// ComposeToolResultWithBoostOrder documents and applies the stable post-process order:
//
//	structured summary (optional) → original body (caller-provided) → skill block (optional)
//
// Used by executionBoost middleware and unit tests so SkillRouter never appears above the summary.
func ComposeToolResultWithBoostOrder(summaryBlock, body, skillBlock string) string {
	var b strings.Builder
	if summaryBlock != "" {
		b.WriteString(summaryBlock)
	}
	b.WriteString(body)
	if skillBlock != "" {
		b.WriteString(skillBlock)
	}
	return b.String()
}
