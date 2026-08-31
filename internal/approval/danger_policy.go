package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// maxMatchTextBytes 限制单次文本匹配输入的长度。规则匹配发生在每次工具
// 调用的热路径上：Go regexp 是 RE2 线性时间（无回溯），但超大输入仍有
// 实际性能成本。超限参数截断后参与匹配——工具名级判定（类别底线）
// 不受影响，仅超长参数的 text/path 特征可能漏配，属可接受取舍。
const maxMatchTextBytes = 32 * 1024

func limitMatchText(value string) string {
	if len(value) <= maxMatchTextBytes {
		return value
	}
	return value[:maxMatchTextBytes]
}

var httpURLPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>\\]+`)

type DangerousActionPolicy struct {
	enabled bool
	loader  *RuleLoader
}

func NewDangerousActionPolicy(enabled bool, loader *RuleLoader) *DangerousActionPolicy {
	return &DangerousActionPolicy{enabled: enabled, loader: loader}
}

func (p *DangerousActionPolicy) Name() string { return "dangerous_action" }

func (p *DangerousActionPolicy) Evaluate(_ context.Context, invocation Invocation) (TriggerResult, error) {
	if p == nil || !p.enabled {
		return TriggerResult{}, nil
	}
	snapshot := p.loader.Snapshot()
	if snapshot == nil {
		return TriggerResult{}, errors.New("danger rule snapshot is unavailable")
	}
	result := TriggerResult{RiskLevel: RiskNone}
	for _, rule := range snapshot.rules {
		matched, metadata := rule.matches(invocation)
		if !matched {
			continue
		}
		result.Findings = append(result.Findings, TriggerFinding{
			Source: p.Name(), RuleID: rule.rule.ID, PolicyID: rule.rule.ID,
			RiskLevel: rule.rule.RiskLevel, Message: "dangerous action rule matched", Metadata: metadata,
		})
		result.PolicyIDs = append(result.PolicyIDs, rule.rule.ID)
		if riskRank(rule.rule.RiskLevel) > riskRank(result.RiskLevel) {
			result.RiskLevel = rule.rule.RiskLevel
		}
	}
	result.PolicyIDs = sortedUnique(result.PolicyIDs)
	result.Matched = len(result.Findings) > 0
	return result, nil
}

func (r compiledRule) matches(invocation Invocation) (bool, map[string]any) {
	toolName := strings.ToLower(strings.TrimSpace(invocation.ToolName))
	if len(r.tools) > 0 {
		if _, all := r.tools["*"]; !all {
			if _, ok := r.tools[toolName]; !ok {
				return false, nil
			}
		}
	}
	blob := limitMatchText(argumentText(invocation.Arguments))
	if r.rule.Matcher.RequireHTTPTransport && !looksLikeHTTPTransport(blob) {
		return false, nil
	}
	metadata := map[string]any{"tool": invocation.ToolName}
	if len(r.httpMethods) > 0 {
		method := strings.ToLower(strings.TrimSpace(stringArgument(invocation.Arguments, "method")))
		if _, ok := r.httpMethods[method]; !ok {
			return false, nil
		}
		metadata["method"] = strings.ToUpper(method)
	}
	if len(r.pathPatterns) > 0 {
		matchedPath := ""
		for _, candidate := range candidatePaths(invocation.Arguments, blob) {
			if matchesAny(r.pathPatterns, candidate) {
				matchedPath = candidate
				break
			}
		}
		if matchedPath == "" {
			return false, nil
		}
		metadata["path"] = matchedPath
	}
	if len(r.argumentPatterns) > 0 {
		matchedArgument := ""
		for name, patterns := range r.argumentPatterns {
			value := limitMatchText(stringArgument(invocation.Arguments, name))
			if value != "" && matchesAny(patterns, value) {
				matchedArgument = name
				break
			}
		}
		if matchedArgument == "" {
			return false, nil
		}
		metadata["argument"] = matchedArgument
	}
	if len(r.textPatterns) > 0 && !matchesAny(r.textPatterns, blob) {
		return false, nil
	}
	return true, metadata
}

func matchesAny(patterns []*regexp.Regexp, value string) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func argumentText(arguments map[string]any) string {
	if arguments == nil {
		return ""
	}
	parts := make([]string, 0, len(arguments)+1)
	for _, key := range []string{"command", "script", "script_content", "code", "body", "data", "url", "raw", "payload"} {
		if value := stringArgument(arguments, key); value != "" {
			parts = append(parts, value)
		}
	}
	if raw, err := json.Marshal(arguments); err == nil {
		parts = append(parts, string(raw))
	}
	return strings.Join(parts, "\n")
}

func stringArgument(arguments map[string]any, key string) string {
	for candidate, value := range arguments {
		if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(key)) {
			switch typed := value.(type) {
			case string:
				return strings.TrimSpace(typed)
			case fmt.Stringer:
				return strings.TrimSpace(typed.String())
			default:
				return strings.TrimSpace(fmt.Sprint(typed))
			}
		}
	}
	return ""
}

func candidatePaths(arguments map[string]any, blob string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 8)
	add := func(candidate string) {
		candidate = strings.TrimSpace(strings.TrimRight(candidate, `"'>,);`))
		if candidate == "" {
			return
		}
		if parsed, err := url.Parse(candidate); err == nil && parsed.Path != "" {
			candidate = parsed.Path
			if parsed.RawQuery != "" {
				candidate += "?" + parsed.RawQuery
			}
		}
		key := strings.ToLower(candidate)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, candidate)
	}
	add(stringArgument(arguments, "url"))
	for _, candidate := range httpURLPattern.FindAllString(blob, 32) {
		add(candidate)
	}
	return out
}

func looksLikeHTTPTransport(blob string) bool {
	lower := strings.ToLower(blob)
	for _, marker := range []string{"http://", "https://", "curl ", "wget ", "requests.", "httpx.", "urllib", "aiohttp", "fetch("} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
