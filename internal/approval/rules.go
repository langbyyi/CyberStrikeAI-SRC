package approval

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
)

//go:embed assets/danger-rules.json
var bundledDangerRulesJSON []byte

type Rule struct {
	ID        string      `json:"id"`
	Enabled   bool        `json:"enabled"`
	Priority  int         `json:"priority"`
	RiskLevel string      `json:"riskLevel"`
	Matcher   RuleMatcher `json:"matcher"`
}

type RuleMatcher struct {
	Tools                []string            `json:"tools,omitempty"`
	HTTPMethods          []string            `json:"httpMethods,omitempty"`
	PathPatterns         []string            `json:"pathPatterns,omitempty"`
	ArgumentPatterns     map[string][]string `json:"argumentPatterns,omitempty"`
	TextPatterns         []string            `json:"textPatterns,omitempty"`
	RequireHTTPTransport bool                `json:"requireHttpTransport,omitempty"`
}

type compiledRule struct {
	rule             Rule
	tools            map[string]struct{}
	httpMethods      map[string]struct{}
	pathPatterns     []*regexp.Regexp
	argumentPatterns map[string][]*regexp.Regexp
	textPatterns     []*regexp.Regexp
}

type RuleSnapshot struct {
	rules []compiledRule
}

type RuleLoader struct {
	current atomic.Pointer[RuleSnapshot]
}

func LoadBundledDangerRules() ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal(bundledDangerRulesJSON, &rules); err != nil {
		return nil, fmt.Errorf("decode bundled danger rules: %w", err)
	}
	if len(rules) == 0 {
		return nil, errors.New("bundled danger rules are empty")
	}
	return rules, nil
}

func NewRuleLoader(rules []Rule) (*RuleLoader, error) {
	snapshot, err := compileRuleSnapshot(rules)
	if err != nil {
		return nil, err
	}
	loader := &RuleLoader{}
	loader.current.Store(snapshot)
	return loader, nil
}

func (l *RuleLoader) Publish(rules []Rule) error {
	if l == nil {
		return errors.New("rule loader is nil")
	}
	snapshot, err := compileRuleSnapshot(rules)
	if err != nil {
		return err
	}
	l.current.Store(snapshot)
	return nil
}

func (l *RuleLoader) Snapshot() *RuleSnapshot {
	if l == nil {
		return nil
	}
	return l.current.Load()
}

func compileRuleSnapshot(rules []Rule) (*RuleSnapshot, error) {
	compiled := make([]compiledRule, 0, len(rules))
	identities := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if err := validateRule(rule); err != nil {
			return nil, err
		}
	identity := rule.ID
	if _, exists := identities[identity]; exists {
		return nil, fmt.Errorf("duplicate danger rule %s", identity)
	}
		identities[identity] = struct{}{}
		item := compiledRule{
			rule:             rule,
			tools:            normalizedSet(rule.Matcher.Tools),
			httpMethods:      normalizedSet(rule.Matcher.HTTPMethods),
			argumentPatterns: make(map[string][]*regexp.Regexp, len(rule.Matcher.ArgumentPatterns)),
		}
		var err error
		if item.pathPatterns, err = compilePatterns(rule.ID, "path", rule.Matcher.PathPatterns); err != nil {
			return nil, err
		}
		if item.textPatterns, err = compilePatterns(rule.ID, "text", rule.Matcher.TextPatterns); err != nil {
			return nil, err
		}
		for argument, patterns := range rule.Matcher.ArgumentPatterns {
			compiledPatterns, compileErr := compilePatterns(rule.ID, "argument "+argument, patterns)
			if compileErr != nil {
				return nil, compileErr
			}
			item.argumentPatterns[strings.ToLower(strings.TrimSpace(argument))] = compiledPatterns
		}
		compiled = append(compiled, item)
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].rule.Priority == compiled[j].rule.Priority {
			return compiled[i].rule.ID < compiled[j].rule.ID
		}
		return compiled[i].rule.Priority > compiled[j].rule.Priority
	})
	return &RuleSnapshot{rules: compiled}, nil
}

func validateRule(rule Rule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return errors.New("danger rule requires an id")
	}
	if rule.RiskLevel != "" && riskRank(rule.RiskLevel) == 0 {
		return fmt.Errorf("danger rule %s has invalid risk level %q", rule.ID, rule.RiskLevel)
	}
	if rule.RiskLevel == "" {
		return fmt.Errorf("danger rule %s requires a risk level", rule.ID)
	}
	matcher := rule.Matcher
	if len(matcher.Tools) == 0 && len(matcher.HTTPMethods) == 0 && len(matcher.PathPatterns) == 0 && len(matcher.ArgumentPatterns) == 0 && len(matcher.TextPatterns) == 0 {
		return fmt.Errorf("danger rule %s has an empty matcher", rule.ID)
	}
	// 预编译校验：发布时语法无效的规则必须被拒绝，否则快照加载时会让
	// 所有经全局审批运行时的工具调用持续失败（fail-closed 自伤）。
	if _, err := compilePatterns(rule.ID, "path", matcher.PathPatterns); err != nil {
		return err
	}
	if _, err := compilePatterns(rule.ID, "text", matcher.TextPatterns); err != nil {
		return err
	}
	for argument, patterns := range matcher.ArgumentPatterns {
		if _, err := compilePatterns(rule.ID, "argument "+argument, patterns); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRule validates a rule submitted through the global administration API.
func ValidateRule(rule Rule) error { return validateRule(rule) }

// maxPatternLength 限制单条正则源的长度：编译期拒绝病态规则，
// 与 RE2 线性时间匹配共同构成热路径防护。
const maxPatternLength = 4096

func compilePatterns(ruleID, field string, patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if len(pattern) > maxPatternLength {
			return nil, fmt.Errorf("danger rule %s %s pattern exceeds %d bytes", ruleID, field, maxPatternLength)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile danger rule %s %s pattern: %w", ruleID, field, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func normalizedSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}
