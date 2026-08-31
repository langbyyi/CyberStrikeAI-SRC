package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/openai"

	"go.uber.org/zap"
)

// auditAgentReview 在 reviewer=audit_agent 时由 LLM 代行审批。
// 白名单工具在 shouldInterrupt 阶段已跳过，到达此处的一律需要裁决。
func (h *AgentHandler) auditAgentReview(ctx context.Context, toolName string, payload map[string]interface{}) hitlDecision {
	if h == nil {
		return hitlDecision{Decision: "reject", Comment: "audit agent: handler unavailable"}
	}
	prompt := config.DefaultHitlAuditAgentPrompt()
	if h.config != nil {
		prompt = h.config.Hitl.EffectiveAuditAgentPrompt()
	}
	llmCfg := h.auditLLMConfig()
	if strings.TrimSpace(llmCfg.APIKey) == "" || strings.TrimSpace(llmCfg.Model) == "" {
		return hitlDecision{Decision: "reject", Comment: "audit agent: LLM 未配置"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	userContent := buildAuditAgentReviewInput(toolName, payload)
	requestBody := map[string]interface{}{
		"model": strings.TrimSpace(llmCfg.Model),
		"messages": []map[string]interface{}{
			{"role": "system", "content": prompt},
			{"role": "user", "content": userContent},
		},
		"temperature": 0.1,
		// 思考型模型（step-3.7-flash 等）会把推理 token 计入输出预算：
		// 上限过低时推理写一半就被截断，决策 JSON 根本来不及输出（日志曾出现
		// "响应无法解析，保守拒绝"）。max_tokens 与 max_completion_tokens 双发，
		// 兼容只认其一的网关。
		"max_tokens":            2048,
		"max_completion_tokens": 2048,
		// 关闭 thinking 双参数：thinking 对象是 DeepSeek/DashScope 网关约定；
		// enable_thinking 是 stepfun 等兼容模式的标准开关，端点不认的会静默忽略。
		"thinking":        map[string]interface{}{"type": "disabled"},
		"enable_thinking": false,
	}

	var apiResponse struct {
		Choices []struct {
			Message struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
	}
	client := openai.NewClient(&llmCfg, nil, h.logger)
	if err := client.ChatCompletion(callCtx, requestBody, &apiResponse); err != nil {
		h.logger.Warn("审计 Agent LLM 调用失败", zap.Error(err), zap.String("tool", toolName))
		return hitlDecision{
			Decision: "reject",
			Comment:  "audit agent: LLM 调用失败，保守拒绝",
		}
	}
	if len(apiResponse.Choices) == 0 {
		return hitlDecision{Decision: "reject", Comment: "audit agent: LLM 无有效响应，保守拒绝"}
	}
	msg := apiResponse.Choices[0].Message
	raw := strings.TrimSpace(msg.Content)
	if raw == "" {
		raw = strings.TrimSpace(msg.ReasoningContent)
	}
	dec, err := parseAuditAgentLLMContent(raw)
	if err != nil {
		snippet := raw
		if len(snippet) > 240 {
			snippet = snippet[:240] + "..."
		}
		h.logger.Warn("审计 Agent 响应解析失败",
			zap.Error(err),
			zap.String("tool", toolName),
			zap.String("snippet", snippet),
		)
		return hitlDecision{Decision: "reject", Comment: "audit agent: 响应无法解析，保守拒绝"}
	}
	if dec.Comment == "" {
		dec.Comment = "audit agent: " + dec.Decision
	} else if !strings.HasPrefix(strings.ToLower(dec.Comment), "audit agent") {
		dec.Comment = "audit agent: " + dec.Comment
	}
	return dec
}

func (h *AgentHandler) auditLLMConfig() config.OpenAIConfig {
	if h != nil && h.config != nil {
		return h.config.Hitl.AuditModelEffective(h.config.OpenAI)
	}
	return config.OpenAIConfig{}
}

func buildAuditAgentReviewInput(toolName string, payload map[string]interface{}) string {
	review := map[string]interface{}{
		"toolName": strings.TrimSpace(toolName),
	}
	if payload != nil {
		// findings/riskLevel：让审计 Agent 看到危险规则命中详情，而非仅凭命令自行推断。
		for _, k := range []string{"arguments", "argumentsObj", "command", "findings", "riskLevel", hitlPayloadUserMessage} {
			if v, ok := payload[k]; ok && v != nil && fmt.Sprint(v) != "" {
				review[k] = v
			}
		}
	}
	b, err := json.MarshalIndent(review, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"toolName":%q}`, toolName)
	}
	return string(b)
}

func parseAuditAgentLLMContent(content string) (hitlDecision, error) {
	s := strings.TrimSpace(content)
	if s == "" {
		return hitlDecision{}, errors.New("empty content")
	}
	for _, candidate := range auditAgentJSONCandidates(s) {
		dec, comment, err := parseAuditAgentDecisionObject(candidate)
		if err == nil {
			return hitlDecision{
				Decision: dec,
				Comment:  comment,
			}, nil
		}
	}
	return hitlDecision{}, fmt.Errorf("no valid decision json in response")
}

func auditAgentJSONCandidates(s string) []string {
	out := make([]string, 0, 4)
	seen := make(map[string]struct{})
	add := func(c string) {
		c = strings.TrimSpace(c)
		if c == "" {
			return
		}
		if _, ok := seen[c]; ok {
			return
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	add(s)
	add(stripMarkdownCodeFence(s))
	if obj := extractFirstJSONObject(s); obj != "" {
		add(obj)
	}
	if obj := extractFirstJSONObject(stripMarkdownCodeFence(s)); obj != "" {
		add(obj)
	}
	return out
}

func stripMarkdownCodeFence(s string) string {
	s = strings.TrimSpace(s)
	for _, fence := range []string{"```json", "```JSON", "```"} {
		if strings.HasPrefix(s, fence) {
			s = strings.TrimPrefix(s, fence)
		}
	}
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

func extractFirstJSONObject(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inStr {
			if esc {
				esc = false
				continue
			}
			if ch == '\\' {
				esc = true
				continue
			}
			if ch == '"' {
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func parseAuditAgentDecisionObject(jsonText string) (decision, comment string, err error) {
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonText), &parsed); err != nil {
		return "", "", err
	}
	rawDecision := auditAgentPickString(parsed, "decision", "Decision", "result", "action", "verdict", "决策", "决定")
	decision = normalizeAuditAgentDecision(rawDecision)
	if decision == "" {
		return "", "", fmt.Errorf("missing decision")
	}
	comment = auditAgentPickString(parsed, "comment", "Comment", "reason", "message", "rationale", "备注", "理由", "说明")
	return decision, strings.TrimSpace(comment), nil
}

func auditAgentPickString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func normalizeAuditAgentDecision(v string) string {
	d := strings.ToLower(strings.TrimSpace(v))
	switch d {
	case "approve", "approved", "pass", "passed", "allow", "allowed", "yes", "ok", "accept", "accepted":
		return "approve"
	case "reject", "rejected", "deny", "denied", "no", "block", "blocked", "refuse", "refused":
		return "reject"
	}
	switch strings.TrimSpace(v) {
	case "通过", "批准", "允许", "同意", "放行":
		return "approve"
	case "拒绝", "驳回", "禁止", "否决":
		return "reject"
	}
	return ""
}
