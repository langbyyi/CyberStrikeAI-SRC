package multiagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/openai"

	"go.uber.org/zap"
)

// SessionIntent is a coarse conversation mode used to gate execution-controller
// record obligations (dependency_blocked). Classified by LLM with rule fallback.
type SessionIntent string

const (
	// SessionIntentChat: Q&A / product help / small talk.
	SessionIntentChat SessionIntent = "chat"
	// SessionIntentRecon: passive asset/info collection — tools OK, no record obligations.
	SessionIntentRecon SessionIntent = "recon"
	// SessionIntentPentest: active security testing / vuln hunting — obligations enabled.
	SessionIntentPentest SessionIntent = "pentest"

	// SessionIntentSecurityOps deprecated alias (= pentest).
	SessionIntentSecurityOps = SessionIntentPentest
)

var (
	explicitChatOnly = regexp.MustCompile(`(?i)(` +
		`先别(测|扫|挖|渗透)|不要(再)?(扫|测|挖|渗透)|只是(聊天|问问|咨询)|` +
		`不是(让你)?(渗透|扫描|测试)|取消(测试|扫描)|停止(测试|扫描)|` +
		`just\s+chat|stop\s+(scanning|testing)|don'?t\s+(scan|pentest|test)` +
		`)`)

	reconKeywords = regexp.MustCompile(`(?i)(` +
		`信息收集|资产收集|资产发现|资产测绘|子域名|枚举域名|空间测绘|` +
		`被动收集|情报收集|osint|recon\b|footprint|资产梳理|域名收集|` +
		`fofa|shodan|quake|zoomeye|whois|备案` +
		`)`)

	// Short English tokens use word boundaries to avoid "epoch"→poc, etc.
	pentestKeywords = regexp.MustCompile(`(?i)(` +
		`渗透|漏扫|漏洞扫描|漏洞测试|挖洞|打点|红队|攻防|授权测试|` +
		`未授权|越权|爆破|注入|提权|复测|验证漏洞|漏洞验证|漏洞利用|` +
		`\bxss\b|\bsqli\b|\bssrf\b|\brce\b|\bpoc\b|\bpayload\b|` +
		`\bpentest\b|\bpenetration\b|\bexploit\b|\bnuclei\b` +
		`)`)

	// Security nouns alone describe knowledge/document/code requests as often as
	// active testing. A confident pentest decision therefore requires an
	// execution verb (or an established active-testing phrase), not merely XSS,
	// SSRF, 未授权, payload, etc.
	pentestExecutionKeywords = regexp.MustCompile(`(?i)(` +
		`渗透|漏扫|漏洞扫描|漏洞测试|挖洞|打点|红队|攻防|授权测试|` +
		`爆破|提权|复测|验证漏洞|漏洞验证|漏洞利用|` +
		`\bpentest\b|\bpenetration\b|\bexploit\b|\bnuclei\b|` +
		`(?:测试|验证|扫描|检测|利用|复现).{0,16}(?:未授权|越权|注入|漏洞|\bxss\b|\bsqli\b|\bssrf\b|\brce\b|\bpoc\b|\bpayload\b)|` +
		`(?:未授权|越权|注入|漏洞|\bxss\b|\bsqli\b|\bssrf\b|\brce\b|\bpoc\b|\bpayload\b).{0,16}(?:测试|验证|扫描|检测|利用|复现)` +
		`)`)

	securityKnowledgeRequest = regexp.MustCompile(`(?i)(` +
		`解释|介绍|原理|是什么|有什么区别|基本流程|写一篇|写一段|文档|文章|风险说明|` +
		`示例代码|代码示例|教程|如何防|怎么防|防护建议|修复建议|` +
		`\bexplain\b|\bwhat\s+is\b|\bwrite\b.{0,12}\b(document|article|code)\b` +
		`)`)
	explicitExecutionAfterKnowledge = regexp.MustCompile(`(?i)(?:帮我|请|然后|并|再).{0,12}(?:测试|验证|扫描|检测|利用|复现)`)
	directSecurityExecutionRequest  = regexp.MustCompile(`(?i)(?:测试|验证|扫描|检测|利用|复现).{0,16}(?:https?://|未授权|越权|注入|漏洞|\bxss\b|\bsqli\b|\bssrf\b|\brce\b|\bpoc\b|\bpayload\b)`)

	chatKeywords = regexp.MustCompile(`(?i)(` +
		`^你好|^您好|^嗨|^在吗|^在不在|^谢谢|^感谢|^早上好|^晚上好|^中午好|` +
		`你是谁|你能做什么|怎么用|如何使用|介绍一下|帮我看看设置|配置怎么写|` +
		`聊[天聊]|随便问问|` +
		`^hi\b|^hello\b|^hey\b|^thanks\b|^thank\s*you\b` +
		`)`)
)

// RecordObligationsEnabled is true ONLY when the user is doing real authorized
// penetration testing against a concrete target. Chat, recon, docs, config, or
// any non-pentest work must never hit dependency_blocked.
//
// Both conditions are required (AND):
//  1. session intent == pentest
//  2. PrimaryTarget is non-empty
func RecordObligationsEnabled(conversationID string) bool {
	state := GetConversationExecutionState(conversationID)
	if state == nil {
		return false
	}
	if state.SessionIntent() != SessionIntentPentest {
		return false
	}
	if strings.TrimSpace(state.Controller().PrimaryTarget()) == "" {
		return false
	}
	return true
}

// sanitizeIntent is the last-line defense against false pentest labels.
// Only user text (not role hints) may justify pentest.
func sanitizeIntent(intent SessionIntent, userText string) SessionIntent {
	text := intentTextForClassification(userText)
	if isPureGreeting(text) {
		return SessionIntentChat
	}
	if explicitChatOnly.MatchString(text) {
		return SessionIntentChat
	}
	if securityKnowledgeRequest.MatchString(text) &&
		!explicitExecutionAfterKnowledge.MatchString(text) &&
		!directSecurityExecutionRequest.MatchString(text) {
		return SessionIntentChat
	}
	if intent == SessionIntentPentest && !pentestExecutionKeywords.MatchString(text) {
		if ExtractTargetFromText(text) != "" || reconKeywords.MatchString(text) {
			return SessionIntentRecon
		}
		return SessionIntentChat
	}
	if intent == "" {
		return SessionIntentChat
	}
	return intent
}

// RoleHintFromTools builds a short role signal for the classifier.
// IMPORTANT: must NOT contain pentest trigger words (渗透/漏洞/…) — if this string is ever
// mixed into the classified text, those words would false-positive as pentest.
func RoleHintFromTools(tools []string) string {
	hasRecord, hasRecon := false, false
	for _, t := range tools {
		n := strings.ToLower(strings.TrimSpace(t))
		if n == "" {
			continue
		}
		if strings.Contains(n, "record_vulnerability") {
			hasRecord = true
		}
		if strings.Contains(n, "fofa") || strings.Contains(n, "subfinder") ||
			strings.Contains(n, "amass") || strings.Contains(n, "shodan") ||
			strings.Contains(n, "quake") || strings.Contains(n, "zoomeye") ||
			strings.Contains(n, "wayback") || strings.Contains(n, "gau") {
			hasRecon = true
		}
	}
	switch {
	case hasRecon && !hasRecord:
		return "role_tools:recon_only"
	case hasRecord && hasRecon:
		return "role_tools:recon_and_record"
	case hasRecord:
		return "role_tools:record_capable"
	default:
		return "role_tools:generic"
	}
}

// isPureGreeting is a hard gate: pure hellos never go through LLM and never become pentest.
func isPureGreeting(msg string) bool {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return false
	}
	if ExtractTargetFromText(msg) != "" {
		return false
	}
	if pentestKeywords.MatchString(msg) || reconKeywords.MatchString(msg) {
		return false
	}
	if utf8.RuneCountInString(msg) > 24 {
		return false
	}
	return chatKeywords.MatchString(msg)
}

// intentTextForClassification prefers the raw user note inside interrupt wrappers,
// so template lines like「重新端口探测」不会把闲聊/收集误判成渗透。
func intentTextForClassification(userMessage string) string {
	msg := strings.TrimSpace(userMessage)
	if msg == "" {
		return ""
	}
	if strings.Contains(msg, "【用户补充") || strings.Contains(msg, "【请在本轮落实】") {
		// Take body after first header line, stop before framework checklist.
		body := msg
		if i := strings.Index(body, "\n"); i >= 0 {
			body = strings.TrimSpace(body[i+1:])
		}
		if j := strings.Index(body, "【请在本轮落实】"); j >= 0 {
			body = strings.TrimSpace(body[:j])
		}
		if body != "" {
			return body
		}
	}
	return msg
}

type sessionIntentRuleDecision struct {
	intent    SessionIntent
	confident bool
}

// classifySessionIntentRules is the single deterministic rule implementation.
// Confidence only means the user text itself carries an explicit signal; role-only
// and default classifications remain eligible for LLM disambiguation.
func classifySessionIntentRules(userMessage, roleHint string) sessionIntentRuleDecision {
	msg := intentTextForClassification(userMessage)
	roleHint = strings.TrimSpace(roleHint)
	if msg == "" {
		return sessionIntentRuleDecision{intent: SessionIntentChat, confident: true}
	}
	if explicitChatOnly.MatchString(msg) {
		return sessionIntentRuleDecision{intent: SessionIntentChat, confident: true}
	}
	if securityKnowledgeRequest.MatchString(msg) &&
		!explicitExecutionAfterKnowledge.MatchString(msg) &&
		!directSecurityExecutionRequest.MatchString(msg) {
		return sessionIntentRuleDecision{intent: SessionIntentChat, confident: true}
	}
	// Explicit exploit/pentest language wins (even without target — obligations still need target).
	if pentestExecutionKeywords.MatchString(msg) || directSecurityExecutionRequest.MatchString(msg) {
		return sessionIntentRuleDecision{intent: SessionIntentPentest, confident: true}
	}
	if reconKeywords.MatchString(msg) {
		return sessionIntentRuleDecision{intent: SessionIntentRecon, confident: true}
	}
	if ExtractTargetFromText(msg) != "" {
		// URL/IP/domain only: recon. Role alone never upgrades to pentest.
		return sessionIntentRuleDecision{intent: SessionIntentRecon, confident: true}
	}
	if chatKeywords.MatchString(msg) {
		return sessionIntentRuleDecision{intent: SessionIntentChat, confident: true}
	}
	if taskContextDialogue.MatchString(msg) {
		return sessionIntentRuleDecision{intent: SessionIntentChat, confident: true}
	}
	if roleLooksRecon(roleHint) {
		return sessionIntentRuleDecision{intent: SessionIntentRecon}
	}
	// Default: non-pentest. Unrelated work must never enable dependency_blocked.
	return sessionIntentRuleDecision{intent: SessionIntentChat}
}

// ClassifySessionIntentRules is a fast rule-based classifier (LLM fallback / seed).
// Never marks pentest without explicit attack/exploit language (role alone is not enough).
func ClassifySessionIntentRules(userMessage, roleHint string) SessionIntent {
	return classifySessionIntentRules(userMessage, roleHint).intent
}

func roleLooksRecon(role string) bool {
	r := strings.ToLower(role)
	return strings.Contains(r, "recon") || strings.Contains(r, "信息收集") ||
		strings.Contains(r, "资产") || strings.Contains(r, "osint") ||
		strings.Contains(r, "情报") || strings.Contains(r, "recon_only")
}

// rulesConfidentIntent returns a high-confidence rule label when the user text
// already contains clear signals. Used to skip the intent LLM under reasoning/auto
// models (long TTFT / thinking budget) so task start is not polluted by avoidable LLM failures.
func rulesConfidentIntent(userMessage, roleHint string) (SessionIntent, bool) {
	decision := classifySessionIntentRules(userMessage, roleHint)
	if !decision.confident {
		return "", false
	}
	return decision.intent, true
}

// ClassifySessionIntentWithLLMModel classifies with LLM; falls back to rules on any failure.
// userMessage may be raw or already stripped; classification always normalizes via intentTextForClassification.
//
// Design notes (why start can fail while the rest of the run is fine):
//   - Intent runs once at task start via openai.Client ChatCompletion (non-streaming, short timeout).
//   - Main agent runs later via Eino with reasoning.auto + long stream timeout — independent path.
//   - With reasoning/thinking models, a tiny max_tokens + short deadline often yields timeout/400,
//     while the subsequent agent turn still works. Prefer rules when signals are clear.
func ClassifySessionIntentWithLLMModel(ctx context.Context, userMessage, roleHint, prevIntent, model string, client *openai.Client, logger *zap.Logger) (SessionIntent, string) {
	text := intentTextForClassification(userMessage)
	// Hard gate BEFORE LLM: pure greetings never call the model (avoids unnecessary LLM calls
	// and any contamination from role hints inside the LLM user payload).
	if isPureGreeting(text) {
		return SessionIntentChat, "rules_fast_chat"
	}
	// Rules fallback MUST classify only the user text, never the LLM prompt blob.
	fallback := ClassifySessionIntentRules(userMessage, roleHint)
	// Safety: never allow fallback pentest without attack language in the user text itself.
	if fallback == SessionIntentPentest && !pentestExecutionKeywords.MatchString(text) {
		if ExtractTargetFromText(text) != "" {
			fallback = SessionIntentRecon
		} else {
			fallback = SessionIntentChat
		}
	}
	// Clear keyword/target signal → skip LLM. Avoids start-of-task noise when the main
	// model has reasoning.mode=auto (intent path is a separate short non-stream call).
	if conf, ok := rulesConfidentIntent(userMessage, roleHint); ok {
		return conf, "rules_confident"
	}
	if client == nil || strings.TrimSpace(text) == "" {
		return fallback, "rules"
	}
	if strings.TrimSpace(model) == "" {
		return fallback, "rules_no_model"
	}

	system := `你是会话意图分类器。根据用户当前消息判断唯一意图，只输出 JSON，不要 markdown。不要思考过程，直接给结果。

intent 必须是以下之一：
- chat：闲聊、产品/配置咨询、写文档/改配置/问功能、问好、明确不要扫描；以及与安全测试无关的其它事
- recon：信息收集、资产发现、子域名/空间测绘/OSINT/被动情报；不做漏洞利用与强验证闭环
- pentest：用户明确要对某目标做渗透测试/漏洞验证利用/打点挖洞（授权安全测试）

硬性规则（宁可不标 pentest）：
1) 只有「真正对目标做渗透/漏洞验证」才标 pentest
2) 信息收集/资产/测绘/fofa → recon，禁止 pentest
3) 聊天、问怎么用、改配置、写代码/文档、无关任务 → chat
4) 仅贴 URL/域名、无渗透动词 → recon
5) 先别测/只是聊天 → chat
6) 不确定时优先 chat 或 recon，不要标 pentest
7) 忽略消息里的系统续跑模板（如「请在本轮落实/端口探测」），只看用户原意

输出严格：
{"intent":"chat|recon|pentest","reason":"不超过40字"}`

	// Keep role hint free of Chinese attack keywords; only pass opaque codes.
	user := "role_hint: " + emptyAs(roleHint, "role_tools:generic") +
		"\nprev_intent: " + emptyAs(prevIntent, "none") +
		"\nuser_message:\n" + truncateRunes(text, 1500)

	messages := []map[string]string{
		{"role": "system", "content": system},
		{"role": "user", "content": user},
	}

	// Intent classification must not hold up task startup. Most compatible gateways
	// accept max_tokens; only request-shape failures get one alternate-field retry.
	const intentTotalBudget = 8 * time.Second
	budgetCtx, budgetCancel := context.WithTimeout(ctx, intentTotalBudget)
	defer budgetCancel()

	type intentAttempt struct {
		name    string
		payload map[string]interface{}
	}
	attempts := []intentAttempt{
		{
			name: "max_tokens",
			payload: map[string]interface{}{
				"model":      model,
				"messages":   messages,
				"max_tokens": 256,
			},
		},
		{
			name: "max_completion_tokens",
			payload: map[string]interface{}{
				"model":                 model,
				"messages":              messages,
				"max_completion_tokens": 256,
			},
		},
	}

	var apiResponse struct {
		Choices []struct {
			Message struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
	}
	for i, att := range attempts {
		if budgetCtx.Err() != nil {
			if logger != nil {
				logger.Warn("session intent LLM canceled, using rules", zap.Error(budgetCtx.Err()))
			}
			return fallback, "rules_fallback"
		}
		apiResponse = struct {
			Choices []struct {
				Message struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
				} `json:"message"`
			} `json:"choices"`
		}{}
		err := client.ChatCompletion(budgetCtx, att.payload, &apiResponse)
		if err != nil {
			if logger != nil {
				logger.Warn("session intent LLM attempt failed",
					zap.Int("attempt", i+1),
					zap.String("variant", att.name),
					zap.Error(err),
				)
			}
			if i == 0 && isIntentCompatibilityError(err) {
				continue
			}
			return fallback, "rules_fallback"
		}
		if len(apiResponse.Choices) == 0 {
			if logger != nil {
				logger.Warn("session intent LLM empty choices, using rules")
			}
			return fallback, "rules_fallback"
		}
		content := extractIntentMessageContent(apiResponse.Choices[0].Message.Content, apiResponse.Choices[0].Message.ReasoningContent)
		if content == "" {
			if logger != nil {
				logger.Warn("session intent LLM empty content, using rules")
			}
			return fallback, "rules_fallback"
		}
		var parsed struct {
			Intent string `json:"intent"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(content), &parsed); err != nil {
			if logger != nil {
				logger.Warn("session intent LLM JSON parse failed",
					zap.Int("attempt", i+1),
					zap.String("variant", att.name),
					zap.Error(err),
				)
			}
			return fallback, "rules_fallback"
		}
		intent := normalizeSessionIntent(parsed.Intent)
		if intent == "" {
			if logger != nil {
				logger.Warn("session intent LLM bad intent label",
					zap.Int("attempt", i+1),
					zap.String("variant", att.name),
				)
			}
			return fallback, "rules_fallback"
		}
		// LLM may over-label pentest; require attack language or keep as recon/chat.
		if intent == SessionIntentPentest && !pentestExecutionKeywords.MatchString(text) {
			if ExtractTargetFromText(text) != "" {
				return SessionIntentRecon, "llm_downgrade_recon"
			}
			return SessionIntentChat, "llm_downgrade_chat"
		}
		return intent, "llm"
	}
	return fallback, "rules_fallback"
}

func isIntentCompatibilityError(err error) bool {
	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusBadRequest || apiErr.StatusCode == http.StatusUnprocessableEntity
}

func stripIntentJSONContent(content string) string {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	if i := strings.Index(content, "{"); i >= 0 {
		if j := strings.LastIndex(content, "}"); j > i {
			content = content[i : j+1]
		}
	}
	return strings.TrimSpace(content)
}

func extractIntentMessageContent(content, reasoning string) string {
	out := stripIntentJSONContent(content)
	if out != "" {
		return out
	}
	// 推理模型偶发：正文空、JSON 只在 reasoning_content
	return stripIntentJSONContent(reasoning)
}

func normalizeSessionIntent(s string) SessionIntent {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "chat", "idle", "qa", "help":
		return SessionIntentChat
	case "recon", "osint", "asset", "info", "information", "collect":
		return SessionIntentRecon
	case "pentest", "security_ops", "ops", "vuln", "exploit":
		return SessionIntentPentest
	default:
		return ""
	}
}

func emptyAs(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// ApplySessionIntentFromUserNote updates intent mid-run (interrupt note) using rules only
// so tool-abort / interrupt-continue can drop obligations without waiting for next ADK segment.
func ApplySessionIntentFromUserNote(conversationID, note string) SessionIntent {
	note = strings.TrimSpace(note)
	if note == "" {
		return GetConversationExecutionState(conversationID).SessionIntent()
	}
	state := GetConversationExecutionState(conversationID)
	prev := state.SessionIntent()
	incoming := ClassifySessionIntentRules(note, RoleHintFromTools(state.RoleTools()))
	next := sanitizeIntent(mergeSessionIntent(prev, incoming, note), note)
	state.SetSessionIntent(next)
	// Chat: drop stale target so a later false pentest label cannot re-enable obligations.
	if next == SessionIntentChat {
		state.Controller().ClearPrimaryTarget()
	}
	if !RecordObligationsEnabled(conversationID) {
		_ = state.Controller().ClearPendingObligations("interrupt_note_" + string(next))
	}
	return next
}

// ResolveAndStoreSessionIntent updates intent for this turn (LLM + rules + sticky merge).
// Returns effective intent and classifier source label.
func ResolveAndStoreSessionIntent(ctx context.Context, conversationID, userMessage, roleHint, model string, client *openai.Client, logger *zap.Logger) (SessionIntent, string) {
	state := GetConversationExecutionState(conversationID)
	prev := state.SessionIntent()
	text := intentTextForClassification(userMessage)
	// Pass full userMessage; classifiers strip interrupt templates internally.
	incoming, source := ClassifySessionIntentWithLLMModel(ctx, userMessage, roleHint, string(prev), model, client, logger)
	safeIncoming := sanitizeIntent(incoming, text)
	if safeIncoming != incoming && logger != nil {
		logger.Info("session intent sanitized",
			zap.String("conversation_id", conversationID),
			zap.String("from", string(incoming)),
			zap.String("to", string(safeIncoming)),
			zap.String("source", source),
		)
		source = source + "+sanitize"
	}
	next := mergeSessionIntent(prev, safeIncoming, text)
	state.SetSessionIntent(next)
	if next == SessionIntentChat {
		state.Controller().ClearPrimaryTarget()
	}
	// Clear duties whenever obligations are not fully enabled (non-pentest OR no target).
	if !RecordObligationsEnabled(conversationID) {
		_ = state.Controller().ClearPendingObligations("session_intent_" + string(next))
	}
	return next, source
}

var continuationAck = regexp.MustCompile(`(?i)^(` +
	`好的?|继续|接着|嗯+|哦+|行|可以|ok|okay|go\s*on|continue|next|收到|明白` +
	`)$`)

var taskContextDialogue = regexp.MustCompile(`(?i)(` +
	`(当前|目前|刚才|这次|测试|扫描|任务).*(进度|状态|情况|结果|发现|成果)|` +
	`(总结|汇总|报告|查看|看看|说说).*(进度|状态|情况|结果|发现|成果)|` +
	`做到哪|到哪一步|\b(progress|status|findings|summary)\b` +
	`)`)

func mergeSessionIntent(prev, incoming SessionIntent, userMessage string) SessionIntent {
	msg := strings.TrimSpace(userMessage)
	if prev == "" {
		return incoming
	}
	if explicitChatOnly.MatchString(msg) {
		return SessionIntentChat
	}
	// Short "continue" during an active task keeps mode; do not invent pentest from ack alone.
	if continuationAck.MatchString(msg) {
		if prev != "" {
			return prev
		}
		return SessionIntentChat
	}
	// Questions about an active task are dialogue inside that task, not a request
	// to abandon its target or execution obligations.
	if (prev == SessionIntentPentest || prev == SessionIntentRecon) &&
		incoming == SessionIntentChat &&
		taskContextDialogue.MatchString(msg) &&
		ExtractTargetFromText(msg) == "" &&
		!pentestKeywords.MatchString(msg) &&
		!reconKeywords.MatchString(msg) {
		return prev
	}
	// Trust this turn's classifier for clear modes (chat/recon/pentest).
	// Do NOT sticky-keep pentest when user switched to chat/recon/unrelated work.
	if incoming == SessionIntentChat || incoming == SessionIntentRecon || incoming == SessionIntentPentest {
		return incoming
	}
	return prev
}

func appendSessionIntentInstruction(instruction string, intent SessionIntent) string {
	var block string
	switch intent {
	case SessionIntentChat:
		block = "\n\n【会话模式：chat】用户当前是咨询/闲聊，不是安全测试任务。\n" +
			"- 只用自然语言回复；禁止调用扫描/探测类工具（http-framework-test、exec、nmap、fofa 等）。\n" +
			"- 即使项目黑板里有历史目标，也禁止自动对其开测；用户未给出新目标且未要求测试时保持闲聊。\n" +
			"- 框架不启用待落库义务，不会 dependency_blocked。\n"
	case SessionIntentRecon:
		block = "\n\n【会话模式：recon】用户意图为信息收集/资产发现（被动为主）。\n" +
			"- 可使用收集类工具；用 upsert_project_fact 记录资产事实。\n" +
			"- 不要按渗透闭环强逼 record_vulnerability；框架不启用 dependency_blocked。\n" +
			"- 仅当用户明确要求渗透/挖洞时再做攻击验证。\n"
	case SessionIntentPentest:
		block = "\n\n【会话模式：pentest】用户明确要对目标做授权渗透/漏洞验证。\n" +
			"- 按目标推进；强证据时 L1/L2 落库或 update_vulnerability。\n" +
			"- 仅此模式可能启用记录义务（dependency_blocked）；聊天/信息收集不会。\n"
	default:
		return instruction
	}
	return strings.TrimRight(instruction, "\n") + block
}
