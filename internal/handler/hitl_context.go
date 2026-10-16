package handler

import (
	"strings"

	"go.uber.org/zap"
)

const (
	hitlPayloadUserMessage = "userMessage"
	// hitlPayloadTestingSpecification 与 userMessage 同为"人类声明"级输入，
	// 是审计 Agent 判断"是否已获授权 / 是否落在声明的范围内"的依据。
	hitlPayloadTestingSpecification = "testingSpecification"

	// hitlUserDeclarationLimit 限制注入审计 Agent 的用户声明条数。
	// 取最近若干条即可覆盖"用户此前授权过这类操作"，不必塞进整场对话。
	hitlUserDeclarationLimit = 20
	// hitlUserDeclarationMaxBytes 单次注入的字节上限，避免超长粘贴撑爆审计请求。
	hitlUserDeclarationMaxBytes = 8 * 1024
	// hitlTestingSpecificationMaxBytes 测试规范注入上限。
	hitlTestingSpecificationMaxBytes = 8 * 1024
)

// enrichHitlApprovalPayload 注入用户声明，供审计 Agent 判断"是否已获得授权"。
// 会话级（DB，跨轮）+ 任务级（内存，含「中断并继续」补充说明）合并，
// 否则用户在第 1 轮说的"同意"到第 2 轮就消失了，同类操作会被反复拒绝。
func (h *AgentHandler) enrichHitlApprovalPayload(conversationID, assistantMessageID string, payload map[string]interface{}) {
	if h == nil || payload == nil {
		return
	}
	declarations := h.conversationUserDeclarations(conversationID, assistantMessageID)
	if h.tasks != nil {
		declarations = append(declarations, h.tasks.GetHitlUserMessages(conversationID)...)
	}
	joined := joinHitlUserDeclarations(declarations, hitlUserDeclarationMaxBytes)
	if joined == "" && h.db != nil {
		// 兜底：会话级与任务级都为空时，至少给出当轮原文。
		if turnMessage, err := h.db.GetTurnUserMessage(conversationID, assistantMessageID); err == nil {
			joined = strings.TrimSpace(turnMessage)
		}
	}
	if joined != "" {
		payload[hitlPayloadUserMessage] = joined
	}
	h.enrichHitlApprovalPayloadWithTestingSpecification(conversationID, payload)
}

// enrichHitlApprovalPayloadWithTestingSpecification 注入任务测试规范。
// 不用 ConversationTestingSpecificationBlock：那段文案是写给执行 Agent 的
// （"规范不授予额外权限，不得绕过审批"），会让审计 Agent 把声明基线又原样否掉。
func (h *AgentHandler) enrichHitlApprovalPayloadWithTestingSpecification(conversationID string, payload map[string]interface{}) {
	if h == nil || h.db == nil || payload == nil {
		return
	}
	snapshot, err := h.db.GetConversationTestingSpecification(conversationID)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("读取任务测试规范失败，审批上下文将不含规范",
				zap.String("conversationId", conversationID),
				zap.Error(err),
			)
		}
		return
	}
	if snapshot == nil || strings.TrimSpace(snapshot.Content) == "" {
		return
	}
	var builder strings.Builder
	builder.WriteString("## 任务测试规范（用户/项目声明）\n")
	builder.WriteString("名称：" + strings.TrimSpace(snapshot.Name) + "\n")
	if source := strings.TrimSpace(snapshot.Source); source != "" {
		builder.WriteString("来源：" + source + "\n")
	}
	builder.WriteString("内容：\n<task_testing_specification>\n")
	builder.WriteString(truncateHitlText(strings.TrimSpace(snapshot.Content), hitlTestingSpecificationMaxBytes))
	builder.WriteString("\n</task_testing_specification>")
	payload[hitlPayloadTestingSpecification] = builder.String()
}

// truncateHitlText 按字节上限截断且不切断 UTF-8 字符。
func truncateHitlText(text string, maxBytes int) string {
	if maxBytes <= 0 || len(text) <= maxBytes {
		return text
	}
	cut := maxBytes
	for cut > 0 && (text[cut]&0xC0) == 0x80 {
		cut--
	}
	return text[:cut]
}

func (h *AgentHandler) conversationUserDeclarations(conversationID, assistantMessageID string) []string {
	if h == nil || h.db == nil {
		return nil
	}
	declarations, err := h.db.ConversationUserDeclarations(conversationID, assistantMessageID, hitlUserDeclarationLimit)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("读取会话用户声明失败，审批上下文退化为任务级消息",
				zap.String("conversationId", conversationID),
				zap.Error(err),
			)
		}
		return nil
	}
	return declarations
}

// joinHitlUserDeclarations 去重后按出现顺序拼接；超限时保留最近的声明
// （用户最新表态权重最高）。
func joinHitlUserDeclarations(messages []string, maxBytes int) string {
	seen := make(map[string]struct{}, len(messages))
	unique := make([]string, 0, len(messages))
	for _, message := range messages {
		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}
		if _, ok := seen[message]; ok {
			continue
		}
		seen[message] = struct{}{}
		unique = append(unique, message)
	}
	if maxBytes > 0 {
		for len(unique) > 1 && len(strings.Join(unique, "\n\n")) > maxBytes {
			unique = unique[1:]
		}
	}
	joined := strings.Join(unique, "\n\n")
	// 单条消息本身就超限时上面的丢弃循环不会生效（len(unique) 已为 1），
	// 这里兜底，保证注入审计 Agent 的量真的有界。
	if maxBytes > 0 && len(joined) > maxBytes {
		joined = truncateHitlText(joined, maxBytes) + "…（已截断）"
	}
	return joined
}
