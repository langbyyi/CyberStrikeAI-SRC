package multiagent

import (
	"strings"

	"github.com/cloudwego/eino/schema"
)

// EinoMessagesToAgentic converts the project's current ADK message history to
// Eino's native AgenticMessage shape. It covers the text, reasoning, function
// tool-call, function tool-result, and image-input (multimodal) channels used by
// the agent runtime today; other provider-specific fields stay in schema.Message.
func EinoMessagesToAgentic(msgs []*schema.Message) []*schema.AgenticMessage {
	if len(msgs) == 0 {
		return nil
	}
	out := make([]*schema.AgenticMessage, 0, len(msgs))
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		out = append(out, EinoMessageToAgentic(msg))
	}
	return out
}

func EinoMessageToAgentic(msg *schema.Message) *schema.AgenticMessage {
	if msg == nil {
		return nil
	}
	out := &schema.AgenticMessage{
		Role:  messageRoleToAgentic(msg.Role),
		Extra: cloneAnyMap(msg.Extra),
	}
	if msg.ResponseMeta != nil {
		out.ResponseMeta = &schema.AgenticResponseMeta{TokenUsage: msg.ResponseMeta.Usage}
	}
	if text := strings.TrimSpace(msg.ReasoningContent); text != "" {
		out.ContentBlocks = append(out.ContentBlocks, schema.NewContentBlock(&schema.Reasoning{Text: msg.ReasoningContent}))
	}
	switch msg.Role {
	case schema.Assistant:
		if msg.Content != "" {
			out.ContentBlocks = append(out.ContentBlocks, schema.NewContentBlock(&schema.AssistantGenText{Text: msg.Content}))
		}
		for _, tc := range msg.ToolCalls {
			out.ContentBlocks = append(out.ContentBlocks, schema.NewContentBlock(&schema.FunctionToolCall{
				CallID:    tc.ID,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			}))
		}
	case schema.Tool:
		out.Role = schema.AgenticRoleTypeUser
		out.ContentBlocks = append(out.ContentBlocks, schema.NewContentBlock(&schema.FunctionToolResult{
			CallID: msg.ToolCallID,
			Name:   msg.ToolName,
			Content: []*schema.FunctionToolResultContentBlock{{
				Type: schema.FunctionToolResultContentBlockTypeText,
				Text: &schema.UserInputText{Text: msg.Content},
			}},
		}))
	default:
		if msg.Content != "" {
			out.ContentBlocks = append(out.ContentBlocks, schema.NewContentBlock(&schema.UserInputText{Text: msg.Content}))
		}
		appendUserInputMultimodalBlocks(out, msg)
	}
	return out
}

// appendUserInputMultimodalBlocks 把经典 schema.Message 的多模态输入块（图片等）
// 转成 AgenticMessage 的原生输入块。文本块仅在 Content 为空时补齐，避免重复。
func appendUserInputMultimodalBlocks(out *schema.AgenticMessage, msg *schema.Message) {
	if out == nil || msg == nil || len(msg.UserInputMultiContent) == 0 {
		return
	}
	contentEmpty := strings.TrimSpace(msg.Content) == ""
	for _, part := range msg.UserInputMultiContent {
		switch {
		case part.Type == schema.ChatMessagePartTypeImageURL && part.Image != nil:
			img := &schema.UserInputImage{
				MIMEType: part.Image.MIMEType,
				Detail:   part.Image.Detail,
			}
			if part.Image.Base64Data != nil {
				img.Base64Data = *part.Image.Base64Data
			}
			if part.Image.URL != nil {
				img.URL = *part.Image.URL
			}
			if img.Base64Data == "" && img.URL == "" {
				continue
			}
			out.ContentBlocks = append(out.ContentBlocks, schema.NewContentBlock(img))
		case part.Type == schema.ChatMessagePartTypeText && contentEmpty && strings.TrimSpace(part.Text) != "":
			out.ContentBlocks = append(out.ContentBlocks, schema.NewContentBlock(&schema.UserInputText{Text: part.Text}))
		}
	}
}

// AgenticMessagesToEino converts AgenticMessage values back into the classic
// schema.Message form used by the existing ADK event drain and persistence code.
func AgenticMessagesToEino(msgs []*schema.AgenticMessage) []*schema.Message {
	if len(msgs) == 0 {
		return nil
	}
	out := make([]*schema.Message, 0, len(msgs))
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		out = append(out, AgenticMessageToEino(msg)...)
	}
	return out
}

func AgenticMessageToEino(msg *schema.AgenticMessage) []*schema.Message {
	if msg == nil {
		return nil
	}
	base := &schema.Message{
		Role:  agenticRoleToMessage(msg.Role),
		Extra: cloneAnyMap(msg.Extra),
	}
	if msg.ResponseMeta != nil {
		base.ResponseMeta = &schema.ResponseMeta{Usage: msg.ResponseMeta.TokenUsage}
	}
	var toolResults []*schema.Message
	var inputParts []schema.MessageInputPart
	for _, block := range msg.ContentBlocks {
		if block == nil {
			continue
		}
		switch {
		case block.Reasoning != nil:
			base.ReasoningContent += block.Reasoning.Text
		case block.UserInputText != nil:
			base.Content += block.UserInputText.Text
		case block.UserInputImage != nil:
			if part, ok := userInputImageToMessagePart(block.UserInputImage); ok {
				inputParts = append(inputParts, part)
			}
		case block.AssistantGenText != nil:
			base.Role = schema.Assistant
			base.Content += block.AssistantGenText.Text
		case block.FunctionToolCall != nil:
			var index *int
			if block.StreamingMeta != nil {
				i := block.StreamingMeta.Index
				index = &i
			}
			base.Role = schema.Assistant
			base.ToolCalls = append(base.ToolCalls, schema.ToolCall{
				Index: index,
				ID:    block.FunctionToolCall.CallID,
				Type:  "function",
				Function: schema.FunctionCall{
					Name:      block.FunctionToolCall.Name,
					Arguments: block.FunctionToolCall.Arguments,
				},
			})
		case block.FunctionToolResult != nil:
			toolResults = append(toolResults, functionToolResultToMessage(block.FunctionToolResult))
		}
	}
	if len(inputParts) > 0 {
		base.UserInputMultiContent = inputParts
	}
	if len(toolResults) > 0 && base.Content == "" && base.ReasoningContent == "" && len(base.ToolCalls) == 0 && len(inputParts) == 0 {
		return toolResults
	}
	out := []*schema.Message{base}
	out = append(out, toolResults...)
	return out
}

// userInputImageToMessagePart 把 AgenticMessage 的图片输入块转回经典 MessageInputPart。
func userInputImageToMessagePart(img *schema.UserInputImage) (schema.MessageInputPart, bool) {
	if img == nil {
		return schema.MessageInputPart{}, false
	}
	common := schema.MessagePartCommon{MIMEType: img.MIMEType}
	if img.Base64Data != "" {
		data := img.Base64Data
		common.Base64Data = &data
	}
	if img.URL != "" {
		u := img.URL
		common.URL = &u
	}
	if common.Base64Data == nil && common.URL == nil {
		return schema.MessageInputPart{}, false
	}
	return schema.MessageInputPart{
		Type:  schema.ChatMessagePartTypeImageURL,
		Image: &schema.MessageInputImage{MessagePartCommon: common, Detail: img.Detail},
	}, true
}

func messageRoleToAgentic(role schema.RoleType) schema.AgenticRoleType {
	switch role {
	case schema.System:
		return schema.AgenticRoleTypeSystem
	case schema.Assistant:
		return schema.AgenticRoleTypeAssistant
	default:
		return schema.AgenticRoleTypeUser
	}
}

func agenticRoleToMessage(role schema.AgenticRoleType) schema.RoleType {
	switch role {
	case schema.AgenticRoleTypeSystem:
		return schema.System
	case schema.AgenticRoleTypeAssistant:
		return schema.Assistant
	default:
		return schema.User
	}
}

func functionToolResultToMessage(result *schema.FunctionToolResult) *schema.Message {
	if result == nil {
		return nil
	}
	parts := make([]string, 0, len(result.Content))
	for _, block := range result.Content {
		if block == nil {
			continue
		}
		switch {
		case block.Text != nil:
			parts = append(parts, block.Text.Text)
		case block.Image != nil:
			// 图片已作为图片输入直发模型：文本通道（监控落库 / SSE / 摘要）只留占位，
			// 避免把 base64 写进数据库与事件流。
			parts = append(parts, toolResultImagePlaceholder(block.Image))
		}
	}
	return &schema.Message{
		Role:       schema.Tool,
		Content:    strings.Join(parts, ""),
		ToolCallID: result.CallID,
		ToolName:   result.Name,
	}
}

// toolResultImagePlaceholder 工具结果中图片的文本占位（不含 base64）。
func toolResultImagePlaceholder(img *schema.UserInputImage) string {
	if img == nil {
		return ""
	}
	mime := strings.TrimSpace(img.MIMEType)
	if mime == "" {
		mime = "image"
	}
	return toolResultMediaPlaceholder(mime, &img.Base64Data)
}

func cloneAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
