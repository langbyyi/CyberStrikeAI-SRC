package multiagent

import (
	"fmt"
	"strings"

	"github.com/cloudwego/eino/schema"

	"cyberstrike-ai/internal/vision"
)

// 多模态部分的统一处理：图片等二进制内容有三条约束——
//  1. 计入上下文预算与日志估算（否则软预算对图片不可见）；
//  2. 不进入「模型视角轨迹」（轨迹会落库 last_react_input 并在续跑时回灌）；
//  3. 不进入文本通道（监控落库 / SSE / 摘要），只留占位。

// countMessageImageParts 统计消息里随请求发送的图片部分数量。
func countMessageImageParts(msgs []*schema.Message) int {
	n := 0
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		for _, part := range msg.UserInputMultiContent {
			if part.Type == schema.ChatMessagePartTypeImageURL && part.Image != nil {
				n++
			}
		}
	}
	return n
}

// imagePartsTokenSurcharge 图片的 token 估算。
// 视觉 token 按 ⌈宽/28⌉×⌈高/28⌉ 计费；本仓库原生通道把长边压到 1568px 以内，
// 单图约 1500~4800 token，取保守常量（vision.NativeImageTokenEstimate）计入，
// 宁可高估也不让图片从预算里消失。
func imagePartsTokenSurcharge(msgs []*schema.Message) int {
	return countMessageImageParts(msgs) * vision.NativeImageTokenEstimate
}

// stripBinaryPartsForTrace 返回消息副本，把多模态二进制部分替换为文本占位。
//
// 模型视角轨迹会被序列化落库（conversations.last_react_input）并在续跑时回灌为历史，
// 若携带 base64 图片：单次写入可达 MB 级、且每轮都随请求重发。占位后语义仍可读，
// 需要看图时模型按消息里的路径重新 read_file 即可。
func stripBinaryPartsForTrace(msg *schema.Message) *schema.Message {
	if msg == nil || (len(msg.UserInputMultiContent) == 0 && len(msg.MultiContent) == 0) {
		return msg
	}
	parts, changed := stripBinaryParts(msg.UserInputMultiContent)
	legacyParts, legacyChanged := stripLegacyBinaryParts(msg.MultiContent)
	if !changed && !legacyChanged {
		return msg
	}
	cp := *msg
	if changed {
		cp.UserInputMultiContent = parts
	}
	if legacyChanged {
		cp.MultiContent = legacyParts
	}
	// 轨迹回放只读 content 字段：若原消息正文为空（纯图片消息），把占位并入正文，
	// 避免续跑时回灌出一条空的 user 消息。
	if strings.TrimSpace(cp.Content) == "" {
		var b strings.Builder
		for _, part := range parts {
			if part.Type == schema.ChatMessagePartTypeText {
				b.WriteString(part.Text)
			}
		}
		cp.Content = b.String()
	}
	return &cp
}

// stripLegacyBinaryParts 处理历史遗留的 Message.MultiContent（[]ChatMessagePart）：
// 类型与 MessageInputPart 不同，只保留文本部分、二进制替换为占位。
func stripLegacyBinaryParts(in []schema.ChatMessagePart) ([]schema.ChatMessagePart, bool) {
	if len(in) == 0 {
		return in, false
	}
	changed := false
	for _, part := range in {
		if part.Type != schema.ChatMessagePartTypeText {
			changed = true
			break
		}
	}
	if !changed {
		return in, false
	}
	parts := make([]schema.ChatMessagePart, 0, len(in))
	for _, part := range in {
		if part.Type == schema.ChatMessagePartTypeText {
			parts = append(parts, part)
			continue
		}
		placeholder := "[二进制内容已省略]"
		if part.Type == schema.ChatMessagePartTypeImageURL && part.ImageURL != nil {
			mime := part.ImageURL.MIMEType
			if mime == "" {
				mime = "image"
			}
			placeholder = fmt.Sprintf("[图片已作为图片输入提供给模型: %s]", mime)
		}
		parts = append(parts, schema.ChatMessagePart{Type: schema.ChatMessagePartTypeText, Text: placeholder})
	}
	return parts, true
}

// stripBinaryParts 把图片/音视频部分替换为文本占位；未命中时返回原切片与 false（避免无谓拷贝）。
func stripBinaryParts(in []schema.MessageInputPart) ([]schema.MessageInputPart, bool) {
	if len(in) == 0 {
		return in, false
	}
	changed := false
	for _, part := range in {
		if part.Type != schema.ChatMessagePartTypeText {
			changed = true
			break
		}
	}
	if !changed {
		return in, false
	}
	parts := make([]schema.MessageInputPart, 0, len(in))
	for _, part := range in {
		switch part.Type {
		case schema.ChatMessagePartTypeImageURL:
			placeholder := "[图片已作为图片输入提供给模型]"
			if part.Image != nil {
				placeholder = toolResultMediaPlaceholder(part.Image.MIMEType, part.Image.Base64Data)
			}
			parts = append(parts, schema.MessageInputPart{Type: schema.ChatMessagePartTypeText, Text: placeholder})
		case schema.ChatMessagePartTypeAudioURL, schema.ChatMessagePartTypeVideoURL:
			parts = append(parts, schema.MessageInputPart{Type: schema.ChatMessagePartTypeText, Text: "[二进制内容已省略]"})
		default:
			parts = append(parts, part)
		}
	}
	return parts, true
}

// stripBinaryPartsForTraceMessages 对一批消息做二进制剥离，未命中时原样返回入参切片元素。
func stripBinaryPartsForTraceMessages(msgs []*schema.Message) []*schema.Message {
	if len(msgs) == 0 {
		return msgs
	}
	out := make([]*schema.Message, 0, len(msgs))
	for _, msg := range msgs {
		out = append(out, stripBinaryPartsForTrace(msg))
	}
	return out
}
