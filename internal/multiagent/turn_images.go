package multiagent

import (
	"context"
	"strings"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

// TurnImage 本轮用户消息随附的图片（多模态主模型原生直发）。
type TurnImage struct {
	Path     string // 服务器上的原图路径（仅供日志/提示词引用）
	Base64   string // 图片字节的 base64
	MIMEType string // 如 image/png
	Detail   string // low | high | auto；空则 auto
}

type turnImagesKey struct{}

// WithTurnImages 把本轮图片挂到 ctx，runner 构建 user 消息时读取。
//
// 用 ctx 承载而不是加形参：RunEinoSingleChatModelAgent / RunDeepAgent 在
// handler、batch、workflow、robot 等有十余处调用，加形参会把改动面扩散到与本功能无关的路径。
// 只有真正带附件的对话入口（chat / multi-agent）会包装 ctx，其余入口自然不带图片。
func WithTurnImages(ctx context.Context, images []TurnImage) context.Context {
	if ctx == nil || len(images) == 0 {
		return ctx
	}
	return context.WithValue(ctx, turnImagesKey{}, images)
}

// TurnImagesFromContext 取出本轮随附图片；无则 nil。
func TurnImagesFromContext(ctx context.Context) []TurnImage {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(turnImagesKey{}).([]TurnImage)
	return v
}

// userMessageWithImages 构建带图片的本轮 user 消息：文本放 Content（兼容所有按 Content
// 读取的既有逻辑），图片作为 UserInputMultiContent 的图片块，避免文本重复。
func userMessageWithImages(text string, images []TurnImage) *schema.Message {
	msg := schema.UserMessage(text)
	parts := make([]schema.MessageInputPart, 0, len(images))
	for _, img := range images {
		data := strings.TrimSpace(img.Base64)
		if data == "" {
			continue
		}
		b64 := data
		mime := strings.TrimSpace(img.MIMEType)
		if mime == "" {
			mime = "image/jpeg"
		}
		parts = append(parts, schema.MessageInputPart{
			Type: schema.ChatMessagePartTypeImageURL,
			Image: &schema.MessageInputImage{
				MessagePartCommon: schema.MessagePartCommon{
					Base64Data: &b64,
					MIMEType:   mime,
				},
				Detail: turnImageDetail(img.Detail),
			},
		})
	}
	if len(parts) == 0 {
		return nil
	}
	msg.UserInputMultiContent = parts
	return msg
}

func turnImageDetail(detail string) schema.ImageURLDetail {
	switch strings.ToLower(strings.TrimSpace(detail)) {
	case "low":
		return schema.ImageURLDetailLow
	case "high":
		return schema.ImageURLDetailHigh
	default:
		return schema.ImageURLDetailAuto
	}
}

// appendUserMessageWithImagesIfNeeded 追加本轮 user 消息；无图片时保持原有行为。
// 若历史尾部已是同一句 user 文本（连续发送相同文本），就地升级为带图消息而不是丢弃图片。
func appendUserMessageWithImagesIfNeeded(msgs []adk.Message, userMessage string, images []TurnImage) []adk.Message {
	if len(images) == 0 {
		return appendUserMessageIfNeeded(msgs, userMessage)
	}
	msg := userMessageWithImages(userMessage, images)
	if msg == nil {
		return appendUserMessageIfNeeded(msgs, userMessage)
	}
	if n := len(msgs); n > 0 {
		last := msgs[n-1]
		if last != nil && last.Role == schema.User && strings.TrimSpace(last.Content) == strings.TrimSpace(userMessage) {
			out := make([]adk.Message, n)
			copy(out, msgs)
			out[n-1] = msg
			return out
		}
	}
	return append(msgs, msg)
}
