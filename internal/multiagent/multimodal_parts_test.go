package multiagent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"cyberstrike-ai/internal/vision"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/summarization"
	"github.com/cloudwego/eino/schema"
)

func messageWithImageParts(text string, images int) *schema.Message {
	msg := schema.UserMessage(text)
	parts := make([]schema.MessageInputPart, 0, images)
	for i := 0; i < images; i++ {
		b64 := strings.Repeat("A", 400)
		parts = append(parts, schema.MessageInputPart{
			Type: schema.ChatMessagePartTypeImageURL,
			Image: &schema.MessageInputImage{
				MessagePartCommon: schema.MessagePartCommon{Base64Data: &b64, MIMEType: "image/png"},
			},
		})
	}
	msg.UserInputMultiContent = parts
	return msg
}

// 图片必须计入 token 预算：否则带图输入对软预算/摘要判据不可见。
func TestSummarizationTokenCounterCountsImages(t *testing.T) {
	counter := einoSummarizationTokenCounter("gpt-4")
	ctx := context.Background()

	base := []*schema.Message{schema.UserMessage("分析这张登录页截图")}
	withImages := []*schema.Message{messageWithImageParts("分析这张登录页截图", 3)}

	baseTokens, err := counter(ctx, &summarization.TokenCounterInput{Messages: base})
	if err != nil {
		t.Fatalf("count base: %v", err)
	}
	imageTokens, err := counter(ctx, &summarization.TokenCounterInput{Messages: withImages})
	if err != nil {
		t.Fatalf("count with images: %v", err)
	}
	diff := imageTokens - baseTokens
	if diff != 3*vision.NativeImageTokenEstimate {
		t.Fatalf("image surcharge = %d, want %d", diff, 3*vision.NativeImageTokenEstimate)
	}
}

func TestImagePartsTokenSurchargeIgnoresTextOnlyMessages(t *testing.T) {
	msgs := []*schema.Message{nil, schema.UserMessage("纯文本"), schema.AssistantMessage("回复", nil)}
	if got := imagePartsTokenSurcharge(msgs); got != 0 {
		t.Fatalf("text-only surcharge = %d, want 0", got)
	}
	if got := countMessageImageParts([]*schema.Message{messageWithImageParts("x", 2)}); got != 2 {
		t.Fatalf("image parts = %d, want 2", got)
	}
}

func TestSplitBinaryPartsForTrace(t *testing.T) {
	original := messageWithImageParts("这里有图", 2)
	stripped := stripBinaryPartsForTrace(original)

	if len(stripped.UserInputMultiContent) != 2 {
		t.Fatalf("parts = %d, want 2 (placeholders)", len(stripped.UserInputMultiContent))
	}
	for _, part := range stripped.UserInputMultiContent {
		if part.Type != schema.ChatMessagePartTypeText {
			t.Fatalf("binary part not replaced: %+v", part)
		}
		if !strings.Contains(part.Text, "image/png") {
			t.Errorf("placeholder should carry mime: %q", part.Text)
		}
	}
	if stripped.Content != "这里有图" {
		t.Errorf("content changed: %q", stripped.Content)
	}
	// 原消息不得被就地修改
	if original.UserInputMultiContent[0].Type != schema.ChatMessagePartTypeImageURL {
		t.Error("original message must not be mutated")
	}
	// 纯文本消息原样返回（同一指针，避免无谓拷贝）
	plain := schema.UserMessage("纯文本")
	if stripBinaryPartsForTrace(plain) != plain {
		t.Error("text-only message should be returned as-is")
	}
}

// 纯图片消息（正文为空）剥离后必须留下可回放的正文，避免续跑出现空 user 消息。
func TestStripBinaryPartsKeepsReplayableContent(t *testing.T) {
	png := messageWithImageParts("", 1)
	stripped := stripBinaryPartsForTrace(png)
	if strings.TrimSpace(stripped.Content) == "" {
		t.Fatal("empty body must be filled with the placeholder so replay keeps something")
	}
	if !strings.Contains(stripped.Content, "image/png") {
		t.Errorf("replayable content should describe the omitted image: %q", stripped.Content)
	}
	// 有正文时正文优先，不被占位覆盖
	withText := stripBinaryPartsForTrace(messageWithImageParts("正文在此", 1))
	if withText.Content != "正文在此" {
		t.Errorf("existing content must be preserved: %q", withText.Content)
	}
}

// 历史遗留的 MultiContent 字段同样要剥离（防止未来路径绕过 UserInputMultiContent 的防护）。
func TestStripBinaryPartsHandlesLegacyMultiContent(t *testing.T) {
	b64 := strings.Repeat("B", 400)
	msg := schema.UserMessage("旧字段带图")
	msg.MultiContent = []schema.ChatMessagePart{{
		Type:     schema.ChatMessagePartTypeImageURL,
		ImageURL: &schema.ChatMessageImageURL{URL: "data:image/jpeg;base64," + b64, MIMEType: "image/jpeg"},
	}}
	stripped := stripBinaryPartsForTrace(msg)
	if len(stripped.MultiContent) != 1 || stripped.MultiContent[0].Type != schema.ChatMessagePartTypeText {
		t.Fatalf("legacy multi-content not stripped: %+v", stripped.MultiContent)
	}
	if !strings.Contains(stripped.MultiContent[0].Text, "image/jpeg") {
		t.Errorf("placeholder should carry mime: %q", stripped.MultiContent[0].Text)
	}
	if strings.Contains(stripped.MultiContent[0].Text, "BBBB") {
		t.Error("legacy binary payload leaked into placeholder")
	}
	if msg.MultiContent[0].Type != schema.ChatMessagePartTypeImageURL {
		t.Error("original message must not be mutated")
	}
	raw, err := json.Marshal(cloneADKMessagesForTrace([]adk.Message{msg}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), strings.Repeat("B", 100)) {
		t.Error("trace still carries legacy base64 payload")
	}
}

// 轨迹落库前后都不能出现 base64：这是 last_react_input 的体积闸门。
func TestCloneForTraceStripsImagePayload(t *testing.T) {
	msgs := []adk.Message{
		schema.SystemMessage("系统提示"),
		messageWithImageParts("看这张图", 2),
		schema.AssistantMessage("好的", nil),
	}
	cloned := cloneADKMessagesForTrace(msgs)
	if len(cloned) != 3 {
		t.Fatalf("cloned = %d, want 3", len(cloned))
	}
	raw, err := json.Marshal(cloned)
	if err != nil {
		t.Fatalf("marshal trace: %v", err)
	}
	if strings.Contains(string(raw), strings.Repeat("A", 100)) {
		t.Error("trace still carries base64 image payload")
	}
	if !strings.Contains(string(raw), "image/png") {
		t.Error("trace should keep the image placeholder with mime")
	}
	if strings.Contains(string(raw), "user_input_image") {
		t.Error("trace should not keep structured image parts")
	}
}
