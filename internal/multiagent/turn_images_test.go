package multiagent

import (
	"context"
	"testing"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

func sampleTurnImages() []TurnImage {
	return []TurnImage{
		{Path: "/tmp/a.png", Base64: "AAAA", MIMEType: "image/png", Detail: "high"},
		{Path: "/tmp/b.jpg", Base64: "BBBB", MIMEType: "image/jpeg"},
		{Path: "/tmp/empty.png", Base64: ""},
	}
}

func TestWithTurnImagesRoundTrip(t *testing.T) {
	imgs := sampleTurnImages()
	ctx := WithTurnImages(context.Background(), imgs)
	got := TurnImagesFromContext(ctx)
	if len(got) != len(imgs) {
		t.Fatalf("got %d images, want %d", len(got), len(imgs))
	}
	if got[0].Path != "/tmp/a.png" {
		t.Errorf("path = %q", got[0].Path)
	}
	if TurnImagesFromContext(context.Background()) != nil {
		t.Error("plain context should carry no images")
	}
	if WithTurnImages(context.Background(), nil) != context.Background() {
		t.Error("nil images should not change context")
	}
}

func TestUserMessageWithImages(t *testing.T) {
	msg := userMessageWithImages("看图回答", sampleTurnImages())
	if msg == nil {
		t.Fatal("want message")
	}
	if msg.Role != schema.User {
		t.Errorf("role = %v, want user", msg.Role)
	}
	if msg.Content != "看图回答" {
		t.Errorf("content = %q, want text kept in Content", msg.Content)
	}
	// 空 base64 的图片应被跳过
	if len(msg.UserInputMultiContent) != 2 {
		t.Fatalf("parts = %d, want 2", len(msg.UserInputMultiContent))
	}
	first := msg.UserInputMultiContent[0]
	if first.Type != schema.ChatMessagePartTypeImageURL || first.Image == nil {
		t.Fatalf("first part not an image part: %+v", first)
	}
	if first.Image.Base64Data == nil || *first.Image.Base64Data != "AAAA" {
		t.Errorf("base64 = %v", first.Image.Base64Data)
	}
	if first.Image.Detail != schema.ImageURLDetailHigh {
		t.Errorf("detail = %q, want high", first.Image.Detail)
	}
	if second := msg.UserInputMultiContent[1]; second.Image.Detail != schema.ImageURLDetailAuto {
		t.Errorf("default detail = %q, want auto", second.Image.Detail)
	}
	if userMessageWithImages("x", []TurnImage{{Path: "/tmp/x.png"}}) != nil {
		t.Error("images without payload should yield nil message")
	}
}

func TestAppendUserMessageWithImagesIfNeeded(t *testing.T) {
	imgs := sampleTurnImages()

	// 无图片：沿用旧行为（纯文本追加）
	plain := appendUserMessageWithImagesIfNeeded(nil, "hello", nil)
	if len(plain) != 1 || plain[0].Content != "hello" || len(plain[0].UserInputMultiContent) != 0 {
		t.Fatalf("plain append changed: %+v", plain[0])
	}

	// 有图片：追加带图片的 user 消息
	msgs := appendUserMessageWithImagesIfNeeded([]adk.Message{schema.AssistantMessage("prev", nil)}, "看图", imgs)
	if len(msgs) != 2 {
		t.Fatalf("len = %d, want 2", len(msgs))
	}
	if len(msgs[1].UserInputMultiContent) != 2 {
		t.Fatalf("tail parts = %d, want 2", len(msgs[1].UserInputMultiContent))
	}

	// 历史尾部已是同一句文本：就地升级为带图消息，不重复追加
	tail := schema.UserMessage("看图")
	upgraded := appendUserMessageWithImagesIfNeeded([]adk.Message{tail}, "看图", imgs)
	if len(upgraded) != 1 {
		t.Fatalf("len = %d, want 1 (in-place upgrade)", len(upgraded))
	}
	if len(upgraded[0].UserInputMultiContent) != 2 {
		t.Errorf("upgraded tail missing images: %+v", upgraded[0])
	}
	if len(tail.UserInputMultiContent) != 0 {
		t.Error("original tail message must not be mutated")
	}
}

func TestEinoMessageToAgenticKeepsImages(t *testing.T) {
	data := "AAAA"
	msg := schema.UserMessage("看图")
	msg.UserInputMultiContent = []schema.MessageInputPart{{
		Type: schema.ChatMessagePartTypeImageURL,
		Image: &schema.MessageInputImage{
			MessagePartCommon: schema.MessagePartCommon{Base64Data: &data, MIMEType: "image/png"},
			Detail:            schema.ImageURLDetailAuto,
		},
	}}
	agentic := EinoMessageToAgentic(msg)
	if agentic == nil {
		t.Fatal("want agentic message")
	}
	var images, texts int
	for _, block := range agentic.ContentBlocks {
		switch {
		case block.UserInputImage != nil:
			images++
			if block.UserInputImage.Base64Data != "AAAA" || block.UserInputImage.MIMEType != "image/png" {
				t.Errorf("image block = %+v", block.UserInputImage)
			}
		case block.UserInputText != nil:
			texts++
		}
	}
	if images != 1 {
		t.Fatalf("image blocks = %d, want 1", images)
	}
	if texts != 1 {
		t.Fatalf("text blocks = %d, want 1 (no duplication)", texts)
	}

	// 往返：agentic → classic 仍保留图片块
	back := AgenticMessageToEino(agentic)
	if len(back) != 1 {
		t.Fatalf("round-trip len = %d, want 1", len(back))
	}
	if len(back[0].UserInputMultiContent) != 1 {
		t.Fatalf("round-trip parts = %d, want 1", len(back[0].UserInputMultiContent))
	}
	rt := back[0].UserInputMultiContent[0]
	if rt.Image == nil || rt.Image.Base64Data == nil || *rt.Image.Base64Data != "AAAA" {
		t.Errorf("round-trip image = %+v", rt.Image)
	}
	if back[0].Content != "看图" {
		t.Errorf("round-trip content = %q", back[0].Content)
	}
}

func TestEinoMessageToAgenticTextPartOnlyWhenContentEmpty(t *testing.T) {
	msg := schema.UserMessage("")
	msg.UserInputMultiContent = []schema.MessageInputPart{{Type: schema.ChatMessagePartTypeText, Text: "来自分片"}}
	agentic := EinoMessageToAgentic(msg)
	texts := 0
	for _, block := range agentic.ContentBlocks {
		if block.UserInputText != nil {
			texts++
		}
	}
	if texts != 1 {
		t.Fatalf("text blocks = %d, want 1", texts)
	}
}

// 端到端接缝：本轮图片 → 模型输入消息（agentic）必须带图片块。
// 覆盖 appendUserMessageWithImagesIfNeeded → EinoMessagesToAgentic → agentic 模型 的整条链路。
func TestTurnImagesReachAgenticModelInput(t *testing.T) {
	ctx := WithTurnImages(context.Background(), sampleTurnImages())
	baseMsgs := historyToMessages(nil, nil, nil)
	baseMsgs = appendUserMessageWithImagesIfNeeded(baseMsgs, "看这张图", TurnImagesFromContext(ctx))

	agentic := EinoMessagesToAgentic(baseMsgs)
	if len(agentic) != 1 {
		t.Fatalf("agentic messages = %d, want 1", len(agentic))
	}
	var images int
	var text string
	for _, block := range agentic[0].ContentBlocks {
		if block.UserInputImage != nil {
			images++
			if block.UserInputImage.Base64Data == "" {
				t.Error("image block without payload")
			}
		}
		if block.UserInputText != nil {
			text += block.UserInputText.Text
		}
	}
	if images != 2 {
		t.Fatalf("image blocks = %d, want 2", images)
	}
	if text != "看这张图" {
		t.Errorf("text = %q, want the user text exactly once", text)
	}
}
