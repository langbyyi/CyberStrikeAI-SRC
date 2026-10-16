package multiagent

import (
	"context"
	"strings"
	"testing"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/reduction"
	"github.com/cloudwego/eino/schema"
)

func newTestAgenticReductionMiddleware(t *testing.T, root string) adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage] {
	t.Helper()
	loc, err := localbk.NewBackend(context.Background(), &localbk.Config{})
	if err != nil {
		t.Fatalf("local backend: %v", err)
	}
	mw, err := reduction.NewTyped[*schema.AgenticMessage](context.Background(), &reduction.TypedConfig[*schema.AgenticMessage]{
		Backend:           loc,
		RootDir:           root,
		MaxTokensForClear: 1,
	})
	if err != nil {
		t.Fatalf("reduction: %v", err)
	}
	return mw
}

func agenticToolRound(callID, name, args string, content []*schema.FunctionToolResultContentBlock) (*schema.AgenticMessage, *schema.AgenticMessage) {
	return &schema.AgenticMessage{
			Role:          schema.AgenticRoleTypeAssistant,
			ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.FunctionToolCall{CallID: callID, Name: name, Arguments: args})},
		}, &schema.AgenticMessage{
			Role: schema.AgenticRoleTypeUser,
			ContentBlocks: []*schema.ContentBlock{
				schema.NewContentBlock(&schema.FunctionToolResult{CallID: callID, Name: name, Content: content}),
			},
		}
}

func textContentBlock(text string) *schema.FunctionToolResultContentBlock {
	return &schema.FunctionToolResultContentBlock{Type: schema.FunctionToolResultContentBlockTypeText, Text: &schema.UserInputText{Text: text}}
}

// 上下文清理会把工具结果里的 base64 图片留成空壳；清洗中间件必须在送入模型前
// 把它降级为文本占位，否则下一次 ChatModel 直接以
// "image message part must have url or base64 data" 终止整个会话。
func TestAgenticEmptyMediaSanitizerDegradesClearedToolImage(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	redMW := newTestAgenticReductionMiddleware(t, root)

	const payload = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg=="

	imgCall, imgResult := agenticToolRound("call-1", "read_file", `{"file_path":"/tmp/shot.png"}`, []*schema.FunctionToolResultContentBlock{
		textContentBlock("已读取图片"),
		{Type: schema.FunctionToolResultContentBlockTypeImage, Image: &schema.UserInputImage{Base64Data: payload, MIMEType: "image/png"}},
	})
	a2, r2 := agenticToolRound("call-2", "exec", `{"cmd":"ls"}`, []*schema.FunctionToolResultContentBlock{textContentBlock("ok")})
	a3, r3 := agenticToolRound("call-3", "exec", `{"cmd":"pwd"}`, []*schema.FunctionToolResultContentBlock{textContentBlock("ok")})

	state := &adk.TypedChatModelAgentState[*schema.AgenticMessage]{Messages: []*schema.AgenticMessage{
		{Role: schema.AgenticRoleTypeUser, ContentBlocks: []*schema.ContentBlock{schema.NewContentBlock(&schema.UserInputText{Text: "看一下这张截图"})}},
		imgCall, imgResult,
		a2, r2,
		a3, r3,
	}}

	_, cleared, err := redMW.BeforeModelRewriteState(ctx, state, &adk.TypedModelContext[*schema.AgenticMessage]{})
	if err != nil {
		t.Fatalf("reduction: %v", err)
	}
	if n := countAgenticEmptyMediaBlocks(cleared.Messages); n == 0 {
		t.Fatalf("前置条件不成立：清理后应出现空壳媒体块，实际 0 个")
	}

	sanitizer := newAgenticEmptyMediaPartSanitizerMiddleware(nil, "test")
	_, out, err := sanitizer.BeforeModelRewriteState(ctx, cleared, &adk.TypedModelContext[*schema.AgenticMessage]{})
	if err != nil {
		t.Fatalf("sanitizer: %v", err)
	}

	if n := countAgenticEmptyMediaBlocks(out.Messages); n != 0 {
		t.Fatalf("清洗后仍存在空壳媒体块 %d 个", n)
	}
	if !agenticMessagesContainText(out.Messages, emptyImagePlaceholder) {
		t.Errorf("缺少图片占位文本 %q", emptyImagePlaceholder)
	}
	// 文本部分由 reduction 正常清理为落盘提示，清洗不得改动它。
	if !agenticMessagesContainSubstring(out.Messages, "persisted-output") {
		t.Errorf("reduction 的文本占位被破坏")
	}
	if names := agenticToolCallNames(out.Messages); len(names) != 3 {
		t.Errorf("工具调用关系被破坏：%v", names)
	}
}

// 有载荷的图片必须原样保留，清洗不得误伤正常多模态输入。
func TestAgenticEmptyMediaSanitizerKeepsPayloadImage(t *testing.T) {
	const payload = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg=="

	msgs := []*schema.AgenticMessage{
		{
			Role: schema.AgenticRoleTypeUser,
			ContentBlocks: []*schema.ContentBlock{
				schema.NewContentBlock(&schema.UserInputImage{Base64Data: payload, MIMEType: "image/png"}),
			},
		},
		{
			Role: schema.AgenticRoleTypeUser,
			ContentBlocks: []*schema.ContentBlock{
				schema.NewContentBlock(&schema.UserInputImage{URL: "https://example.com/a.png", MIMEType: "image/png"}),
			},
		},
	}

	cleaned, replaced := sanitizeAgenticEmptyMediaParts(msgs)
	if replaced != 0 {
		t.Fatalf("replaced = %d, want 0", replaced)
	}
	if &cleaned[0] != &msgs[0] {
		t.Error("无改动时不应重建消息")
	}
}

// user 消息里的空壳媒体块同样要降级，避免整轮失败。
func TestAgenticEmptyMediaSanitizerDegradesEmptyUserMedia(t *testing.T) {
	msgs := []*schema.AgenticMessage{
		{
			Role: schema.AgenticRoleTypeUser,
			ContentBlocks: []*schema.ContentBlock{
				schema.NewContentBlock(&schema.UserInputText{Text: "看这张图"}),
				schema.NewContentBlock(&schema.UserInputImage{MIMEType: "image/png"}),
				schema.NewContentBlock(&schema.UserInputAudio{MIMEType: "audio/wav"}),
			},
		},
	}

	cleaned, replaced := sanitizeAgenticEmptyMediaParts(msgs)
	if replaced != 2 {
		t.Fatalf("replaced = %d, want 2", replaced)
	}
	for _, block := range cleaned[0].ContentBlocks {
		if block.UserInputImage != nil || block.UserInputAudio != nil {
			t.Errorf("空壳媒体块未被降级: %+v", block)
		}
	}
	if !agenticMessagesContainText(cleaned, emptyImagePlaceholder) || !agenticMessagesContainText(cleaned, emptyAudioPlaceholder) {
		t.Error("缺少媒体占位文本")
	}
}

// tool result 里整块缺失媒体对象（nil）也要降级，不能留给模型。
func TestAgenticEmptyMediaSanitizerDegradesNilMediaInToolResult(t *testing.T) {
	msgs := []*schema.AgenticMessage{
		{
			Role: schema.AgenticRoleTypeUser,
			ContentBlocks: []*schema.ContentBlock{
				schema.NewContentBlock(&schema.FunctionToolResult{
					CallID: "call-1",
					Name:   "read_file",
					Content: []*schema.FunctionToolResultContentBlock{
						{Type: schema.FunctionToolResultContentBlockTypeImage},
						textContentBlock("文本仍在"),
					},
				}),
			},
		},
	}

	cleaned, replaced := sanitizeAgenticEmptyMediaParts(msgs)
	if replaced != 1 {
		t.Fatalf("replaced = %d, want 1", replaced)
	}
	content := cleaned[0].ContentBlocks[0].FunctionToolResult.Content
	if content[0].Type != schema.FunctionToolResultContentBlockTypeText || content[0].Text.Text != emptyImagePlaceholder {
		t.Errorf("首个块未降级为占位文本: %+v", content[0])
	}
	if content[1].Text.Text != "文本仍在" {
		t.Error("原有文本块被破坏")
	}
}

func countAgenticEmptyMediaBlocks(msgs []*schema.AgenticMessage) int {
	n := 0
	for _, msg := range msgs {
		for _, block := range msg.ContentBlocks {
			if block == nil {
				continue
			}
			switch {
			case block.UserInputImage != nil && mediaPayloadEmpty(block.UserInputImage.URL, block.UserInputImage.Base64Data):
				n++
			case block.UserInputAudio != nil && mediaPayloadEmpty(block.UserInputAudio.URL, block.UserInputAudio.Base64Data):
				n++
			case block.UserInputVideo != nil && mediaPayloadEmpty(block.UserInputVideo.URL, block.UserInputVideo.Base64Data):
				n++
			case block.UserInputFile != nil && mediaPayloadEmpty(block.UserInputFile.URL, block.UserInputFile.Base64Data):
				n++
			case block.FunctionToolResult != nil:
				for _, c := range block.FunctionToolResult.Content {
					if c == nil {
						continue
					}
					switch c.Type {
					case schema.FunctionToolResultContentBlockTypeImage:
						if c.Image == nil || mediaPayloadEmpty(c.Image.URL, c.Image.Base64Data) {
							n++
						}
					case schema.FunctionToolResultContentBlockTypeAudio:
						if c.Audio == nil || mediaPayloadEmpty(c.Audio.URL, c.Audio.Base64Data) {
							n++
						}
					case schema.FunctionToolResultContentBlockTypeVideo:
						if c.Video == nil || mediaPayloadEmpty(c.Video.URL, c.Video.Base64Data) {
							n++
						}
					case schema.FunctionToolResultContentBlockTypeFile:
						if c.File == nil || mediaPayloadEmpty(c.File.URL, c.File.Base64Data) {
							n++
						}
					}
				}
			}
		}
	}
	return n
}

func agenticMessagesContainText(msgs []*schema.AgenticMessage, want string) bool {
	for _, msg := range msgs {
		for _, block := range msg.ContentBlocks {
			if block == nil {
				continue
			}
			if block.UserInputText != nil && block.UserInputText.Text == want {
				return true
			}
			if block.FunctionToolResult != nil {
				for _, c := range block.FunctionToolResult.Content {
					if c != nil && c.Text != nil && c.Text.Text == want {
						return true
					}
				}
			}
		}
	}
	return false
}

func agenticMessagesContainSubstring(msgs []*schema.AgenticMessage, want string) bool {
	for _, msg := range msgs {
		for _, block := range msg.ContentBlocks {
			if block == nil {
				continue
			}
			if block.UserInputText != nil && strings.Contains(block.UserInputText.Text, want) {
				return true
			}
			if block.FunctionToolResult != nil {
				for _, c := range block.FunctionToolResult.Content {
					if c != nil && c.Text != nil && strings.Contains(c.Text.Text, want) {
						return true
					}
				}
			}
		}
	}
	return false
}

func agenticToolCallNames(msgs []*schema.AgenticMessage) []string {
	var names []string
	for _, msg := range msgs {
		for _, block := range msg.ContentBlocks {
			if block != nil && block.FunctionToolCall != nil {
				names = append(names, block.FunctionToolCall.Name)
			}
		}
	}
	return names
}
