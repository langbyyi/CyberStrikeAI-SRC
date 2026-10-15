package multiagent

import (
	"context"
	"encoding/json"
	"image/color"
	"path/filepath"
	"strings"
	"testing"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/disintegration/imaging"
)

func newTestFilesystemMiddleware(t *testing.T, multiModalRead bool) adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage] {
	t.Helper()
	loc, err := localbk.NewBackend(context.Background(), &localbk.Config{})
	if err != nil {
		t.Fatalf("local backend: %v", err)
	}
	mw, err := subAgentAgenticFilesystemMiddleware(
		context.Background(), loc, nil, "test-agent", "conv-1", "", "", 0, nil,
		nil, nil, nil, nil, nil, 0, 0, 0, nil, multiModalRead,
	)
	if err != nil {
		t.Fatalf("filesystem middleware: %v", err)
	}
	if mw == nil {
		t.Fatal("filesystem middleware is nil")
	}
	return mw
}

func toolByName(tools []tool.BaseTool, name string) tool.BaseTool {
	for _, tl := range tools {
		if tl == nil {
			continue
		}
		if info, err := tl.Info(context.Background()); err == nil && info != nil && info.Name == name {
			return tl
		}
	}
	return nil
}

// 主模型可读图时 read_file 必须是框架的多模态读文件工具：读图片直接返回图片输入
// （与 Codex / Claude Code 的 read 行为一致）；主模型不支持图片时保持纯文本工具。
func TestFilesystemReadFileBecomesMultimodalOnlyForVisionChannels(t *testing.T) {
	dir := t.TempDir()
	imagePath := filepath.Join(dir, "shot.png")
	if err := imaging.Save(imaging.New(48, 24, color.RGBA{R: 7, G: 7, B: 7, A: 255}), imagePath); err != nil {
		t.Fatalf("write test image: %v", err)
	}
	args, err := json.Marshal(map[string]string{"file_path": imagePath})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		multi    bool
		enhanced bool
	}{
		{name: "text-only channel keeps plain read_file", multi: false, enhanced: false},
		{name: "vision channel upgrades read_file", multi: true, enhanced: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := newTestFilesystemMiddleware(t, tc.multi)
			ctx, runCtx, err := mw.BeforeAgent(context.Background(), &adk.ChatModelAgentContext{})
			if err != nil {
				t.Fatalf("BeforeAgent: %v", err)
			}
			readFileTool := toolByName(runCtx.Tools, "read_file")
			if readFileTool == nil {
				t.Fatal("read_file tool not registered by filesystem middleware")
			}
			enhanced, isEnhanced := readFileTool.(tool.EnhancedInvokableTool)
			if isEnhanced != tc.enhanced {
				t.Fatalf("enhanced = %v, want %v", isEnhanced, tc.enhanced)
			}
			if !tc.enhanced {
				return
			}
			res, err := enhanced.InvokableRun(ctx, &schema.ToolArgument{Text: string(args)})
			if err != nil {
				t.Fatalf("read image: %v", err)
			}
			var images, texts int
			for _, part := range res.Parts {
				switch part.Type {
				case schema.ToolPartTypeImage:
					images++
					if part.Image == nil || part.Image.Base64Data == nil || strings.TrimSpace(*part.Image.Base64Data) == "" {
						t.Errorf("image part without base64 payload: %+v", part.Image)
					}
					if part.Image.MIMEType != "image/png" {
						t.Errorf("mime = %q, want image/png", part.Image.MIMEType)
					}
				case schema.ToolPartTypeText:
					texts++
				}
			}
			if images != 1 {
				t.Fatalf("image parts = %d (text parts = %d), want exactly 1 image", images, texts)
			}
		})
	}
}

// 文本裁剪不能吃掉图片：图片部分原样保留给模型。
func TestBoundEnhancedToolResultKeepsImages(t *testing.T) {
	mw := &einoAgenticFilesystemToolMiddleware{toolMaxBytes: 64}
	longText := strings.Repeat("x", 512)
	result := &schema.ToolResult{Parts: []schema.ToolOutputPart{
		{Type: schema.ToolPartTypeText, Text: longText},
		{Type: schema.ToolPartTypeImage, Image: &schema.ToolOutputImage{}},
	}}
	out := mw.boundEnhancedToolResult("call-1", result)
	if len(out.Parts) != 2 {
		t.Fatalf("parts = %d, want 2", len(out.Parts))
	}
	if out.Parts[0].Type != schema.ToolPartTypeText {
		t.Fatalf("first part type = %v, want text", out.Parts[0].Type)
	}
	if len(out.Parts[0].Text) >= len(longText) {
		t.Errorf("long text should be reduced, still %d bytes", len(out.Parts[0].Text))
	}
	if out.Parts[1].Type != schema.ToolPartTypeImage || out.Parts[1].Image == nil {
		t.Errorf("image part must survive reduction: %+v", out.Parts[1])
	}
	// 未超预算时原样返回
	short := &schema.ToolResult{Parts: []schema.ToolOutputPart{{Type: schema.ToolPartTypeText, Text: "ok"}}}
	if got := mw.boundEnhancedToolResult("call-2", short); got != short {
		t.Error("short result should pass through unchanged")
	}
}

// 工具结果里的图片不进文本通道：监控落库 / SSE / 摘要只保留占位，不能把 base64 写进去。
func TestFunctionToolResultToMessageUsesImagePlaceholder(t *testing.T) {
	payload := strings.Repeat("A", 4000)
	msg := functionToolResultToMessage(&schema.FunctionToolResult{
		CallID: "call-1",
		Name:   "read_file",
		Content: []*schema.FunctionToolResultContentBlock{
			{Type: schema.FunctionToolResultContentBlockTypeText, Text: &schema.UserInputText{Text: "已读取图片"}},
			{Type: schema.FunctionToolResultContentBlockTypeImage, Image: &schema.UserInputImage{Base64Data: payload, MIMEType: "image/png"}},
		},
	})
	if msg == nil {
		t.Fatal("want classic tool message")
	}
	if strings.Contains(msg.Content, "AAAA") {
		t.Error("base64 payload must not leak into the text channel")
	}
	if !strings.Contains(msg.Content, "已读取图片") {
		t.Errorf("text part lost: %q", msg.Content)
	}
	if !strings.Contains(msg.Content, "image/png") {
		t.Errorf("image placeholder missing mime: %q", msg.Content)
	}
	if msg.ToolCallID != "call-1" || msg.ToolName != "read_file" {
		t.Errorf("tool identity lost: %+v", msg)
	}
}
