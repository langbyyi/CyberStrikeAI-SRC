package multiagent

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

func imageEnhancedOutput(payload string) *compose.EnhancedInvokableToolOutput {
	return &compose.EnhancedInvokableToolOutput{Result: &schema.ToolResult{Parts: []schema.ToolOutputPart{
		{Type: schema.ToolPartTypeText, Text: "已读取图片"},
		{Type: schema.ToolPartTypeImage, Image: &schema.ToolOutputImage{
			MessagePartCommon: schema.MessagePartCommon{MIMEType: "image/png", Base64Data: &payload},
		}},
	}}}
}

// 多模态工具经过文本语义中间件后：放行时结构化结果（图片）必须保留。
func TestEnhancedAdapterKeepsStructuredResultWhenPassThrough(t *testing.T) {
	passThrough := func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
			return next(ctx, input)
		}
	}
	endpoint := withEnhancedToolMiddlewares([]compose.ToolMiddleware{{Invokable: passThrough}})[0].EnhancedInvokable(
		func(ctx context.Context, input *compose.ToolInput) (*compose.EnhancedInvokableToolOutput, error) {
			return imageEnhancedOutput("AAAA"), nil
		},
	)
	out, err := endpoint(context.Background(), &compose.ToolInput{Name: "read_file"})
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	if len(out.Result.Parts) != 2 {
		t.Fatalf("parts = %d, want 2 (image must survive)", len(out.Result.Parts))
	}
	if out.Result.Parts[1].Image == nil || out.Result.Parts[1].Image.Base64Data == nil || *out.Result.Parts[1].Image.Base64Data != "AAAA" {
		t.Errorf("image payload lost: %+v", out.Result.Parts[1])
	}
}

// 中间件改写结果（RBAC 拒绝 / 审批拦截）时：只返回改写后的文本，不得把原始图片带出去。
func TestEnhancedAdapterDropsImageWhenMiddlewareRewrites(t *testing.T) {
	deny := func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
			if input != nil && input.Name == "read_file" {
				return &compose.ToolOutput{Result: "Permission denied: agent:local-execute is required"}, nil
			}
			return next(ctx, input)
		}
	}
	endpoint := withEnhancedToolMiddlewares([]compose.ToolMiddleware{{Invokable: deny}})[0].EnhancedInvokable(
		func(ctx context.Context, input *compose.ToolInput) (*compose.EnhancedInvokableToolOutput, error) {
			return imageEnhancedOutput("AAAA"), nil
		},
	)
	out, err := endpoint(context.Background(), &compose.ToolInput{Name: "read_file"})
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	if len(out.Result.Parts) != 1 || out.Result.Parts[0].Type != schema.ToolPartTypeText {
		t.Fatalf("denied call must yield text only, got %+v", out.Result.Parts)
	}
	if !strings.Contains(out.Result.Parts[0].Text, "Permission denied") {
		t.Errorf("denial text lost: %q", out.Result.Parts[0].Text)
	}
	if strings.Contains(out.Result.Parts[0].Text, "AAAA") {
		t.Error("image payload must not leak into the denial text")
	}
}

// 文本投影：图片只留占位、不带 base64；正文顺序保持。
func TestStructuredToolResultText(t *testing.T) {
	out := imageEnhancedOutput(strings.Repeat("Q", 4000))
	text := structuredToolResultText(out)
	if strings.Contains(text, "QQQQ") {
		t.Error("base64 must not appear in the text projection")
	}
	if !strings.HasPrefix(text, "已读取图片") {
		t.Errorf("text projection should keep leading text: %q", text)
	}
	if !strings.Contains(text, "image/png") || !strings.Contains(text, "3KB") {
		t.Errorf("placeholder should carry mime and size: %q", text)
	}
	if structuredToolResultText(nil) != "" {
		t.Error("nil output should project to empty text")
	}
}

// 装配点必须同时提供 Invokable 与 EnhancedInvokable，否则多模态工具会绕过 RBAC/审批/守卫。
func TestAgenticToolMiddlewaresCoverEnhancedChannel(t *testing.T) {
	chain := einoAgenticToolMiddlewares()
	if len(chain) != 4 {
		t.Fatalf("middleware count = %d, want 4", len(chain))
	}
	for i, mw := range chain {
		if mw.Invokable == nil {
			t.Errorf("middleware[%d] missing Invokable", i)
		}
		if mw.EnhancedInvokable == nil {
			t.Errorf("middleware[%d] missing EnhancedInvokable (multimodal tools would bypass it)", i)
		}
	}
	// 追加型中间件（transfer）也要补齐
	withTransfer := withEnhancedToolMiddlewares([]compose.ToolMiddleware{{Invokable: chain[0].Invokable}, {Invokable: chain[1].Invokable}})
	for i, mw := range withTransfer {
		if mw.EnhancedInvokable == nil {
			t.Errorf("appended middleware[%d] missing EnhancedInvokable", i)
		}
	}
}
