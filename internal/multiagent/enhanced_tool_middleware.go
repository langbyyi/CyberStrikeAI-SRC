package multiagent

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// 多模态工具（EnhancedInvokableTool，例如 UseMultiModalRead 打开后的 read_file）走 compose 的
// 独立中间件通道（ToolMiddleware.EnhancedInvokable）；只实现 Invokable 的中间件对它们不生效。
// 若不补映射，RBAC、统一审批、输出守卫、错误恢复会在这些工具上被绕过——所以统一补齐。

// einoAgenticToolMiddlewares 返回 agent 运行的统一工具中间件链（含多模态通道映射）。
func einoAgenticToolMiddlewares() []compose.ToolMiddleware {
	return withEnhancedToolMiddlewares([]compose.ToolMiddleware{
		modelOutputExecutionGuardMiddleware(),
		localToolRBACMiddleware(),
		hitlToolCallMiddleware(),
		softRecoveryToolMiddleware(),
	})
}

type structuredToolResultHolderKey struct{}

type structuredToolResultHolder struct {
	result *compose.EnhancedInvokableToolOutput
	text   string
}

// withEnhancedToolMiddlewares 为只实现 Invokable 的中间件补上 EnhancedInvokable 等价包装。
func withEnhancedToolMiddlewares(in []compose.ToolMiddleware) []compose.ToolMiddleware {
	if len(in) == 0 {
		return in
	}
	out := make([]compose.ToolMiddleware, 0, len(in))
	for _, mw := range in {
		if mw.EnhancedInvokable == nil && mw.Invokable != nil {
			mw.EnhancedInvokable = enhancedInvokableFromInvokable(mw.Invokable)
		}
		out = append(out, mw)
	}
	return out
}

// enhancedInvokableFromInvokable 让文本语义的中间件同时覆盖多模态工具：
// 把结构化结果投影成文本喂给既有中间件（拒绝/审批/错误恢复都是文本语义），
// 中间件放行且未改写时返回原始结构化结果——图片不丢；一旦被改写（如审批拦截、RBAC 拒绝），
// 只返回改写后的文本，保持既有语义。
func enhancedInvokableFromInvokable(mw compose.InvokableToolMiddleware) compose.EnhancedInvokableToolMiddleware {
	return func(next compose.EnhancedInvokableToolEndpoint) compose.EnhancedInvokableToolEndpoint {
		asText := mw(func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
			out, err := next(ctx, input)
			if err != nil {
				return nil, err
			}
			text := structuredToolResultText(out)
			if holder, ok := ctx.Value(structuredToolResultHolderKey{}).(*structuredToolResultHolder); ok && holder != nil {
				holder.result = out
				holder.text = text
			}
			return &compose.ToolOutput{Result: text}, nil
		})
		return func(ctx context.Context, input *compose.ToolInput) (*compose.EnhancedInvokableToolOutput, error) {
			holder := &structuredToolResultHolder{}
			out, err := asText(context.WithValue(ctx, structuredToolResultHolderKey{}, holder), input)
			if err != nil {
				return nil, err
			}
			if holder.result != nil && out != nil && out.Result == holder.text {
				return holder.result, nil
			}
			return enhancedTextOnlyOutput(out), nil
		}
	}
}

func enhancedTextOnlyOutput(out *compose.ToolOutput) *compose.EnhancedInvokableToolOutput {
	text := ""
	if out != nil {
		text = out.Result
	}
	return &compose.EnhancedInvokableToolOutput{Result: &schema.ToolResult{
		Parts: []schema.ToolOutputPart{{Type: schema.ToolPartTypeText, Text: text}},
	}}
}

// structuredToolResultText 结构化工具结果的文本投影（二进制部分只留占位）。
func structuredToolResultText(out *compose.EnhancedInvokableToolOutput) string {
	if out == nil || out.Result == nil {
		return ""
	}
	var b strings.Builder
	for _, part := range out.Result.Parts {
		switch part.Type {
		case schema.ToolPartTypeText:
			b.WriteString(part.Text)
		case schema.ToolPartTypeImage:
			if part.Image != nil {
				b.WriteString(toolResultMediaPlaceholder(part.Image.MIMEType, part.Image.Base64Data))
			}
		case schema.ToolPartTypeFile:
			if part.File != nil {
				b.WriteString(toolResultMediaPlaceholder(part.File.MIMEType, part.File.Base64Data))
			}
		}
	}
	return b.String()
}

// toolResultMediaPlaceholder 二进制媒体在文本通道里的占位文案（不含 base64）。
func toolResultMediaPlaceholder(mime string, base64Data *string) string {
	label := strings.TrimSpace(mime)
	if label == "" {
		label = "binary"
	}
	size := 0
	if base64Data != nil {
		size = len(*base64Data) * 3 / 4
	}
	return fmt.Sprintf("[图片/文件已作为图片输入返回给模型: %s ~%dKB]", label, (size+1023)/1024)
}
