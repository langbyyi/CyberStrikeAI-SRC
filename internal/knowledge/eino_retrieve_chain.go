package knowledge

import (
	"context"
	"fmt"

	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// BuildKnowledgeRetrieveChain 编译「查询字符串 → 文档列表」的 Eino Chain，底层为 SQLite 向量检索（[VectorEinoRetriever]）。
// 去重、上下文预算截断与最终 Top-K 均在 [VectorEinoRetriever.Retrieve] 内完成，与 HTTP/MCP 检索路径一致。
func BuildKnowledgeRetrieveChain(ctx context.Context, r *Retriever) (compose.Runnable[string, []*schema.Document], error) {
	if r == nil {
		return nil, fmt.Errorf("retriever is nil")
	}
	ch := compose.NewChain[string, []*schema.Document]()
	ch.AppendRetriever(r.AsEinoRetriever())
	return ch.Compile(ctx)
}

// CompileRetrieveChain 等价于 [BuildKnowledgeRetrieveChain](ctx, r)。
func (r *Retriever) CompileRetrieveChain(ctx context.Context) (compose.Runnable[string, []*schema.Document], error) {
	return BuildKnowledgeRetrieveChain(ctx, r)
}
