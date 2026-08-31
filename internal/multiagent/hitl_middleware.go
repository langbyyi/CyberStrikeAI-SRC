package multiagent

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"cyberstrike-ai/internal/approval"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

type approvalInterceptorKey struct{}
type ApprovalToolInterceptor func(ctx context.Context, toolName, arguments string) (context.Context, string, error)

type humanRejectError struct {
	reason string
}

func (e *humanRejectError) Error() string {
	if strings.TrimSpace(e.reason) == "" {
		return "rejected by user"
	}
	return "rejected by user: " + strings.TrimSpace(e.reason)
}

func NewHumanRejectError(reason string) error {
	return &humanRejectError{reason: strings.TrimSpace(reason)}
}

func IsHumanRejectError(err error) bool {
	var target *humanRejectError
	return errors.As(err, &target)
}

func WithApprovalToolInterceptor(ctx context.Context, fn ApprovalToolInterceptor) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, approvalInterceptorKey{}, fn)
}

// hitlToolCallMiddleware 同时注册 Invokable 与 Streamable。
// Eino filesystem 的 execute 为流式工具（StreamableTool），仅挂 Invokable 时人机协同不会拦截，会直接执行。
// hitlToolCallMiddleware 是统一的工具拦截链（Phase 2b 退役后单链化）：
// 仅保留统一审批管线层。旧 HITL 运行时路径已退役，
// 不再参与裁决；人拒的软结果与 returnDirectly 清理由本层承接（三坑修复保留）。
func hitlToolCallMiddleware() compose.ToolMiddleware {
	return compose.ToolMiddleware{
		Invokable:  approvalInvokableToolCallMiddleware(),
		Streamable: approvalStreamableToolCallMiddleware(),
	}
}

func approvalInvokableToolCallMiddleware() compose.InvokableToolMiddleware {
	return func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
			if input != nil {
				if fn, ok := ctx.Value(approvalInterceptorKey{}).(ApprovalToolInterceptor); ok && fn != nil {
					approvedCtx, frozenArgs, err := fn(ctx, input.Name, input.Arguments)
					if err != nil {
						if IsHumanRejectError(err) {
							// 人拒必须是软工具结果（模型可继续迭代）：
							// - tool_search 拒绝结果须保持 JSON 形状，否则 Eino toolsearch
							//   中间件解析历史时会硬崩 ChatModel；
							// - transfer_to_agent 在 Eino 中 returnDirectly：拒绝时未执行
							//   真实工具，必须清掉该标记，否则监督者直接 END 不再迭代。
							hitlClearReturnDirectlyIfTransfer(ctx, input.Name)
							return &compose.ToolOutput{Result: HitlRejectToolResult(input.Name, err.Error())}, nil
						}
						return nil, err
					}
					if approvedCtx != nil {
						// Grant ctx + ExecutionFinalizer 透传给下游执行。
						ctx = approvedCtx
					}
					if frozenArgs != "" {
						input.Arguments = frozenArgs
					}
				}
			}
			out, err := next(ctx, input)
			if finalizer, ok := approval.ExecutionFinalizerFromContext(ctx); ok {
				result := approval.ExecutionResult{Success: err == nil, CompletedAt: time.Now().UTC()}
				if out != nil {
					result.Summary = out.Result
				}
				if err != nil {
					result.Summary = err.Error()
				}
				if finalizeErr := finalizer(ctx, result); finalizeErr != nil && err == nil {
					return nil, finalizeErr
				}
			}
			return out, err
		}
	}
}

func approvalStreamableToolCallMiddleware() compose.StreamableToolMiddleware {
	return func(next compose.StreamableToolEndpoint) compose.StreamableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.StreamToolOutput, error) {
			if input != nil {
				if fn, ok := ctx.Value(approvalInterceptorKey{}).(ApprovalToolInterceptor); ok && fn != nil {
					approvedCtx, frozenArgs, err := fn(ctx, input.Name, input.Arguments)
					if err != nil {
						if IsHumanRejectError(err) {
							// 与 Invokable 路径相同的三坑处理（见上）。
							hitlClearReturnDirectlyIfTransfer(ctx, input.Name)
							return &compose.StreamToolOutput{
								Result: schema.StreamReaderFromArray([]string{HitlRejectToolResult(input.Name, err.Error())}),
							}, nil
						}
						return nil, err
					}
					if approvedCtx != nil {
						// Grant ctx + ExecutionFinalizer 透传给下游执行。
						ctx = approvedCtx
					}
					if frozenArgs != "" {
						input.Arguments = frozenArgs
					}
				}
			}
			out, err := next(ctx, input)
			finalizer, finalize := approval.ExecutionFinalizerFromContext(ctx)
			if !finalize {
				return out, err
			}
			result := approval.ExecutionResult{Success: err == nil, CompletedAt: time.Now().UTC()}
			if err == nil && out != nil {
				var collectErr error
				result.Summary, collectErr = hitlCollectStringStream(out.Result)
				if collectErr != nil {
					err = collectErr
					result.Success = false
					result.Summary = collectErr.Error()
				} else {
					out.Result = schema.StreamReaderFromArray([]string{result.Summary})
				}
			} else if err != nil {
				result.Summary = err.Error()
			}
			if finalizeErr := finalizer(ctx, result); finalizeErr != nil && err == nil {
				return nil, finalizeErr
			}
			return out, err
		}
	}
}

func hitlClearReturnDirectlyIfTransfer(ctx context.Context, toolName string) {
	if !strings.EqualFold(strings.TrimSpace(toolName), adk.TransferToAgentToolName) {
		return
	}
	_ = compose.ProcessState[*adk.State](ctx, func(_ context.Context, st *adk.State) error {
		if st == nil {
			return nil
		}
		st.ReturnDirectlyToolCallID = ""
		st.HasReturnDirectly = false
		st.ReturnDirectlyEvent = nil
		return nil
	})
}

func hitlCollectStringStream(sr *schema.StreamReader[string]) (string, error) {
	if sr == nil {
		return "", nil
	}
	defer sr.Close()
	var b strings.Builder
	for {
		chunk, err := sr.Recv()
		if errors.Is(err, io.EOF) {
			return b.String(), nil
		}
		if err != nil {
			return b.String(), err
		}
		b.WriteString(chunk)
	}
}
