package multiagent

import (
	"encoding/json"
	"strings"
	"context"
	"testing"

	"cyberstrike-ai/internal/approval"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

type approvalContextMarker struct{}

func TestApprovalMiddlewareInvokablePassesGrantContextAndFrozenArguments(t *testing.T) {
	ctx := WithApprovalToolInterceptor(context.Background(), func(ctx context.Context, _ string, _ string) (context.Context, string, error) {
		return context.WithValue(ctx, approvalContextMarker{}, "grant"), `{"command":"frozen"}`, nil
	})
	var calls int
	next := compose.InvokableToolEndpoint(func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
		calls++
		if ctx.Value(approvalContextMarker{}) != "grant" {
			t.Fatal("approved context did not reach tool")
		}
		if input.Arguments != `{"command":"frozen"}` {
			t.Fatalf("arguments = %s", input.Arguments)
		}
		return &compose.ToolOutput{Result: "ok"}, nil
	})
	out, err := approvalInvokableToolCallMiddleware()(next)(ctx, &compose.ToolInput{Name: "exec", Arguments: `{"command":"original"}`})
	if err != nil || out == nil || out.Result != "ok" || calls != 1 {
		t.Fatalf("out=%+v err=%v calls=%d", out, err, calls)
	}
}

func TestApprovalMiddlewareStreamablePassesGrantContextOnce(t *testing.T) {
	ctx := WithApprovalToolInterceptor(context.Background(), func(ctx context.Context, _ string, args string) (context.Context, string, error) {
		return context.WithValue(ctx, approvalContextMarker{}, "grant"), args, nil
	})
	var calls int
	next := compose.StreamableToolEndpoint(func(ctx context.Context, _ *compose.ToolInput) (*compose.StreamToolOutput, error) {
		calls++
		if ctx.Value(approvalContextMarker{}) != "grant" {
			t.Fatal("approved context did not reach streamable tool")
		}
		return &compose.StreamToolOutput{Result: schema.StreamReaderFromArray([]string{"ok"})}, nil
	})
	out, err := approvalStreamableToolCallMiddleware()(next)(ctx, &compose.ToolInput{Name: "execute", Arguments: `{}`})
	if err != nil || out == nil || calls != 1 {
		t.Fatalf("out=%+v err=%v calls=%d", out, err, calls)
	}
	result, err := hitlCollectStringStream(out.Result)
	if err != nil || result != "ok" {
		t.Fatalf("result=%q err=%v", result, err)
	}
}

func TestApprovalMiddlewareFinalizesInvokableExecution(t *testing.T) {
	var finalized int
	ctx := WithApprovalToolInterceptor(context.Background(), func(ctx context.Context, _ string, args string) (context.Context, string, error) {
		ctx = approval.WithExecutionFinalizer(ctx, func(_ context.Context, result approval.ExecutionResult) error {
			finalized++
			if !result.Success {
				t.Fatalf("execution result = %+v", result)
			}
			return nil
		})
		return ctx, args, nil
	})
	next := compose.InvokableToolEndpoint(func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
		return &compose.ToolOutput{Result: "ok"}, nil
	})
	if _, err := approvalInvokableToolCallMiddleware()(next)(ctx, &compose.ToolInput{Name: "exec", Arguments: `{}`}); err != nil {
		t.Fatal(err)
	}
	if finalized != 1 {
		t.Fatalf("finalized = %d", finalized)
	}
}

// TestHumanRejectProducesSoftResult 是 eino 三坑回归（Phase 8）：
// 统一审批层的人拒必须是软工具结果——tool_search 保持 JSON 形状
// （坑：toolsearch 中间件解析历史会硬崩 ChatModel）；transfer_to_agent
// 拒绝时清除 returnDirectly（坑：监督者会直接 END 不再迭代）。
// Streamable 与 Invokable 双挂（坑：仅挂 Invokable 时流式工具漏拦直接执行）。
func TestHumanRejectProducesSoftJSONResultForToolSearch(t *testing.T) {
	ctx := WithApprovalToolInterceptor(context.Background(), func(context.Context, string, string) (context.Context, string, error) {
		return nil, "", NewHumanRejectError("操作被人工拒绝")
	})
	next := compose.InvokableToolEndpoint(func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
		t.Fatal("next must not be reached after rejection")
		return nil, nil
	})
	out, err := hitlToolCallMiddleware().Invokable(next)(ctx, &compose.ToolInput{Name: "tool_search", Arguments: `{}`})
	if err != nil {
		t.Fatalf("rejection must be a soft tool result, got error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(out.Result), &payload); err != nil {
		t.Fatalf("tool_search rejection must stay JSON-shaped, got %q", out.Result)
	}
	if payload["_hitlRejected"] != true {
		t.Fatalf("rejection payload must be marked, got %v", payload)
	}
}

func TestHumanRejectProducesSoftResultForTransferAndStreamable(t *testing.T) {
	ctx := WithApprovalToolInterceptor(context.Background(), func(context.Context, string, string) (context.Context, string, error) {
		return nil, "", NewHumanRejectError("操作被人工拒绝")
	})
	next := compose.InvokableToolEndpoint(func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
		t.Fatal("next must not be reached after rejection")
		return nil, nil
	})
	// transfer_to_agent：拒绝必须软结果且不 panic（returnDirectly 清理在无图 state 时安全空转）。
	out, err := hitlToolCallMiddleware().Invokable(next)(ctx, &compose.ToolInput{Name: "transfer_to_agent", Arguments: `{}`})
	if err != nil || out == nil || strings.TrimSpace(out.Result) == "" {
		t.Fatalf("transfer rejection must be soft result, err=%v result=%+v", err, out)
	}
	// Streamable 双挂回归：流式工具同样被拦截。
	snext := compose.StreamableToolEndpoint(func(context.Context, *compose.ToolInput) (*compose.StreamToolOutput, error) {
		t.Fatal("streamable next must not be reached after rejection")
		return nil, nil
	})
	sout, err := hitlToolCallMiddleware().Streamable(snext)(ctx, &compose.ToolInput{Name: "tool_search", Arguments: `{}`})
	if err != nil {
		t.Fatalf("streamable rejection must be soft, err=%v", err)
	}
	chunk, serr := sout.Result.Recv()
	if serr != nil || chunk == "" {
		t.Fatalf("streamable soft result must carry the rejection payload, err=%v", serr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(chunk), &payload); err != nil || payload["_hitlRejected"] != true {
		t.Fatalf("streamable tool_search rejection must stay JSON-shaped, got %q", chunk)
	}
}

