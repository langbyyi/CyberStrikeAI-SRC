package multiagent

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
)

// agenticShapedReactState 复刻 typedState[*schema.AgenticMessage] 的导出字段形状：
// 与经典 *adk.State 类型不同，但字段名一致（反射 helper 必须两者都能改）。
type agenticShapedReactState struct {
	HasReturnDirectly        bool
	ReturnDirectlyToolCallID string
	ReturnDirectlyEvent      any
	ToolGenActions           map[string]*adk.AgentAction
}

func TestClearADKReturnDirectlyZerosClassicState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chain := compose.NewChain[string, string](compose.WithGenLocalState(func(context.Context) *adk.State {
		return &adk.State{HasReturnDirectly: true, ReturnDirectlyToolCallID: "call-1"}
	}))
	chain.AppendLambda(compose.InvokableLambda(func(ctx context.Context, in string) (string, error) {
		if err := clearADKReturnDirectly(ctx); err != nil {
			return "", err
		}
		return in, compose.ProcessState(ctx, func(_ context.Context, st *adk.State) error {
			if st.HasReturnDirectly || st.ReturnDirectlyToolCallID != "" || st.ReturnDirectlyEvent != nil {
				return errors.New("return-directly fields were not cleared")
			}
			return nil
		})
	}))
	r, err := chain.Compile(ctx)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := r.Invoke(ctx, "ok"); err != nil {
		t.Fatalf("invoke: %v", err)
	}
}

func TestClearADKReturnDirectlyZerosAgenticShapedState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chain := compose.NewChain[string, string](compose.WithGenLocalState(func(context.Context) *agenticShapedReactState {
		return &agenticShapedReactState{HasReturnDirectly: true, ReturnDirectlyToolCallID: "call-1"}
	}))
	chain.AppendLambda(compose.InvokableLambda(func(ctx context.Context, in string) (string, error) {
		if err := clearADKReturnDirectly(ctx); err != nil {
			return "", err
		}
		return in, compose.ProcessState(ctx, func(_ context.Context, st *agenticShapedReactState) error {
			if st.HasReturnDirectly || st.ReturnDirectlyToolCallID != "" || st.ReturnDirectlyEvent != nil {
				return errors.New("return-directly fields were not cleared")
			}
			return nil
		})
	}))
	r, err := chain.Compile(ctx)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := r.Invoke(ctx, "ok"); err != nil {
		t.Fatalf("invoke: %v", err)
	}
}
