package multiagent

import (
	"context"
	"fmt"
	"reflect"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
)

// mutateADKReactState 更新 ChatModelAgent 的 react state，不关心实时图里存放的是
// typedState[*schema.Message] 还是 typedState[*schema.AgenticMessage]。
// Eino v0.9.14 只导出针对经典 Message state 的 adk.SendToolGenAction，
// 直接用 compose.ProcessState[*adk.State] 在 Agentic 主路径上会静默取不到 state。
func mutateADKReactState(ctx context.Context, mutate func(st reflect.Value) error) error {
	if mutate == nil {
		return fmt.Errorf("adk react state mutate is nil")
	}
	return compose.ProcessState(ctx, func(_ context.Context, st any) error {
		if st == nil {
			return fmt.Errorf("adk react state is nil")
		}
		v := reflect.ValueOf(st)
		if v.Kind() != reflect.Pointer || v.IsNil() {
			return fmt.Errorf("unexpected adk react state type %T", st)
		}
		return mutate(v.Elem())
	})
}

// sendADKToolGenAction 等价于 eino 的 adk.SendToolGenAction，但写的是实时图里的
// react state（经典 Message 或 AgenticMessage 都能命中）。
// Eino v0.9.14 的官方工具（transfer_to_agent 等）只导出经典 state 版本，
// 在 Agentic 主路径上调用会因类型不匹配而失败。
func sendADKToolGenAction(ctx context.Context, toolName string, action *adk.AgentAction) error {
	if action == nil {
		return fmt.Errorf("adk tool gen action is nil")
	}
	key := toolName
	if toolCallID := compose.GetToolCallID(ctx); toolCallID != "" {
		key = toolCallID
	}
	return mutateADKReactState(ctx, func(st reflect.Value) error {
		field := st.FieldByName("ToolGenActions")
		if !field.IsValid() || field.Kind() != reflect.Map {
			return fmt.Errorf("adk react state missing ToolGenActions")
		}
		if !field.CanSet() {
			return fmt.Errorf("cannot set ToolGenActions on adk react state")
		}
		if field.IsNil() {
			field.Set(reflect.MakeMap(field.Type()))
		}
		field.SetMapIndex(reflect.ValueOf(key), reflect.ValueOf(action))
		return nil
	})
}

// clearADKReturnDirectly 清空 returnDirectly 相关字段（HITL 拒绝 transfer 时用）。
func clearADKReturnDirectly(ctx context.Context) error {
	return mutateADKReactState(ctx, func(st reflect.Value) error {
		zeroExportedField(st, "ReturnDirectlyToolCallID")
		zeroExportedField(st, "HasReturnDirectly")
		zeroExportedField(st, "ReturnDirectlyEvent")
		return nil
	})
}

func zeroExportedField(st reflect.Value, name string) {
	field := st.FieldByName(name)
	if !field.IsValid() || !field.CanSet() {
		return
	}
	field.Set(reflect.Zero(field.Type()))
}
