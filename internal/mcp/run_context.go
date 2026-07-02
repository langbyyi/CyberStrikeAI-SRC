package mcp

import (
	"context"
	"strings"
)

// ToolRunRegistry 在工具开始/结束时登记当前 executionId，供对话页「仅终止当前工具」与监控页共用取消逻辑。
type ToolRunRegistry interface {
	RegisterRunningTool(conversationID, executionID string)
	UnregisterRunningTool(conversationID, executionID string)
}

// EinoExecuteRunRegistry 登记进行中的 Eino filesystem execute，供「中断并继续」终止 amass 等长命令。
type EinoExecuteRunRegistry interface {
	RegisterActiveEinoExecute(conversationID string, cancel context.CancelFunc)
	UnregisterActiveEinoExecute(conversationID string)
	AbortActiveEinoExecute(conversationID, note string) bool
	TakeEinoExecuteAbortNote(conversationID string) string
}

type toolRunRegistryCtxKey struct{}
type einoExecuteRunRegistryCtxKey struct{}
type mcpConversationIDCtxKey struct{}

// WithToolRunRegistry 将登记器注入 ctx（Eino / 原生 Agent 任务 ctx）。
func WithToolRunRegistry(ctx context.Context, reg ToolRunRegistry) context.Context {
	if ctx == nil || reg == nil {
		return ctx
	}
	return context.WithValue(ctx, toolRunRegistryCtxKey{}, reg)
}

// ToolRunRegistryFromContext 取出登记器（无则 nil）。
func ToolRunRegistryFromContext(ctx context.Context) ToolRunRegistry {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(toolRunRegistryCtxKey{}).(ToolRunRegistry)
	return v
}

// WithEinoExecuteRunRegistry 将 Eino execute 取消登记器注入 ctx。
func WithEinoExecuteRunRegistry(ctx context.Context, reg EinoExecuteRunRegistry) context.Context {
	if ctx == nil || reg == nil {
		return ctx
	}
	return context.WithValue(ctx, einoExecuteRunRegistryCtxKey{}, reg)
}

// EinoExecuteRunRegistryFromContext 取出 Eino execute 登记器（无则 nil）。
func EinoExecuteRunRegistryFromContext(ctx context.Context) EinoExecuteRunRegistry {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(einoExecuteRunRegistryCtxKey{}).(EinoExecuteRunRegistry)
	return v
}

// WithMCPConversationID 将对话 ID 注入 ctx，供 CallTool 内与 executionId 关联。
func WithMCPConversationID(ctx context.Context, conversationID string) context.Context {
	if ctx == nil {
		return nil
	}
	id := strings.TrimSpace(conversationID)
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, mcpConversationIDCtxKey{}, id)
}

// MCPConversationIDFromContext 读取对话 ID。
func MCPConversationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(mcpConversationIDCtxKey{}).(string)
	return v
}

func notifyToolRunBegin(ctx context.Context, executionID string) {
	reg := ToolRunRegistryFromContext(ctx)
	if reg == nil {
		return
	}
	conv := MCPConversationIDFromContext(ctx)
	if conv == "" || strings.TrimSpace(executionID) == "" {
		return
	}
	reg.RegisterRunningTool(conv, executionID)
}

func notifyToolRunEnd(ctx context.Context, executionID string) {
	reg := ToolRunRegistryFromContext(ctx)
	if reg == nil {
		return
	}
	conv := MCPConversationIDFromContext(ctx)
	if conv == "" || strings.TrimSpace(executionID) == "" {
		return
	}
	reg.UnregisterRunningTool(conv, executionID)
}
