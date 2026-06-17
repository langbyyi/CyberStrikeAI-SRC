package einomcp

import "sync"

// ToolInvokeNotifyHolder 由 Eino run loop 在迭代开始前 Set 回调；MCP 桥在每次 InvokableRun 结束时 Fire，
// 用于在 ADK 未透出 schema.Tool 事件时仍推送 tool_result、清 pending，避免 UI 卡在「执行中」或迭代末 force-close。
type ToolInvokeNotifyHolder struct {
	mu sync.RWMutex
	fn func(toolCallID, toolName, einoAgent string, success bool, content string, invokeErr error)
}

// NewToolInvokeNotifyHolder 创建可在 ToolsFromDefinitions 与 run loop 之间共享的 holder。
func NewToolInvokeNotifyHolder() *ToolInvokeNotifyHolder {
	return &ToolInvokeNotifyHolder{}
}

// Set 由 runEinoADKAgentLoop 在开始消费 iter 之前调用；可多次覆盖（通常仅一次）。
func (h *ToolInvokeNotifyHolder) Set(fn func(toolCallID, toolName, einoAgent string, success bool, content string, invokeErr error)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fn = fn
}

// Fire 由 mcpBridgeTool 在工具调用返回时调用；若尚未 Set 或 toolCallID 为空则忽略。
func (h *ToolInvokeNotifyHolder) Fire(toolCallID, toolName, einoAgent string, success bool, content string, invokeErr error) {
	if h == nil {
		return
	}
	h.mu.RLock()
	fn := h.fn
	h.mu.RUnlock()
	if fn == nil {
		return
	}
	fn(toolCallID, toolName, einoAgent, success, content, invokeErr)
}
