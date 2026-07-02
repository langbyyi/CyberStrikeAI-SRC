package multiagent

import "strings"

// MCPExecutionBinder maps ADK toolCallID → MCP monitor execution ID for a single agent run.
type MCPExecutionBinder struct {
	byToolCall map[string]string
}

func NewMCPExecutionBinder() *MCPExecutionBinder {
	return &MCPExecutionBinder{byToolCall: make(map[string]string)}
}

func (b *MCPExecutionBinder) Bind(toolCallID, executionID string) {
	if b == nil {
		return
	}
	tid := strings.TrimSpace(toolCallID)
	eid := strings.TrimSpace(executionID)
	if tid == "" || eid == "" {
		return
	}
	b.byToolCall[tid] = eid
}

func (b *MCPExecutionBinder) ExecutionID(toolCallID string) string {
	if b == nil {
		return ""
	}
	return b.byToolCall[strings.TrimSpace(toolCallID)]
}
