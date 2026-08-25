package multiagent

import (
	"fmt"
	"strings"
	"sync"
)

type einoPendingToolCalls struct {
	conversationID string
	progress       func(eventType, message string, data interface{})

	mu           sync.Mutex
	byID         map[string]toolCallPendingInfo
	queueByAgent map[string][]string
}

func newEinoPendingToolCalls(conversationID string, progress func(eventType, message string, data interface{})) *einoPendingToolCalls {
	return &einoPendingToolCalls{
		conversationID: conversationID,
		progress:       progress,
		byID:           make(map[string]toolCallPendingInfo),
		queueByAgent:   make(map[string][]string),
	}
}

func (p *einoPendingToolCalls) Mark(tc toolCallPendingInfo) {
	if p == nil || strings.TrimSpace(tc.ToolCallID) == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byID[tc.ToolCallID] = tc
	p.queueByAgent[tc.EinoAgent] = append(p.queueByAgent[tc.EinoAgent], tc.ToolCallID)
}

func (p *einoPendingToolCalls) PopNextForAgent(agentName string) (toolCallPendingInfo, bool) {
	if p == nil {
		return toolCallPendingInfo{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	q := p.queueByAgent[agentName]
	for len(q) > 0 {
		id := q[0]
		q = q[1:]
		p.queueByAgent[agentName] = q
		if tc, ok := p.byID[id]; ok {
			delete(p.byID, id)
			return tc, true
		}
	}
	return toolCallPendingInfo{}, false
}

func (p *einoPendingToolCalls) RemoveByID(toolCallID string) {
	if p == nil || strings.TrimSpace(toolCallID) == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.byID, toolCallID)
}

func (p *einoPendingToolCalls) PopAny() (toolCallPendingInfo, bool) {
	if p == nil {
		return toolCallPendingInfo{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, tc := range p.byID {
		delete(p.byID, id)
		return tc, true
	}
	return toolCallPendingInfo{}, false
}

// ExtractDelivered 移除并返回「结果已实际送达模型」的 pending 项。
// 未知工具（compose UnknownToolsHandler）等路径的结果不产生 ADK 工具事件，
// 只出现在模型侧轨迹里；这些项不应被误判为孤儿并强制关闭。
func (p *einoPendingToolCalls) ExtractDelivered(delivered map[string]string) []toolCallPendingInfo {
	if p == nil || len(delivered) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []toolCallPendingInfo
	for id, tc := range p.byID {
		if _, ok := delivered[id]; !ok {
			continue
		}
		delete(p.byID, id)
		out = append(out, tc)
	}
	return out
}

func (p *einoPendingToolCalls) Count() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byID)
}

func (p *einoPendingToolCalls) FlushAsFailed(err error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	pendingSnapshot := make([]toolCallPendingInfo, 0, len(p.byID))
	for _, tc := range p.byID {
		pendingSnapshot = append(pendingSnapshot, tc)
	}
	p.byID = make(map[string]toolCallPendingInfo)
	p.queueByAgent = make(map[string][]string)
	p.mu.Unlock()

	if p.progress == nil {
		return
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	for _, tc := range pendingSnapshot {
		toolName := tc.ToolName
		if strings.TrimSpace(toolName) == "" {
			toolName = "unknown"
		}
		p.progress("tool_result", fmt.Sprintf("工具结果 (%s)", toolName), map[string]interface{}{
			"toolName":       toolName,
			"success":        false,
			"isError":        true,
			"result":         msg,
			"resultPreview":  msg,
			"toolCallId":     tc.ToolCallID,
			"conversationId": p.conversationID,
			"einoAgent":      tc.EinoAgent,
			"einoRole":       tc.EinoRole,
			"source":         "eino",
		})
	}
}
