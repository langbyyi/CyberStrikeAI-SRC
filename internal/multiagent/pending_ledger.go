package multiagent

import (
	"sort"
	"strings"
	"sync"
)

// PendingLedger is the single lifecycle authority for one ADK run's tool
// calls. Tombstones make drop/resolve-before-register safe when middleware and
// streamed runner events arrive in different orders.
type PendingLedger struct {
	mu         sync.Mutex
	pending    map[string]toolCallPendingInfo
	tombstones map[string]struct{}
	byAgent    map[string][]string
}

func NewPendingLedger() *PendingLedger {
	return &PendingLedger{
		pending:    make(map[string]toolCallPendingInfo),
		tombstones: make(map[string]struct{}),
		byAgent:    make(map[string][]string),
	}
}

func (l *PendingLedger) Register(call toolCallPendingInfo) bool {
	if l == nil {
		return false
	}
	id := strings.TrimSpace(call.ToolCallID)
	if id == "" {
		return false
	}
	call.ToolCallID = id
	call.EinoAgent = strings.TrimSpace(call.EinoAgent)
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, dropped := l.tombstones[id]; dropped {
		return false
	}
	if _, exists := l.pending[id]; !exists {
		l.byAgent[call.EinoAgent] = append(l.byAgent[call.EinoAgent], id)
	}
	l.pending[id] = call
	return true
}

func (l *PendingLedger) Resolve(callID string) bool {
	if l == nil {
		return false
	}
	callID = strings.TrimSpace(callID)
	if callID == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, existed := l.pending[callID]
	delete(l.pending, callID)
	l.tombstones[callID] = struct{}{}
	return existed
}

func (l *PendingLedger) Drop(call toolCallPendingInfo) bool {
	return l.Resolve(call.ToolCallID)
}

func (l *PendingLedger) Flush() []toolCallPendingInfo {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]toolCallPendingInfo, 0, len(l.pending))
	for id, call := range l.pending {
		out = append(out, call)
		l.tombstones[id] = struct{}{}
	}
	l.pending = make(map[string]toolCallPendingInfo)
	l.byAgent = make(map[string][]string)
	return out
}

func (l *PendingLedger) Count() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending)
}

func (l *PendingLedger) Snapshot() []toolCallPendingInfo {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]toolCallPendingInfo, 0, len(l.pending))
	for _, call := range l.pending {
		out = append(out, call)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ToolCallID < out[j].ToolCallID
	})
	return out
}

func (l *PendingLedger) PopNext(agentName string) (toolCallPendingInfo, bool) {
	if l == nil {
		return toolCallPendingInfo{}, false
	}
	agentName = strings.TrimSpace(agentName)
	l.mu.Lock()
	defer l.mu.Unlock()
	queue := l.byAgent[agentName]
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		l.byAgent[agentName] = queue
		call, ok := l.pending[id]
		if !ok {
			continue
		}
		delete(l.pending, id)
		l.tombstones[id] = struct{}{}
		return call, true
	}
	delete(l.byAgent, agentName)
	return toolCallPendingInfo{}, false
}

func (l *PendingLedger) PopAny() (toolCallPendingInfo, bool) {
	if l == nil {
		return toolCallPendingInfo{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, call := range l.pending {
		delete(l.pending, id)
		l.tombstones[id] = struct{}{}
		return call, true
	}
	return toolCallPendingInfo{}, false
}

func (l *PendingLedger) ResolveAgent(agentName string) []toolCallPendingInfo {
	if l == nil {
		return nil
	}
	agentName = strings.TrimSpace(agentName)
	l.mu.Lock()
	defer l.mu.Unlock()
	queue := l.byAgent[agentName]
	delete(l.byAgent, agentName)
	resolved := make([]toolCallPendingInfo, 0, len(queue))
	for _, id := range queue {
		call, ok := l.pending[id]
		if !ok {
			continue
		}
		delete(l.pending, id)
		l.tombstones[id] = struct{}{}
		resolved = append(resolved, call)
	}
	return resolved
}
