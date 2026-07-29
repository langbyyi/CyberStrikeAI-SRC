package multiagent

import (
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
}

func NewPendingLedger() *PendingLedger {
	return &PendingLedger{
		pending:    make(map[string]toolCallPendingInfo),
		tombstones: make(map[string]struct{}),
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
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, dropped := l.tombstones[id]; dropped {
		return false
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
