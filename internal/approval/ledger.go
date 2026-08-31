package approval

import (
	"context"
	"errors"
	"strings"
	"time"
)

// LedgerEventTypes 是台账事件类型：decision（裁决时一次）与 execution
// （执行终态时一次），以 invocation_id 关联。台账是 append-only 的：
// 代码中不存在任何 UPDATE/DELETE 路径；保留期清理（如配置 retention）
// 是唯一允许的删除来源。
const (
	LedgerEventDecision  = "decision"
	LedgerEventExecution = "execution"
)

// EnforcementDecision 描述最终强制结果：调用是否被执行。
const (
	EnforcementAllow = "allow"
	EnforcementDeny  = "deny"
)

// LedgerEvent 是一条不可变台账记录。decision 事件记录裁决全貌
// （类别、命中规则、策略版本、裁决者），execution 事件记录真实执行结果。
type LedgerEvent struct {
	ID              string    `json:"id"`
	EventType       string    `json:"eventType"`
	InvocationID    string    `json:"invocationId"`
	ApprovalID      string    `json:"approvalId,omitempty"`
	Source          string    `json:"source,omitempty"`
	ConversationID  string    `json:"conversationId,omitempty"`
	ProjectID       string    `json:"projectId,omitempty"`
	RequesterUserID string    `json:"requesterUserId,omitempty"`
	ToolName        string    `json:"toolName,omitempty"`
	ToolCallID      string    `json:"toolCallId,omitempty"`
	Enforcement     string    `json:"enforcement,omitempty"`
	Reviewer        string    `json:"reviewer,omitempty"`
	RiskLevel       string    `json:"riskLevel,omitempty"`
	ArgsHash        string    `json:"argsHash,omitempty"`
	ActorType       string    `json:"actorType,omitempty"`
	ActorID         string    `json:"actorId,omitempty"`
	MatchedRules    []string  `json:"matchedRules,omitempty"`
	Comment         string    `json:"comment,omitempty"`
	Success         *bool     `json:"success,omitempty"`
	Summary         string    `json:"summary,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
}

// LedgerFilter 是台账查询过滤条件。
type LedgerFilter struct {
	InvocationID string
	From         *time.Time
	To           *time.Time
	Limit        int
}

// Ledger 是决策台账的存储契约。实现必须保证 append 语义：
// Append 只插入，不更新既有行。
type Ledger interface {
	Append(ctx context.Context, event LedgerEvent) error
	ListByInvocation(ctx context.Context, invocationID string) ([]LedgerEvent, error)
	ListRecent(ctx context.Context, limit int) ([]LedgerEvent, error)
	ListFiltered(ctx context.Context, filter LedgerFilter) ([]LedgerEvent, error)
}

// MemoryLedger 是进程内台账实现（测试与无持久化场景）。
type MemoryLedger struct {
	events []LedgerEvent
}

func NewMemoryLedger() *MemoryLedger { return &MemoryLedger{} }

func (l *MemoryLedger) Append(_ context.Context, event LedgerEvent) error {
	if l == nil {
		return errors.New("ledger is nil")
	}
	if strings.TrimSpace(event.ID) == "" || strings.TrimSpace(event.EventType) == "" ||
		strings.TrimSpace(event.InvocationID) == "" {
		return errors.New("ledger event requires id, event type and invocation id")
	}
	l.events = append(l.events, event)
	return nil
}

func (l *MemoryLedger) ListByInvocation(_ context.Context, invocationID string) ([]LedgerEvent, error) {
	if l == nil {
		return nil, nil
	}
	out := make([]LedgerEvent, 0)
	for _, event := range l.events {
		if event.InvocationID == invocationID {
			out = append(out, event)
		}
	}
	return out, nil
}

func (l *MemoryLedger) ListFiltered(_ context.Context, filter LedgerFilter) ([]LedgerEvent, error) {
	if l == nil {
		return nil, nil
	}
	matched := make([]LedgerEvent, 0)
	for i := len(l.events) - 1; i >= 0; i-- {
		event := l.events[i]
		if filter.InvocationID != "" && event.InvocationID != filter.InvocationID {
			continue
		}
		if filter.From != nil && event.CreatedAt.Before(*filter.From) {
			continue
		}
		if filter.To != nil && event.CreatedAt.After(*filter.To) {
			continue
		}
		matched = append(matched, event)
		if filter.Limit > 0 && len(matched) >= filter.Limit {
			break
		}
	}
	return matched, nil
}

func (l *MemoryLedger) ListRecent(_ context.Context, limit int) ([]LedgerEvent, error) {
	if l == nil {
		return nil, nil
	}
	if limit <= 0 || limit > len(l.events) {
		limit = len(l.events)
	}
	out := make([]LedgerEvent, 0, limit)
	for i := len(l.events) - limit; i < len(l.events); i++ {
		out = append(out, l.events[i])
	}
	return out, nil
}
