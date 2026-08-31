package approval

import (
	"context"
	"errors"
	"time"
)

const (
	StatusPendingAgent = "pending_agent"
	StatusPendingHuman = "pending_human"
	StatusApproved     = "approved"
	StatusRejected     = "rejected"
	StatusExpired      = "expired"
	StatusCancelled    = "cancelled"
	StatusExecuting    = "executing"
	StatusSucceeded    = "succeeded"
	StatusFailed       = "failed"
)

const (
	StageAgentReview = "agent_review"
	StageHumanReview = "human_review"
	StageApproved    = "approved"
	StageExecution   = "execution"
	StageTerminal    = "terminal"
)

var (
	ErrNotFound          = errors.New("approval request not found")
	ErrStateConflict     = errors.New("approval state conflict")
	ErrInvalidTransition = errors.New("invalid approval state transition")
)

type Request struct {
	ID               string           `json:"id"`
	InvocationID     string           `json:"invocationId"`
	InvocationHash   string           `json:"invocationHash"`
	Source           string           `json:"source"`
	ConversationID   string           `json:"conversationId"`
	MessageID        string           `json:"messageId"`
	ProjectID        string           `json:"projectId"`
	RequesterUserID  string           `json:"requesterUserId"`
	ToolName         string           `json:"toolName"`
	ToolCallID       string           `json:"toolCallId"`
	Arguments        map[string]any   `json:"arguments"`
	RiskLevel        string           `json:"riskLevel"`
	TriggerSources   []string         `json:"triggerSources"`
	MatchedPolicies  []string         `json:"matchedPolicies"`
	Reviewer         string           `json:"reviewer"`
	Stage            string           `json:"stage"`
	Status           string           `json:"status"`
	ExpiresAt        *time.Time       `json:"expiresAt,omitempty"`
	ExecutionID      string           `json:"executionId,omitempty"`
	ExecutionSummary string           `json:"executionSummary,omitempty"`
	Decisions        []DecisionRecord `json:"decisions,omitempty"`
	CreatedAt        time.Time        `json:"createdAt"`
	UpdatedAt        time.Time        `json:"updatedAt"`
}

type DecisionRecord struct {
	ID         string         `json:"id"`
	ApprovalID string         `json:"approvalId"`
	Stage      string         `json:"stage"`
	ActorType  string         `json:"actorType"`
	ActorID    string         `json:"actorId"`
	Decision   string         `json:"decision"`
	Comment    string         `json:"comment"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  time.Time      `json:"createdAt"`
}

type ListFilter struct {
	ConversationID  string
	ProjectID       string
	RequesterUserID string
	Status          string
	TerminalOnly    bool
	Query           string
	Decision        string
	ActorType       string
	Limit           int
	Offset          int
}

type Store interface {
	EnsureSchema(context.Context) error
	CreateRequest(context.Context, *Request) error
	GetRequest(context.Context, string) (*Request, error)
	AppendDecision(context.Context, DecisionRecord) error
	RecordDecision(context.Context, DecisionRecord, string, string, string) error
	Claim(context.Context, string, string) error
	Complete(context.Context, string, ExecutionResult) error
	List(context.Context, ListFilter) ([]*Request, error)
	CancelUnrecoverable(context.Context, time.Time) (int64, error)
}

func CanTransition(from, to string) bool {
	switch from {
	case StatusPendingAgent:
		return to == StatusApproved || to == StatusRejected || to == StatusPendingHuman || to == StatusExpired || to == StatusCancelled
	case StatusPendingHuman:
		return to == StatusApproved || to == StatusRejected || to == StatusExpired || to == StatusCancelled
	case StatusApproved:
		return to == StatusExecuting || to == StatusCancelled
	case StatusExecuting:
		return to == StatusSucceeded || to == StatusFailed
	default:
		return false
	}
}
