package approval

import "time"

func riskRank(risk string) int {
	switch risk {
	case RiskProhibited:
		return 5
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	case RiskLow:
		return 1
	default:
		return 0
	}
}

const (
	RiskNone       = "none"
	RiskLow        = "low"
	RiskMedium     = "medium"
	RiskHigh       = "high"
	RiskCritical   = "critical"
	RiskProhibited = "prohibited"
)

// Invocation is the immutable approval subject produced by an execution Adapter.
// ID identifies one concrete attempt; a later identical call must use a new ID.
type Invocation struct {
	ID                 string
	Source             string
	ConversationID     string
	AssistantMessageID string
	ProjectID          string
	RequesterUserID    string
	ToolName           string
	ToolCallID         string
	Arguments          map[string]any
}

type Assessment struct {
	RequiresApproval bool             `json:"requiresApproval"`
	TriggerSources   []string         `json:"triggerSources,omitempty"`
	TriggerFindings  []TriggerFinding `json:"triggerFindings,omitempty"`
	RiskLevel        string           `json:"riskLevel"`
	PolicyIDs        []string         `json:"policyIds,omitempty"`
}

type ExecutionResult struct {
	ExecutionID string
	Success     bool
	Summary     string
	CompletedAt time.Time
}
