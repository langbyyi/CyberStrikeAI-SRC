package approval

import "strings"

const (
	ReviewerHuman = "human"
	ReviewerAgent = "agent"

	PolicyTypeToolApproval    = "tool_approval"
	PolicyTypeDangerousAction = "dangerous_action"
)

// TriggerConfig controls one source that can require the shared approval flow.
type TriggerConfig struct {
	Enabled       bool     `json:"enabled"`
	ToolWhitelist []string `json:"toolWhitelist,omitempty"`
}

// Config is the single deployment-wide approval contract.
type Config struct {
	Reviewer        string        `json:"reviewer"`
	TimeoutSeconds  int           `json:"timeoutSeconds"`
	ToolApproval    TriggerConfig `json:"toolApproval"`
	DangerousAction TriggerConfig `json:"dangerousAction"`
}

func NormalizeConfig(input Config) Config {
	switch strings.ToLower(strings.TrimSpace(input.Reviewer)) {
	case ReviewerAgent, "audit_agent", "ai":
		input.Reviewer = ReviewerAgent
	default:
		input.Reviewer = ReviewerHuman
	}
	if input.TimeoutSeconds <= 0 {
		input.TimeoutSeconds = 300
	}
	tools := make([]string, 0, len(input.ToolApproval.ToolWhitelist))
	for _, tool := range input.ToolApproval.ToolWhitelist {
		if normalized := strings.ToLower(strings.TrimSpace(tool)); normalized != "" {
			tools = append(tools, normalized)
		}
	}
	input.ToolApproval.ToolWhitelist = sortedUnique(tools)
	return input
}
