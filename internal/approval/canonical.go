package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

type invocationHashPayload struct {
	InvocationID    string   `json:"invocationId"`
	Source          string   `json:"source,omitempty"`
	RequesterUserID string   `json:"requesterUserId"`
	ConversationID  string   `json:"conversationId,omitempty"`
	ProjectID       string   `json:"projectId,omitempty"`
	ToolName        string   `json:"toolName"`
	ToolCallID      string   `json:"toolCallId,omitempty"`
	Arguments       string   `json:"canonicalArguments"`
	PolicyIDs       []string `json:"policyIds"`
}

// CanonicalArguments returns stable JSON for JSON-compatible tool arguments.
// Tool argument maps originate from JSON schemas, so unsupported Go values are
// represented by an empty string and must be rejected by the Coordinator.
func CanonicalArguments(arguments map[string]any) string {
	if arguments == nil {
		arguments = map[string]any{}
	}
	raw, err := json.Marshal(arguments)
	if err != nil {
		return ""
	}
	return string(raw)
}

// InvocationHash binds a grant to one concrete invocation and the exact policy
// identifiers used to assess it.
func InvocationHash(inv Invocation, policyIDs []string) string {
	payload := invocationHashPayload{
		InvocationID:    inv.ID,
		Source:          inv.Source,
		RequesterUserID: inv.RequesterUserID,
		ConversationID:  inv.ConversationID,
		ProjectID:       inv.ProjectID,
		ToolName:        inv.ToolName,
		ToolCallID:      inv.ToolCallID,
		Arguments:       CanonicalArguments(inv.Arguments),
		PolicyIDs:       sortedUnique(policyIDs),
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
