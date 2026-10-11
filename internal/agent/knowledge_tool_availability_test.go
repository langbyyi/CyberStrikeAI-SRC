package agent

import (
	"cyberstrike-ai/internal/knowledge"
	"cyberstrike-ai/internal/mcp/builtin"
	"go.uber.org/zap"
	"testing"
)

func TestRegisteredKnowledgeToolsAreAvailableToDefaultAndSelectedRoles(t *testing.T) {
	a := setupTestAgent(t)
	knowledge.RegisterKnowledgeTool(a.mcpServer, nil, nil, zap.NewNop())
	for _, role := range [][]string{nil, {builtin.ToolSearchKnowledgeBase, builtin.ToolListKnowledgeRiskTypes}} {
		available := map[string]bool{}
		for _, tool := range a.ToolsForRole(role) {
			available[tool.Function.Name] = true
		}
		for _, name := range []string{builtin.ToolSearchKnowledgeBase, builtin.ToolListKnowledgeRiskTypes} {
			if !available[name] {
				t.Errorf("registered tool %s unavailable to role %v", name, role)
			}
		}
	}
	// Explicit role restrictions remain effective.
	for _, tool := range a.ToolsForRole([]string{builtin.ToolListKnowledgeRiskTypes}) {
		if tool.Function.Name == builtin.ToolSearchKnowledgeBase {
			t.Fatal("role restriction bypassed")
		}
	}
}
