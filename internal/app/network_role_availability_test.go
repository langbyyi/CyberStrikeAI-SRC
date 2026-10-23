package app

import (
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/network"
	"go.uber.org/zap"
)

func TestBundledRolesExposeNetworkToolsToAgentDiscovery(t *testing.T) {
	roles, err := config.LoadRolesFromDir("../../roles")
	if err != nil || len(roles) == 0 {
		t.Fatalf("load bundled roles: %v", err)
	}
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server := mcp.NewServer(zap.NewNop())
	registerNetworkTools(server, s, nil, nil)
	ag := agent.NewAgent(&config.OpenAIConfig{}, nil, server, nil, zap.NewNop(), 1)
	networkNames := []string{builtin.ToolNetworkStatus, builtin.ToolNetworkDiagnose, builtin.ToolNetworkAcquire, builtin.ToolNetworkRelease, builtin.ToolNetworkBindAsset, builtin.ToolNetworkSyncSource}
	for name, role := range roles {
		if !role.Enabled {
			continue
		}
		t.Run(name, func(t *testing.T) {
			available := map[string]bool{}
			for _, tool := range ag.ToolsForRole(role.Tools) {
				available[tool.Function.Name] = true
			}
			for _, name := range networkNames {
				if !available[name] {
					t.Errorf("bundled role cannot discover %s", name)
				}
			}
		})
	}
	// Custom role restrictions and tool-search pinning remain administrator choices.
	if tools := ag.ToolsForRole([]string{"exec"}); len(tools) != 0 {
		t.Fatal("custom role restriction was bypassed")
	}
}
