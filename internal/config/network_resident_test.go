package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"cyberstrike-ai/internal/mcp/builtin"
	"gopkg.in/yaml.v3"
)

func TestNetworkToolsDefaultToConfigurableResidentWhitelist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("multi_agent:\n  eino_middleware:\n    tool_search_always_visible_tools: [exec]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{builtin.ToolNetworkStatus, builtin.ToolNetworkDiagnose, builtin.ToolNetworkAcquire, builtin.ToolNetworkRelease, builtin.ToolNetworkBindAsset, builtin.ToolNetworkSyncSource}
	for _, candidate := range []*Config{cfg, Default()} {
		for _, name := range names {
			if !slices.Contains(candidate.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools, name) {
				t.Errorf("%s not defaulted in configurable resident list", name)
			}
		}
	}
	if !slices.Contains(cfg.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools, "exec") {
		t.Fatal("existing resident tools lost")
	}
	// Serialize the user's opt-out exactly as configuration saving does. An
	// explicit choice must survive subsequent startup default initialization.
	cfg.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools = []string{"exec"}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if slices.Contains(reloaded.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools, name) {
			t.Errorf("%s was forced back after opting out", name)
		}
		if slices.Contains(builtin.GetAllBuiltinTools(), name) {
			t.Errorf("%s became a forced builtin resident", name)
		}
	}
}
