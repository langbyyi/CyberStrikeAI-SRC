package handler

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp/builtin"
	"gopkg.in/yaml.v3"
)

func TestConfigSavePreservesNetworkResidentOptOutAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("multi_agent:\n  eino_middleware:\n    tool_search_always_visible_tools: [exec]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(cfg.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools, builtin.ToolNetworkAcquire) {
		t.Fatal("network tools were not default checked")
	}
	cfg.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools = []string{"exec"}
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	updateMultiAgentConfig(doc, cfg.MultiAgent)
	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(reloaded.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools, builtin.ToolNetworkAcquire) {
		t.Fatal("saving configuration lost the resident opt-out marker")
	}
}
