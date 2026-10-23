package config

import (
	"strings"

	"cyberstrike-ai/internal/mcp/builtin"
)

func (c *MultiAgentEinoMiddlewareConfig) applyNetworkResidentDefaults() {
	if c.NetworkToolDefaultsApplied {
		return
	}
	seen := make(map[string]bool, len(c.ToolSearchAlwaysVisibleTools))
	for _, name := range c.ToolSearchAlwaysVisibleTools {
		seen[strings.ToLower(strings.TrimSpace(name))] = true
	}
	for _, name := range []string{builtin.ToolNetworkStatus, builtin.ToolNetworkDiagnose, builtin.ToolNetworkAcquire, builtin.ToolNetworkRelease, builtin.ToolNetworkBindAsset, builtin.ToolNetworkSyncSource} {
		if !seen[name] {
			c.ToolSearchAlwaysVisibleTools = append(c.ToolSearchAlwaysVisibleTools, name)
		}
	}
	c.NetworkToolDefaultsApplied = true
}
