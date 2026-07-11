package multiagent

import (
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp/builtin"
)

// DefaultHuntingAlwaysVisibleTools is the production always_visible baseline for SRC hunting.
// Merged when ExecutionBoost is enabled (in addition to configured names + all builtin MCP tools).
var DefaultHuntingAlwaysVisibleTools = []string{
	// Manual verification / analysis (heavy scanners removed: SRC targets are tested by hand)
	"http-framework-test",
	// Execution / scripting
	"exec",
	"execute",
	"execute-python-script",
	// Auth / OOB / skill
	"jwt-analyzer",
	"dnslog",
	"skill",
	// Vulnerability / fact / knowledge (also covered by GetAllBuiltinTools; listed for clarity)
	builtin.ToolRecordVulnerability,
	builtin.ToolRecordVulnerabilityCandidate,
	builtin.ToolListVulnerabilities,
	builtin.ToolGetVulnerability,
	builtin.ToolUpsertProjectFact,
	builtin.ToolGetProjectFact,
	builtin.ToolListProjectFacts,
	builtin.ToolSearchProjectFacts,
	// Coverage / finalize gate
	builtin.ToolUpsertExecutionCoverage,
	builtin.ToolGetExecutionCoverage,
	builtin.ToolShouldContinueExecution,
	// Logic Track probe
	builtin.ToolLogicProbeDiff,
}

// DefaultReductionClearExcludeHunting tools whose large outputs should not be cleared from history
// (structured trunc + on-disk path preferred over wipe).
var DefaultReductionClearExcludeHunting = []string{
	"http-framework-test",
	"execute-python-script",
	"jwt-analyzer",
	"dnslog",
	builtin.ToolRecordVulnerability,
	builtin.ToolRecordVulnerabilityCandidate,
	builtin.ToolUpsertProjectFact,
	builtin.ToolUpsertExecutionCoverage,
	builtin.ToolGetExecutionCoverage,
	builtin.ToolShouldContinueExecution,
	builtin.ToolLogicProbeDiff,
}

// mergeAlwaysVisibleToolNames merges configured names, builtin MCP tools, and (when boost) hunting defaults.
func mergeAlwaysVisibleToolNames(configured []string) []string {
	return mergeAlwaysVisibleToolNamesWithBoost(configured, true)
}

// mergeAlwaysVisibleToolNamesWithBoost is the testable merge entry for always_visible tool names.
func mergeAlwaysVisibleToolNamesWithBoost(configured []string, executionBoost bool) []string {
	merged := make([]string, 0, len(configured)+64)
	seen := make(map[string]struct{}, len(configured)+64)
	add := func(name string) {
		n := strings.TrimSpace(strings.ToLower(name))
		if n == "" {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		merged = append(merged, n)
	}
	for _, n := range configured {
		add(n)
	}
	for _, n := range builtin.GetAllBuiltinTools() {
		add(n)
	}
	if executionBoost {
		for _, n := range DefaultHuntingAlwaysVisibleTools {
			add(n)
		}
	}
	return merged
}

// mergeReductionClearExclude merges user exclude list with production hunting defaults when boost is on.
func mergeReductionClearExclude(configured []string, executionBoost bool) []string {
	merged := make([]string, 0, len(configured)+32)
	seen := make(map[string]struct{}, len(configured)+32)
	add := func(name string) {
		n := strings.TrimSpace(name)
		if n == "" {
			return
		}
		key := strings.ToLower(n)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		merged = append(merged, n)
	}
	for _, n := range configured {
		add(n)
	}
	// Framework meta-tools always excluded from clear
	for _, n := range []string{
		"task", "transfer_to_agent", "exit", "write_todos", "skill", "tool_search",
		"TaskCreate", "TaskGet", "TaskUpdate", "TaskList",
	} {
		add(n)
	}
	if executionBoost {
		for _, n := range DefaultReductionClearExcludeHunting {
			add(n)
		}
	}
	return merged
}

// executionBoostFromMW reads Effective boost flag from middleware config (nil-safe).
func executionBoostFromMW(mw *config.MultiAgentEinoMiddlewareConfig) bool {
	if mw == nil {
		return true
	}
	return mw.ExecutionBoostEffective()
}
