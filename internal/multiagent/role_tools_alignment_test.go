package multiagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp/builtin"
)

// Core hunting tools that default roles must list (execution_boost always_visible is useless otherwise).
// Heavy scanners (nuclei/ffuf/sqlmap/dalfox/katana/arjun) are intentionally excluded: SRC targets
// are tested by hand via exec + skill, not by scanners.
func huntingCoreToolsRequired() []string {
	return []string{
		"http-framework-test",
		"exec", "execute-python-script", "jwt-analyzer", "dnslog", "skill",
		builtin.ToolRecordVulnerability,
		builtin.ToolRecordVulnerabilityCandidate,
		builtin.ToolListVulnerabilities,
		builtin.ToolGetVulnerability,
		builtin.ToolUpsertProjectFact,
		builtin.ToolGetProjectFact,
		builtin.ToolListProjectFacts,
		builtin.ToolSearchProjectFacts,
		builtin.ToolUpsertExecutionCoverage,
		builtin.ToolGetExecutionCoverage,
		builtin.ToolShouldContinueExecution,
		builtin.ToolLogicProbeDiff,
	}
}

// Documented hunting roles (EXECUTION_BOOST §2 + common scanners).
func documentedHuntingRoles() []string {
	return []string{
		"渗透测试",
		"企业SRC渗透测试",
		"EDUSRC渗透测试",
		"Web应用扫描",
		"综合漏洞扫描",
		"API安全测试",
		"Web框架测试",
	}
}

func TestHuntingRolesToolsIncludeCoreSet(t *testing.T) {
	t.Parallel()
	rolesDir := findRolesDir(t)
	roles, err := config.LoadRolesFromDir(rolesDir)
	if err != nil {
		t.Fatalf("LoadRolesFromDir: %v", err)
	}
	core := huntingCoreToolsRequired()
	for _, name := range documentedHuntingRoles() {
		role, found := findRole(roles, name)
		if !found {
			t.Fatalf("role %q not loaded from %s (have %d roles)", name, rolesDir, len(roles))
		}
		set := map[string]struct{}{}
		for _, tl := range role.Tools {
			set[strings.ToLower(strings.TrimSpace(tl))] = struct{}{}
		}
		var missing []string
		for _, c := range core {
			if _, ok := set[strings.ToLower(c)]; !ok {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			t.Errorf("role %q missing tools: %v", name, missing)
		}
	}
}

func TestHuntingRoleToolsExistInToolsDirOrBuiltin(t *testing.T) {
	t.Parallel()
	rolesDir := findRolesDir(t)
	toolsDir := filepath.Join(filepath.Dir(rolesDir), "tools")
	if st, err := os.Stat(toolsDir); err != nil || !st.IsDir() {
		t.Fatalf("tools/ directory not found next to roles: %s", toolsDir)
	}
	// Collect yaml basenames (without .yaml)
	yamlTools := map[string]struct{}{}
	entries, err := os.ReadDir(toolsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			base := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
			yamlTools[strings.ToLower(base)] = struct{}{}
		}
	}
	// Builtins that are not security tool yamls
	builtins := map[string]struct{}{}
	for _, n := range builtin.GetAllBuiltinTools() {
		builtins[strings.ToLower(n)] = struct{}{}
	}
	// Common non-yaml framework tools
	for _, n := range []string{"skill", "task", "transfer_to_agent", "exit", "write_todos", "tool_search",
		"read_file", "write_file", "edit_file", "glob", "grep", "execute", "exec"} {
		builtins[n] = struct{}{}
	}

	roles, err := config.LoadRolesFromDir(rolesDir)
	if err != nil {
		t.Fatal(err)
	}
	// Only assert core hunting set existence (not every role tool may have yaml if MCP external)
	core := huntingCoreToolsRequired()
	var missingYAML []string
	for _, c := range core {
		key := strings.ToLower(c)
		if _, ok := yamlTools[key]; ok {
			continue
		}
		if _, ok := builtins[key]; ok {
			continue
		}
		missingYAML = append(missingYAML, c)
	}
	if len(missingYAML) > 0 {
		t.Fatalf("core tools missing from tools/*.yaml and builtins: %v (toolsDir=%s)", missingYAML, toolsDir)
	}

	// Also verify documented roles' core subset is loadable
	for _, name := range documentedHuntingRoles() {
		role, ok := findRole(roles, name)
		if !ok {
			t.Fatalf("role %q missing", name)
		}
		for _, tl := range role.Tools {
			key := strings.ToLower(strings.TrimSpace(tl))
			if key == "" {
				continue
			}
			// only fail for core set missing yaml
			isCore := false
			for _, c := range core {
				if strings.ToLower(c) == key {
					isCore = true
					break
				}
			}
			if !isCore {
				continue
			}
			if _, ok := yamlTools[key]; ok {
				continue
			}
			if _, ok := builtins[key]; ok {
				continue
			}
			t.Errorf("role %q tool %q has no tools/%s.yaml and is not builtin", name, tl, tl)
		}
	}
}

func TestDefaultHuntingAlwaysVisibleCoveredByRoleCore(t *testing.T) {
	t.Parallel()
	joined := strings.Join(DefaultHuntingAlwaysVisibleTools, ",")
	for _, n := range []string{"http-framework-test", "record_vulnerability_candidate", "should_continue_execution"} {
		if !strings.Contains(joined, n) {
			t.Fatalf("DefaultHuntingAlwaysVisibleTools missing %s", n)
		}
	}
}

func findRole(roles map[string]config.RoleConfig, name string) (config.RoleConfig, bool) {
	if r, ok := roles[name]; ok {
		return r, true
	}
	for _, r := range roles {
		if r.Name == name {
			return r, true
		}
	}
	return config.RoleConfig{}, false
}

func findRolesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, "roles")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("roles/ directory not found walking up from " + wd)
	return ""
}
