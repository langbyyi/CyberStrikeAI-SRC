package multiagent

import (
	"strings"

	"cyberstrike-ai/internal/config"
)

// Framework meta-tools (Eino ADK)，非 MCP 角色 tools；reduction 永不 clear。
var frameworkMetaToolsNeverClear = []string{
	"task", "transfer_to_agent", "exit", "write_todos", "skill", "tool_search",
	"TaskCreate", "TaskGet", "TaskUpdate", "TaskList",
}

// resolveAlwaysVisibleToolNames 计算 tool_search 的 always_visible 名称列表。
//
// 规则（禁止编排层硬编码 MCP 工具名）：
//  1. 仅允许出现在 boundNames 中的名字（boundNames = 本轮已按角色 ToolsForRole 绑定的工具）；
//  2. 优先使用 configured（config.tool_search_always_visible_tools），与 bound 求交；
//  3. 若求交为空且 fallbackCount>0，则按 bound 原有顺序取前 fallbackCount 个（即角色 tools 顺序）。
//
// boundNames 为空时返回 nil（无角色工具则无 always_visible 注入）。
func resolveAlwaysVisibleToolNames(configured, boundNames []string, fallbackCount int) []string {
	if len(boundNames) == 0 {
		return nil
	}
	boundOrder := make([]string, 0, len(boundNames))
	boundSet := make(map[string]struct{}, len(boundNames))
	for _, n := range boundNames {
		key := strings.ToLower(strings.TrimSpace(n))
		if key == "" {
			continue
		}
		if _, ok := boundSet[key]; ok {
			continue
		}
		boundSet[key] = struct{}{}
		boundOrder = append(boundOrder, key)
	}
	if len(boundOrder) == 0 {
		return nil
	}

	out := make([]string, 0, len(boundOrder))
	seen := make(map[string]struct{}, len(boundOrder))
	add := func(name string) {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			return
		}
		if _, ok := boundSet[key]; !ok {
			return // 禁止注入未绑定（非角色）工具
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}

	for _, n := range configured {
		add(n)
	}
	if len(out) > 0 {
		return out
	}
	// 无有效配置：按角色绑定顺序取前 N 个常驻
	if fallbackCount <= 0 {
		return nil
	}
	if fallbackCount > len(boundOrder) {
		fallbackCount = len(boundOrder)
	}
	return append([]string(nil), boundOrder[:fallbackCount]...)
}

// mergeAlwaysVisibleToolNamesWithBoost 已废弃语义：不再因 boost 注入内置/挖洞硬编码列表。
// 仅透传 configured；真正与角色求交在 resolveAlwaysVisibleToolNames + bound 列表。
// 保留函数签名供旧测试/调用兼容；executionBoost 参数忽略。
func mergeAlwaysVisibleToolNamesWithBoost(configured []string, executionBoost bool) []string {
	_ = executionBoost
	return resolveAlwaysVisibleToolNames(configured, configured, 0)
}

// mergeAlwaysVisibleToolNames 兼容旧名：仅配置列表自身去重（不注入框架硬编码）。
func mergeAlwaysVisibleToolNames(configured []string) []string {
	return mergeAlwaysVisibleToolNamesWithBoost(configured, true)
}

// mergeReductionClearExclude 合并 reduction 不清空列表。
// 仅：用户配置 + 框架元工具 + 本轮已绑定工具名（角色来源），禁止额外硬编码 MCP 工具名。
func mergeReductionClearExclude(configured []string, boundToolNames []string) []string {
	merged := make([]string, 0, len(configured)+len(boundToolNames)+16)
	seen := make(map[string]struct{}, len(configured)+len(boundToolNames)+16)
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
	for _, n := range frameworkMetaToolsNeverClear {
		add(n)
	}
	for _, n := range boundToolNames {
		add(n)
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
