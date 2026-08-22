package multiagent

import (
	"context"
	"strings"

	"github.com/cloudwego/eino/components/tool"
)

// injectToolNamesOnlyInstruction prepends a compact tool-name-only section into
// the system instruction so the model can reference current callable names.
// toolSearchMiddlewareActive must be true when prependEinoMiddlewares mounted toolsearch (dynamic tools); do not infer this
// by scanning tool names — tool_search is injected by middleware and is usually absent from the pre-split tools list.
// mountedTools is the post-split tool list actually bound to the agent (schema attached each turn);
// tools minus mountedTools is the dynamic pool that only tool_search can unlock. Passing mountedTools
// lets the instruction tell static/dynamic tools apart explicitly, so the model neither calls
// tool_search for always-visible tools (which can never match — matches:null) nor calls dynamic
// tools before unlocking them.
func injectToolNamesOnlyInstruction(ctx context.Context, instruction string, tools []tool.BaseTool, mountedTools []tool.BaseTool, toolSearchMiddlewareActive bool) string {
	names := collectToolNames(ctx, tools)
	if len(names) == 0 {
		return strings.TrimSpace(instruction)
	}
	mountedSet := make(map[string]struct{}, len(mountedTools))
	for _, n := range collectToolNames(ctx, mountedTools) {
		mountedSet[strings.ToLower(n)] = struct{}{}
	}
	dynamic := make([]string, 0, len(names))
	static := make([]string, 0, len(names))
	for _, n := range names {
		if _, ok := mountedSet[strings.ToLower(n)]; ok {
			static = append(static, n)
		} else {
			dynamic = append(dynamic, n)
		}
	}
	hasToolSearch := toolSearchMiddlewareActive
	if !hasToolSearch {
		for _, n := range names {
			if strings.EqualFold(strings.TrimSpace(n), "tool_search") {
				hasToolSearch = true
				break
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("以下是当前会话绑定的工具名称索引（仅名称，无参数 JSON Schema）。\n")
	splitIndex := hasToolSearch && len(dynamic) > 0 && len(static) > 0
	if splitIndex {
		sb.WriteString("工具分两类：【常驻】工具的完整参数 schema 已随当前请求的 tools 定义直接附上，可直接调用；【非常驻】工具默认不下发 schema，必须先用 tool_search 解锁后才可调用。\n")
		sb.WriteString("【常驻工具】（schema 已附上，直接调用即可，禁止先调 tool_search 加载它们）\n")
		for _, name := range static {
			sb.WriteString("- ")
			sb.WriteString(name)
			sb.WriteByte('\n')
		}
		sb.WriteString("\n【非常驻工具】（当前请求看不到其 schema，须先 tool_search 解锁）\n")
		for _, name := range dynamic {
			sb.WriteString("- ")
			sb.WriteString(name)
			sb.WriteByte('\n')
		}
	} else {
		if hasToolSearch {
			sb.WriteString("说明：列表里可能含「非常驻」工具——它们不一定出现在当前轮次下发给模型的工具定义中；在未看到该工具的完整 schema 前，禁止凭名称臆测参数。\n")
		}
		for _, name := range names {
			sb.WriteString("- ")
			sb.WriteString(name)
			sb.WriteByte('\n')
		}
	}
	sb.WriteString("\n使用规则：\n")
	sb.WriteString("1) 上表仅为名称索引，不含参数定义。禁止猜测参数名、类型、枚举取值或是否必填。\n")
	if hasToolSearch {
		sb.WriteString("2) 判定标准：在「当前请求所附 tools 定义」里看得到完整 schema 的工具即为常驻，直接调用；看不到 schema 的工具为非常驻，必须先 tool_search 解锁。为省 token 或赶进度而跳过 tool_search 直接盲调非常驻工具，属于明确禁止的错误流程。\n")
		sb.WriteString("3) tool_search 唯一必填参数是 query（字符串，不是 regex_pattern）：填关键词做模糊搜索（最多返回 5 条），或填 \"select:工具名\" 精确加载（多个工具用逗号分隔，如 select:nuclei,dirsearch）。\n")
		sb.WriteString("4) tool_search 只索引【非常驻】工具：对常驻工具查询返回空（matches:null）属于预期行为，绝不代表该工具不存在或不可用——常驻工具直接调用即可，不要因 matches:null 而判定工具不可用。\n")
		sb.WriteString("5) tool_search 的返回仅为匹配到的工具名列表；schema 在解锁后的下一轮才会下发。禁止在 schema 未出现时编造 JSON 参数。\n")
		sb.WriteString("6) 不要臆造不存在的工具名。\n\n")
	} else {
		sb.WriteString("2) 调用具体工具前，请先确认该工具的参数要求（以当前请求中的工具定义为准）；不确定时先澄清再调用。\n")
		sb.WriteString("3) 不要臆造不存在的工具名。\n\n")
	}
	if s := strings.TrimSpace(injectShellToolGuidance("", names)); s != "" {
		sb.WriteString(s)
		sb.WriteString("\n\n")
	}
	if s := strings.TrimSpace(instruction); s != "" {
		sb.WriteString(s)
	}
	return sb.String()
}

func collectToolNames(ctx context.Context, tools []tool.BaseTool) []string {
	if len(tools) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tools))
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		info, err := t.Info(ctx)
		if err != nil || info == nil {
			continue
		}
		name := strings.TrimSpace(info.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	return out
}

