package project

import (
	"strings"

	"cyberstrike-ai/internal/mcp/builtin"
)

// 边渗透边记录：统一节奏文案（agents/*.md 须与 FactRecordingIncrementalRhythmMarkdown 保持一致）。
const (
	factRhythmCore = "勿等会话结束或收尾再批量写入。每**确认**一条新认知（开放端口/服务版本、入口路径、认证态或凭据特征、可利用点或攻击面变化）后，**立即**调用 `upsert_project_fact`（同 fact_key 覆盖更新）。每**验证**出一条可复现漏洞（含 POC/影响）后，**立即**调用 `record_vulnerability`；与事实可各记一次。继续下一步工作前优先落库，避免上下文压缩后细节丢失。未绑项目时说明无法写黑板，仍在本轮保留证据摘要。"
	factRhythmCoordinatorSuffix = "委派/子任务返回新认知或漏洞时，由协调者及时写入，勿假定子代理已记。"
	factRhythmSubAgentSuffix      = "若工具集中无上述工具，须在交付物末尾给出「待落库」结构化条目（fact_key 建议、summary、body/POC 要点），供协调者**立即**写入。"
)

// FactRecordingIncrementalRhythmMarkdown 返回边渗透边记录节奏（Markdown，供 agents/*.md 与文档对齐）。
func FactRecordingIncrementalRhythmMarkdown(coordinator, subAgent bool) string {
	var b strings.Builder
	b.WriteString("- **边渗透边记录（强制节奏）**：")
	b.WriteString(factRhythmCore)
	if coordinator {
		b.WriteString(factRhythmCoordinatorSuffix)
	}
	if subAgent {
		b.WriteString(factRhythmSubAgentSuffix)
	}
	return b.String()
}

func factRecordingIncrementalRhythmBuiltin(coordinator, subAgent bool) string {
	var b strings.Builder
	b.WriteString("- **边渗透边记录（强制节奏）**：勿等会话结束或收尾再批量写入。每**确认**一条新认知（开放端口/服务版本、入口路径、认证态或凭据特征、可利用点或攻击面变化）后，**立即**调用 ")
	b.WriteString(builtin.ToolUpsertProjectFact)
	b.WriteString("（同 fact_key 覆盖更新）。每**验证**出一条可复现漏洞（含 POC/影响）后，**立即**调用 ")
	b.WriteString(builtin.ToolRecordVulnerability)
	b.WriteString("；与事实可各记一次。继续下一步工作前优先落库，避免上下文压缩后细节丢失。未绑项目时说明无法写黑板，仍在本轮保留证据摘要。")
	if coordinator {
		b.WriteString(factRhythmCoordinatorSuffix)
	}
	if subAgent {
		b.WriteString(factRhythmSubAgentSuffix)
	}
	return b.String()
}

// FactRecordingBlackboardSection 项目黑板与漏洞记录的完整系统提示块（单/多 Agent 主代理共用）。
// coordinatorDelegate 为 true 时追加「协调者代子代理落库」说明（Deep / plan_execute / supervisor）。
func FactRecordingBlackboardSection(coordinatorDelegate bool) string {
	var b strings.Builder
	b.WriteString("## 项目黑板（事实）与漏洞记录（分离）\n\n")
	b.WriteString("当前对话若已绑定项目，系统会自动注入「项目黑板索引」（仅 fact_key + 摘要）。**摘要不足时必须调用 ")
	b.WriteString(builtin.ToolGetProjectFact)
	b.WriteString("(fact_key) 获取 body，禁止凭摘要臆造细节。**\n\n")
	b.WriteString(factRecordingIncrementalRhythmBuiltin(coordinatorDelegate, false))
	b.WriteString("\n\n")
	b.WriteString("- **环境/目标/认证等认知**（非正式漏洞条目）：使用 ")
	b.WriteString(builtin.ToolUpsertProjectFact)
	b.WriteString("，fact_key 建议 `category/slug`（如 target/primary_domain），同 key 覆盖更新；body 记端口/版本/凭据特征与证据来源。\n")
	b.WriteString("- **发现与利用上下文**（审计复现）：fact_key 建议 finding/、chain/、exploit/、poc/ 前缀；**body 必填**完整攻击链（入口 → 步骤 → 原始请求/响应或命令 → 现象 → 关联 related_vulnerability_id），**禁止仅写结论**；summary 写「什么 + 在哪 + 如何验证」一行要点。\n")
	b.WriteString("- **可交付漏洞**：使用 ")
	b.WriteString(builtin.ToolRecordVulnerability)
	b.WriteString("，含标题、严重程度、类型、目标、证明（POC）、影响、修复建议。记前可先 ")
	b.WriteString(builtin.ToolListVulnerabilities)
	b.WriteString(" 查重，详情用 ")
	b.WriteString(builtin.ToolGetVulnerability)
	b.WriteString("(id)（默认仅当前项目/会话）。\n")
	b.WriteString("- 同一发现可能需**各记一次**（事实记**完整攻击链与 exploit 细节**供复现，漏洞记正式 findings）。误报用 ")
	b.WriteString(builtin.ToolDeprecateProjectFact)
	b.WriteString(" 或漏洞状态 false_positive。\n")
	b.WriteString("- 事实多时用 ")
	b.WriteString(builtin.ToolListProjectFacts)
	b.WriteString(" / ")
	b.WriteString(builtin.ToolSearchProjectFacts)
	b.WriteString(" 检索。\n\n")
	b.WriteString(FactRecordingGuidanceBlock())
	b.WriteString("\n\n严重程度：critical / high / medium / low / info。证明须含足够证据（请求响应、截图、命令输出等）。")
	return b.String()
}

// FactRecordingSubAgentSection 子代理边渗透边记录（无工具时输出待落库条目）。
func FactRecordingSubAgentSection() string {
	return "## 边渗透边记录\n\n" + factRecordingIncrementalRhythmBuiltin(false, true) + "\n"
}

// FactRecordingBlackboardSectionMarkdown 与 FactRecordingBlackboardSection 等价的 Markdown（工具名为字面量，供 agents/*.md）。
func FactRecordingBlackboardSectionMarkdown(coordinatorDelegate bool) string {
	var b strings.Builder
	b.WriteString("## 项目黑板（事实）与漏洞记录（分离）\n\n")
	b.WriteString("当前对话若已绑定项目，系统会自动注入「项目黑板索引」（仅 `fact_key` + 摘要）。**摘要不足时必须调用 `get_project_fact(fact_key)` 获取 body，禁止凭摘要臆造细节。**\n\n")
	b.WriteString(FactRecordingIncrementalRhythmMarkdown(coordinatorDelegate, false))
	b.WriteString("\n\n")
	b.WriteString("- **环境/目标/认证等认知**（非正式漏洞）：使用 **`upsert_project_fact`**，`fact_key` 建议 `category/slug`（如 `target/primary_domain`），同 key 覆盖更新；body 记端口/版本/凭据特征与证据来源。\n")
	b.WriteString("- **发现与利用上下文**（审计复现）：`fact_key` 建议 `finding/`、`chain/`、`exploit/`、`poc/` 前缀；**body 必填**完整攻击链（入口 → 步骤 → 原始请求/响应或命令 → 现象 → 关联 `related_vulnerability_id`），**禁止仅写结论**；summary 写「什么 + 在哪 + 如何验证」一行要点。\n")
	b.WriteString("- **可交付漏洞**：使用 **`record_vulnerability`**（标题、描述、严重程度、类型、目标、证明 POC、影响、修复建议）。严重程度 critical / high / medium / low / info。\n")
	b.WriteString("- 同一发现可能需**各记一次**（事实记可复现攻击链，漏洞记正式 findings）。误报用 **`deprecate_project_fact`** 或漏洞状态 false_positive。\n")
	b.WriteString("- 事实多时用 **`list_project_facts`** / **`search_project_facts`** 检索。\n\n")
	b.WriteString(FactRecordingGuidanceBlock())
	b.WriteString("\n\n严重程度：critical / high / medium / low / info。证明须含足够证据（请求响应、截图、命令输出等）。")
	return b.String()
}
