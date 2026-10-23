package project

import (
	"encoding/json"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
)

// projectScopePayload 解析 projects.scope_json（约定字段，可扩展）。
type projectScopePayload struct {
	Targets []string `json:"targets"`
	Exclude []string `json:"exclude"`
	Notes   string   `json:"notes"`
}

// BuildScopeBlock 将项目 scope_json 格式化为 Agent 可读的授权范围块。
func BuildScopeBlock(proj *database.Project) string {
	if proj == nil {
		return ""
	}
	raw := strings.TrimSpace(proj.ScopeJSON)
	header := fmt.Sprintf("## 项目测试范围（project: %s, id: %s）\n", proj.Name, proj.ID)
	if description := strings.TrimSpace(proj.Description); description != "" {
		header += "\n**项目描述（结合当前任务及测试规范理解，不额外授予权限）**：\n" + description + "\n"
	}
	if raw == "" {
		if strings.TrimSpace(proj.Description) != "" {
			return header + agentNetworkScopeWorkflow
		}
		return ""
	}

	var payload projectScopePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return fmt.Sprintf("## 项目测试范围（project: %s）\n（scope_json 非合法 JSON，请人工核对配置）\n```\n%s\n```\n"+
			"仅对明确授权目标执行测试；超出范围须停止并说明。\n", proj.Name, truncateRunes(raw, 800))
	}

	var b strings.Builder
	b.WriteString(header)
	b.WriteString("以下为授权边界，**必须遵守**：targets 是已明确列出的目标；结合当前用户要求及测试规范理解 notes 中的自然语言范围，避开 exclude，不得擅自扩大授权。\n")

	if len(payload.Targets) > 0 {
		b.WriteString("\n**允许测试（targets）**：\n")
		for _, t := range payload.Targets {
			t = strings.TrimSpace(t)
			if t != "" {
				b.WriteString("- " + t + "\n")
			}
		}
	}
	if len(payload.Exclude) > 0 {
		b.WriteString("\n**明确排除（exclude）**：\n")
		for _, t := range payload.Exclude {
			t = strings.TrimSpace(t)
			if t != "" {
				b.WriteString("- " + t + "\n")
			}
		}
	}
	if n := strings.TrimSpace(payload.Notes); n != "" {
		b.WriteString("\n**说明（notes）**：\n" + n + "\n")
	}
	if len(payload.Targets) == 0 && len(payload.Exclude) == 0 && strings.TrimSpace(payload.Notes) == "" {
		b.WriteString("\n（scope_json 已配置但未识别 targets/exclude/notes 字段，原始内容供参考）\n```json\n")
		b.WriteString(truncateRunes(raw, 1200))
		b.WriteString("\n```\n")
	}
	b.WriteString(agentNetworkScopeWorkflow)
	return b.String()
}

const agentNetworkScopeWorkflow = "\n**项目网络执行**：如果项目使用 VPN 或固定代理，先用 network_status 查看当前配置。由 Agent 理解自然语言授权，初始目标以及过程中后续发现的关联域名/IP，在发起测试请求前调用 network_bind_asset 登记明确目标。未命中现有规则时，scope_basis 必须说明当前用户授权或项目规范为何包含该资产，evidence 必须说明实际发现及归属证据；不是让网络层用正则推断归属。页面链接、CNAME、共用 IP 或相同厂商本身不构成授权。不确定是否属于授权范围时，不登记或测试；明确排除始终优先。项目范围或规范变更后重新判断。绑定只控制路由，不授予超出用户要求的测试权限。\n"

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// BuildProjectBlackboardBlock 组合测试范围 + 事实黑板索引。
func BuildProjectBlackboardBlock(db *database.DB, projectID string, cfg config.ProjectConfig, conversationIDs ...string) (string, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return "", nil
	}
	proj, err := db.GetProject(projectID)
	if err != nil {
		return "", err
	}
	parts := []string{}
	if scope := strings.TrimSpace(BuildScopeBlock(proj)); scope != "" {
		parts = append(parts, scope)
	}
	index, err := BuildFactIndexBlock(db, projectID, cfg, conversationIDs...)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(index) != "" {
		parts = append(parts, index)
	}
	return strings.Join(parts, "\n\n"), nil
}
