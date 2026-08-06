package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

// tavilySearchEndpoint 默认搜索端点。
const tavilySearchEndpoint = "https://api.tavily.com/search"

// registerWebSearchTools 注册联网搜索工具。
//
// web_search：走 Tavily API（免费层，本机需 IPv4 出站至 api.tavily.com）。支持通用网页搜索
// （实时资讯、历史 CVE、漏洞情报、技术文档、厂商公告等），返回结构化结果（标题/URL/正文摘要/相关度分数）。
// 需要更完整正文时用 include_raw_content=true 重搜（Tavily 返回原始正文）。
//
// 凭据经 config（websearch.api_key）或 TAVILY_API_KEY 环境变量注入，模型不得传入密钥；
// 未配置 key 时返回清晰提示而非静默失败。有网络外发，须受角色与 RBAC 门控。
func registerWebSearchTools(server *mcp.Server, cfg *config.Config, logger *zap.Logger) {
	if server == nil {
		return
	}
	if cfg == nil || (cfg.WebSearch.Enabled != nil && !*cfg.WebSearch.Enabled) {
		if logger != nil {
			logger.Info("联网搜索工具未注册（websearch 未启用）")
		}
		return
	}

	searchTool := mcp.Tool{
		Name:             builtin.ToolWebSearch,
		ShortDescription: "联网搜索（Tavily，实时网页搜索）",
		Description: "通过 Tavily 引擎执行实时网页搜索，返回结构化结果（标题/URL/摘要/相关度分数）。\n" +
			"适合：查实时资讯与热点、检索历史 CVE 与漏洞利用、找技术文档/厂商公告、验证模型知识盲区、\n" +
			"看目标系统组件是否有已知漏洞（先搜 CVE 编号或「产品名 版本 漏洞」）。\n" +
			"search_depth=advanced 时返回更长正文摘要，适合深挖技术细节。\n" +
			"需更完整原始正文时设置 include_raw_content=true。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "搜索关键词，如 `CVE-2024-4577`、`Apache Tomcat 9.0.87 exploit`、`今天科技圈发生了什么`",
				},
				"max_results": map[string]interface{}{
					"type":        "integer",
					"description": "返回条数，默认 5，最大 10",
				},
				"search_depth": map[string]interface{}{
					"type":        "string",
					"description": "basic（默认，摘要较短）/ advanced（更长正文摘要）",
				},
				"include_raw_content": map[string]interface{}{
					"type":        "boolean",
					"description": "是否包含原始正文（默认 false；true 时结果更大）",
				},
				"topic": map[string]interface{}{
					"type":        "string",
					"description": "可选限定：general（默认）/ news（新闻）/ finance / github（GitHub 代码）",
				},
			},
			"required": []string{"query"},
		},
	}

	server.RegisterTool(searchTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		query := strings.TrimSpace(strArg(args, "query"))
		if query == "" {
			return textResult("错误: query 必填", true), nil
		}
		apiKey := cfg.WebSearch.ResolveAPIKey()
		if apiKey == "" {
			return textResult("联网搜索未配置：请在系统设置 → 联网搜索配置（Tavily）填写 API Key，或设置环境变量 TAVILY_API_KEY（https://tavily.com 免费申请）", true), nil
		}
		maxResults := intArg(args, "max_results", defaultWebMaxResults(cfg))
		if maxResults <= 0 {
			maxResults = 5
		}
		if maxResults > 10 {
			maxResults = 10
		}
		depth := strArg(args, "search_depth")
		if depth == "" {
			depth = "basic"
		}
		rawContent := boolArg(args, "include_raw_content")
		topic := strArg(args, "topic")
		if topic == "" {
			topic = "general"
		}

		payload := map[string]interface{}{
			"api_key":             apiKey,
			"query":               query,
			"max_results":         maxResults,
			"search_depth":        depth,
			"include_raw_content": rawContent,
			"topic":               topic,
			"include_answer":      true,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return textResult("请求构造失败: "+err.Error(), true), nil
		}

		endpoint := tavilySearchEndpoint
		if u := strings.TrimSpace(cfg.WebSearch.BaseURL); u != "" {
			endpoint = u
		}
		client := &http.Client{Timeout: time.Duration(webTimeoutSeconds(cfg)) * time.Second}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
		if err != nil {
			return textResult("构建请求失败: "+err.Error(), true), nil
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "cyberstrike-ai-security-testing")
		resp, err := client.Do(req)
		if err != nil {
			if logger != nil {
				logger.Warn("web_search failed", zap.String("query", query), zap.Error(err))
			}
			return textResult("联网搜索失败（网络错误，请确认本机可 IPv4 出站至 api.tavily.com）: "+err.Error(), true), nil
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if resp.StatusCode != http.StatusOK {
			return textResult(fmt.Sprintf("联网搜索失败: HTTP %d，%s", resp.StatusCode, strings.TrimSpace(string(respBody))), true), nil
		}

		var parsed struct {
			Answer   string `json:"answer"`
			Query    string `json:"query"`
			Results  []struct {
				Title    string  `json:"title"`
				URL      string  `json:"url"`
				Content  string  `json:"content"`
				Score    float64 `json:"score"`
			} `json:"results"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return textResult("搜索结果解析失败: "+err.Error(), true), nil
		}
		if len(parsed.Results) == 0 {
			return textResult("未搜索到结果，请调整关键词（如补上软件版本号或 CVE 年份）后重试", false), nil
		}

		var b strings.Builder
		fmt.Fprintf(&b, "搜索结果 %q（%d 条）:\n", parsed.Query, len(parsed.Results))
		if parsed.Answer != "" {
			fmt.Fprintf(&b, "\n★ 综合回答: %s\n", parsed.Answer)
		}
		for i, r := range parsed.Results {
			score := ""
			if r.Score > 0 {
				score = fmt.Sprintf(" [%.3f]", r.Score)
			}
			fmt.Fprintf(&b, "\n[%d]%s %s\n  URL: %s\n  %s\n", i+1, score, r.Title, r.URL, strings.TrimSpace(r.Content))
		}
		b.WriteString("\n提示: 已含正文摘要；如需更完整正文，可把 include_raw_content 设为 true 重搜。")
		return textResult(b.String(), false), nil
	})
}

// defaultWebMaxResults 返回默认结果条数（配置 > 5）。
func defaultWebMaxResults(cfg *config.Config) int {
	if cfg != nil && cfg.WebSearch.MaxResults > 0 {
		return cfg.WebSearch.MaxResults
	}
	return 5
}

// webTimeoutSeconds 返回搜索超时（配置 > 30 秒）。
func webTimeoutSeconds(cfg *config.Config) int {
	if cfg != nil && cfg.WebSearch.TimeoutSeconds > 0 {
		return cfg.WebSearch.TimeoutSeconds
	}
	return 30
}
