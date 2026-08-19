package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/fofaruntime"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	openaiClient "cyberstrike-ai/internal/openai"

	"go.uber.org/zap"
)

const fofaDefaultFields = "host,ip,port,domain,title,protocol,country,province,city,server"

// registerFOFASearchTool 把空间测绘 runtime 适配为 Agent/MCP 工具。
//
// provider 选择空间测绘引擎（fofa/quake/zoomeye/shodan，默认 fofa），各引擎走自身
// 原生协议：fofa→qbase64+key GET；quake→POST JSON + X-QuakeToken；shodan→
// GET /shodan/host/search + key；zoomeye→POST JSON + API-KEY。统一经 runtime 的
// SearchByProvider 分发与归一化。natural_language=true 时先把 query 作为自然语言
// 意图，经 LLM 转换为对应引擎的查询语法，再执行搜索。凭据、TLS、fallback 均由
// 管理员配置，模型不得传入密钥。runtime 每次请求按最新配置懒加载，Web 界面改动即时生效。
func registerFOFASearchTool(server *mcp.Server, cfg *config.Config, logger *zap.Logger) {
	if server == nil {
		return
	}
	tool := mcp.Tool{
		Name:             builtin.ToolFOFASearch,
		ShortDescription: "网络空间测绘搜索（FOFA/Quake/ZoomEye/Shodan，支持自然语言转语法）",
		Description: "使用服务器统一 runtime 搜索已授权的互联网资产，各引擎走原生协议。" +
			"provider 可选 fofa（默认，qbase64+key）/quake（X-QuakeToken）/zoomeye（API-KEY）/shodan（key），" +
			"支持对应引擎的原生查询语法、分页、字段选择、full 模式；" +
			"natural_language=true 时先把 query 作为自然语言意图，经 LLM 转换为对应引擎查询语法再搜索。" +
			"凭据、TLS、fallback 均由管理员配置，模型不得传入或看到密钥。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "查询表达式，如 domain=\"example.com\"；或自然语言意图（搭配 natural_language=true）",
				},
				"provider": map[string]interface{}{
					"type":        "string",
					"description": "空间测绘引擎：fofa（默认）/quake/zoomeye/shodan",
				},
				"natural_language": map[string]interface{}{
					"type":        "boolean",
					"description": "为 true 时把 query 视为自然语言意图，先用 LLM 转换为对应 provider 的查询语法再搜索",
				},
				"size": map[string]interface{}{
					"type":        "integer",
					"description": "返回数量，默认 100，最大 10000",
				},
				"page": map[string]interface{}{
					"type":        "integer",
					"description": "页码，默认 1",
				},
				"fields": map[string]interface{}{
					"type":        "string",
					"description": "逗号分隔字段，默认 host,ip,port,domain,title,protocol,country,province,city,server",
				},
				"full": map[string]interface{}{
					"type":        "boolean",
					"description": "是否请求完整数据（受账户权限限制）",
				},
			},
			"required": []string{"query"},
		},
	}

	// NL→语法 走 OpenAI 兼容 LLM；客户端廉价，注册期一次性构造。
	var nlClient *openaiClient.Client
	if cfg != nil {
		nlClient = openaiClient.NewClient(&cfg.OpenAI, &http.Client{Timeout: 2 * time.Minute}, logger)
	}

	server.RegisterTool(tool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		query := strings.TrimSpace(strArg(args, "query"))
		if query == "" {
			return textResult("错误: query 必填", true), nil
		}
		provider := normalizeFOFAProvider(strArg(args, "provider"))
		size := intArg(args, "size", 100)
		if size <= 0 {
			size = 100
		}
		if size > 10000 {
			size = 10000
		}
		page := intArg(args, "page", 1)
		if page <= 0 {
			page = 1
		}
		fields := strings.TrimSpace(strArg(args, "fields"))
		if fields == "" {
			fields = defaultFieldsForProvider(provider)
		}
		full := boolArg(args, "full")

		if boolArg(args, "natural_language") {
			converted, err := convertNaturalLanguageToQuery(ctx, nlClient, cfg, provider, query, logger)
			if err != nil {
				return textResult("自然语言解析失败: "+err.Error(), true), nil
			}
			if converted == "" {
				return textResult("自然语言解析未生成可用查询语法，请补充关键条件（国家/端口/产品/域名等）后重试", true), nil
			}
			query = converted
		}

		searchRuntime, err := resolveProviderRuntime(cfg, provider)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}

		response, err := searchRuntime.SearchByProvider(ctx, provider, fofaruntime.SearchRequest{
			Query: query, Size: size, Page: page, Fields: fields, Full: full,
		})
		if err != nil {
			if logger != nil {
				logger.Warn("Agent FOFA search failed", zap.String("provider", provider), zap.Error(err))
			}
			return textResult("空间测绘搜索失败: "+err.Error(), true), nil
		}
		encoded, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return textResult(fmt.Sprintf("搜索成功，但结果编码失败: %v", err), true), nil
		}
		return textResult(string(encoded), false), nil
	})
}

// normalizeFOFAProvider 与 handler 的 normalizeSpaceSearchProvider 保持一致；
// 非法值兜底为 fofa，保证 agent 工具始终可用。
func normalizeFOFAProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "fofa":
		return "fofa"
	case "zoomeye", "zoom-eye":
		return "zoomeye"
	case "quake":
		return "quake"
	case "shodan":
		return "shodan"
	default:
		return "fofa"
	}
}

func providerEngineName(provider string) string {
	switch provider {
	case "zoomeye":
		return "ZoomEye"
	case "quake":
		return "Quake"
	case "shodan":
		return "Shodan"
	default:
		return "FOFA"
	}
}

func defaultFieldsForProvider(provider string) string {
	switch provider {
	case "zoomeye":
		return "ip,port,domain,hostname,title,service,app,country,city"
	case "quake":
		return "ip,port,domain,service.name,service.http.title,location.country_cn,location.province_cn,location.city_cn"
	case "shodan":
		return "ip_str,port,hostnames,domains,org,isp,location.country_name,location.city,product,transport"
	default:
		return fofaDefaultFields
	}
}

// resolveProviderRuntime 返回适用于指定 provider 的 runtime。所有 provider 统一走
// runtime.SearchByProvider，由 runtime 按 provider 分发到各自原生协议（fofa→qbase64+key；
// quake/shodan/zoomeye→各自原生）。均按最新配置懒加载，Web 界面/配置文件变更即时生效。
func resolveProviderRuntime(cfg *config.Config, provider string) (*fofaruntime.Runtime, error) {
	if cfg == nil {
		return nil, errors.New("系统配置未初始化")
	}
	if provider == "fofa" {
		// 懒加载：每次请求按最新 cfg.FOFA 重建，使 FOFA 配置变更即时生效，无需重启。
		// cfg.FOFA 的多端点（Endpoints/FallbackBaseURLs）与 TLS 策略在 buildSnapshot 中完整保留。
		if !fofaHasAnyCredential(cfg) {
			return nil, errors.New("FOFA 未配置 API Key（请在系统设置 → 资产管理中填写，或设置环境变量 FOFA_API_KEY）")
		}
		return fofaruntime.New(cfg.FOFA, strings.TrimSpace(os.Getenv("FOFA_API_KEY")))
	}
	baseURL := resolveProviderBaseURL(cfg, provider)
	apiKey := resolveProviderAPIKey(cfg, provider)
	if apiKey == "" {
		return nil, fmt.Errorf("%s 未配置 API Key（请在 config.yaml 设置 %s.api_key 或对应环境变量）",
			providerEngineName(provider), provider)
	}
	return fofaruntime.New(config.FofaConfig{BaseURL: baseURL, APIKey: apiKey}, "")
}

// fofaHasAnyCredential 判断 FOFA 是否配置了任一有效凭据：顶层 APIKey、环境变量，
// 或任一 endpoint 的 key / bearer token（多端点配置时凭据挂在 endpoint 上）。
func fofaHasAnyCredential(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	if strings.TrimSpace(cfg.FOFA.APIKey) != "" || strings.TrimSpace(os.Getenv("FOFA_API_KEY")) != "" {
		return true
	}
	for _, ep := range cfg.FOFA.Endpoints {
		if strings.TrimSpace(ep.APIKey) != "" || strings.TrimSpace(ep.BearerToken) != "" {
			return true
		}
	}
	return false
}

// canonicalizeProviderBaseURL 迁移引擎旧域名（api.zoomeye.org → api.zoomeye.ai、
// quake.360.cn → quake.360.net，官方 v1.7.15 域名切换），用户 config.yaml 里的
// 旧地址自动改写，与 handler/fofa.go 的 canonicalizeSpaceSearchBaseURL 保持一致。
func canonicalizeProviderBaseURL(provider, raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return v
	}
	switch provider {
	case "zoomeye":
		v = strings.Replace(v, "://api.zoomeye.org", "://api.zoomeye.ai", 1)
	case "quake":
		v = strings.Replace(v, "://quake.360.cn", "://quake.360.net", 1)
	}
	return v
}

func resolveProviderBaseURL(cfg *config.Config, provider string) string {
	switch provider {
	case "zoomeye":
		if v := strings.TrimSpace(cfg.ZoomEye.BaseURL); v != "" {
			return canonicalizeProviderBaseURL(provider, v)
		}
		return "https://api.zoomeye.ai/v2/search"
	case "quake":
		if v := strings.TrimSpace(cfg.Quake.BaseURL); v != "" {
			return canonicalizeProviderBaseURL(provider, v)
		}
		return "https://quake.360.net/api/v3/search/quake_service"
	case "shodan":
		if v := strings.TrimSpace(cfg.Shodan.BaseURL); v != "" {
			return v
		}
		return "https://api.shodan.io"
	default:
		if v := strings.TrimSpace(cfg.FOFA.BaseURL); v != "" {
			return v
		}
		return "https://fofa.info/api/v1/search/all"
	}
}

func resolveProviderAPIKey(cfg *config.Config, provider string) string {
	envKey := map[string]string{
		"fofa":    "FOFA_API_KEY",
		"zoomeye": "ZOOMEYE_API_KEY",
		"quake":   "QUAKE_API_KEY",
		"shodan":  "SHODAN_API_KEY",
	}[provider]
	if apiKey := strings.TrimSpace(os.Getenv(envKey)); apiKey != "" {
		return apiKey
	}
	switch provider {
	case "zoomeye":
		return strings.TrimSpace(cfg.ZoomEye.APIKey)
	case "quake":
		return strings.TrimSpace(cfg.Quake.APIKey)
	case "shodan":
		return strings.TrimSpace(cfg.Shodan.APIKey)
	default:
		return strings.TrimSpace(cfg.FOFA.APIKey)
	}
}

// convertNaturalLanguageToQuery 调用 OpenAI 兼容 LLM，把自然语言意图转为对应
// 引擎的查询语法。仅返回 query 字符串（空串表示未生成可用语法）。逻辑与
// handler.ParseNaturalLanguage 一致，使 agent 工具无需依赖 gin 上下文即可转换。
func convertNaturalLanguageToQuery(ctx context.Context, client *openaiClient.Client, cfg *config.Config, provider, text string, logger *zap.Logger) (string, error) {
	if cfg == nil || strings.TrimSpace(cfg.OpenAI.APIKey) == "" || strings.TrimSpace(cfg.OpenAI.Model) == "" {
		return "", errors.New("未配置 AI 模型（openai.api_key / openai.model），无法做自然语言转换")
	}
	if client == nil {
		return "", errors.New("AI 客户端未初始化")
	}
	engineName := providerEngineName(provider)
	systemPrompt := buildSpaceSearchSystemPrompt(provider, engineName)
	requestBody := map[string]interface{}{
		"model": cfg.OpenAI.Model,
		"messages": []map[string]interface{}{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": fmt.Sprintf("自然语言意图：%s", text)},
		},
		"temperature":           0.1,
		"max_completion_tokens": 12000,
	}

	var apiResponse struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	nlCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := client.ChatCompletion(nlCtx, requestBody, &apiResponse); err != nil {
		if logger != nil {
			logger.Warn("Agent FOFA 自然语言解析失败", zap.String("provider", provider), zap.Error(err))
		}
		return "", err
	}
	if len(apiResponse.Choices) == 0 {
		return "", errors.New("AI 未返回有效结果")
	}
	content := strings.TrimSpace(apiResponse.Choices[0].Message.Content)
	jsonContent, err := extractNLJSONObject(content)
	if err != nil {
		return "", errors.New("AI 返回内容无法解析为 JSON")
	}
	var parsed struct {
		Query    string   `json:"query"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(jsonContent), &parsed); err != nil {
		return "", errors.New("AI 返回内容无法解析为 JSON")
	}
	return strings.TrimSpace(parsed.Query), nil
}

func buildSpaceSearchSystemPrompt(provider, engineName string) string {
	syntaxNotes := spaceSearchSyntaxNotes[provider]
	return strings.TrimSpace(fmt.Sprintf(`
你是“%s 查询语法生成器”。任务：把用户输入的自然语言搜索意图，转换成 %s 查询语法。

输出要求（非常重要）：
1) 只输出 JSON（不要 markdown、不要代码块、不要额外解释文本）
2) JSON 结构必须是：
{
  "query": "string，%s 查询语法（可直接粘贴到 %s 或本系统查询框）",
  "explanation": "string，可选，解释你如何映射字段/逻辑",
  "warnings": ["string"...] 可选，列出歧义/风险/需要人工确认的点
}
3) 如果用户输入本身已经是 %s 查询语法（或非常接近该语法的表达式），应当“原样返回”为 query：
   - 不要擅自改写字段名、操作符、括号结构
   - 不要改写任何字符串值（尤其是地理位置类值），不要做缩写/同义词替换/翻译/音译

当前搜索引擎语法速查：
%s

通用生成约束：
- 严格遵守“当前搜索引擎语法速查”里的字段名、操作符和示例风格；不同数据源语法不同，不要混用。
- 字符串值保持用户原意：不要无依据缩写、翻译、音译、替换同义词或改写大小写。
- 地理位置、组织名、产品名、域名、证书名、CVE 编号等实体值必须尽量保留原文；确需推断（如“中国”到 CN）时在 explanation 或 warnings 中说明。
- 不要捏造字段。不确定字段是否支持时，选择更通用且确定的字段，或把不确定点写进 warnings。
- 当用户描述里有多个与/或条件，必须使用该数据源支持的括号和逻辑操作符明确优先级。
- 如果用户输入已经是当前数据源查询语法或非常接近，应原样返回；只在明显有语法错误且能确定修复方式时轻微修正，并在 explanation 说明。
- 如果需求范围过大、关键目标缺失或语义矛盾，允许 query 为空字符串，并在 warnings 中明确需要补充的信息。
- 只生成资产测绘/信息收集查询语法，不生成扫描、利用、爆破、绕过、命令执行或攻击步骤。
`, engineName, engineName, engineName, engineName, engineName, syntaxNotes))
}

// spaceSearchSyntaxNotes 各引擎查询语法速查，与 handler 保持一致。
var spaceSearchSyntaxNotes = map[string]string{
	"fofa": `
FOFA 官方查询语法参考：
- 基本格式：field="value"，字符串值使用英文双引号；多个条件用 &&（与）、||（或）、!（非）连接。
- 组合优先级：复杂表达式必须使用 () 明确优先级，例如：(app="Apache" || app="nginx") && country="CN"。
- 常用字段：app、title、body、header、host、domain、ip、port、protocol、country、province、city、server、icp、cert、icon_hash、fid。
- 字段示例：
  - app="Apache"
  - title="后台管理"
  - body="Powered by"
  - header="JSESSIONID"
  - domain="example.com"
  - host="https://example.com"
  - ip="1.1.1.1"
  - port="443"
  - country="CN"
  - city="Hangzhou"
  - cert="example.com"
  - icon_hash="-247388890"
- 组合示例：
  - app="Apache" && country="CN"
  - title="login" || title="登录"
  - (app="Apache" || app="nginx") && port="443"
  - domain="example.com" && !title="404"
  - cert="example.com" && port="443"
  - header="JSESSIONID" && country="CN"
- 生成注意：
  - 用户说“排除/不要/非”时优先使用 !field="value"。
  - 用户说“标题包含/页面标题”映射为 title；说“正文包含/页面包含”映射为 body；说“响应头/cookie/header”映射为 header。
  - 端口在 FOFA 中通常写成 port="443"。
`,
	"zoomeye": `
ZoomEye 查询语法参考：
- 基本格式：field="value" 或 field=value；字符串/短语建议使用英文双引号。
- 逻辑连接：可使用 && / || / !，也可使用 AND / OR / NOT；复杂表达式使用 () 明确优先级。
- 常用字段：app、service、title、domain、hostname、ip、port、country、city、org、isp、asn、cidr、ssl、ssl.cert.fingerprint、iconhash。
- 字段示例：
  - app="Apache"
  - service="ssh"
  - title="登录"
  - domain="example.com"
  - hostname="example.com"
  - ip="1.1.1.1"
  - cidr="1.1.1.0/24"
  - port=443
  - country="CN"
  - city="Beijing"
  - org="Tencent"
  - ssl="example.com"
  - ssl.cert.fingerprint="F3C98F223D82CC41CF83D94671CCC6C69873FABF"
  - iconhash="-247388890"
- 组合示例：
  - app="nginx" && country="CN"
  - service="http" && (title="login" || title="登录")
  - domain="example.com" && !app="cloudflare"
  - port=443 && country="US"
  - app="Elasticsearch" && port=9200
- 生成注意：
  - 用户说“服务/协议是 SSH、HTTP、RDP”优先映射为 service。
  - 用户说“站点/网站标题”映射为 title；说“域名/主域”优先映射为 domain 或 hostname。
  - 端口可以不加引号，例如 port=443；如果用户原文已给出冒号风格表达式且接近 ZoomEye 语法，可原样保留。
`,
	"quake": `
Quake 查询语法参考：
- 基本格式：field:"value" 或 field:value；字符串/中文/短语使用英文双引号。
- 逻辑连接：使用 AND、OR、NOT；复杂表达式必须使用 () 明确优先级。
- 常用字段：domain、ip、port、service.name、service.http.title、service.http.server、service.http.response.header、service.http.favicon.hash、country_cn、province_cn、city_cn、location.country_cn、location.province_cn、location.city_cn、asn、org。
- 字段示例：
  - domain:"example.com"
  - ip:"1.1.1.1"
  - port:443
  - service.name:"http"
  - service.name:"ssh"
  - service.http.title:"登录"
  - service.http.server:"nginx"
  - service.http.response.header:"JSESSIONID"
  - service.http.favicon.hash:"-247388890"
  - country_cn:"中国"
  - province_cn:"浙江"
  - city_cn:"杭州"
- 组合示例：
  - service.name:"http" AND country_cn:"中国"
  - (service.name:"http" OR service.name:"https") AND port:443
  - domain:"example.com" AND NOT service.http.title:"404"
  - service.http.title:"login" AND port:443
  - service.name:"ssh" AND country_cn:"中国"
- 生成注意：
  - 用户说“中国/浙江/杭州”等中文地理位置时，Quake 优先使用 country_cn/province_cn/city_cn 并保留中文值。
  - 用户说“标题”映射为 service.http.title；说“Server/服务端软件”映射为 service.http.server；说“favicon/hash/icon”映射为 service.http.favicon.hash。
  - Quake 不使用 && / || 作为首选输出；优先输出 AND / OR / NOT。
`,
	"shodan": `
Shodan 官方查询语法参考：
- 默认裸关键词只搜索 banner 的 data 内容；精确条件使用 filter:value。
- filter 与 value 中间不能有空格；值包含空格时用英文双引号，例如 org:"Amazon Web Services"。
- 多个过滤器并列表示同时满足（AND）；Shodan 查询不要使用 &&、||，除非用户明确给出并要求保留。
- 常用过滤器：product、port、country、city、org、asn、hostname、net、ssl、ssl.cert.subject.cn、http.title、has_screenshot、vuln。
- 字段示例：
  - product:nginx
  - port:443
  - country:CN
  - city:Shanghai
  - org:"Amazon"
  - asn:AS15169
  - hostname:example.com
  - ssl.cert.subject.cn:example.com
  - http.title:"Dashboard"
  - has_screenshot:true
  - vuln:CVE-2021-41773
- 组合示例：
  - product:nginx country:CN
  - apache country:DE
  - org:"Amazon" port:443
  - ssl.cert.subject.cn:example.com port:443
  - http.title:"login" country:CN
  - ssl:true port:443 hostname:example.com
- 生成注意：
  - 用户说“产品/组件/服务软件”优先映射为 product；说“组织/公司/云厂商”映射为 org；说“证书 CN/SAN/域名证书”优先映射为 ssl.cert.subject.cn。
  - 国家用两位国家代码；如果用户给出中文国家名且无法确定代码，把推断写入 explanation 或 warnings。
  - Shodan 没有通用 NOT 排除语法；遇到“排除/不要”时应在 warnings 说明可能需要人工调整，不要强行编造过滤器。
`,
}

// extractNLJSONObject 从 LLM 输出里抽取首个有效 JSON 对象（兼容裸 JSON、
// ```json 代码块、以及前后带解释文本的情况）。
func extractNLJSONObject(content string) (string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return "", errors.New("empty content")
	}
	candidates := []string{content}
	if fenced := extractFencedJSON(content); fenced != "" {
		candidates = append([]string{fenced}, candidates...)
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if json.Valid([]byte(candidate)) {
			return candidate, nil
		}
		if obj := scanBalancedJSONObject(candidate); obj != "" && json.Valid([]byte(obj)) {
			return obj, nil
		}
	}
	return "", errors.New("json object not found")
}

func extractFencedJSON(content string) string {
	start := strings.Index(content, "```")
	if start < 0 {
		return ""
	}
	rest := content[start+3:]
	if nl := strings.Index(rest, "\n"); nl >= 0 {
		lang := strings.ToLower(strings.TrimSpace(rest[:nl]))
		if lang == "" || lang == "json" || strings.HasPrefix(lang, "json ") {
			rest = rest[nl+1:]
		}
	}
	end := strings.Index(rest, "```")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

func scanBalancedJSONObject(content string) string {
	start := strings.Index(content, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(content); i++ {
		ch := content[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch ch {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return strings.TrimSpace(content[start : i+1])
			}
		}
	}
	return ""
}
