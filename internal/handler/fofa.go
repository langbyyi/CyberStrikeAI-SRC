package handler

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
	openaiClient "cyberstrike-ai/internal/openai"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type FofaHandler struct {
	cfg          *config.Config
	logger       *zap.Logger
	client       *http.Client
	openAIClient *openaiClient.Client
}

func NewFofaHandler(cfg *config.Config, logger *zap.Logger) *FofaHandler {
	// LLM 请求通常比 FOFA 查询更慢一点，单独给一个更宽松的超时。
	llmHTTPClient := &http.Client{Timeout: 2 * time.Minute}
	var llmCfg *config.OpenAIConfig
	if cfg != nil {
		llmCfg = &cfg.OpenAI
	}
	return &FofaHandler{
		cfg:          cfg,
		logger:       logger,
		client:       &http.Client{Timeout: 60 * time.Second},
		openAIClient: openaiClient.NewClient(llmCfg, llmHTTPClient, logger),
	}
}

type fofaSearchRequest struct {
	Provider string `json:"provider,omitempty"`
	Query    string `json:"query" binding:"required"`
	Size     int    `json:"size,omitempty"`
	Page     int    `json:"page,omitempty"`
	Fields   string `json:"fields,omitempty"`
	Full     bool   `json:"full,omitempty"`
}

type fofaParseRequest struct {
	Provider string `json:"provider,omitempty"`
	Text     string `json:"text" binding:"required"`
}

type fofaParseResponse struct {
	Query       string   `json:"query"`
	Explanation string   `json:"explanation,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// fofaSearchResponse 复用 fofaruntime 的统一归一化结果类型，保证 handler HTTP
// 输出与 agent 工具同源（单一真相源），JSON 标签与历史响应格式一致。
type fofaSearchResponse = fofaruntime.SearchResponse

func normalizeSpaceSearchProvider(provider string) string {
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
		return ""
	}
}

func providerDisplayName(provider string) string {
	switch normalizeSpaceSearchProvider(provider) {
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
	switch normalizeSpaceSearchProvider(provider) {
	case "zoomeye":
		return "ip,port,domain,hostname,title,service,app,country,city"
	case "quake":
		return "ip,port,domain,service.name,service.http.title,location.country_cn,location.province_cn,location.city_cn"
	case "shodan":
		return "ip_str,port,hostnames,domains,org,isp,location.country_name,location.city,product,transport"
	default:
		return "host,ip,port,domain,title,protocol,country,province,city,server"
	}
}

func (h *FofaHandler) resolveAPIKey(provider string) string {
	// 优先环境变量（便于容器部署），其次配置文件。
	provider = normalizeSpaceSearchProvider(provider)
	envKey := map[string]string{
		"fofa":    "FOFA_API_KEY",
		"zoomeye": "ZOOMEYE_API_KEY",
		"quake":   "QUAKE_API_KEY",
		"shodan":  "SHODAN_API_KEY",
	}[provider]
	if apiKey := strings.TrimSpace(os.Getenv(envKey)); apiKey != "" {
		return apiKey
	}
	if h.cfg != nil {
		switch provider {
		case "zoomeye":
			return strings.TrimSpace(h.cfg.ZoomEye.APIKey)
		case "quake":
			return strings.TrimSpace(h.cfg.Quake.APIKey)
		case "shodan":
			return strings.TrimSpace(h.cfg.Shodan.APIKey)
		default:
			return strings.TrimSpace(h.cfg.FOFA.APIKey)
		}
	}
	return ""
}

// canonicalizeSpaceSearchBaseURL 迁移引擎旧域名（api.zoomeye.org → api.zoomeye.ai、
// quake.360.cn → quake.360.net），用户 config.yaml 里的旧地址自动改写。
func canonicalizeSpaceSearchBaseURL(provider, raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return v
	}
	switch normalizeSpaceSearchProvider(provider) {
	case "zoomeye":
		v = strings.Replace(v, "://api.zoomeye.org", "://api.zoomeye.ai", 1)
	case "quake":
		v = strings.Replace(v, "://quake.360.cn", "://quake.360.net", 1)
	}
	return v
}

func (h *FofaHandler) resolveBaseURL(provider string) string {
	if h.cfg != nil {
		switch normalizeSpaceSearchProvider(provider) {
		case "zoomeye":
			if v := strings.TrimSpace(h.cfg.ZoomEye.BaseURL); v != "" {
				return canonicalizeSpaceSearchBaseURL(provider, v)
			}
		case "quake":
			if v := strings.TrimSpace(h.cfg.Quake.BaseURL); v != "" {
				return canonicalizeSpaceSearchBaseURL(provider, v)
			}
		case "shodan":
			if v := strings.TrimSpace(h.cfg.Shodan.BaseURL); v != "" {
				return v
			}
		default:
			if v := strings.TrimSpace(h.cfg.FOFA.BaseURL); v != "" {
				return v
			}
		}
	}
	switch normalizeSpaceSearchProvider(provider) {
	case "zoomeye":
		return "https://api.zoomeye.ai/v2/search"
	case "quake":
		return "https://quake.360.net/api/v3/search/quake_service"
	case "shodan":
		return "https://api.shodan.io"
	default:
		return "https://fofa.info/api/v1/search/all"
	}
}

// ParseNaturalLanguage 将自然语言解析为 FOFA 查询语法（仅生成，不执行查询）
func (h *FofaHandler) ParseNaturalLanguage(c *gin.Context) {
	var req fofaParseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
		return
	}
	req.Text = strings.TrimSpace(req.Text)
	provider := normalizeSpaceSearchProvider(req.Provider)
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider 不支持，可选：fofa、zoomeye、quake、shodan"})
		return
	}
	if req.Text == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "text 不能为空"})
		return
	}

	if h.cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "系统配置未初始化"})
		return
	}
	if strings.TrimSpace(h.cfg.OpenAI.APIKey) == "" || strings.TrimSpace(h.cfg.OpenAI.Model) == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "未配置 AI 模型：请在系统设置中填写 openai.api_key 与 openai.model（支持 OpenAI 兼容 API，如 DeepSeek）",
			"need":  []string{"openai.api_key", "openai.model"},
		})
		return
	}
	if h.openAIClient == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI 客户端未初始化"})
		return
	}

	engineName := providerDisplayName(provider)
	syntaxNotes := map[string]string{
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
	}[provider]

	systemPrompt := strings.TrimSpace(fmt.Sprintf(`
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

	userPrompt := fmt.Sprintf("自然语言意图：%s", req.Text)

	requestBody := map[string]interface{}{
		"model": h.cfg.OpenAI.Model,
		"messages": []map[string]interface{}{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature":           0.1,
		"max_completion_tokens": 12000,
	}

	// OpenAI 返回结构：只需要 choices[0].message.content
	var apiResponse struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 90*time.Second)
	defer cancel()

	if err := h.openAIClient.ChatCompletion(ctx, requestBody, &apiResponse); err != nil {
		var apiErr *openaiClient.APIError
		if errors.As(err, &apiErr) {
			h.logger.Warn("FOFA自然语言解析：LLM返回错误", zap.Int("status", apiErr.StatusCode))
			c.JSON(http.StatusBadGateway, gin.H{"error": "AI 解析失败（上游返回非 200），请检查模型配置或稍后重试"})
			return
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": "AI 解析失败: " + err.Error()})
		return
	}
	if len(apiResponse.Choices) == 0 {
		c.JSON(http.StatusBadGateway, gin.H{"error": "AI 未返回有效结果"})
		return
	}

	content := strings.TrimSpace(apiResponse.Choices[0].Message.Content)
	jsonContent, extractErr := extractInfoCollectJSONObject(content)
	if extractErr != nil {
		snippet := trimSnippet(content, 1200)
		c.JSON(http.StatusBadGateway, gin.H{
			"error":   "AI 返回内容无法解析为 JSON，请稍后重试或换个描述方式",
			"snippet": snippet,
		})
		return
	}

	var parsed fofaParseResponse
	if err := json.Unmarshal([]byte(jsonContent), &parsed); err != nil {
		// 直接回传一部分原文，方便排查，但避免太大
		snippet := trimSnippet(content, 1200)
		c.JSON(http.StatusBadGateway, gin.H{
			"error":   "AI 返回内容无法解析为 JSON，请稍后重试或换个描述方式",
			"snippet": snippet,
		})
		return
	}
	parsed.Query = strings.TrimSpace(parsed.Query)
	if parsed.Query == "" {
		// query 允许为空（表示需求不明确），但前端需要明确提示
		if len(parsed.Warnings) == 0 {
			parsed.Warnings = []string{"需求信息不足，未能生成可用的 " + engineName + " 查询语法，请补充关键条件（如国家/端口/产品/域名等）。"}
		}
	}

	c.JSON(http.StatusOK, parsed)
}

func extractInfoCollectJSONObject(content string) (string, error) {
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

func trimSnippet(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes])
}

// fofaHasAnyCredential 判断 FOFA 是否配置了任一有效凭据：顶层 APIKey、环境变量，
// 或任一 endpoint 的 key / bearer token（多端点配置时凭据挂在 endpoint 上）。
func (h *FofaHandler) fofaHasAnyCredential() bool {
	if h.cfg == nil {
		return false
	}
	if strings.TrimSpace(h.cfg.FOFA.APIKey) != "" || strings.TrimSpace(os.Getenv("FOFA_API_KEY")) != "" {
		return true
	}
	for _, ep := range h.cfg.FOFA.Endpoints {
		if strings.TrimSpace(ep.APIKey) != "" || strings.TrimSpace(ep.BearerToken) != "" {
			return true
		}
	}
	return false
}

// resolveFofaRuntime 按最新配置懒加载 FOFA runtime，与 MCP fofa_search 工具共用
// 同一 runtime（多端点 fallback / key|bearer 鉴权 / TLS 策略），Web 界面改动即时生效。
func (h *FofaHandler) resolveFofaRuntime() (*fofaruntime.Runtime, error) {
	if h.cfg == nil {
		return nil, errors.New("系统配置未初始化")
	}
	if !h.fofaHasAnyCredential() {
		return nil, errors.New("FOFA 未配置 API Key（请在系统设置中填写，或设置环境变量 FOFA_API_KEY）")
	}
	return fofaruntime.New(h.cfg.FOFA, strings.TrimSpace(os.Getenv("FOFA_API_KEY")))
}

// Search FOFA 查询（后端代理，避免前端暴露 key）
func (h *FofaHandler) Search(c *gin.Context) {
	var req fofaSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
		return
	}
	provider := normalizeSpaceSearchProvider(req.Provider)
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider 不支持，可选：fofa、zoomeye、quake、shodan"})
		return
	}

	req.Query = strings.TrimSpace(req.Query)
	if req.Query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query 不能为空"})
		return
	}
	if req.Size <= 0 {
		req.Size = 100
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	// FOFA 接口 size 上限和账户权限相关，这里只做一个合理的保护
	if req.Size > 10000 {
		req.Size = 10000
	}
	if req.Fields == "" {
		req.Fields = defaultFieldsForProvider(provider)
	}

	if provider != "fofa" {
		h.searchExternalProvider(c, provider, req)
		return
	}

	runtime, err := h.resolveFofaRuntime()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := runtime.SearchByProvider(c.Request.Context(), "fofa", fofaruntime.SearchRequest{
		Query: req.Query, Size: req.Size, Page: req.Page, Fields: req.Fields, Full: req.Full,
	})
	if err != nil {
		h.logger.Warn("FOFA 搜索失败", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *FofaHandler) searchExternalProvider(c *gin.Context, provider string, req fofaSearchRequest) {
	apiKey := h.resolveAPIKey(provider)
	if apiKey == "" {
		envKey := map[string]string{
			"zoomeye": "ZOOMEYE_API_KEY",
			"quake":   "QUAKE_API_KEY",
			"shodan":  "SHODAN_API_KEY",
		}[provider]
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   providerDisplayName(provider) + " 未配置：请在 config.yaml 中填写 api_key，或设置环境变量 " + envKey,
			"need":    []string{provider + ".api_key"},
			"env_key": []string{envKey},
		})
		return
	}

	switch provider {
	case "zoomeye":
		h.searchZoomEye(c, req, apiKey)
	case "quake":
		h.searchQuake(c, req, apiKey)
	case "shodan":
		h.searchShodan(c, req, apiKey)
	}
}

func (h *FofaHandler) searchZoomEye(c *gin.Context, req fofaSearchRequest, apiKey string) {
	resp, err := fofaruntime.SearchZoomEyeNative(c.Request.Context(), h.client, h.resolveBaseURL("zoomeye"), apiKey,
		fofaruntime.SearchRequest{Query: req.Query, Size: req.Size, Page: req.Page, Fields: req.Fields, Full: req.Full})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *FofaHandler) searchQuake(c *gin.Context, req fofaSearchRequest, apiKey string) {
	resp, err := fofaruntime.SearchQuakeNative(c.Request.Context(), h.client, h.resolveBaseURL("quake"), apiKey,
		fofaruntime.SearchRequest{Query: req.Query, Size: req.Size, Page: req.Page, Fields: req.Fields, Full: req.Full})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *FofaHandler) searchShodan(c *gin.Context, req fofaSearchRequest, apiKey string) {
	resp, err := fofaruntime.SearchShodanNative(c.Request.Context(), h.client, h.resolveBaseURL("shodan"), apiKey,
		fofaruntime.SearchRequest{Query: req.Query, Size: req.Size, Page: req.Page, Fields: req.Fields, Full: req.Full})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

