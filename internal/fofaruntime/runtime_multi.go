package fofaruntime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultQuakeBaseURL   = "https://quake.360.net/api/v3/search/quake_service"
	defaultShodanBaseURL  = "https://api.shodan.io"
	defaultZoomEyeBaseURL = "https://api.zoomeye.ai/v2/search"

	quakeSuccessCode      = 0
	zoomeyeSuccessCode    = 60000
	shodanPageLimit       = 100
	shodanMaxResultLimit  = 1000
	nativeRequestUA       = "CyberStrikeAI/1.7"
	nativeProviderTimeout = 60 * time.Second
)

// canonicalizeLegacyProviderBaseURL 迁移引擎旧域名：ZoomEye api.zoomeye.org →
// api.zoomeye.ai，Quake quake.360.cn → quake.360.net（官方 v1.7.15 域名切换，
// 用户 config.yaml 里的旧地址自动改写，无需手工升级）。
func canonicalizeLegacyProviderBaseURL(baseURL string) string {
	v := strings.TrimSpace(baseURL)
	if v == "" {
		return v
	}
	v = strings.Replace(v, "://api.zoomeye.org", "://api.zoomeye.ai", 1)
	v = strings.Replace(v, "://quake.360.cn", "://quake.360.net", 1)
	return v
}

// SearchResponse 是所有空间测绘引擎的统一归一化结果。
// Provider="fofa" 时 Results 为按 fields 投影后的键值映射；quake/shodan/zoomeye
// 为各自原生响应经 dot-path 投影后的键值映射。JSON 标签与 handler 的历史响应
// 格式保持一致，确保 HTTP API 行为不变。
type SearchResponse struct {
	Provider      string                   `json:"provider,omitempty"`
	Query         string                   `json:"query"`
	Size          int                      `json:"size"`
	Page          int                      `json:"page"`
	Total         int                      `json:"total"`
	Fields        []string                 `json:"fields"`
	ResultsCount  int                      `json:"results_count"`
	ExpectedCount int                      `json:"expected_count,omitempty"`
	Shortfall     int                      `json:"shortfall,omitempty"`
	Warning       string                   `json:"warning,omitempty"`
	Results       []map[string]interface{} `json:"results"`
}

// NormalizeProvider 与 app.normalizeFOFAProvider / handler.normalizeSpaceSearchProvider
// 保持一致：非法值兜底为 fofa，保证调用方始终拿到可用引擎。
func NormalizeProvider(provider string) string {
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

// SearchByProvider 是多引擎统一入口，按 provider 分发到对应原生协议：
//   - fofa    → 现有 FOFA 协议（qbase64+key GET，多端点 fallback），结果归一化
//   - quake   → POST JSON，header X-QuakeToken
//   - shodan  → GET /shodan/host/search，param key/query/page，分页 100/页
//   - zoomeye → POST JSON，header API-KEY
//
// 非出厂 baseURL/凭据由调用方通过 New(config.FofaConfig{BaseURL, APIKey}) 注入；
// runtime 按快照端点的 baseURL/apiKey/client 执行请求。
func (r *Runtime) SearchByProvider(ctx context.Context, provider string, request SearchRequest) (*SearchResponse, error) {
	if r == nil {
		return nil, errors.New("空间测绘 runtime 未初始化")
	}
	current := r.current.Load()
	if current == nil || len(current.endpoints) == 0 {
		return nil, errors.New("空间测绘未配置有效端点")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		timeout := current.timeout
		if timeout <= 0 {
			timeout = nativeProviderTimeout
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	switch NormalizeProvider(provider) {
	case "fofa":
		// 复用既有 FOFA 协议实现（多端点 fallback / key|bearer 鉴权），仅做归一化包装。
		resp, err := r.Search(ctx, request)
		if err != nil {
			return nil, err
		}
		return normalizeFOFAResponse(resp, request), nil
	case "quake":
		return runNative(ctx, current, request, SearchQuakeNative)
	case "shodan":
		return runNative(ctx, current, request, SearchShodanNative)
	case "zoomeye":
		return runNative(ctx, current, request, SearchZoomEyeNative)
	}
	return nil, errors.New("unsupported provider: " + provider)
}

// nativeSearchFunc 是单端点原生协议函数的统一签名。
type nativeSearchFunc func(ctx context.Context, client *http.Client, baseURL, apiKey string, request SearchRequest) (*SearchResponse, error)

// runNative 在快照端点上依次尝试原生协议，直到成功。非 fofa 引擎通常单端点，
// 但保留 fallback 语义以便未来扩展多端点。
func runNative(ctx context.Context, snap *snapshot, request SearchRequest, fn nativeSearchFunc) (*SearchResponse, error) {
	var lastErr error
	for _, ep := range snap.endpoints {
		if ep.apiKey == "" {
			lastErr = errors.New("空间测绘端点缺少鉴权凭据")
			continue
		}
		resp, err := fn(ctx, ep.client, ep.baseURL, ep.apiKey, request)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("空间测绘未配置可用端点")
	}
	return nil, lastErr
}

// isQuakeSuccessCode 判断 Quake 返回 code 是否为成功（0）；
// Quake 偶尔以字符串形式返回 code，需同时容忍数字与 "0" 字符串。
func isQuakeSuccessCode(code interface{}) bool {
	switch v := code.(type) {
	case nil:
		return false
	case int:
		return v == quakeSuccessCode
	case int64:
		return v == quakeSuccessCode
	case float64:
		return v == quakeSuccessCode
	case string:
		return strings.TrimSpace(v) == "0"
	default:
		return false
	}
}

// isZoomEyeSuccessCode 判断 ZoomEye code 是否成功（60000）；官方 v1.7.16 起
// code 兼容字符串形式，且 code 缺失/为 0 时按 message 判定（迁移自官方）。
func isZoomEyeSuccessCode(code interface{}) bool {
	switch v := code.(type) {
	case int:
		return v == zoomeyeSuccessCode
	case int64:
		return v == zoomeyeSuccessCode
	case float64:
		return v == zoomeyeSuccessCode
	case string:
		return strings.TrimSpace(v) == "60000"
	default:
		return false
	}
}

func isZeroSpaceSearchCode(code interface{}) bool {
	switch v := code.(type) {
	case int:
		return v == 0
	case int64:
		return v == 0
	case float64:
		return v == 0
	case string:
		return strings.TrimSpace(v) == "0"
	default:
		return false
	}
}

func zoomEyeRequestFailed(code interface{}, message string) bool {
	if isZoomEyeSuccessCode(code) {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(message))
	if code == nil || isZeroSpaceSearchCode(code) {
		return msg != "" && msg != "success" && msg != "ok" && msg != "successful."
	}
	return true
}

// SearchQuakeNative 按 Quake 原生协议搜索：POST JSON，header X-QuakeToken，
// body {query,size,start,latest,include}，解析 code/message/total_count/data。
func SearchQuakeNative(ctx context.Context, client *http.Client, baseURL, apiKey string, request SearchRequest) (*SearchResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultQuakeBaseURL
	}
	baseURL = canonicalizeLegacyProviderBaseURL(baseURL)
	baseURL = ensureSearchPath(baseURL, "/api/v3/search/quake_service")
	fields := splitAndCleanCSV(request.Fields)
	body := map[string]interface{}{
		"query":  request.Query,
		"size":   request.Size,
		"start":  (request.Page - 1) * request.Size,
		"latest": request.Full,
	}
	if len(fields) > 0 {
		body["include"] = fields
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("创建 Quake 请求失败: " + err.Error())
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("创建 Quake 请求失败: " + err.Error())
	}
	httpReq.Header.Set("User-Agent", nativeRequestUA)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-QuakeToken", apiKey)

	data, err := doAndReadAll(ctx, client, httpReq, "Quake")
	if err != nil {
		return nil, err
	}
	var apiResp struct {
		Code       interface{}     `json:"code"`
		Message    string          `json:"message"`
		TotalCount int             `json:"total_count"`
		Data       json.RawMessage `json:"data"`
		Meta       struct {
			Pagination struct {
				Total int `json:"total"`
			} `json:"pagination"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(data, &apiResp); err != nil {
		return nil, errors.New("解析 Quake 响应失败: " + err.Error())
	}
	if !isQuakeSuccessCode(apiResp.Code) {
		msg := firstNonEmpty(apiResp.Message, spaceSearchMessageFromRawObject(apiResp.Data), "Quake 返回错误")
		return nil, errors.New(msg)
	}
	rows, err := decodeSpaceSearchRows(apiResp.Data)
	if err != nil {
		return nil, errors.New("解析 Quake 响应失败: " + err.Error())
	}
	total := firstPositive(apiResp.TotalCount, apiResp.Meta.Pagination.Total)
	results := projectRows(rows, fields)
	return &SearchResponse{
		Provider: "quake", Query: request.Query, Size: request.Size, Page: request.Page,
		Total: total, Fields: fields, ResultsCount: len(results), Results: results,
	}, nil
}

// SearchShodanNative 按 Shodan 原生协议搜索：GET /shodan/host/search，
// param key/query/page/minify，每页上限 100，自动翻页直到达到 size。解析 total/matches。
func SearchShodanNative(ctx context.Context, client *http.Client, baseURL, apiKey string, request SearchRequest) (*SearchResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultShodanBaseURL
	}
	baseURL = ensureSearchPath(baseURL, "/shodan/host/search")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.New("Shodan base_url 无效: " + err.Error())
	}
	targetSize := request.Size
	if targetSize <= 0 {
		targetSize = shodanPageLimit
	}
	if targetSize > shodanMaxResultLimit {
		targetSize = shodanMaxResultLimit
	}
	page := request.Page
	if page < 1 {
		page = 1
	}
	fieldsCSV := strings.TrimSpace(request.Fields)
	fields := splitAndCleanCSV(request.Fields)
	pagesNeeded := (targetSize + shodanPageLimit - 1) / shodanPageLimit
	matches := make([]map[string]interface{}, 0, targetSize)
	total := 0
	for i := 0; i < pagesNeeded; i++ {
		pageURL := *u
		params := pageURL.Query()
		params.Set("key", apiKey)
		params.Set("query", request.Query)
		params.Set("page", fmt.Sprintf("%d", page+i))
		params.Set("minify", "false")
		if fieldsCSV != "" {
			params.Set("fields", fieldsCSV)
		}
		pageURL.RawQuery = params.Encode()
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL.String(), nil)
		if err != nil {
			return nil, errors.New("创建 Shodan 请求失败: " + err.Error())
		}
		httpReq.Header.Set("User-Agent", nativeRequestUA)
		httpReq.Header.Set("Accept", "application/json")
		data, err := doAndReadAll(ctx, client, httpReq, "Shodan")
		if err != nil {
			return nil, err
		}
		var apiResp struct {
			Total   int                      `json:"total"`
			Matches []map[string]interface{} `json:"matches"`
			Error   string                   `json:"error"`
		}
		if err := json.Unmarshal(data, &apiResp); err != nil {
			return nil, errors.New("解析 Shodan 响应失败: " + err.Error())
		}
		if strings.TrimSpace(apiResp.Error) != "" {
			return nil, errors.New(apiResp.Error)
		}
		total = apiResp.Total
		if len(apiResp.Matches) == 0 {
			break
		}
		matches = append(matches, apiResp.Matches...)
		if len(matches) >= targetSize {
			matches = matches[:targetSize]
			break
		}
	}
	expectedCount := shodanExpectedResultCount(total, page, targetSize)
	shortfall := expectedCount - len(matches)
	warning := ""
	if shortfall > 0 {
		warning = fmt.Sprintf("Shodan 统计总数为 %d，但本次分页实际只返回 %d/%d 条明细", total, len(matches), expectedCount)
	}
	results := projectRows(matches, fields)
	return &SearchResponse{
		Provider: "shodan", Query: request.Query, Size: targetSize, Page: page,
		Total: total, Fields: fields, ResultsCount: len(results),
		ExpectedCount: expectedCount, Shortfall: max(0, shortfall), Warning: warning,
		Results: results,
	}, nil
}

// SearchZoomEyeNative 按 ZoomEye 原生协议搜索：POST JSON，header API-KEY，
// body {qbase64,page,pagesize,fields?}，解析 code/message/total/data（code==60000 为成功）。
func SearchZoomEyeNative(ctx context.Context, client *http.Client, baseURL, apiKey string, request SearchRequest) (*SearchResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultZoomEyeBaseURL
	}
	baseURL = canonicalizeLegacyProviderBaseURL(baseURL)
	baseURL = ensureSearchPath(baseURL, "/v2/search")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.New("ZoomEye base_url 无效: " + err.Error())
	}
	fields := splitAndCleanCSV(request.Fields)
	body := map[string]interface{}{
		"qbase64":  base64.StdEncoding.EncodeToString([]byte(request.Query)),
		"page":     request.Page,
		"pagesize": request.Size,
	}
	if fieldsCSV := strings.TrimSpace(request.Fields); fieldsCSV != "" {
		body["fields"] = fieldsCSV
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("创建 ZoomEye 请求失败: " + err.Error())
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("创建 ZoomEye 请求失败: " + err.Error())
	}
	httpReq.Header.Set("User-Agent", nativeRequestUA)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("API-KEY", apiKey)

	data, err := doAndReadAll(ctx, client, httpReq, "ZoomEye")
	if err != nil {
		return nil, err
	}
	var apiResp struct {
		Code     interface{}     `json:"code"`
		Message  string          `json:"message"`
		Query    string          `json:"query"`
		Total    int             `json:"total"`
		Page     int             `json:"page"`
		PageSize int             `json:"pagesize"`
		Data     json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &apiResp); err != nil {
		return nil, errors.New("解析 ZoomEye 响应失败: " + err.Error())
	}
	if zoomEyeRequestFailed(apiResp.Code, apiResp.Message) {
		msg := firstNonEmpty(apiResp.Message, spaceSearchMessageFromRawObject(apiResp.Data), "ZoomEye 返回错误")
		return nil, errors.New(msg)
	}
	rows, err := decodeSpaceSearchRows(apiResp.Data)
	if err != nil {
		return nil, errors.New("解析 ZoomEye 响应失败: " + err.Error())
	}
	results := projectRows(rows, fields)
	return &SearchResponse{
		Provider: "zoomeye",
		Query:    firstNonEmpty(apiResp.Query, request.Query),
		Size:     firstPositive(apiResp.PageSize, request.Size),
		Page:     firstPositive(apiResp.Page, request.Page),
		Total:    apiResp.Total, Fields: fields, ResultsCount: len(results), Results: results,
	}, nil
}

// decodeSpaceSearchRows 解析引擎返回的 data 字段（官方 v1.7.16 引入的多形态容错）：
// 直接数组 [...]、嵌套对象 {data|items|matches|results|list|records: [...]} 均可，
// 空值/null 返回空集。域名迁移伴随的 API 形态变化不再导致解析失败。
func decodeSpaceSearchRows(raw json.RawMessage) ([]map[string]interface{}, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	switch raw[0] {
	case '[':
		var rows []map[string]interface{}
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, err
		}
		if rows == nil {
			return []map[string]interface{}{}, nil
		}
		return rows, nil
	case '{':
		var obj map[string]interface{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, err
		}
		for _, key := range []string{"data", "items", "matches", "results", "list", "records"} {
			nested, ok := obj[key]
			if !ok {
				continue
			}
			if slice, ok := nested.([]interface{}); ok {
				return interfaceSliceToRowMaps(slice), nil
			}
		}
		return []map[string]interface{}{}, nil
	default:
		return nil, fmt.Errorf("unexpected JSON value")
	}
}

func interfaceSliceToRowMaps(slice []interface{}) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0, len(slice))
	for _, item := range slice {
		if m, ok := item.(map[string]interface{}); ok {
			rows = append(rows, m)
		}
	}
	return rows
}

// spaceSearchMessageFromRawObject 从 data 字段为对象时提取错误信息（message/error/errmsg/msg），
// 部分引擎失败时把错误详情放在 data 里而非顶层 message。
func spaceSearchMessageFromRawObject(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return ""
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	for _, key := range []string{"message", "error", "errmsg", "msg"} {
		if s, ok := obj[key].(string); ok {
			if msg := strings.TrimSpace(s); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// normalizeFOFAResponse 把 FOFA 协议返回的 [][]interface{} 结果按 fields 投影为
// 统一的 []map[string]interface{}。
func normalizeFOFAResponse(resp *Response, request SearchRequest) *SearchResponse {
	fields := splitAndCleanCSV(request.Fields)
	results := make([]map[string]interface{}, 0, len(resp.Results))
	for _, row := range resp.Results {
		item := make(map[string]interface{}, len(fields))
		for i, f := range fields {
			if i < len(row) {
				item[f] = row[i]
			} else {
				item[f] = nil
			}
		}
		results = append(results, item)
	}
	return &SearchResponse{
		Provider: "fofa", Query: resp.Query, Size: resp.Size, Page: resp.Page,
		Total: resp.Total, Fields: fields, ResultsCount: len(results), Results: results,
	}
}

// doAndReadAll 执行请求并读取有限长度的响应体，统一处理网络错误与 HTTP 状态码。
func doAndReadAll(ctx context.Context, client *http.Client, httpReq *http.Request, label string) ([]byte, error) {
	resp, err := client.Do(httpReq)
	if err != nil {
		if isContextTimeout(ctx, err) {
			return nil, fmt.Errorf("%s 请求超时，请稍后重试或减少返回数量", label)
		}
		return nil, fmt.Errorf("无法连接 %s 服务，请检查网络或代理配置", label)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if readErr != nil {
		return nil, fmt.Errorf("读取 %s 响应失败: %v", label, readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s 返回非 2xx: %d", label, resp.StatusCode)
	}
	return data, nil
}

func isContextTimeout(ctx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if ctx != nil && ctx.Err() == context.DeadlineExceeded {
		return true
	}
	return false
}

// shodanExpectedResultCount 计算从给定页起始、按 Shodan 每页 100 条预期可拿到的明细数。
func shodanExpectedResultCount(total, page, size int) int {
	if total <= 0 || size <= 0 {
		return 0
	}
	if page <= 0 {
		page = 1
	}
	startOffset := (page - 1) * shodanPageLimit
	remaining := total - startOffset
	if remaining <= 0 {
		return 0
	}
	if remaining < size {
		return remaining
	}
	return size
}

// ensureSearchPath 自动补齐 API 路径：仅当 baseURL 为域名根（path 为空或 "/"）时
// 拼接 defaultPath，保留用户自定义的完整路径。例如 fofa 的 https://fofoapi.com
// 会补齐为 https://fofoapi.com/api/v1/search/all，避免请求落到前端页面。
// 解析失败或 baseURL 为空时原样返回，交由调用方兜底。
func ensureSearchPath(baseURL, defaultPath string) string {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return ""
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" {
		return baseURL
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return baseURL
	}
	parsed.Path = defaultPath
	parsed.RawPath = ""
	return parsed.String()
}

func splitAndCleanCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// projectRows 按.fields（支持 service.http.title 这样的 dot-path）从原生行投影出键值映射。
func projectRows(rows []map[string]interface{}, fields []string) []map[string]interface{} {
	if len(fields) == 0 {
		return rows
	}
	out := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		item := make(map[string]interface{}, len(fields))
		for _, field := range fields {
			item[field] = valueByPath(row, field)
		}
		out = append(out, item)
	}
	return out
}

func valueByPath(row map[string]interface{}, path string) interface{} {
	if row == nil {
		return nil
	}
	if v, ok := row[path]; ok {
		return v
	}
	parts := strings.Split(path, ".")
	var current interface{} = row
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current, ok = m[part]
		if !ok {
			return nil
		}
	}
	return current
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
