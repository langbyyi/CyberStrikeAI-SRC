// Package fofaruntime owns FOFA endpoint selection, authentication, TLS and
// fallback behavior. Callers publish immutable configurations atomically, so
// a request cannot combine fields from different config generations.
package fofaruntime

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"cyberstrike-ai/internal/config"
)

const (
	defaultBaseURL  = "https://fofa.info/api/v1/search/all"
	defaultAPIPath  = "/api/v1/search/all"
	maxEndpoints    = 8
	maxResponseSize = 8 << 20
)

type SearchRequest struct {
	Query  string
	Size   int
	Page   int
	Fields string
	Full   bool
}

type Response struct {
	Error   bool            `json:"error"`
	ErrMsg  string          `json:"errmsg"`
	Size    int             `json:"size"`
	Page    int             `json:"page"`
	Total   int             `json:"total"`
	Mode    string          `json:"mode"`
	Query   string          `json:"query"`
	Results [][]interface{} `json:"results"`
}

type endpoint struct {
	baseURL     string
	authMode    string
	apiKey      string
	email       string
	bearerToken string
	verifySSL   bool
	client      *http.Client
}

type snapshot struct {
	endpoints []endpoint
	timeout   time.Duration
}

type Runtime struct {
	current atomic.Pointer[snapshot]
}

func New(cfg config.FofaConfig, environmentAPIKey string) (*Runtime, error) {
	runtime := &Runtime{}
	if err := runtime.Update(cfg, environmentAPIKey); err != nil {
		return nil, err
	}
	return runtime, nil
}

// Update validates and atomically publishes a complete immutable generation.
func (r *Runtime) Update(cfg config.FofaConfig, environmentAPIKey string) error {
	if r == nil {
		return errors.New("FOFA runtime 未初始化")
	}
	next, err := buildSnapshot(cfg, environmentAPIKey)
	if err != nil {
		return err
	}
	previous := r.current.Swap(next)
	if previous != nil {
		previous.closeIdleConnections()
	}
	return nil
}

func buildSnapshot(cfg config.FofaConfig, environmentAPIKey string) (*snapshot, error) {
	timeout := 30 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}
	if timeout > 5*time.Minute {
		return nil, errors.New("FOFA timeout_seconds 不得超过 300")
	}

	configured := append([]config.FofaEndpointConfig(nil), cfg.Endpoints...)
	if len(configured) == 0 {
		baseURL := strings.TrimSpace(cfg.BaseURL)
		if baseURL == "" {
			baseURL = defaultBaseURL
		}
		urls := append([]string{baseURL}, cfg.FallbackBaseURLs...)
		apiKey := strings.TrimSpace(environmentAPIKey)
		if apiKey == "" {
			apiKey = strings.TrimSpace(cfg.APIKey)
		}
		for _, baseURL := range urls {
			configured = append(configured, config.FofaEndpointConfig{
				BaseURL: baseURL, AuthMode: cfg.AuthMode, APIKey: apiKey, Email: cfg.Email,
				BearerToken: cfg.BearerToken, VerifySSL: cfg.VerifySSL,
			})
		}
	}
	if len(configured) > maxEndpoints {
		return nil, fmt.Errorf("FOFA endpoints 最多允许 %d 个", maxEndpoints)
	}

	endpoints := make([]endpoint, 0, len(configured))
	seen := make(map[string]struct{}, len(configured))
	for index, item := range configured {
		rawURL := strings.TrimSpace(item.BaseURL)
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("FOFA endpoint[%d] 不是有效的 HTTP(S) URL", index)
		}
		if parsed.Scheme == "http" && !item.AllowInsecureHTTP && !isLoopbackHost(parsed.Hostname()) {
			return nil, fmt.Errorf("FOFA endpoint[%d] 使用 HTTP，需显式 allow_insecure_http=true", index)
		}
		if _, duplicate := seen[rawURL]; duplicate {
			continue
		}
		seen[rawURL] = struct{}{}

		mode := strings.ToLower(strings.TrimSpace(item.AuthMode))
		if mode == "" || mode == "auto" {
			if strings.TrimSpace(item.BearerToken) != "" {
				mode = "bearer"
			} else {
				mode = "key"
			}
		}
		if mode != "key" && mode != "bearer" {
			return nil, fmt.Errorf("FOFA endpoint[%d] auth_mode 无效: %s", index, mode)
		}
		verifySSL := true
		if item.VerifySSL != nil {
			verifySSL = *item.VerifySSL
		}
		endpoints = append(endpoints, endpoint{
			baseURL: rawURL, authMode: mode, apiKey: strings.TrimSpace(item.APIKey),
			email: strings.TrimSpace(item.Email), bearerToken: strings.TrimSpace(item.BearerToken), verifySSL: verifySSL,
			client: newHTTPClient(timeout, verifySSL),
		})
	}
	if len(endpoints) == 0 {
		return nil, errors.New("FOFA 未配置有效端点")
	}
	return &snapshot{endpoints: endpoints, timeout: timeout}, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	return net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

// Search loads exactly one generation and uses it for the entire fallback
// sequence. Credentials are owned by individual endpoints.
func (r *Runtime) Search(ctx context.Context, request SearchRequest) (*Response, error) {
	if r == nil {
		return nil, errors.New("FOFA runtime 未初始化")
	}
	current := r.current.Load()
	if current == nil || len(current.endpoints) == 0 {
		return nil, errors.New("FOFA 未配置有效端点")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, current.timeout)
		defer cancel()
	}

	queryBase64 := base64.StdEncoding.EncodeToString([]byte(request.Query))
	lastMessage := "FOFA 请求失败"
	for _, endpoint := range current.endpoints {
		credential := endpoint.apiKey
		if endpoint.authMode == "bearer" {
			credential = endpoint.bearerToken
		}
		if credential == "" {
			lastMessage = "FOFA 端点缺少鉴权凭据"
			continue
		}
		parsed, _ := url.Parse(ensureSearchPath(endpoint.baseURL, defaultAPIPath))
		params := parsed.Query()
		params.Set("qbase64", queryBase64)
		params.Set("size", fmt.Sprintf("%d", request.Size))
		params.Set("page", fmt.Sprintf("%d", request.Page))
		params.Set("fields", strings.TrimSpace(request.Fields))
		params.Set("full", fmt.Sprintf("%t", request.Full))
		if endpoint.authMode == "key" {
			params.Set("key", credential)
			if endpoint.email != "" {
				params.Set("email", endpoint.email)
			}
		}
		parsed.RawQuery = params.Encode()
		httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			lastMessage = "创建 FOFA 请求失败"
			continue
		}
		httpRequest.Header.Set("Accept", "application/json")
		httpRequest.Header.Set("User-Agent", "CyberStrikeAI/1.7")
		if endpoint.authMode == "bearer" {
			httpRequest.Header.Set("Authorization", "Bearer "+credential)
		}

		response, err := endpoint.client.Do(httpRequest)
		if err != nil {
			if isContextTimeout(ctx, err) {
				lastMessage = "FOFA 请求超时，请稍后重试或减少返回数量"
			} else {
				lastMessage = "FOFA 端点连接失败"
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseSize))
		_ = response.Body.Close()
		if readErr != nil {
			lastMessage = "读取 FOFA 响应失败"
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			lastMessage = fmt.Sprintf("FOFA 端点返回 HTTP %d", response.StatusCode)
			continue
		}
		var result Response
		if err := json.Unmarshal(body, &result); err != nil {
			head := strings.TrimSpace(string(body))
			if len(head) > 160 {
				head = head[:160] + "…"
			}
			if head != "" {
				lastMessage = fmt.Sprintf("解析 FOFA 响应失败（响应非预期 JSON，前 %d 字节: %q）", len(head), head)
			} else {
				lastMessage = "解析 FOFA 响应失败（响应为空）"
			}
			continue
		}
		if result.Error {
			lastMessage = strings.TrimSpace(result.ErrMsg)
			if lastMessage == "" {
				lastMessage = "FOFA 返回错误"
			}
			continue
		}
		normalizeFOFAResponseFields(&result, body)
		return &result, nil
	}
	return nil, errors.New(lastMessage)
}

// normalizeFOFAResponseFields 归一化不同 FOFA 实现之间的 size/total 字段语义：
//   - 官方 FOFA API：size=本次返回条数，total=总匹配数（偶发 total 为 0，此时用返回条数兜底）。
//   - 部分中转站（如 fofoapi.com）不返回 total，size 直接携带总匹配数，results 长度才是返回条数。
//
// 判断依据：响应 JSON 是否含 total 键，避免把"字段缺失"误判为"total=0"。
func normalizeFOFAResponseFields(result *Response, body []byte) {
	if !jsonContainsKey(body, "total") {
		if result.Size > 0 {
			if len(result.Results) < result.Size {
				result.Total = result.Size
				result.Size = len(result.Results)
			} else {
				result.Total = result.Size
			}
		}
		return
	}
	if result.Total == 0 {
		result.Total = len(result.Results)
	}
}

func jsonContainsKey(data []byte, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

func (s *snapshot) closeIdleConnections() {
	for _, endpoint := range s.endpoints {
		if endpoint.client != nil {
			endpoint.client.CloseIdleConnections()
		}
	}
}

func newHTTPClient(timeout time.Duration, verifySSL bool) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// IPv4-only dial: the pure-Go resolver concurrently issues AAAA(IPv6) queries
		// alongside A queries. NAT/intranet DNS silently drops AAAA for domains with no
		// IPv6 address (e.g. FOFA proxy fofoapi.com), blocking the resolver until its
		// timeout. Pinning the dial network to "tcp4" makes the resolver issue A records
		// only, restoring sub-100ms resolution without touching system DNS config.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: !verifySSL}, //nolint:gosec // only explicit config disables verification
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
