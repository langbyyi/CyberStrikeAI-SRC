package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestFofaSearchUsesAPIKeyWithoutEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FOFA_API_KEY", "")
	t.Setenv("FOFA_EMAIL", "legacy@example.com")

	var receivedEmail string
	var receivedKey string
	fofaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedEmail = r.URL.Query().Get("email")
		receivedKey = r.URL.Query().Get("key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":1,"page":1,"results":[["https://example.com"]]}`))
	}))
	defer fofaServer.Close()

	h := NewFofaHandler(&config.Config{
		FOFA: config.FofaConfig{
			BaseURL: fofaServer.URL,
			APIKey:  "test-api-key",
		},
	}, zap.NewNop())

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	body := `{"query":"domain=\"example.com\"","fields":"host"}`
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/fofa/search", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.Search(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Search() status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if receivedEmail != "" {
		t.Fatalf("FOFA request unexpectedly included email = %q", receivedEmail)
	}
	if receivedKey != "test-api-key" {
		t.Fatalf("FOFA request key = %q, want %q", receivedKey, "test-api-key")
	}

	var response fofaSearchResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.ResultsCount != 1 {
		t.Fatalf("results_count = %d, want 1", response.ResultsCount)
	}
	if response.Total != 1 {
		t.Fatalf("total = %d, want 1 (should fall back to results_count when FOFA omits total)", response.Total)
	}
}

func TestFofaSearchHonorsEndpointsConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FOFA_API_KEY", "")

	fofaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer endpoint-token" {
			t.Fatalf("Authorization = %q, want Bearer endpoint-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":1,"total":1,"results":[["https://example.com"]]}`))
	}))
	defer fofaServer.Close()

	h := NewFofaHandler(&config.Config{
		FOFA: config.FofaConfig{Endpoints: []config.FofaEndpointConfig{{
			BaseURL: fofaServer.URL, AuthMode: "bearer", BearerToken: "endpoint-token", AllowInsecureHTTP: true,
		}}},
	}, zap.NewNop())

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	body := `{"query":"domain=\"example.com\"","fields":"host"}`
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/fofa/search", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.Search(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Search() status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response fofaSearchResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.ResultsCount != 1 {
		t.Fatalf("results_count = %d, want 1", response.ResultsCount)
	}
}

func TestFofaSearchMissingEndpointsConfigReturnsClearHint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("FOFA_API_KEY", "")

	h := NewFofaHandler(&config.Config{FOFA: config.FofaConfig{}}, zap.NewNop())

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	body := `{"query":"domain=\"example.com\""}`
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/fofa/search", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.Search(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("Search() status = %d, want 400", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "未配置") {
		t.Fatalf("missing-key hint not surfaced: %s", recorder.Body.String())
	}
}

func TestFofaConfigUpdatePreservesAdvancedFields(t *testing.T) {
	base := config.FofaConfig{
		BaseURL:        "https://fofa.info/api/v1/search/all",
		APIKey:         "legacy-key",
		TimeoutSeconds: 45,
		VerifySSL:      boolP(false),
		Endpoints: []config.FofaEndpointConfig{{
			BaseURL: "https://mirror.example.com", AuthMode: "bearer", BearerToken: "tok",
		}},
	}

	// 模拟 Web 界面保存：仅提交 api_key/base_url（对应 settings.js 的 fofa 段）。
	var req UpdateConfigRequest
	if err := json.Unmarshal([]byte(`{"fofa":{"api_key":"new-key","base_url":"https://fofoapi.com"}}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.FOFA == nil {
		t.Fatal("fofa segment missing after decode")
	}
	applyFofaConfigUpdate(&base, req.FOFA)

	if base.APIKey != "new-key" || base.BaseURL != "https://fofoapi.com" {
		t.Fatalf("api_key/base_url not applied: %#v", base)
	}
	if len(base.Endpoints) != 1 || base.Endpoints[0].BearerToken != "tok" {
		t.Fatalf("endpoints wiped by partial update: %#v", base.Endpoints)
	}
	if base.TimeoutSeconds != 45 {
		t.Fatalf("timeout_seconds wiped by partial update: %d", base.TimeoutSeconds)
	}
	if base.VerifySSL == nil || *base.VerifySSL != false {
		t.Fatalf("verify_ssl lost by partial update: %#v", base.VerifySSL)
	}
}

func boolP(b bool) *bool { return &b }

func TestShodanSearchReportsShortfallWhenTotalExceedsMatches(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("SHODAN_API_KEY", "")

	shodanServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/shodan/host/search" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("key"); got != "test-shodan-key" {
			t.Fatalf("Shodan key = %q, want test-shodan-key", got)
		}
		page := r.URL.Query().Get("page")
		count := 0
		switch page {
		case "1":
			count = 100
		case "2":
			count = 3
		default:
			count = 0
		}
		matches := make([]map[string]interface{}, 0, count)
		for i := 0; i < count; i++ {
			matches = append(matches, map[string]interface{}{
				"ip_str": fmt.Sprintf("192.0.2.%d", i+1),
				"port":   80,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total":   104,
			"matches": matches,
		})
	}))
	defer shodanServer.Close()

	h := NewFofaHandler(&config.Config{
		Shodan: config.SpaceSearchConfig{
			BaseURL: shodanServer.URL,
			APIKey:  "test-shodan-key",
		},
	}, zap.NewNop())

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	body := `{"provider":"shodan","query":"product:nginx","fields":"ip_str,port","size":1000,"page":1}`
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/fofa/search", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.Search(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Search() status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response fofaSearchResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Total != 104 || response.ResultsCount != 103 {
		t.Fatalf("counts: total=%d results_count=%d, want 104/103", response.Total, response.ResultsCount)
	}
	if response.ExpectedCount != 104 || response.Shortfall != 1 {
		t.Fatalf("shortfall: expected=%d shortfall=%d, want 104/1", response.ExpectedCount, response.Shortfall)
	}
	if response.Warning == "" {
		t.Fatal("warning should explain shortfall")
	}
}

func TestQuakeSearchHandlesStringErrorCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("QUAKE_API_KEY", "")

	quakeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-QuakeToken"); got != "test-quake-key" {
			t.Fatalf("Quake token = %q, want test-quake-key", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"q5000","message":"查询语法错误"}`))
	}))
	defer quakeServer.Close()

	h := NewFofaHandler(&config.Config{
		Quake: config.SpaceSearchConfig{
			BaseURL: quakeServer.URL,
			APIKey:  "test-quake-key",
		},
	}, zap.NewNop())

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	body := `{"provider":"quake","query":"bad query","fields":"ip,port","size":10,"page":1}`
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/fofa/search", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.Search(ctx)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("Search() status = %d, want %d, body = %s", recorder.Code, http.StatusBadGateway, recorder.Body.String())
	}
	bodyText := recorder.Body.String()
	if !strings.Contains(bodyText, "查询语法错误") {
		t.Fatalf("response should include Quake error message, got %s", bodyText)
	}
	if strings.Contains(bodyText, "cannot unmarshal") {
		t.Fatalf("response exposed JSON type decoding failure: %s", bodyText)
	}
}

func TestExtractInfoCollectJSONObject(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain json",
			in:   `{"query":"title:\"CyberStrikeAI\"","warnings":[]}`,
			want: `{"query":"title:\"CyberStrikeAI\"","warnings":[]}`,
		},
		{
			name: "fenced json",
			in:   "```json\n{\"query\":\"product:nginx\"}\n```",
			want: `{"query":"product:nginx"}`,
		},
		{
			name: "prefixed explanation",
			in:   "解析结果如下：\n{\"query\":\"ssl.cert.subject.cn:example.com\",\"explanation\":\"ok\"}\n请确认。",
			want: `{"query":"ssl.cert.subject.cn:example.com","explanation":"ok"}`,
		},
		{
			name: "braces inside string",
			in:   "结果：{\"query\":\"title:\\\"{admin}\\\"\",\"warnings\":[\"check\"]}",
			want: `{"query":"title:\"{admin}\"","warnings":["check"]}`,
		},
		{
			name: "valid json with trailing text",
			in:   "{\"query\":\"ok\",\"explanation\":\"keep\",\"warnings\":[\"w\"]}\nextra",
			want: `{"query":"ok","explanation":"keep","warnings":["w"]}`,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := extractInfoCollectJSONObject(tc.in)
			if err != nil {
				t.Fatalf("extractInfoCollectJSONObject() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("extractInfoCollectJSONObject() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractInfoCollectJSONObjectDoesNotMaskMalformedOptionalFields(t *testing.T) {
	t.Parallel()
	for _, content := range []string{
		`{"query":"ok","warnings":oops}`,
		`{"query":"title="E3全渠道中台"","warnings":oops}`,
		`prefix "query":"title="x"","warnings":[] suffix`,
		`{"query":"title="x"","foo":"bar"}`,
		`{"query":"body="foo","warnings":[],"explanation":"keep"}`,
	} {
		content := content
		t.Run(content, func(t *testing.T) {
			t.Parallel()
			if _, err := extractInfoCollectJSONObject(content); err == nil {
				t.Fatal("extractInfoCollectJSONObject() unexpectedly accepted malformed warnings")
			}
		})
	}
}

func TestExtractInfoCollectJSONObjectRecoversUnescapedQuotesInQuery(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		in        string
		wantQuery string
	}{
		{
			name:      "production fofa response",
			in:        `{"query":"title="E3全渠道中台"","explanation":"用户输入已是合法的 FOFA 查询语法。","warnings":[]}`,
			wantQuery: `title="E3全渠道中台"`,
		},
		{
			name:      "natural language response",
			in:        `{"query": "title="E3全渠道中台"", "explanation": "映射为 FOFA 的 title 字段。", "warnings": []}`,
			wantQuery: `title="E3全渠道中台"`,
		},
		{
			name:      "commas and multiple quoted values",
			in:        `{"query":"title="E3", country="CN" && port="443"","explanation":"组合查询"}`,
			wantQuery: `title="E3", country="CN" && port="443"`,
		},
		{
			name:      "query only with closing brace in value",
			in:        `{"query":"body="}""}`,
			wantQuery: `body="}"`,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := extractInfoCollectJSONObject(tc.in)
			if err != nil {
				t.Fatalf("extractInfoCollectJSONObject() error = %v", err)
			}
			var parsed fofaParseResponse
			if err := json.Unmarshal([]byte(got), &parsed); err != nil {
				t.Fatalf("decode recovered response: %v", err)
			}
			if parsed.Query != tc.wantQuery {
				t.Fatalf("recovered query = %q, want %q", parsed.Query, tc.wantQuery)
			}
		})
	}
}
