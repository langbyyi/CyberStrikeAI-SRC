package app

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

// TestMCPFofaSearchToolFullRoundTrip 用本地 mock FOFA 服务验证 MCP fofa_search 工具
// 的完整调用：请求参数构造（qbase64/key/size/fields）、懒加载按最新配置发请求、
// 正常响应解析、错误响应传递、未配置提示。不依赖外部 FOFA 服务。
func TestMCPFofaSearchToolFullRoundTrip(t *testing.T) {
	var gotKey, gotSize, gotFields, gotQBase64 string
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("key")
		gotSize = r.URL.Query().Get("size")
		gotFields = r.URL.Query().Get("fields")
		gotQBase64 = r.URL.Query().Get("qbase64")
		w.Header().Set("Content-Type", "application/json")
		// 标准 FOFA 响应：results 为二维数组，字段顺序与 fields 对应
		_, _ = w.Write([]byte(`{"error":false,"size":1,"page":1,"total":3,"results":[["https://example.com","1.2.3.4","443"]]}`))
	}))
	defer mock.Close()

	db, err := database.NewDB(t.TempDir()+"/fofa-tool.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	cfg := &config.Config{FOFA: config.FofaConfig{Endpoints: []config.FofaEndpointConfig{{
		BaseURL: mock.URL, AuthMode: "key", APIKey: "test-fofa-key", AllowInsecureHTTP: true,
	}}}}
	registerFOFASearchTool(server, cfg, zap.NewNop())

	ctx := authctx.WithPrincipal(context.Background(),
		authctx.NewPrincipal("u1", "user", database.RBACScopeAll, map[string]bool{"asset:read": true}))

	res, _, err := server.CallTool(ctx, builtin.ToolFOFASearch, map[string]interface{}{
		"query": `domain="example.com"`, "size": 3, "fields": "host,ip,port",
	})
	if err != nil {
		t.Fatalf("CallTool err: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("expected success, got IsError=%v", res != nil && res.IsError)
	}
	if gotKey != "test-fofa-key" {
		t.Fatalf("key not passed: got %q", gotKey)
	}
	if gotSize != "3" {
		t.Fatalf("size not passed: got %q", gotSize)
	}
	if gotFields != "host,ip,port" {
		t.Fatalf("fields not passed: got %q", gotFields)
	}
	decoded, err := base64.StdEncoding.DecodeString(gotQBase64)
	if err != nil || string(decoded) != `domain="example.com"` {
		t.Fatalf("qbase64 not correctly encoded: %q err=%v", gotQBase64, err)
	}
	// 响应应包含结果与归一化 JSON
	if !strings.Contains(res.Content[0].Text, "https://example.com") {
		t.Fatalf("result missing from output: %s", res.Content[0].Text)
	}
}

// TestMCPFofaSearchToolErrors 验证错误分支：mock 返回错误 JSON、mock 返回非 JSON、
// 未配置 key 时的提示。
func TestMCPFofaSearchToolErrors(t *testing.T) {
	t.Run("FOFA error response surfaces errmsg", func(t *testing.T) {
		mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":true,"errmsg":"[-700] 账号无效"}`))
		}))
		defer mock.Close()
		db, _ := database.NewDB(t.TempDir()+"/e1.db", zap.NewNop())
		defer db.Close()
		server := mcp.NewServer(zap.NewNop())
		server.SetToolAuthorizer(mcpToolAuthorizer(db))
		cfg := &config.Config{FOFA: config.FofaConfig{Endpoints: []config.FofaEndpointConfig{{
			BaseURL: mock.URL, AuthMode: "key", APIKey: "k", AllowInsecureHTTP: true,
		}}}}
		registerFOFASearchTool(server, cfg, zap.NewNop())
		ctx := authctx.WithPrincipal(context.Background(),
			authctx.NewPrincipal("u1", "u", database.RBACScopeAll, map[string]bool{"asset:read": true}))
		res, _, err := server.CallTool(ctx, builtin.ToolFOFASearch, map[string]interface{}{"query": "x"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Content[0].Text, "账号无效") {
			t.Fatalf("errmsg not surfaced: %s", res.Content[0].Text)
		}
	})

	t.Run("non-JSON response includes body head diagnostic", func(t *testing.T) {
		mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<!doctype html><html>challenge</html>"))
		}))
		defer mock.Close()
		db, _ := database.NewDB(t.TempDir()+"/e2.db", zap.NewNop())
		defer db.Close()
		server := mcp.NewServer(zap.NewNop())
		server.SetToolAuthorizer(mcpToolAuthorizer(db))
		cfg := &config.Config{FOFA: config.FofaConfig{Endpoints: []config.FofaEndpointConfig{{
			BaseURL: mock.URL, AuthMode: "key", APIKey: "k", AllowInsecureHTTP: true,
		}}}}
		registerFOFASearchTool(server, cfg, zap.NewNop())
		ctx := authctx.WithPrincipal(context.Background(),
			authctx.NewPrincipal("u1", "u", database.RBACScopeAll, map[string]bool{"asset:read": true}))
		res, _, err := server.CallTool(ctx, builtin.ToolFOFASearch, map[string]interface{}{"query": "x"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Content[0].Text, "非预期 JSON") || !strings.Contains(res.Content[0].Text, "doctype") {
			t.Fatalf("non-JSON diagnostic missing: %s", res.Content[0].Text)
		}
	})

	t.Run("missing key returns clear hint", func(t *testing.T) {
		db, _ := database.NewDB(t.TempDir()+"/e3.db", zap.NewNop())
		defer db.Close()
		server := mcp.NewServer(zap.NewNop())
		server.SetToolAuthorizer(mcpToolAuthorizer(db))
		cfg := &config.Config{FOFA: config.FofaConfig{}}
		registerFOFASearchTool(server, cfg, zap.NewNop())
		ctx := authctx.WithPrincipal(context.Background(),
			authctx.NewPrincipal("u1", "u", database.RBACScopeAll, map[string]bool{"asset:read": true}))
		res, _, err := server.CallTool(ctx, builtin.ToolFOFASearch, map[string]interface{}{"query": "x"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Content[0].Text, "未配置") {
			t.Fatalf("missing-key hint not surfaced: %s", res.Content[0].Text)
		}
	})
}

// TestMCPFofaSearchToolHotReload 验证懒加载：注册后修改 cfg.FOFA（模拟 Web 界面保存配置），
// 下一次调用立即使用新配置，无需重启服务。
func TestMCPFofaSearchToolHotReload(t *testing.T) {
	var gotKey string
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":1,"total":1,"results":[["ok"]]}`))
	}))
	defer mock.Close()

	db, _ := database.NewDB(t.TempDir()+"/fofa-hot.db", zap.NewNop())
	defer db.Close()
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	cfg := &config.Config{FOFA: config.FofaConfig{Endpoints: []config.FofaEndpointConfig{{
		BaseURL: mock.URL, AuthMode: "key", APIKey: "key-v1", AllowInsecureHTTP: true,
	}}}}
	registerFOFASearchTool(server, cfg, zap.NewNop())
	ctx := authctx.WithPrincipal(context.Background(),
		authctx.NewPrincipal("u1", "u", database.RBACScopeAll, map[string]bool{"asset:read": true}))

	if _, _, err := server.CallTool(ctx, builtin.ToolFOFASearch, map[string]interface{}{"query": "x"}); err != nil {
		t.Fatal(err)
	}
	if gotKey != "key-v1" {
		t.Fatalf("expected key-v1, got %q", gotKey)
	}

	cfg.FOFA.Endpoints[0].APIKey = "key-v2"
	if _, _, err := server.CallTool(ctx, builtin.ToolFOFASearch, map[string]interface{}{"query": "x"}); err != nil {
		t.Fatal(err)
	}
	if gotKey != "key-v2" {
		t.Fatalf("expected hot-reload to key-v2, got %q", gotKey)
	}
}
