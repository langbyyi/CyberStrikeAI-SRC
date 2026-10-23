package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/network"
	"go.uber.org/zap"
)

func TestAgentAssessedNetworkAssetsFollowProjectScopeAndExecution(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "assessment.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	project, err := db.CreateProject(&database.Project{Name: "synthetic app", Description: "测试 portal.example.test 及该应用自有后端，排除第三方支付。", ScopeJSON: `{"targets":["portal.example.test"],"exclude":["blocked.example.test","192.0.2.0/28"],"notes":"自有 API 可能使用独立域名或 IP；Agent 根据授权和发现证据确认归属。"}`})
	if err != nil {
		t.Fatal(err)
	}
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "project-proxy:"+r.URL.Hostname())
	}))
	defer proxy.Close()
	node, err := service.AddProjectProxy(project.ID, proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SavePolicy(project.ID, network.Policy{Mode: "fixed_proxy", ProxyID: node.ID}, 0); err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNetworkTools(server, service, db, nil)
	ctx := mcp.WithMCPProjectID(authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"project:read": true, "agent:execute": true})), project.ID)
	conversation, err := db.CreateConversation("assessment task", database.ConversationCreateMeta{ProjectID: project.ID})
	if err != nil {
		t.Fatal(err)
	}
	ctx = mcp.WithMCPConversationID(ctx, conversation.ID)
	key := currentNetworkAssessmentKey(t, server, ctx)
	bind := func(target string, basis interface{}, wantError bool) {
		t.Helper()
		args := map[string]interface{}{"target": target, "evidence": "入口中实际 API 请求及项目测试规范共同确认该自有后端。", "scope_context": key}
		if basis != nil {
			args["scope_basis"] = basis
		}
		result, _, err := server.CallTool(ctx, "network_bind_asset", args)
		if err != nil || result == nil || result.IsError != wantError {
			t.Fatalf("bind %s: want error=%v, result=%+v, err=%v", target, wantError, result, err)
		}
	}
	// A relationship alone is insufficient: the Agent must state its authorization basis.
	bind("api.backend.test", nil, true)
	bind("api.backend.test", true, true)
	bind("api.backend.test", "项目说明允许该应用自有后端，规范中的服务标识与发现的 API 一致。", false)
	bind("192.0.2.42", "规范确认该独立地址属于已授权 API 服务。", false)
	bind("blocked.example.test", "同一应用的后端", true)
	bind("192.0.2.7", "同一应用的后端", true)
	bind("*.backend.test", "推测所有子域都是自有的", true)
	bind("0.0.0.0/0", "所有流量都走 VPN", true)
	identity, scope, err := networkContext(ctx, db, service)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"api.backend.test", "192.0.2.42"} {
		parsed, err := network.ParseTarget(target)
		if err != nil || !scope.Contains(parsed) || service.TargetPolicy(identity, scope, parsed).Mode != "fixed_proxy" {
			t.Fatalf("assessed target did not enter project routing: %s, %+v, %v", target, scope, err)
		}
		client, err := networkHTTPClient(db, service)(ctx, project.ID, &http.Client{})
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Get("http://" + target + "/api")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		client.CloseIdleConnections()
		if string(body) != "project-proxy:"+target {
			t.Fatalf("request bypassed assigned proxy: %s", body)
		}
	}
	status, _, err := server.CallTool(ctx, "network_status", map[string]interface{}{"target": "http://api.backend.test"})
	if err != nil || status == nil || status.IsError || !strings.Contains(status.Content[0].Text, "execute_with_project_policy") {
		t.Fatalf("status disagrees with execution: %+v %v", status, err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(status.Content[0].Text), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["project_context"] == nil {
		t.Fatal("Agent cannot read project natural-language scope")
	}
	other, err := db.CreateProject(&database.Project{Name: "other project", ScopeJSON: project.ScopeJSON})
	if err != nil {
		t.Fatal(err)
	}
	_, otherScope, err := networkContext(mcp.WithMCPProjectID(ctx, other.ID), db, service)
	parsed, _ := network.ParseTarget("api.backend.test")
	if err != nil || otherScope.Contains(parsed) {
		t.Fatal("assessment leaked into another project")
	}
	// Editing the user's scope invalidates semantic decisions without editing the saved user scope.
	project.Description = "仅测试 portal.example.test，不包含独立后端。"
	if err := db.UpdateProject(project); err != nil {
		t.Fatal(err)
	}
	_, narrowed, err := networkContext(ctx, db, service)
	if err != nil || narrowed.Contains(parsed) || service.TargetPolicy(identity, narrowed, parsed).Mode != "auto" {
		t.Fatalf("stale assessment survived changed authorization: %+v %v", narrowed, err)
	}
}

func TestAgentCanBootstrapExplicitNetworkTargetsFromNaturalLanguage(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "bootstrap.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	project, err := db.CreateProject(&database.Project{Name: "synthetic project", Description: "测试应用入口 portal.example.test。", ScopeJSON: `{"notes":"由 Agent 识别本应用的已授权测试目标。"}`})
	if err != nil {
		t.Fatal(err)
	}
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	node, err := service.AddProjectProxy(project.ID, "http://127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SavePolicy(project.ID, network.Policy{Mode: "fixed_proxy", ProxyID: node.ID}, 0); err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNetworkTools(server, service, db, nil)
	ctx := mcp.WithMCPProjectID(authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"project:read": true, "agent:execute": true})), project.ID)
	status, _, err := server.CallTool(ctx, "network_status", map[string]interface{}{"target": "http://portal.example.test"})
	if err != nil || status == nil || status.IsError || !strings.Contains(status.Content[0].Text, "assess_initial_targets") {
		t.Fatalf("empty scope did not guide Agent to register initial targets: %+v %v", status, err)
	}
	result, _, err := server.CallTool(ctx, "network_bind_asset", map[string]interface{}{"target": "portal.example.test", "evidence": "用户给出的应用入口。", "scope_basis": "项目描述明确授权该入口。", "scope_context": currentNetworkAssessmentKey(t, server, ctx)})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("Agent could not initialize explicit route: %+v %v", result, err)
	}
	_, scope, err := networkContext(ctx, db, service)
	parsed, _ := network.ParseTarget("portal.example.test")
	if err != nil || !scope.Contains(parsed) {
		t.Fatalf("initial target not executable: %+v %v", scope, err)
	}
	project.Description = "该项目已改为其他目标。"
	if err := db.UpdateProject(project); err != nil {
		t.Fatal(err)
	}
	_, scope, err = networkContext(ctx, db, service)
	if err != nil || scope.Contains(parsed) || service.TargetPolicy(network.Identity{ProjectID: project.ID}, scope, parsed).Mode != "auto" {
		t.Fatalf("empty base scope revived stale initial target: %+v %v", scope, err)
	}
}

func TestAgentCanRegisterUserDeclaredWildcardButCannotInferIt(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "declared.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&database.Project{Name: "declared scope", Description: "用户授权 *.owned.test 和 198.51.100.0/24，排除 blocked.owned.test。", ScopeJSON: `{"exclude":["blocked.owned.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNetworkTools(server, s, db, nil)
	ctx := mcp.WithMCPProjectID(authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"project:read": true, "agent:execute": true})), p.ID)
	key := currentNetworkAssessmentKey(t, server, ctx)
	for _, tc := range []struct {
		target, origin string
		failed         bool
	}{
		{"*.owned.test", "discovered", true},
		{"*.owned.test", "declared", false},
		{"198.51.100.0/24", "declared", false},
		{"0.0.0.0/0", "declared", true},
		{"::/0", "declared", true},
		{"blocked.owned.test", "declared", true},
		{"unrelated.test", "guessed", true},
	} {
		result, _, err := server.CallTool(ctx, "network_bind_asset", map[string]interface{}{"target": tc.target, "scope_origin": tc.origin, "scope_basis": "当前用户在项目描述明确给出了该范围。", "evidence": "用户提供的范围原文及测试规范。", "scope_context": key})
		if err != nil || result == nil || result.IsError != tc.failed {
			t.Fatalf("declared %s (%s): %+v %v", tc.target, tc.origin, result, err)
		}
	}
	_, scope, err := networkContext(ctx, db, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target  string
		allowed bool
	}{{"api.owned.test", true}, {"blocked.owned.test", false}, {"198.51.100.42", true}, {"203.0.113.42", false}} {
		parsed, _ := network.ParseTarget(tc.target)
		if scope.Contains(parsed) != tc.allowed {
			t.Fatalf("declared routing mismatch: %s, %+v", tc.target, scope)
		}
	}
	result, _, err := server.CallTool(ctx, "network_bind_asset", map[string]interface{}{"target": "api.owned.test", "evidence": "API observed under previously assessed wildcard"})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("semantic parent created permanent unassessed child: %+v %v", result, err)
	}
}

func currentNetworkAssessmentKey(t *testing.T, server *mcp.Server, ctx context.Context) string {
	t.Helper()
	result, _, err := server.CallTool(ctx, "network_status", map[string]interface{}{})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("read scope context: %+v %v", result, err)
	}
	var response struct {
		ProjectContext struct {
			Key string `json:"scope_context"`
		} `json:"project_context"`
	}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &response); err != nil || response.ProjectContext.Key == "" {
		t.Fatalf("scope context missing: %v", err)
	}
	return response.ProjectContext.Key
}

func TestAgentScopeAssessmentRequiresCurrentContext(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "stale-assessment.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&database.Project{Name: "synthetic", Description: "owned API permitted"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNetworkTools(server, s, db, nil)
	ctx := mcp.WithMCPProjectID(authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"project:read": true, "agent:execute": true})), p.ID)
	status, _, err := server.CallTool(ctx, "network_status", map[string]interface{}{})
	if err != nil || status == nil || status.IsError {
		t.Fatal("read assessment context", err)
	}
	var response struct {
		ProjectContext struct {
			Key string `json:"scope_context"`
		} `json:"project_context"`
	}
	if json.Unmarshal([]byte(status.Content[0].Text), &response) != nil || response.ProjectContext.Key == "" {
		t.Fatal("status omitted the authorization context version")
	}
	p.Description = "only the portal is permitted now"
	if err := db.UpdateProject(p); err != nil {
		t.Fatal(err)
	}
	result, _, err := server.CallTool(ctx, "network_bind_asset", map[string]interface{}{"target": "api.backend.test", "evidence": "previous discovery", "scope_basis": "previous project description", "scope_context": response.ProjectContext.Key})
	if err != nil || result == nil || !result.IsError || !strings.Contains(result.Content[0].Text, "changed") {
		t.Fatalf("stale Agent judgment was stamped with new authorization: %+v %v", result, err)
	}
}
