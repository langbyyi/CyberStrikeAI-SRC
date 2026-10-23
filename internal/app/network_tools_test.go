package app

import (
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/handler"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"

	"context"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/network"
	"cyberstrike-ai/internal/security"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNetworkStatusCanPageBeyondFirstFiftyNodes(t *testing.T) {
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var addresses []string
	for port := 18000; port < 18055; port++ {
		addresses = append(addresses, fmt.Sprintf("http://127.0.0.1:%d", port))
	}
	if _, err = s.ImportProxyText(strings.Join(addresses, "\n"), "manual"); err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(nil))
	registerNetworkTools(server, s, nil, nil)
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"agent:execute": true}))
	for _, target := range []string{"", "http://target.test"} {
		t.Run(target, func(t *testing.T) {
			seen := map[string]bool{}
			for _, page := range []struct{ offset, count, next int }{{0, 10, 10}, {10, 10, 20}, {20, 10, 30}, {30, 10, 40}, {40, 10, 50}, {50, 5, 0}, {100, 0, 0}} {
				result, _, callErr := server.CallTool(ctx, "network_status", map[string]interface{}{"target": target, "offset": float64(page.offset)})
				if callErr != nil || result == nil || result.IsError {
					t.Fatalf("page failed: %+v, %v", result, callErr)
				}
				var response struct {
					Nodes      []network.Node      `json:"nodes"`
					Candidates []network.Candidate `json:"candidates"`
					Total      int                 `json:"total"`
					Next       int                 `json:"next_offset"`
				}
				if err := json.Unmarshal([]byte(result.Content[0].Text), &response); err != nil {
					t.Fatal(err)
				}
				if len(response.Nodes) != page.count || response.Total != 55 || response.Next != page.next {
					t.Fatalf("incomplete pool page: nodes=%d total=%d next=%d", len(response.Nodes), response.Total, response.Next)
				}
				if target != "" && len(response.Candidates) != page.count {
					t.Fatalf("candidate page count=%d, want %d", len(response.Candidates), page.count)
				}
				for _, node := range response.Nodes {
					if seen[node.ID] {
						t.Fatalf("page repeated node %s", node.ID)
					}
					seen[node.ID] = true
				}
			}
			if len(seen) != 55 {
				t.Fatalf("only %d pool nodes discoverable", len(seen))
			}
		})
	}
	for _, args := range []map[string]interface{}{{"offset": float64(-1)}, {"offset": 0.5}, {"offset": "50"}, {"limit": float64(51)}, {"limit": float64(0)}} {
		result, _, callErr := server.CallTool(ctx, "network_status", args)
		if callErr == nil && result != nil && !result.IsError {
			t.Fatalf("invalid page accepted: %v", args)
		}
	}
}

func TestNetworkToolWithoutProjectAndRedaction(t *testing.T) {
	s, _ := network.Open(t.TempDir())
	defer s.Close()
	_, err := s.AddProxy("socks5://fixture:synthetic-secret@127.0.0.1:1080", "manual")
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(nil))
	registerNetworkTools(server, s, nil, nil)
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"agent:execute": true}))
	result, _, err := server.CallTool(ctx, "network_status", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	if !strings.Contains(string(raw), "socks5") || strings.Contains(string(raw), "synthetic-secret") {
		t.Fatalf("unexpected network status: %s", raw)
	}
}

func TestNetworkAgentFallbackTargetsPreserveProjectAndPolicyExclusions(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "fallback-exclusions.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	project, err := db.CreateProject(&database.Project{Name: "agent fallback exclusions", ScopeJSON: `{"targets":[],"exclude":["project-blocked.example.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := db.CreateConversation("fallback task", database.ConversationCreateMeta{ProjectID: project.ID})
	if err != nil {
		t.Fatal(err)
	}
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, err := service.SavePolicy(project.ID, network.Policy{Mode: "auto", Targets: []string{"*.example.test"}, Exclude: []string{"policy-blocked.example.test"}}, 0); err != nil {
		t.Fatal(err)
	}
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	node, err := service.AddProxy(proxy.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	ctx := mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "fixture", "all", map[string]bool{"project:read": true, "agent:execute": true})), conversation.ID)
	identity, scope, err := networkContext(ctx, db, service)
	if err != nil || identity.ProjectID != project.ID {
		t.Fatalf("resolve conversation network context: %+v %v", identity, err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNetworkTools(server, service, db, nil)
	for _, target := range []string{"project-blocked.example.test", "policy-blocked.example.test", "outside.test"} {
		parsed, err := network.ParseTarget(target)
		if err != nil {
			t.Fatal(err)
		}
		if scope.Contains(parsed) {
			t.Errorf("agent context allowed excluded or outside target %s: %+v", target, scope)
		}
		result, _, err := server.CallTool(ctx, "network_acquire", map[string]interface{}{"target": "http://" + target, "node_id": node.ID})
		if err != nil || result == nil || !result.IsError || len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "outside the project testing scope") {
			t.Errorf("network_acquire did not reject %s: %+v %v", target, result, err)
		}
	}
	if proxyRequests.Load() != 0 {
		t.Errorf("excluded targets reached the synthetic proxy: requests=%d", proxyRequests.Load())
	}
	allowed, err := network.ParseTarget("allowed.example.test")
	if err != nil || !scope.Contains(allowed) {
		t.Fatalf("fallback lost allowed policy target: %+v %v", scope, err)
	}
}

func TestWebshellClientUsesTrustedProjectNetwork(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "network-http.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	project, err := db.CreateProject(&database.Project{Name: "network fixture", ScopeJSON: `{"targets":["target.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	service, _ := network.Open(t.TempDir())
	defer service.Close()
	hits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = io.WriteString(w, "through-project-proxy")
	}))
	defer proxy.Close()
	node, err := service.AddProjectProxy(project.ID, proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SavePolicy(project.ID, network.Policy{Mode: "fixed_proxy", ProxyID: node.ID}, 0); err != nil {
		t.Fatal(err)
	}
	h := handler.NewWebShellHandler(zap.NewNop(), db)
	h.SetTargetHTTPClient(networkHTTPClient(db, service))
	conn := &database.WebShellConnection{ProjectID: project.ID, URL: "http://target.test/endpoint", Type: "cmd", Method: "get"}
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "fixture", "all", map[string]bool{"project:read": true, "webshell:write": true}))
	output, ok, reason := h.ExecWithConnection(conn, "synthetic-command", ctx)
	if !ok || output != "through-project-proxy" || hits != 1 {
		t.Fatalf("target routing: %v %q %q hits=%d", ok, output, reason, hits)
	}
	_, ok, _ = h.ExecWithConnection(conn, "synthetic-command", mcp.WithMCPProjectID(ctx, "another-project"))
	if ok || hits != 1 {
		t.Fatal("cross-project context reached target")
	}
	_, ok, _ = h.ExecWithConnection(conn, "synthetic-command", context.Background())
	if ok || hits != 1 {
		t.Fatal("unauthenticated context reached project proxy")
	}
}

func TestProjectHTTPClientRejectsScopeChangedAfterConstruction(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "scope-change.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	project, err := db.CreateProject(&database.Project{Name: "changing scope", ScopeJSON: `{"targets":["target.example.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	hits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	node, err := service.AddProjectProxy(project.ID, proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SavePolicy(project.ID, network.Policy{Mode: "fixed_proxy", ProxyID: node.ID}, 0); err != nil {
		t.Fatal(err)
	}
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "fixture", "all", map[string]bool{"project:read": true}))
	client, err := networkHTTPClient(db, service)(ctx, project.ID, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	project.ScopeJSON = `{"targets":["replacement.example.test"]}`
	if err := db.UpdateProject(project); err != nil {
		t.Fatal(err)
	}
	if err := service.DisconnectVPN(project.ID); err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("http://target.example.test")
	if response != nil {
		response.Body.Close()
	}
	if err == nil || hits != 0 {
		t.Fatalf("client used a revoked project scope: requests=%d error=%v", hits, err)
	}
	current, err := networkHTTPClient(db, service)(ctx, project.ID, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	defer current.CloseIdleConnections()
	response, err = current.Get("http://replacement.example.test")
	if response != nil {
		response.Body.Close()
	}
	if err != nil || hits != 1 {
		t.Fatalf("fresh client could not use the revised project scope: requests=%d error=%v", hits, err)
	}
}

func TestNetworkStatusFiltersHealthAndReportsExecutionContext(t *testing.T) {
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(407) }))
	defer bad.Close()
	goodNode, err := service.AddProxy(good.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	badNode, err := service.AddProxy(bad.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(nil))
	registerNetworkTools(server, service, nil, nil)
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"agent:execute": true}))
	ctx = mcp.WithMCPConversationID(ctx, "status-conversation")
	run := security.NewProcessScope()
	defer run.Close()
	ctx = security.WithProcessScope(ctx, run)
	call := func(name string, args map[string]interface{}) map[string]interface{} {
		t.Helper()
		result, _, err := server.CallTool(ctx, name, args)
		if err != nil || result == nil || result.IsError {
			t.Fatalf("%s failed: %+v %v", name, result, err)
		}
		var decoded map[string]interface{}
		if err = json.Unmarshal([]byte(result.Content[0].Text), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	target := "http://target.example.test"
	result, _, err := server.CallTool(ctx, "network_diagnose", map[string]interface{}{"target": target, "node_ids": []string{badNode.ID, goodNode.ID}})
	if err != nil || result.IsError {
		t.Fatalf("diagnose: %+v %v", result, err)
	}
	call("network_acquire", map[string]interface{}{"target": target, "node_id": goodNode.ID})
	status := call("network_status", map[string]interface{}{"target": target, "status": "passed", "protocol": "http", "limit": float64(1)})
	if status["total"] != float64(1) {
		t.Fatalf("status filter ignored: %v", status["total"])
	}
	summary, ok := status["summary"].(map[string]interface{})
	if !ok || summary["passed"] != float64(1) || summary["failed"] != float64(1) {
		t.Fatalf("missing health summary: %v", status["summary"])
	}
	execution, ok := status["execution"].(map[string]interface{})
	if !ok || execution["conversation_id"] != "status-conversation" || execution["run_id"] != run.ID {
		t.Fatalf("missing task identity: %v", status["execution"])
	}
	lease, ok := execution["selected_lease"].(map[string]interface{})
	if !ok || lease["node_id"] != goodNode.ID {
		t.Fatalf("missing selected lease: %v", execution)
	}
	status = call("network_status", map[string]interface{}{"target": target, "status": "failed"})
	nodes := status["nodes"].([]interface{})
	if len(nodes) != 1 || nodes[0].(map[string]interface{})["id"] != badNode.ID {
		t.Fatalf("failed filter: %v", nodes)
	}
	for _, args := range []map[string]interface{}{{"status": "unknown"}, {"status": true}, {"protocol": "ftp"}, {"target": false}} {
		result, _, err := server.CallTool(ctx, "network_status", args)
		if err == nil && result != nil && !result.IsError {
			t.Fatalf("invalid status arguments accepted: %v", args)
		}
	}
	other := mcp.WithMCPConversationID(ctx, "another-conversation")
	result, _, err = server.CallTool(other, "network_status", nil)
	if err != nil || result.IsError {
		t.Fatalf("other status: %v", err)
	}
	var isolated struct {
		Execution struct {
			SelectedLease *network.Lease `json:"selected_lease"`
		} `json:"execution"`
	}
	if err = json.Unmarshal([]byte(result.Content[0].Text), &isolated); err != nil {
		t.Fatal(err)
	}
	if isolated.Execution.SelectedLease != nil {
		t.Fatal("another task's lease leaked")
	}
}

func TestNetworkStatusUsesPoolHealthWithoutStartingProbes(t *testing.T) {
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	var hits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("fixture")) }))
	defer proxy.Close()
	node, err := service.AddProxy(proxy.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SaveValidationSettings(network.ValidationSettings{Target: "http://target.example.test", FailureAction: "keep", FailureThreshold: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ValidatePool(context.Background(), network.Identity{}, []string{node.ID}); err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(nil))
	registerNetworkTools(server, service, nil, nil)
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"agent:execute": true}))
	result, _, err := server.CallTool(ctx, "network_status", map[string]interface{}{"status": "passed"})
	if err != nil || result.IsError {
		t.Fatalf("status: %+v %v", result, err)
	}
	var response struct {
		Total     int                            `json:"total"`
		Health    map[string]network.Observation `json:"pool_observations"`
		Execution struct {
			StatusOnly bool           `json:"status_only"`
			Lease      *network.Lease `json:"selected_lease"`
		} `json:"execution"`
	}
	if err = json.Unmarshal([]byte(result.Content[0].Text), &response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 1 || !response.Health[node.ID].Reachable || !response.Execution.StatusOnly || response.Execution.Lease != nil || hits.Load() != 1 {
		t.Fatalf("passive status lost pool health or activated a probe: %+v hits=%d", response, hits.Load())
	}
	if _, err = service.UpdateProxy(node.ID, "", false); err != nil {
		t.Fatal(err)
	}
	result, _, err = server.CallTool(ctx, "network_status", map[string]interface{}{"status": "passed"})
	if err != nil || result.IsError {
		t.Fatalf("status: %+v %v", result, err)
	}
	if err = json.Unmarshal([]byte(result.Content[0].Text), &response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 0 {
		t.Fatal("disabled node offered as a usable candidate")
	}
}

func TestNetworkInvocationRejectsMalformedNodeSelectionBeforeProbing(t *testing.T) {
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	var hits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer proxy.Close()
	node, err := service.AddProxy(proxy.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(nil))
	registerNetworkTools(server, service, nil, nil)
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"agent:execute": true}))
	for _, item := range []struct {
		name string
		args map[string]interface{}
	}{
		{"network_acquire", map[string]interface{}{"target": "http://target.example.test", "node_id": true}},
		{"network_diagnose", map[string]interface{}{"target": "http://target.example.test", "node_ids": node.ID}},
		{"network_diagnose", map[string]interface{}{"target": "http://target.example.test", "node_ids": []interface{}{node.ID, 123}}},
	} {
		result, _, err := server.CallTool(ctx, item.name, item.args)
		if err == nil && result != nil && !result.IsError {
			t.Errorf("malformed selection silently triggered automatic choice: %s", item.name)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("invalid arguments started %d proxy requests", hits.Load())
	}
}

func TestNetworkStatusPagingDoesNotMoveWhenHealthChanges(t *testing.T) {
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	for i := 0; i < 3; i++ {
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
		defer proxy.Close()
		if _, err = service.AddProxy(proxy.URL, "manual"); err != nil {
			t.Fatal(err)
		}
	}
	nodes := service.Nodes()
	identity := network.Identity{RunnerID: "local"}
	target := "http://target.example.test"
	first, err := networkStatus(service, identity, network.Scope{}, map[string]interface{}{"target": target, "limit": float64(2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Diagnose(context.Background(), identity, network.Scope{}, target, []string{nodes[2].ID}); err != nil {
		t.Fatal(err)
	}
	second, err := networkStatus(service, identity, network.Scope{}, map[string]interface{}{"target": target, "offset": float64(2)})
	if err != nil {
		t.Fatal(err)
	}
	page := second.(map[string]interface{})["nodes"].([]network.Node)
	if len(page) != 1 || page[0].ID != nodes[2].ID {
		t.Fatalf("health ranking changed offset pagination: first=%v second=%v", first, second)
	}
}

func TestNetworkStatusExplainsTargetLeaseAndNextInvocation(t *testing.T) {
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer proxy.Close()
	node, err := service.AddProxy(proxy.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	identity := network.Identity{UserID: "fixture", ConversationID: "task", RunID: "run", RunnerID: "local"}
	targetA, targetB := "http://a.example.test", "http://b.example.test"
	leaseA, err := service.Acquire(context.Background(), identity, network.Scope{}, network.AcquireRequest{Target: targetA, NodeID: node.ID})
	if err != nil {
		t.Fatal(err)
	}
	leaseB, err := service.Acquire(context.Background(), identity, network.Scope{}, network.AcquireRequest{Target: targetB, NodeID: node.ID})
	if err != nil {
		t.Fatal(err)
	}
	output, err := networkStatus(service, identity, network.Scope{}, map[string]interface{}{"target": targetA})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(output)
	var response struct {
		Execution struct {
			Selected *network.Lease `json:"selected_lease"`
			Target   *network.Lease `json:"target_lease"`
			Matches  bool           `json:"selected_lease_matches_target"`
			Needs    bool           `json:"needs_acquire_for_exec_target"`
		} `json:"execution"`
		NextAction string `json:"next_action"`
		NextCall   struct {
			Tool      string            `json:"tool"`
			Arguments map[string]string `json:"arguments"`
		} `json:"next_call"`
	}
	if err = json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if response.Execution.Selected == nil || response.Execution.Selected.ID != leaseB.ID || response.Execution.Target == nil || response.Execution.Target.ID != leaseA.ID || response.Execution.Matches || !response.Execution.Needs {
		t.Fatalf("target lease confused with latest command selection: %s", encoded)
	}
	if runtime.GOOS == "linux" && (response.NextCall.Tool != "network_acquire" || response.NextCall.Arguments["target"] != targetA || response.NextCall.Arguments["node_id"] != node.ID) {
		t.Fatalf("missing actionable reacquire invocation: %s", encoded)
	}
	output, err = networkStatus(service, identity, network.Scope{}, map[string]interface{}{"target": targetB})
	if err != nil {
		t.Fatal(err)
	}
	execution := output.(map[string]interface{})["execution"].(map[string]interface{})
	if execution["selected_lease_matches_target"] != true || execution["needs_acquire_for_exec_target"] != false {
		t.Fatalf("current target lease not recognized: %v", execution)
	}
	output, err = networkStatus(service, network.Identity{UserID: "fixture", RunnerID: "local"}, network.Scope{}, map[string]interface{}{"target": targetA})
	if err != nil {
		t.Fatal(err)
	}
	if output.(map[string]interface{})["next_action"] != "open_task_context" {
		t.Fatalf("missing trusted conversation was not explained: %v", output)
	}
}

func TestNetworkStatusDoesNotReturnSourceSecretsOrLargeQueries(t *testing.T) {
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	_, err = service.SaveSource(network.Source{Name: "fixture", Kind: "fofa", Query: strings.Repeat("synthetic-query-secret", 350), Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SaveSource(network.Source{Name: "fixture-subscription", Kind: "subscription", URL: "https://fixture.example.test/private-token?token=synthetic-subscription-secret", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, err := networkStatus(service, network.Identity{}, network.Scope{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	if len(raw) > 16000 || strings.Contains(string(raw), "synthetic-query-secret") || strings.Contains(string(raw), "synthetic-subscription-secret") {
		t.Fatalf("status returned execution-unrelated source secrets or oversized config: %d bytes", len(raw))
	}
}

func TestNetworkStatusGuidanceUsesEffectiveTargetPolicy(t *testing.T) {
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	fixed, err := service.AddProjectProxy("p", "http://127.0.0.1:19080")
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SavePolicy("p", network.Policy{Mode: "fixed_proxy", ProxyID: fixed.ID, Targets: []string{"fixed.test", "excluded.test", "binding.test"}, Exclude: []string{"excluded.test"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	scope := network.Scope{Targets: []string{"fixed.test", "excluded.test", "binding.test", "pool.test"}}
	_, err = service.BindAsset(context.Background(), "p", "binding.test", "synthetic user exclusion", true, "user", scope)
	if err != nil {
		t.Fatal(err)
	}
	identity := network.Identity{ProjectID: "p", ConversationID: "task"}
	for _, host := range []string{"fixed.test", "excluded.test", "binding.test", "pool.test"} {
		output, err := networkStatus(service, identity, scope, map[string]interface{}{"target": "http://" + host})
		if err != nil {
			t.Fatal(err)
		}
		execution := output.(map[string]interface{})["execution"].(map[string]interface{})
		wantFixed := host == "fixed.test"
		if execution["automatic_project_network"] != wantFixed || execution["needs_acquire_for_exec_target"] != !wantFixed {
			t.Fatalf("%s routing guidance disagrees with effective project policy: %v", host, execution)
		}
	}
}

func TestNetworkStatusSuggestionRespectsFilters(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux execution guidance")
	}
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer proxy.Close()
	node, err := service.AddProxy(proxy.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	identity := network.Identity{ConversationID: "task"}
	for _, acquire := range []bool{false, true} {
		if acquire {
			_, err = service.Acquire(context.Background(), identity, network.Scope{}, network.AcquireRequest{Target: "http://first.test", NodeID: node.ID})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Acquire(context.Background(), identity, network.Scope{}, network.AcquireRequest{Target: "http://second.test", NodeID: node.ID})
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, filters := range []map[string]interface{}{{"protocol": "socks5"}, {"status": "disabled"}} {
			filters["target"] = "http://first.test"
			output, err := networkStatus(service, identity, network.Scope{}, filters)
			if err != nil {
				t.Fatal(err)
			}
			result := output.(map[string]interface{})
			if result["next_call"] != nil {
				t.Fatalf("suggestion ignored filters (existing lease=%v): %v", acquire, result["next_call"])
			}
		}
	}
}
