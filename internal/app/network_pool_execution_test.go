package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/handler"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/network"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestTaskNetworkCleanupSurvivesProjectIdentityChanges(t *testing.T) {
	for _, change := range []string{"revoke_access", "move_project", "unbind_project"} {
		t.Run(change, func(t *testing.T) {
			db, err := database.NewDB(filepath.Join(t.TempDir(), "task-network.db"), zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			project, err := db.CreateProject(&database.Project{Name: "cleanup fixture", ScopeJSON: `{"targets":["target.example.test"]}`})
			if err != nil {
				t.Fatal(err)
			}
			conversation, err := db.CreateConversation("cleanup task", database.ConversationCreateMeta{ProjectID: project.ID})
			if err != nil {
				t.Fatal(err)
			}
			user, err := db.CreateRBACUser("cleanup-fixture", "Fixture", "synthetic-unused-hash", true, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = db.AssignResourceToUser(user.ID, "project", project.ID); err != nil {
				t.Fatal(err)
			}
			service, err := network.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
			defer proxy.Close()
			node, err := service.AddProxy(proxy.URL, "manual")
			if err != nil {
				t.Fatal(err)
			}
			server := mcp.NewServer(zap.NewNop())
			server.SetToolAuthorizer(mcpToolAuthorizer(db))
			registerNetworkTools(server, service, db, nil)
			processes := security.NewProcessScope()
			principal := authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeAssigned, map[string]bool{"agent:execute": true, "project:read": true})
			ctx := security.WithProcessScope(mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), principal), conversation.ID), processes)
			identity, scope, err := networkContext(ctx, db, service)
			if err != nil {
				t.Fatal(err)
			}
			security.SetNetworkTaskCloser(networkTaskCloser(service))
			defer security.SetNetworkTaskCloser(nil)
			result, _, err := server.CallTool(ctx, "network_acquire", map[string]interface{}{"target": "http://target.example.test", "node_id": node.ID})
			if err != nil || result == nil || result.IsError {
				t.Fatalf("acquire fixture lease: %v %+v", err, result)
			}
			// A newer run of the same conversation must survive delayed old-run cleanup.
			nextIdentity := identity
			nextIdentity.RunID = security.NewProcessScope().ID
			if _, err = service.Acquire(context.Background(), nextIdentity, scope, network.AcquireRequest{Target: "http://target.example.test", NodeID: node.ID}); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "revoke_access":
				assignments, err := db.ListRBACResourceAssignments(user.ID)
				if err != nil {
					t.Fatal(err)
				}
				for _, assignment := range assignments {
					if err = db.DeleteRBACResourceAssignment(assignment.ID); err != nil {
						t.Fatal(err)
					}
				}
			case "move_project":
				other, err := db.CreateProject(&database.Project{Name: "moved fixture", ScopeJSON: project.ScopeJSON})
				if err != nil {
					t.Fatal(err)
				}
				if err = db.AssignResourceToUser(user.ID, "project", other.ID); err != nil {
					t.Fatal(err)
				}
				if err = db.SetConversationProjectID(conversation.ID, other.ID); err != nil {
					t.Fatal(err)
				}
			case "unbind_project":
				if err = db.SetConversationProjectID(conversation.ID, ""); err != nil {
					t.Fatal(err)
				}
			}
			if err = processes.Close(); err != nil {
				t.Fatal(err)
			}
			if _, exists := service.SelectedLease(identity); exists {
				t.Fatal("ended run retained its lease after project identity changed")
			}
			if _, exists := service.SelectedLease(nextIdentity); !exists {
				t.Fatal("old-run cleanup released a newer run's lease")
			}
		})
	}
}

func TestNetworkAcquireIsReleasedWhenTaskEndsWithoutCommand(t *testing.T) {
	for _, closeDuringAcquire := range []bool{false, true} {
		t.Run(fmt.Sprint(closeDuringAcquire), func(t *testing.T) {
			service, err := network.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			entered, resume := make(chan struct{}), make(chan struct{})
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if closeDuringAcquire {
					close(entered)
					<-resume
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer proxy.Close()
			node, err := service.AddProxy(proxy.URL, "manual")
			if err != nil {
				t.Fatal(err)
			}
			server := mcp.NewServer(zap.NewNop())
			server.SetToolAuthorizer(mcpToolAuthorizer(nil))
			registerNetworkTools(server, service, nil, nil)
			processes := security.NewProcessScope()
			ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "fixture", "all", map[string]bool{"agent:execute": true}))
			ctx = security.WithProcessScope(mcp.WithMCPConversationID(ctx, "lease-only-task"), processes)
			identity, _, err := networkContext(ctx, nil, service)
			if err != nil {
				t.Fatal(err)
			}
			security.SetNetworkTaskCloser(func(context.Context) { service.ReleaseTask(identity) })
			defer security.SetNetworkTaskCloser(nil)
			finished := make(chan *mcp.ToolResult, 1)
			go func() {
				result, _, _ := server.CallTool(ctx, "network_acquire", map[string]interface{}{"target": "http://target.example.test", "node_id": node.ID})
				finished <- result
			}()
			if closeDuringAcquire {
				select {
				case <-entered:
				case result := <-finished:
					t.Fatalf("acquire returned before probing: %+v", result)
				case <-time.After(3 * time.Second):
					t.Fatal("acquire did not start its probe")
				}
				if err := processes.Close(); err != nil {
					t.Fatal(err)
				}
				close(resume)
			}
			result := <-finished
			if !closeDuringAcquire && (result == nil || result.IsError) {
				t.Fatalf("acquire: %+v", result)
			}
			if !closeDuringAcquire {
				if _, exists := service.SelectedLease(identity); !exists {
					t.Fatalf("successful acquire did not create fixture lease: %+v", result)
				}
			}
			if err := processes.Close(); err != nil {
				t.Fatal(err)
			}
			if _, exists := service.SelectedLease(identity); exists {
				t.Fatal("task ended without a shell command but its network lease survived")
			}
		})
	}
}

// Exercise the page API and the real MCP invocation boundary against the same
// store; isolated command gateways have separate Linux/SOCKS integration tests.
func TestNetworkPoolPageImportToAgentTargetExecution(t *testing.T) {
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "baseline") }))
	defer direct.Close()
	var forwarded atomic.Int32
	wantedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture:synthetic-secret"))
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != wantedAuth || r.URL.String() != direct.URL+"/" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		forwarded.Add(1)
		_, _ = io.WriteString(w, "selected-proxy")
	}))
	defer proxy.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusProxyAuthRequired) }))
	defer bad.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	proxyURL.User = url.UserPassword("fixture", "synthetic-secret")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "admin-fixture", Scope: database.RBACScopeAll, Permissions: map[string]bool{"config:write": true}})
	})
	h := handler.NewNetworkHandler(s, nil)
	defer h.Close()
	h.Register(router.Group("/api"))
	raw, _ := json.Marshal(map[string]string{"addresses": proxyURL.String() + "\n" + bad.URL})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/network/proxies", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "synthetic-secret") {
		t.Fatalf("page import failed or exposed credentials: %d", response.Code)
	}
	var imported network.ImportResult
	if err = json.Unmarshal(response.Body.Bytes(), &imported); err != nil || len(imported.Nodes) != 2 {
		t.Fatalf("page import result: %+v, %v", imported, err)
	}
	var goodID, badID string
	for _, node := range imported.Nodes {
		if node.HasAuth {
			goodID = node.ID
		} else {
			badID = node.ID
		}
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(nil))
	registerNetworkTools(server, s, nil, nil)
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("operator-fixture", "operator", "all", map[string]bool{"agent:execute": true}))
	ctx = mcp.WithMCPConversationID(ctx, "proxy-task")
	ctx = security.WithProcessScope(ctx, security.NewProcessScope())
	call := func(name string, args map[string]interface{}, output interface{}, wantError bool) {
		t.Helper()
		result, _, err := server.CallTool(ctx, name, args)
		if err != nil || result == nil || result.IsError != wantError || len(result.Content) != 1 {
			t.Fatalf("%s call: %+v, %v", name, result, err)
		}
		if strings.Contains(result.Content[0].Text, "synthetic-secret") {
			t.Fatalf("%s exposed proxy credentials", name)
		}
		if output != nil {
			if err := json.Unmarshal([]byte(result.Content[0].Text), output); err != nil {
				t.Fatalf("%s returned invalid JSON: %v", name, err)
			}
		}
	}
	var status struct {
		Nodes []network.Node `json:"nodes"`
	}
	call("network_status", nil, &status, false)
	if len(status.Nodes) != 2 {
		t.Fatal("page-imported nodes were not available to the Agent")
	}
	var observations []network.Observation
	call("network_diagnose", map[string]interface{}{"target": direct.URL, "node_ids": []string{badID, goodID}}, &observations, false)
	if len(observations) != 2 || observations[0].Reachable || observations[0].Stage != "proxy_auth" || !observations[1].Reachable {
		t.Fatalf("per-node target results lost: %+v", observations)
	}
	call("network_acquire", map[string]interface{}{"target": direct.URL, "node_id": badID}, nil, true)
	var lease network.Lease
	call("network_acquire", map[string]interface{}{"target": direct.URL, "node_id": goodID}, &lease, false)
	if lease.NodeID != goodID {
		t.Fatal("Agent-selected node was ignored")
	}
	clientFor := networkHTTPClient(nil, s)
	read := func(ctx context.Context, want string) {
		t.Helper()
		client, err := clientFor(ctx, "", &http.Client{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseIdleConnections()
		response, err := client.Get(direct.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != want {
			t.Fatalf("target path: %q, want %q, %v", body, want, err)
		}
	}
	read(ctx, "selected-proxy")
	read(mcp.WithMCPConversationID(ctx, "other-task"), "baseline")
	if forwarded.Load() != 2 {
		t.Fatalf("expected one probe and one execution through proxy, got %d", forwarded.Load())
	}
	call("network_release", map[string]interface{}{"lease_id": lease.ID}, nil, false)
	read(ctx, "baseline")
	// A configured source uses the same pool, and an ordinary Agent can refresh
	// it without receiving administrator configuration permissions or secrets.
	source, err := s.SaveSource(network.Source{Name: "fixture", Kind: "fofa", Query: `protocol="socks5"`, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	registerNetworkTools(server, s, nil, func(context.Context, network.Source, int) ([]string, bool, error) {
		return []string{"socks5://127.0.0.1:18081"}, true, nil
	})
	call("network_sync_source", map[string]interface{}{"source_id": source.ID}, nil, false)
	call("network_status", nil, &status, false)
	if len(status.Nodes) != 3 {
		t.Fatal("Agent source sync did not feed the shared page pool")
	}
}

func TestLinuxNetworkStatusAcquireExecRoundTrip(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("CYBERSTRIKE_NETWORK_INTEGRATION") != "1" {
		t.Skip("opt-in Linux command routing integration")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration requires root namespace manager")
	}
	t.Setenv("CYBERSTRIKE_NETWORK_UID", "1000")
	t.Setenv("CYBERSTRIKE_NETWORK_GID", "1000")
	service, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	var forwarded atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Hostname() != "network-exec.example.test" {
			t.Errorf("unexpected proxy destination: %s", r.URL.Host)
			w.WriteHeader(502)
			return
		}
		forwarded.Add(1)
		io.WriteString(w, "via-selected-proxy")
	}))
	defer proxy.Close()
	baseline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "baseline") }))
	defer baseline.Close()
	node, err := service.AddProxy(proxy.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(nil))
	registerNetworkTools(server, service, nil, nil)
	cfg := config.SecurityConfig{Tools: []config.ToolConfig{{Name: "exec", Command: "sh", Enabled: true}}}
	security.NewExecutor(&cfg, server, zap.NewNop()).RegisterTools(server)
	security.SetNetworkCommandPreparer(networkCommandPreparer(nil, service))
	defer security.SetNetworkCommandPreparer(nil)
	security.SetNetworkTaskCloser(networkTaskCloser(service))
	defer security.SetNetworkTaskCloser(nil)
	processes := security.NewProcessScope()
	defer processes.Close()
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"agent:execute": true, "agent:local-execute": true}))
	ctx = security.WithProcessScope(mcp.WithMCPConversationID(ctx, "registered-exec-task"), processes)
	call := func(name string, args map[string]interface{}) *mcp.ToolResult {
		t.Helper()
		result, _, err := server.CallTool(ctx, name, args)
		if err != nil || result == nil || result.IsError {
			t.Fatalf("registered %s failed: %+v %v", name, result, err)
		}
		return result
	}
	target := "http://network-exec.example.test"
	status := call("network_status", map[string]interface{}{"target": target})
	var before struct {
		NextCall struct {
			Tool      string                 `json:"tool"`
			Arguments map[string]interface{} `json:"arguments"`
		} `json:"next_call"`
	}
	if err = json.Unmarshal([]byte(status.Content[0].Text), &before); err != nil {
		t.Fatal(err)
	}
	if before.NextCall.Tool != "network_acquire" || before.NextCall.Arguments["node_id"] != node.ID {
		t.Fatalf("missing usable invocation: %s", status.Content[0].Text)
	}
	acquired := call(before.NextCall.Tool, before.NextCall.Arguments)
	var lease network.Lease
	if err = json.Unmarshal([]byte(acquired.Content[0].Text), &lease); err != nil {
		t.Fatal(err)
	}
	status = call("network_status", map[string]interface{}{"target": target})
	var selected struct {
		Execution struct {
			Matches bool   `json:"selected_lease_matches_target"`
			Run     string `json:"run_id"`
		} `json:"execution"`
		NextAction string `json:"next_action"`
	}
	if err = json.Unmarshal([]byte(status.Content[0].Text), &selected); err != nil {
		t.Fatal(err)
	}
	if !selected.Execution.Matches || selected.Execution.Run != processes.ID || selected.NextAction != "execute_local_tool" {
		t.Fatalf("selected route not reported: %s", status.Content[0].Text)
	}
	executed := call("exec", map[string]interface{}{"command": "id -u; curl --fail --silent --show-error --max-time 8 http://network-exec.example.test/", "workdir": "/tmp"})
	if !strings.Contains(executed.Content[0].Text, "1000") || !strings.Contains(executed.Content[0].Text, "via-selected-proxy") || forwarded.Load() != 2 {
		t.Fatalf("exec did not use the selected proxy: %+v forwarded=%d", executed, forwarded.Load())
	}
	call("network_release", map[string]interface{}{"lease_id": lease.ID})
	status = call("network_status", map[string]interface{}{"target": target})
	var released struct {
		Execution struct {
			Lease *network.Lease `json:"selected_lease"`
		} `json:"execution"`
	}
	if err = json.Unmarshal([]byte(status.Content[0].Text), &released); err != nil {
		t.Fatal(err)
	}
	if released.Execution.Lease != nil {
		t.Fatal("released lease remained visible")
	}
	executed = call("exec", map[string]interface{}{"command": "curl --noproxy '*' --fail --silent --show-error --max-time 5 " + baseline.URL, "workdir": "/tmp"})
	if !strings.Contains(executed.Content[0].Text, "baseline") || forwarded.Load() != 2 {
		t.Fatalf("released task did not return to default network: %+v", executed)
	}
}
