package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/network"
	"go.uber.org/zap"
)

func TestEmptyFixedScopeCannotProbeAcquireOrUseBaseline(t *testing.T) {
	for _, mode := range []string{"fixed_proxy", "fixed_vpn"} {
		t.Run(mode, func(t *testing.T) {
			db, err := database.NewDB(filepath.Join(t.TempDir(), "empty-scope.db"), zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			p, err := db.CreateProject(&database.Project{Name: "synthetic", Description: "authorized owned app"})
			if err != nil {
				t.Fatal(err)
			}
			s, err := network.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var hits atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(http.StatusOK) }))
			defer proxy.Close()
			assigned, err := s.AddProjectProxy(p.ID, proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			global, err := s.AddProxy(proxy.URL, "manual")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.SavePolicy(p.ID, network.Policy{Mode: mode, ProxyID: assigned.ID, VPNProfileID: "synthetic-profile"}, 0); err != nil {
				t.Fatal(err)
			}
			server := mcp.NewServer(zap.NewNop())
			server.SetToolAuthorizer(mcpToolAuthorizer(db))
			registerNetworkTools(server, s, db, nil)
			ctx := mcp.WithMCPProjectID(authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"project:read": true, "agent:execute": true})), p.ID)
			for _, phase := range []string{"initial", "expired"} {
				t.Run(phase, func(t *testing.T) {
					if phase == "expired" {
						key := currentNetworkAssessmentKey(t, server, ctx)
						result, _, err := server.CallTool(ctx, "network_bind_asset", map[string]interface{}{"target": "api.backend.test", "evidence": "observed API", "scope_basis": "project permits owned API", "scope_context": key})
						if err != nil || result == nil || result.IsError {
							t.Fatalf("register fixture: %+v %v", result, err)
						}
						p.Description = "project now authorizes a different app"
						if err := db.UpdateProject(p); err != nil {
							t.Fatal(err)
						}
					}
					before := hits.Load()
					for _, name := range []string{"network_diagnose", "network_acquire"} {
						args := map[string]interface{}{"target": "http://api.backend.test", "node_id": global.ID, "node_ids": []string{global.ID}}
						result, _, err := server.CallTool(ctx, name, args)
						if err != nil || result == nil || !result.IsError {
							t.Errorf("%s bypassed empty fixed scope: %+v %v", name, result, err)
						}
					}
					proxyURL, _ := url.Parse(proxy.URL)
					client, err := networkHTTPClient(db, s)(ctx, p.ID, &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}})
					if err != nil {
						t.Fatal(err)
					}
					defer client.CloseIdleConnections()
					response, err := client.Get("http://api.backend.test")
					if response != nil {
						response.Body.Close()
					}
					if err == nil {
						t.Error("target request used baseline before registering initial scope")
					}
					if hits.Load() != before {
						t.Errorf("empty fixed scope sent %d requests", hits.Load()-before)
					}
				})
			}
		})
	}
}

func TestProjectScopeSnapshotCannotExecuteAfterNarrativeEdit(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "scope-snapshot.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&database.Project{Name: "synthetic", Description: "owned backend permitted", ScopeJSON: `{"targets":["portal.example.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	assigned, err := s.AddProjectProxy(p.ID, "http://127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SavePolicy(p.ID, network.Policy{Mode: "fixed_proxy", ProxyID: assigned.ID}, 0); err != nil {
		t.Fatal(err)
	}
	ctx := mcp.WithMCPProjectID(authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"project:read": true, "agent:execute": true})), p.ID)
	identity, old, err := networkContext(ctx, db, s)
	if err != nil {
		t.Fatal(err)
	}
	identity.ConversationID = "synthetic-task"
	p.Description = "owned backend revoked"
	if err := db.UpdateProject(p); err != nil {
		t.Fatal(err)
	}
	if err := s.DisconnectVPN(p.ID); err != nil {
		t.Fatal(err)
	}
	err = s.PrepareCommand(ctx, identity, old, exec.Command("unused"))
	if err == nil || !strings.Contains(err.Error(), "scope changed") {
		t.Fatalf("old project scope was admitted to command preparation: %v", err)
	}
}

func TestResolvedScopeRejectsLaterPolicyRangeChange(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "policy-snapshot.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreateProject(&database.Project{Name: "synthetic", Description: "owned API allowed", ScopeJSON: `{"targets":["portal.example.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(http.StatusOK) }))
	defer proxy.Close()
	node, err := s.AddProjectProxy(p.ID, proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SavePolicy(p.ID, network.Policy{Mode: "fixed_proxy", ProxyID: node.ID}, 0); err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNetworkTools(server, s, db, nil)
	ctx := mcp.WithMCPProjectID(authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "operator", "all", map[string]bool{"project:read": true, "agent:execute": true})), p.ID)
	result, _, err := server.CallTool(ctx, "network_bind_asset", map[string]interface{}{"target": "api.backend.test", "evidence": "observed owned API", "scope_basis": "current user authorizes owned API", "scope_context": currentNetworkAssessmentKey(t, server, ctx)})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("register API: %+v %v", result, err)
	}
	identity, old, err := networkContext(ctx, db, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SavePolicy(p.ID, network.Policy{Mode: "fixed_proxy", ProxyID: node.ID, Targets: []string{"portal.example.test"}}, 1); err != nil {
		t.Fatal(err)
	}
	transport := s.TargetHTTPTransport(identity, old, nil)
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get("http://api.backend.test")
	if response != nil {
		response.Body.Close()
	}
	if err == nil || hits.Load() != 0 {
		t.Fatalf("stale policy range reached a revoked API: hits=%d err=%v", hits.Load(), err)
	}
}
