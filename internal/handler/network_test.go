package handler

import (
	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/config"
	"go.uber.org/zap"

	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/network"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
)

func TestNetworkAPIProxyRedactionAndNoProject(t *testing.T) {
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "fixture", Scope: database.RBACScopeAll, Permissions: map[string]bool{"agent:execute": true, "config:write": true}})
	})
	h := NewNetworkHandler(s, nil)
	h.Register(router.Group("/api"))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/network/proxies", strings.NewReader(`{"addresses":"socks5://fixture:synthetic-password@127.0.0.1:1080"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != 200 || strings.Contains(w.Body.String(), "synthetic-password") {
		t.Fatalf("unsafe import response: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/network/proxies", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "socks5") || strings.Contains(w.Body.String(), "synthetic-password") {
		t.Fatal("global pool listing failed or exposed secrets")
	}
}

func TestNetworkAPIGlobalMutationRequiresAdministration(t *testing.T) {
	s, _ := network.Open(t.TempDir())
	defer s.Close()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "viewer", Scope: database.RBACScopeAll, Permissions: map[string]bool{"agent:execute": true}})
	})
	NewNetworkHandler(s, nil).Register(r.Group("/api"))
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/network/proxies", strings.NewReader(`{"addresses":"http://127.0.0.1:8080"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("ordinary caller mutated shared catalog")
	}
	var failure struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(w.Body.Bytes(), &failure) != nil || failure.Error != "network_forbidden" || failure.Message == "" {
		t.Fatalf("network error contract is unstable: %s", w.Body.String())
	}
}

func TestNetworkAPIProjectIsolationAndVersionConflict(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	project, err := db.CreateProject(&database.Project{Name: "network fixture", ScopeJSON: `{"targets":["*.example.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := gin.New()
	scope := database.RBACScopeAssigned
	r.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: scope, Permissions: map[string]bool{"project:read": true, "project:write": true}})
	})
	NewNetworkHandler(s, db).Register(r.Group("/api"))
	path := "/api/projects/" + project.ID + "/network-policy"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != 403 {
		t.Fatalf("unassigned project network exposed: %d", w.Code)
	}
	scope = database.RBACScopeAll
	for index, code := range []int{200, 409} {
		w = httptest.NewRecorder()
		req := httptest.NewRequest("PUT", path, strings.NewReader(`{"mode":"fixed_proxy","version":0,"proxy_address":"socks5://fixture:private-credential@127.0.0.1:1080","targets":["*.example.test"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != code {
			t.Fatalf("save %d: %d %s", index, w.Code, w.Body.String())
		}
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	var data map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || strings.Contains(w.Body.String(), "private-credential") {
		t.Fatal("project read exposed proxy credential")
	}
	if len(s.Nodes()) != 0 {
		t.Fatal("project proxy entered shared pool")
	}
}

func TestNetworkManagementAPIAndAuditIsolation(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	s, _ := network.Open(t.TempDir())
	defer s.Close()
	node, _ := s.AddProxy("http://fixture:old@127.0.0.1:8080", "manual")
	private, _ := s.AddProjectProxy("private-project", "http://127.0.0.1:8081")
	handler := NewNetworkHandler(s, db)
	handler.SetAudit(audit.NewService(db, &config.Config{}, zap.NewNop()))
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Username: "fixture-operator", Scope: database.RBACScopeAll, Permissions: map[string]bool{"config:write": true}})
	})
	group := router.Group("/api")
	handler.Register(group)
	group.POST("/unrelated", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	send := func(method, path, body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		return recorder
	}
	edited := send("PUT", "/api/network/proxies/"+node.ID, `{"address":"socks5://fixture:new-synthetic-secret@127.0.0.1:1080"}`)
	if edited.Code != 200 || strings.Contains(edited.Body.String(), "new-synthetic-secret") || !strings.Contains(edited.Body.String(), `"port":"1080"`) {
		t.Fatalf("edit: %d %s", edited.Code, edited.Body)
	}
	if result := send("DELETE", "/api/network/proxies/"+private.ID, ""); result.Code == 200 {
		t.Fatal("global management deleted project private node")
	}
	if _, err := s.SavePolicy("p", network.Policy{Mode: "fixed_proxy", ProxyID: node.ID, Targets: []string{"target.test"}}, 0); err != nil {
		t.Fatal(err)
	}
	if result := send("DELETE", "/api/network/proxies/"+node.ID, ""); result.Code != 409 {
		t.Fatalf("referenced node deletion: %d", result.Code)
	}
	_, _ = s.SavePolicy("p", network.Policy{Mode: "auto"}, 1)
	if result := send("DELETE", "/api/network/proxies/"+node.ID, ""); result.Code != 200 {
		t.Fatalf("delete: %d %s", result.Code, result.Body)
	}
	if result := send("POST", "/api/unrelated", `{"password":"unrelated-synthetic-secret"}`); result.Code != 200 {
		t.Fatal(result.Code)
	}
	logs, err := db.ListAuditLogs(database.ListAuditLogsFilter{Category: "network", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 4 {
		t.Fatalf("audit middleware touched unrelated routes or missed mutations: %d", len(logs))
	}
	raw, _ := json.Marshal(logs)
	if strings.Contains(string(raw), "synthetic-secret") {
		t.Fatal("network audit recorded request secrets")
	}
	failed := 0
	for _, entry := range logs {
		if entry.Result == "failure" {
			failed++
		}
	}
	if failed != 2 {
		t.Fatalf("audit success/failure inaccurate: %d failures", failed)
	}
}

func TestProjectScopeEditsInvalidateNetworkAfterSave(t *testing.T) {
	db, _ := setupConversationRBACTest(t)
	project, err := db.CreateProject(&database.Project{Name: "scope fixture", ScopeJSON: `{"targets":["a.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewProjectHandler(db, zap.NewNop())
	invalidated := 0
	handler.SetNetworkInvalidator(func(id string) {
		invalidated++
		saved, e := db.GetProject(id)
		if e != nil || !strings.Contains(saved.ScopeJSON, "b.test") {
			t.Error("invalidated before persisting scope")
		}
	})
	router := gin.New()
	router.PUT("/projects/:id", handler.UpdateProject)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/projects/"+project.ID, strings.NewReader(`{"scope_json":"{\"targets\":[\"b.test\"]}"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != 200 || invalidated != 1 {
		t.Fatalf("scope invalidation: %d calls=%d %s", recorder.Code, invalidated, recorder.Body)
	}
}

func TestNetworkPolicyCannotExtendProjectTestingScope(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	project, err := db.CreateProject(&database.Project{Name: "bounded fixture", ScopeJSON: `{"targets":["*.example.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	service, _ := network.Open(t.TempDir())
	defer service.Close()
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAll, Permissions: map[string]bool{"project:read": true, "project:write": true}})
	})
	NewNetworkHandler(service, db).Register(router.Group("/api"))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/projects/"+project.ID+"/network-policy", strings.NewReader(`{"mode":"auto","version":0,"targets":["outside.test"]}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != 400 || service.Policy(project.ID).Version != 0 {
		t.Fatalf("network policy expanded test scope: %d %s", recorder.Code, recorder.Body)
	}
}

func TestNetworkAPIFallbackTargetsPreserveProjectAndPolicyExclusions(t *testing.T) {
	for name, scopeJSON := range map[string]string{
		"omitted": `{"exclude":["project-blocked.example.test"]}`,
		"empty":   `{"targets":[],"exclude":["project-blocked.example.test"]}`,
		"null":    `{"targets":null,"exclude":["project-blocked.example.test"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			db, user := setupConversationRBACTest(t)
			project, err := db.CreateProject(&database.Project{Name: "fallback exclusions fixture", ScopeJSON: scopeJSON})
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
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAll, Permissions: map[string]bool{"project:read": true, "project:write": true}})
			})
			NewNetworkHandler(service, db).Register(router.Group("/api"))
			path := "/api/projects/" + project.ID
			read := httptest.NewRecorder()
			router.ServeHTTP(read, httptest.NewRequest(http.MethodGet, path+"/network-policy", nil))
			var result struct {
				Scope network.Scope `json:"scope"`
			}
			if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &result) != nil {
				t.Fatalf("read effective scope: %d %s", read.Code, read.Body.String())
			}
			for _, target := range []string{"project-blocked.example.test", "policy-blocked.example.test", "outside.test"} {
				parsed, err := network.ParseTarget(target)
				if err != nil {
					t.Fatal(err)
				}
				if result.Scope.Contains(parsed) {
					t.Errorf("effective scope allowed excluded or outside target %s: %+v", target, result.Scope)
				}
				write := httptest.NewRecorder()
				request := httptest.NewRequest(http.MethodPut, path+"/network-policy", strings.NewReader(`{"mode":"auto","version":1,"targets":["`+target+`"]}`))
				request.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(write, request)
				if write.Code != http.StatusBadRequest || service.Policy(project.ID).Version != 1 {
					t.Errorf("policy accepted excluded or outside target %s: %d %s", target, write.Code, write.Body.String())
				}
			}
			allowed, err := network.ParseTarget("allowed.example.test")
			if err != nil || !result.Scope.Contains(allowed) {
				t.Fatalf("fallback lost allowed policy target: %+v %v", result.Scope, err)
			}
		})
	}
}
