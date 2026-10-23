package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/network"
	projectctx "cyberstrike-ai/internal/project"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestProjectNetworkPageUsesCurrentAgentAssessment(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	p, err := db.CreateProject(&database.Project{Name: "synthetic app", Description: "允许应用自有后端", ScopeJSON: `{"targets":["portal.example.test"]}`})
	if err != nil {
		t.Fatal(err)
	}
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base, key, err := projectctx.NetworkScope(p, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindAssessedAsset(context.Background(), p.ID, "api.backend.test", "observed API", "authorized owned backend", key, base); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Scope: database.RBACScopeAll, Permissions: map[string]bool{"project:read": true}})
	})
	NewNetworkHandler(s, db).Register(router.Group("/api"))
	read := func(want bool) {
		t.Helper()
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/projects/"+p.ID+"/network-policy", nil))
		var payload struct {
			Scope    network.Scope `json:"scope"`
			Bindings []struct {
				ScopeState string `json:"scope_state"`
			} `json:"bindings"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &payload) != nil {
			t.Fatalf("read project network: %d %s", response.Code, response.Body.String())
		}
		target, _ := network.ParseTarget("api.backend.test")
		if payload.Scope.Contains(target) != want {
			t.Fatalf("page and execution scope disagree: %+v", payload.Scope)
		}
		expected := "needs_reassessment"
		if want {
			expected = "active"
		}
		if len(payload.Bindings) != 1 || payload.Bindings[0].ScopeState != expected {
			t.Fatalf("page binding shows wrong scope state: %+v", payload.Bindings)
		}
	}
	read(true)
	p.ScopeJSON = `{"targets":["portal.example.test"],"notes":"仅入口，不含后端"}`
	if err := db.UpdateProject(p); err != nil {
		t.Fatal(err)
	}
	read(false)
}

func TestProjectNarrativeEditsInvalidateAssessedNetworkAfterSave(t *testing.T) {
	db, _ := setupConversationRBACTest(t)
	p, err := db.CreateProject(&database.Project{Name: "synthetic", Description: "original scope"})
	if err != nil {
		t.Fatal(err)
	}
	h := NewProjectHandler(db, zap.NewNop())
	invalidated := 0
	h.SetNetworkInvalidator(func(id string) {
		invalidated++
		saved, err := db.GetProject(id)
		if err != nil || saved.Description != "updated scope" {
			t.Errorf("invalidated before saved narrative: %+v %v", saved, err)
		}
	})
	router := gin.New()
	router.PUT("/projects/:id", h.UpdateProject)
	for _, body := range []string{`{"description":"updated scope"}`, `{"testing_specification":{"name":"scope","content":"only portal.example.test"}}`} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, "/projects/"+p.ID, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("update narrative: %d %s", response.Code, response.Body.String())
		}
	}
	if invalidated != 2 {
		t.Fatalf("narrative updates did not retire old network: %d", invalidated)
	}
}
