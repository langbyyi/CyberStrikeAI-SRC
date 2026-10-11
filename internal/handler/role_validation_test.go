package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestRoleNameValidation(t *testing.T) {
	for _, name := range []string{"", " ", "../role", "a/b", `a\b`, "a..b", "a\n", strings.Repeat("中", 65)} {
		if validateRoleName(name) == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	for _, name := range []string{"安全分析", "Web Audit", "role-v2", strings.Repeat("中", 64)} {
		if err := validateRoleName(name); err != nil {
			t.Fatalf("rejected %q: %v", name, err)
		}
	}
}

func TestRoleWorkflowValidationAndDeletion(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "roles.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.UpsertWorkflowDefinition(&database.WorkflowDefinition{ID: "wf", Name: "test", GraphJSON: `{"nodes":[],"edges":[]}`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Roles: map[string]config.RoleConfig{"bound": {Name: "bound", WorkflowID: "wf"}}}
	h := NewRoleHandler(cfg, filepath.Join(t.TempDir(), "config.yaml"), zap.NewNop())
	h.SetDB(db)
	wf := NewWorkflowHandler(db, zap.NewNop())
	wf.SetRuntime(nil, cfg)
	r := gin.New()
	r.POST("/roles", h.CreateRole)
	r.PUT("/roles/:name", h.UpdateRole)
	r.DELETE("/workflows/:id", wf.Delete)
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		path := "/roles"
		if method == http.MethodPut {
			path += "/bound"
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(`{"name":"new-role","workflow_id":"missing"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", method, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/workflows/wf", nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("delete referenced: %d %s", w.Code, w.Body.String())
	}
	if err := h.validateRole(config.RoleConfig{Name: "valid", WorkflowID: "wf"}); err != nil {
		t.Fatal(err)
	}
	if cfg.Roles["bound"].WorkflowID != "wf" {
		t.Fatal("rejected update mutated roles")
	}
	delete(cfg.Roles, "bound")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/workflows/wf", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete unreferenced: %d %s", w.Code, w.Body.String())
	}
}
