package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestRBACRoleMaintenanceSessionIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name        string
		method      string
		member      bool
		scope       string
		permissions []string
		target      string
		status      int
		revoke      bool
	}{
		{name: "delete empty role", method: http.MethodDelete, status: 200},
		{name: "delete member role", method: http.MethodDelete, member: true, status: 200, revoke: true},
		{name: "metadata only", method: http.MethodPut, member: true, scope: "all", permissions: []string{"auth:self", "chat:write"}, status: 200},
		{name: "equivalent permission set", method: http.MethodPut, member: true, scope: " all ", permissions: []string{" chat:write ", "auth:self", "chat:write", " "}, status: 200},
		{name: "permission reduction", method: http.MethodPut, member: true, scope: "all", permissions: []string{"auth:self"}, status: 200, revoke: true},
		{name: "permission expansion", method: http.MethodPut, member: true, scope: "all", permissions: []string{"auth:self", "chat:write", "chat:read"}, status: 200, revoke: true},
		{name: "scope reduction", method: http.MethodPut, member: true, scope: "own", permissions: []string{"auth:self", "chat:write"}, status: 200, revoke: true},
		{name: "empty role permission change", method: http.MethodPut, scope: "own", permissions: []string{"auth:self"}, status: 200},
		{name: "invalid permission", method: http.MethodPut, member: true, scope: "all", permissions: []string{"invalid:permission"}, status: 400},
		{name: "missing role update", method: http.MethodPut, member: true, target: "missing-role", status: 404},
		{name: "system role update", method: http.MethodPut, member: true, target: database.RBACSystemRoleViewer, status: 400},
		{name: "system role deletion", method: http.MethodDelete, member: true, target: database.RBACSystemRoleViewer, status: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := database.NewDB(filepath.Join(t.TempDir(), "roles.db"), zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			auth := security.NewAuthManager(12)
			adminPassword, err := auth.AttachRBACStore(db)
			if err != nil {
				t.Fatal(err)
			}
			role, err := db.UpsertRBACRole("", "probe", "before", database.RBACScopeAll, []string{"auth:self", "chat:write"})
			if err != nil {
				t.Fatal(err)
			}
			hash, err := security.HashPassword("member-password")
			if err != nil {
				t.Fatal(err)
			}
			roles := []string{database.RBACSystemRoleViewer}
			if tc.member {
				roles = append(roles, role.ID)
			}
			if _, err := db.CreateRBACUser("member", "Member", hash, true, roles); err != nil {
				t.Fatal(err)
			}
			if _, err := db.CreateRBACUser("unrelated", "Unrelated", hash, true, []string{database.RBACSystemRoleViewer}); err != nil {
				t.Fatal(err)
			}
			login := func(username, password string) string {
				t.Helper()
				token, _, err := auth.Authenticate(username, password)
				if err != nil {
					t.Fatal(err)
				}
				return token
			}
			adminToken := login("admin", adminPassword)
			memberTokens := []string{login("member", "member-password"), login("member", "member-password")}
			unrelatedToken := login("unrelated", "member-password")
			h := NewRBACHandler(db, zap.NewNop())
			h.SetAuthManager(auth)
			router := gin.New()
			router.Use(security.AuthMiddleware(auth), security.RBACMiddleware(db))
			router.GET("/api/rbac/me", h.Me)
			router.PUT("/api/rbac/roles/:id", h.UpdateRole)
			router.DELETE("/api/rbac/roles/:id", h.DeleteRole)
			request := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(method, path, bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				return w
			}
			checkMe := func(token string, want int) {
				t.Helper()
				w := request(http.MethodGet, "/api/rbac/me", token, nil)
				if w.Code != want {
					t.Fatalf("me status = %d, want %d: %s", w.Code, want, w.Body.String())
				}
			}
			for _, token := range append([]string{adminToken, unrelatedToken}, memberTokens...) {
				checkMe(token, http.StatusOK)
			}
			body, err := json.Marshal(map[string]interface{}{
				"name": "probe renamed", "description": "after", "scope": tc.scope, "permissions": tc.permissions,
			})
			if err != nil {
				t.Fatal(err)
			}
			target := role.ID
			if tc.target != "" {
				target = tc.target
			}
			w := request(tc.method, "/api/rbac/roles/"+target, adminToken, body)
			if w.Code != tc.status {
				t.Fatalf("maintenance status = %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			checkMe(adminToken, http.StatusOK)
			checkMe(unrelatedToken, http.StatusOK)
			want := http.StatusOK
			if tc.revoke {
				want = http.StatusUnauthorized
			}
			for _, token := range memberTokens {
				checkMe(token, want)
			}
			if tc.revoke {
				newToken := login("member", "member-password")
				checkMe(newToken, http.StatusOK)
				session, _ := auth.ValidateToken(newToken)
				if tc.method == http.MethodDelete || tc.name == "permission reduction" {
					if session.Permissions["chat:write"] {
						t.Fatal("new login retained revoked chat:write permission")
					}
				}
				if tc.name == "scope reduction" && session.ScopeFor("chat:write") != database.RBACScopeOwn {
					t.Fatal("new login retained old chat:write scope")
				}
			}
		})
	}
}
