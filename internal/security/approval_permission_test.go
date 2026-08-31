package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
)

func TestApprovalPermissionMapping(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodGet, "/api/approvals", "approval:read"},
		{http.MethodGet, "/api/approvals/:id", "approval:read"},
		{http.MethodPost, "/api/approvals/:id/decision", "approval:decide"},
		{http.MethodGet, "/api/approval-config", "approval:read"},
		{http.MethodPut, "/api/approval-config", "approval:policy:write"},
		{http.MethodPost, "/api/approval-rules", "approval:policy:write"},
	}
	for _, tt := range tests {
		if got := permissionForRequest(tt.method, tt.path); got != tt.want {
			t.Errorf("%s %s permission = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
	for _, permission := range []string{"approval:read", "approval:decide", "approval:policy:write"} {
		if _, ok := PermissionCatalog[permission]; !ok {
			t.Errorf("permission catalog missing %s", permission)
		}
	}
}

func TestApprovalPolicyMutationPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name       string
		method     string
		path       string
		permission string
		want       int
	}{
		{name: "legacy hitl cannot update global config", method: http.MethodPut, path: "/api/approval-config", permission: "hitl:write", want: http.StatusForbidden},
		{name: "policy writer can update global config", method: http.MethodPut, path: "/api/approval-config", permission: "approval:policy:write", want: http.StatusOK},
		{name: "legacy hitl cannot publish danger rules", method: http.MethodPost, path: "/api/approval-rules", permission: "hitl:write", want: http.StatusForbidden},
		{name: "policy writer can publish danger rules", method: http.MethodPost, path: "/api/approval-rules", permission: "approval:policy:write", want: http.StatusOK},
		{name: "legacy hitl cannot decide approvals", method: http.MethodPost, path: "/api/approvals/request-1/decision", permission: "hitl:write", want: http.StatusForbidden},
		{name: "approval decider can decide approvals", method: http.MethodPost, path: "/api/approvals/request-1/decision", permission: "approval:decide", want: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(ContextSessionKey, Session{
					UserID: "user-1", Permissions: map[string]bool{tt.permission: true}, Scope: database.RBACScopeAll,
				})
				c.Next()
			})
			router.Use(RBACMiddleware(nil))
			router.Handle(tt.method, tt.path, func(c *gin.Context) { c.Status(http.StatusOK) })

			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))
			if w.Code != tt.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tt.want, w.Body.String())
			}
		})
	}
}
