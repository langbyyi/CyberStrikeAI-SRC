package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cyberstrike-ai/internal/database"
	"github.com/gin-gonic/gin"
)

func TestNetworkManagementUsesExistingConfigWritePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/network/sources"},
		{http.MethodPost, "/api/network/sources"},
		{http.MethodDelete, "/api/network/sources/:source"},
		{http.MethodDelete, "/api/network/proxies/:node"},
		{http.MethodGet, "/api/network/validation"},
		{http.MethodGet, "/api/network/export"},
		{http.MethodPut, "/api/network/validation"},
		{http.MethodPost, "/api/network/validate"},
		{http.MethodPost, "/api/network/subscriptions/import"},
	} {
		for _, allowed := range []bool{true, false} {
			t.Run(route.method+route.path+map[bool]string{true: "/admin", false: "/reader"}[allowed], func(t *testing.T) {
				router := gin.New()
				router.Use(func(c *gin.Context) {
					c.Set(ContextSessionKey, Session{UserID: "fixture-user", Permissions: map[string]bool{"config:write": allowed, "config:read": true}, Scope: database.RBACScopeAll})
					c.Next()
				}, RBACMiddleware(nil))
				router.Handle(route.method, route.path, func(c *gin.Context) { c.Status(http.StatusOK) })
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))
				want := http.StatusForbidden
				if allowed {
					want = http.StatusOK
				}
				if w.Code != want {
					t.Fatalf("status = %d, want %d: %s", w.Code, want, w.Body.String())
				}
			})
		}
	}
}
