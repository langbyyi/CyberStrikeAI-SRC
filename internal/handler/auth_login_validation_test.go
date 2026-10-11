package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLoginRejectsMissingAndLongUsernameBeforeAuthentication(t *testing.T) {
	h := &AuthHandler{}
	r := gin.New()
	r.POST("/login", h.Login)
	for _, username := range []string{"", "  ", strings.Repeat("x", 65), strings.Repeat("中", 65)} {
		body, _ := json.Marshal(map[string]string{"username": username, "password": "test-only-password"})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("username %q: %d", username, w.Code)
		}
	}
}
