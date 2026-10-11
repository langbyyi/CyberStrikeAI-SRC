package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestWebshellMasksResponsesAndPreservesStoredPassword(t *testing.T) {
	db, user, allowed, _ := setupWebshellRBACTest(t)
	allowed.Password = "test-only-webshell-password"
	if err := db.UpdateWebshellConnection(allowed); err != nil {
		t.Fatal(err)
	}
	h := NewWebShellHandler(zap.NewNop(), db)
	w := performWebshellJSON(user, http.MethodGet, "/connections", nil, h.ListConnections)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), allowed.Password) || !strings.Contains(w.Body.String(), maskedSecret) {
		t.Fatalf("unsafe list: %d", w.Code)
	}
	update := func(c *gin.Context) { c.Params = gin.Params{{Key: "id", Value: allowed.ID}}; h.UpdateConnection(c) }
	for _, password := range []string{maskedSecret, "test-only-new-password", ""} {
		w = performWebshellJSON(user, http.MethodPut, "/connections/"+allowed.ID, map[string]interface{}{"url": allowed.URL, "type": "php", "method": "post", "password": password, "remark": "updated"}, update)
		if w.Code != http.StatusOK {
			t.Fatalf("update: %d %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "test-only-") {
			t.Fatal("update returned secret")
		}
		saved, err := db.GetWebshellConnection(allowed.ID)
		if err != nil {
			t.Fatal(err)
		}
		expected := password
		if password == maskedSecret {
			expected = allowed.Password
		}
		if saved.Password != expected {
			t.Fatal("password was not preserved/replaced/cleared as requested")
		}
	}
}

func TestWebshellExecUsesStoredPasswordForMaskedConnection(t *testing.T) {
	db, user, allowed, _ := setupWebshellRBACTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("pass") != "test-only-stored" {
			t.Error("executor did not use stored password")
		}
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()
	allowed.URL, allowed.Password = srv.URL, "test-only-stored"
	if err := db.UpdateWebshellConnection(allowed); err != nil {
		t.Fatal(err)
	}
	h := NewWebShellHandler(zap.NewNop(), db)
	w := performWebshellJSON(user, http.MethodPost, "/exec", map[string]interface{}{"url": allowed.URL, "connection_id": allowed.ID, "password": maskedSecret, "command": "printf OK"}, h.Exec)
	if w.Code != http.StatusOK {
		t.Fatalf("saved exec: %d %s", w.Code, w.Body.String())
	}
	w = performWebshellJSON(user, http.MethodPost, "/exec", map[string]interface{}{"url": allowed.URL, "password": maskedSecret, "command": "printf OK"}, h.Exec)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ad hoc marker accepted: %d", w.Code)
	}
}
