package handler

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/c2"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestC2ListenerEditRejectsInvalidFieldsWithoutSaving(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "listener.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	original := &database.C2Listener{ID: "listener", Name: "original", Type: "http_beacon", BindHost: "127.0.0.1", BindPort: 8080, Status: "stopped", CreatedAt: time.Now()}
	if err := db.CreateC2Listener(original); err != nil {
		t.Fatal(err)
	}
	h := NewC2Handler(c2.NewManager(db, zap.NewNop(), t.TempDir()), zap.NewNop())
	r := gin.New()
	r.PUT("/listeners/:id", h.UpdateListener)
	for _, tc := range []struct {
		name   string
		port   int
		status int
	}{{"", 8080, 400}, {"  ", 8080, 400}, {"changed", 0, 400}, {"changed", 65536, 400}, {"changed", 8081, 200}} {
		body := fmt.Sprintf(`{"name":%q,"bind_host":"127.0.0.1","bind_port":%d,"remark":"new remark"}`, tc.name, tc.port)
		req := httptest.NewRequest(http.MethodPut, "/listeners/listener", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		saved, err := db.GetC2Listener("listener")
		if err != nil {
			t.Fatal(err)
		}
		if tc.status == 400 && (saved.Name != "original" || saved.BindPort != 8080 || saved.Remark != "") {
			t.Fatalf("invalid request saved fields: %#v", saved)
		}
		if tc.status == 200 && (saved.Name != "changed" || saved.BindPort != 8081 || saved.Remark != "new remark") {
			t.Fatalf("valid edit not saved: %#v", saved)
		}
	}
}

func TestC2OnelinerRejectsInvalidCallbackAndUsesListenerScheme(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "callback.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	listener := &database.C2Listener{ID: "https", Name: "test", Type: "https_beacon", BindHost: "127.0.0.1", BindPort: 8443, ImplantToken: "test-only-token", CreatedAt: time.Now()}
	if err := db.CreateC2Listener(listener); err != nil {
		t.Fatal(err)
	}
	h := NewC2Handler(c2.NewManager(db, zap.NewNop(), t.TempDir()), zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "test-owner", Scope: database.RBACScopeAll})
	})
	r.POST("/oneliner", h.PayloadOneliner)
	for _, host := range []string{"bad host/abc", "https://example.com", "example.com:8443", "example.com", "::1"} {
		req := httptest.NewRequest(http.MethodPost, "/oneliner", bytes.NewBufferString(fmt.Sprintf(`{"listener_id":"https","kind":"curl_beacon","host":%q}`, host)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		valid := host == "example.com" || host == "::1"
		if !valid && w.Code != 400 {
			t.Fatalf("invalid callback status: %d", w.Code)
		}
		if valid {
			if w.Code != 200 {
				t.Fatalf("valid callback status: %d", w.Code)
			}
			expected := "https://example.com:8443"
			if host == "::1" {
				expected = "https://[::1]:8443"
			}
			if !bytes.Contains(w.Body.Bytes(), []byte(expected)) {
				t.Fatalf("scheme or IPv6 formatting lost")
			}
		}
	}
}
