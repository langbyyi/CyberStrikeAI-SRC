package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/c2"
	"cyberstrike-ai/internal/database"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestC2ProfilePreservesFieldsAndRejectsInvalidJitter(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "profile.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h := NewC2Handler(c2.NewManager(db, zap.NewNop(), t.TempDir()), zap.NewNop())
	r := gin.New()
	r.POST("/profiles", h.CreateProfile)
	r.PUT("/profiles/:id", h.UpdateProfile)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}
	w := request(http.MethodPost, "/profiles", `{"name":"test","userAgent":"test-only-agent","uris":["/test"],"jitterMinMs":0,"jitterMaxMs":100,"responseHeaders":{"X-Test":"test"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var data struct {
		Profile database.C2Profile `json:"profile"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	saved, err := db.GetC2Profile(data.Profile.ID)
	if err != nil || saved == nil || saved.UserAgent != "test-only-agent" || saved.ResponseHeaders["X-Test"] != "test" || saved.JitterMinMS != 0 || saved.JitterMaxMS != 100 {
		t.Fatalf("fields lost: %#v %v", saved, err)
	}
	for _, body := range []string{`{"name":"bad","jitterMinMs":500,"jitterMaxMs":100}`, `{"name":"bad","jitterMinMs":-1,"jitterMaxMs":100}`} {
		for _, method := range []string{http.MethodPost, http.MethodPut} {
			path := "/profiles"
			if method == http.MethodPut {
				path += "/" + saved.ID
			}
			w := request(method, path, body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s invalid jitter: %d %s", method, w.Code, w.Body.String())
			}
		}
	}
}
