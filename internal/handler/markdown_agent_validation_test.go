package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMarkdownAgentValidationAndIDUniqueness(t *testing.T) {
	dir := t.TempDir()
	h := NewMarkdownAgentsHandler(dir)
	r := gin.New()
	r.POST("/agents", h.CreateMarkdownAgent)
	r.PUT("/agents/:filename", h.UpdateMarkdownAgent)
	send := func(method, path string, body markdownAgentBody) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}
	good := markdownAgentBody{Filename: "first.md", ID: "unique", Name: "valid", Instruction: "Reply OK"}
	if w := send(http.MethodPost, "/agents", good); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	original, _ := os.ReadFile(filepath.Join(dir, good.Filename))
	duplicateFile := good
	duplicateFile.Instruction = "overwrite"
	if w := send(http.MethodPost, "/agents", duplicateFile); w.Code != http.StatusConflict {
		t.Fatalf("duplicate file: %d", w.Code)
	}
	duplicateID := good
	duplicateID.Filename = "second.md"
	if w := send(http.MethodPost, "/agents", duplicateID); w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate ID: %d", w.Code)
	}
	after, _ := os.ReadFile(filepath.Join(dir, good.Filename))
	if !bytes.Equal(original, after) {
		t.Fatal("rejected create overwrote existing file")
	}
	if w := send(http.MethodPut, "/agents/first.md", good); w.Code != http.StatusOK {
		t.Fatalf("self update: %d %s", w.Code, w.Body.String())
	}
	if w := send(http.MethodPut, "/agents/missing.md", good); w.Code != http.StatusNotFound {
		t.Fatalf("created missing update: %d", w.Code)
	}
	for _, body := range []markdownAgentBody{
		{Filename: "bad.md", ID: "bad", Name: "bad/name", Instruction: "text"},
		{Filename: "bad.md", ID: "bad/id", Name: "valid", Instruction: "text"},
		{Filename: "bad.md", ID: "bad", Name: "valid"},
		{Filename: "bad.md", ID: "bad", Name: "valid", Raw: "---\nname: valid\nid: raw/id\n---\ntext"},
		{Filename: "bad.md", ID: "bad", Name: "valid", Raw: "---\nid: raw\n---\ntext"},
	} {
		if w := send(http.MethodPost, "/agents", body); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid %#v: %d %s", body, w.Code, w.Body.String())
		}
	}
	other := good
	other.Filename, other.ID = "second.md", "second"
	if w := send(http.MethodPost, "/agents", other); w.Code != http.StatusOK {
		t.Fatalf("other create: %d %s", w.Code, w.Body.String())
	}
	other.ID = "unique"
	if w := send(http.MethodPut, "/agents/second.md", other); w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate update: %d", w.Code)
	}
}
