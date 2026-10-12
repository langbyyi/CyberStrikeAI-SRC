package app

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestFrontendStaticCompressionAndRevalidation(t *testing.T) {
	root := t.TempDir()
	body := strings.Repeat("const example = '静态资源';\n", 200)
	file := filepath.Join(root, "example.js")
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	registerFrontendStatic(r, root)
	request := func(encoding, etag, byteRange string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/static/example.js?v=1", nil)
		req.Header.Set("Accept-Encoding", encoding)
		req.Header.Set("If-None-Match", etag)
		req.Header.Set("Range", byteRange)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	w := request("gzip, br", "", "")
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("not compressed: %d %v", w.Code, w.Header())
	}
	z, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	z.Close()
	if string(decoded) != body {
		t.Fatal("compressed content changed")
	}
	if w.Header().Get("Vary") != "Accept-Encoding" || w.Header().Get("ETag") == "" {
		t.Fatal("missing cache variant or validator")
	}
	if got := request("gzip", w.Header().Get("ETag"), ""); got.Code != 304 || got.Body.Len() != 0 {
		t.Fatal("conditional request did not return empty 304")
	}
	for _, encoding := range []string{"", "gzip;q=0", "gzip;q=0, *;q=1", "gzip;q=0.0, br"} {
		got := request(encoding, "", "")
		if got.Header().Get("Content-Encoding") != "" || got.Body.String() != body {
			t.Fatalf("identity negotiation failed: %q", encoding)
		}
	}
	if got := request("gzip", "", "bytes=0-4"); got.Code != 206 || got.Body.String() != body[:5] || got.Header().Get("Content-Encoding") != "" {
		t.Fatal("range response broken")
	}
	if err := os.WriteFile(file, []byte(body+"updated"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := request("gzip", w.Header().Get("ETag"), ""); got.Code != 200 || got.Header().Get("ETag") == w.Header().Get("ETag") {
		t.Fatal("updated file used stale compressed cache")
	}
	for _, path := range []string{"/static/", "/static/missing.js", "/static/../private.txt"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		got := httptest.NewRecorder()
		r.ServeHTTP(got, req)
		if got.Code != 404 {
			t.Fatalf("unexpected file access: %s %d", path, got.Code)
		}
	}
	for _, encoding := range []string{"gzip", ""} {
		req := httptest.NewRequest(http.MethodHead, "/static/example.js", nil)
		req.Header.Set("Accept-Encoding", encoding)
		got := httptest.NewRecorder()
		r.ServeHTTP(got, req)
		if got.Code != 200 || got.Body.Len() != 0 {
			t.Fatal("HEAD response broken")
		}
	}
}

func TestFrontendHTMLCompressionExcludesAPIs(t *testing.T) {
	r := gin.New()
	r.Use(frontendHTMLCompression())
	body := strings.Repeat("<p>CyberStrikeAI</p>", 100)
	r.GET("/", func(c *gin.Context) { c.Data(200, "text/html; charset=utf-8", []byte(body)) })
	r.GET("/api/events", func(c *gin.Context) { c.Data(200, "text/event-stream", []byte("data: event\n\n")) })
	for _, path := range []string{"/", "/api/events"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if path == "/api/events" {
			if w.Header().Get("Content-Encoding") != "" || w.Body.String() != "data: event\n\n" {
				t.Fatal("SSE was modified")
			}
			continue
		}
		if w.Header().Get("Content-Encoding") != "gzip" {
			t.Fatal("HTML not compressed")
		}
		z, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(z)
		z.Close()
		if err != nil || string(decoded) != body {
			t.Fatal("HTML compression corrupted body")
		}
	}
}
