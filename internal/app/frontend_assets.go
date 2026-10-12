package app

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func acceptsFrontendGzip(value string) bool {
	wildcard := false
	for _, item := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(item), ";")
		quality := 1.0
		for _, parameter := range parts[1:] {
			key, val, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if ok && strings.EqualFold(key, "q") {
				parsed, err := strconv.ParseFloat(val, 64)
				if err != nil || parsed < 0 || parsed > 1 {
					quality = 0
				} else {
					quality = parsed
				}
			}
		}
		if strings.EqualFold(parts[0], "gzip") {
			return quality > 0
		}
		if parts[0] == "*" {
			wildcard = quality > 0
		}
	}
	return wildcard
}

type compressedFrontendAsset struct {
	modified time.Time
	size     int64
	body     []byte
	etag     string
}

// Cache only compressed text; recheck disk metadata so deployments invalidate it.
func registerFrontendStatic(router *gin.Engine, root string) {
	files := http.Dir(root)
	cache := make(map[string]compressedFrontendAsset)
	var cacheMu sync.Mutex
	handler := func(c *gin.Context) {
		name := c.Param("filepath")
		for _, segment := range strings.Split(name, "/") {
			if segment == ".." {
				c.Status(http.StatusNotFound)
				return
			}
		}
		file, err := files.Open(name)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || info.IsDir() {
			c.Status(http.StatusNotFound)
			return
		}
		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType != "" {
			c.Header("Content-Type", contentType)
		}
		// Existing URLs use fixed version strings: validate instead of caching stale code.
		c.Header("Cache-Control", "public, max-age=0, must-revalidate")
		text := strings.HasPrefix(contentType, "text/") || strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json") || strings.Contains(contentType, "svg")
		if text {
			c.Writer.Header().Add("Vary", "Accept-Encoding")
		}
		if !text || info.Size() < 256 || info.Size() > 8*1024*1024 || c.GetHeader("Range") != "" || !acceptsFrontendGzip(c.GetHeader("Accept-Encoding")) {
			http.ServeContent(c.Writer, c.Request, info.Name(), info.ModTime(), file)
			return
		}
		cacheMu.Lock()
		asset, found := cache[name]
		if !found || asset.size != info.Size() || !asset.modified.Equal(info.ModTime()) {
			var buffer bytes.Buffer
			compressor := gzip.NewWriter(&buffer)
			_, copyErr := io.Copy(compressor, file)
			closeErr := compressor.Close()
			if copyErr != nil || closeErr != nil {
				cacheMu.Unlock()
				c.Status(http.StatusInternalServerError)
				return
			}
			asset = compressedFrontendAsset{modified: info.ModTime(), size: info.Size(), body: buffer.Bytes(), etag: fmt.Sprintf("\"%x-gzip\"", sha256.Sum256(buffer.Bytes()))}
			// Bound cache memory even if additional files are added at runtime.
			if len(cache) >= 128 {
				clear(cache)
			}
			cache[name] = asset
		}
		cacheMu.Unlock()
		c.Header("Content-Encoding", "gzip")
		c.Header("ETag", asset.etag)
		http.ServeContent(c.Writer, c.Request, info.Name(), asset.modified, bytes.NewReader(asset.body))
	}
	router.GET("/static/*filepath", handler)
	router.HEAD("/static/*filepath", handler)
}

type frontendGzipWriter struct {
	gin.ResponseWriter
	compressor *gzip.Writer
}

func (w *frontendGzipWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

func (w *frontendGzipWriter) Write(data []byte) (int, error) {
	w.Header().Del("Content-Length")
	if !w.Written() {
		w.ResponseWriter.WriteHeaderNow()
	}
	return w.compressor.Write(data)
}

func (w *frontendGzipWriter) WriteString(value string) (int, error) { return w.Write([]byte(value)) }

// Limit compression to public HTML; authenticated APIs, SSE and WebSockets bypass it.
func frontendHTMLCompression() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet || (c.Request.URL.Path != "/" && c.Request.URL.Path != "/api-docs") {
			c.Next()
			return
		}
		c.Writer.Header().Add("Vary", "Accept-Encoding")
		if !acceptsFrontendGzip(c.GetHeader("Accept-Encoding")) {
			c.Next()
			return
		}
		original := c.Writer
		compressor := gzip.NewWriter(original)
		c.Header("Content-Encoding", "gzip")
		c.Writer = &frontendGzipWriter{ResponseWriter: original, compressor: compressor}
		defer func() { compressor.Close(); c.Writer = original }()
		c.Next()
	}
}
