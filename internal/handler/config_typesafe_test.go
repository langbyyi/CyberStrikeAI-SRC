package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	"github.com/gin-gonic/gin"
)

// callTestTypeSafe 走真实路由调用 POST /api/config/test-typesafe。
// 该 handler 不依赖 ConfigHandler 的其他字段，故空结构体即可。
func callTestTypeSafe(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/config/test-typesafe", (&ConfigHandler{}).TestTypeSafe)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/config/test-typesafe", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	payload := map[string]any{}
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode response: %v body=%s", err, recorder.Body.String())
		}
	}
	return recorder.Code, payload
}

func TestTestTypeSafeRequiresAPIKey(t *testing.T) {
	code, payload := callTestTypeSafe(t, `{"base_url":"http://127.0.0.1:9"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v, want 400", code, payload)
	}
	if message, _ := payload["error"].(string); !strings.Contains(message, "TypeSafe API Key") {
		t.Fatalf("error=%v", payload["error"])
	}
}

func TestTestTypeSafeRejectsInvalidJSON(t *testing.T) {
	code, payload := callTestTypeSafe(t, `{`)
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v, want 400", code, payload)
	}
	if message, _ := payload["error"].(string); !strings.Contains(message, "无效的请求参数") {
		t.Fatalf("error=%v", payload["error"])
	}
}

func TestTestTypeSafeReportsUpstreamModel(t *testing.T) {
	var gotPath, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "jev-1.13.0",
			"answers": map[string]any{"ok": map[string]any{"type": "noul", "noul": 0.91}},
		})
	}))
	defer server.Close()

	code, payload := callTestTypeSafe(t, fmt.Sprintf(`{"base_url":%q,"api_key":"ts-key"}`, server.URL))
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v, want 200", code, payload)
	}
	if payload["success"] != true {
		t.Fatalf("success=%v error=%v", payload["success"], payload["error"])
	}
	// 未传 model 时以默认值请求上游，响应里的 model 覆盖返回值。
	if gotPath != "/v1/systemone" || gotAuth != "Bearer ts-key" {
		t.Fatalf("upstream path=%q auth=%q", gotPath, gotAuth)
	}
	if payload["model"] != "jev-1.13.0" {
		t.Fatalf("model=%v, want upstream model", payload["model"])
	}
}

func TestTestTypeSafeFallsBackToDefaultModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "", "answers": map[string]any{}})
	}))
	defer server.Close()

	_, payload := callTestTypeSafe(t, fmt.Sprintf(`{"base_url":%q,"api_key":"ts-key"}`, server.URL))
	if payload["success"] != true || payload["model"] != config.TypeSafeDefaultModel {
		t.Fatalf("payload=%v, want default model %s", payload, config.TypeSafeDefaultModel)
	}
}

// 上游非 2xx 也走 HTTP 200，用 success:false + status_code 表达，前端据此提示。
func TestTestTypeSafeSurfacesUpstreamError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer server.Close()

	code, payload := callTestTypeSafe(t, fmt.Sprintf(`{"base_url":%q,"api_key":"bad"}`, server.URL))
	if code != http.StatusOK {
		t.Fatalf("status=%d, want 200", code)
	}
	if payload["success"] != false {
		t.Fatalf("success=%v", payload["success"])
	}
	if payload["status_code"] != float64(http.StatusUnauthorized) {
		t.Fatalf("status_code=%v, want 401", payload["status_code"])
	}
	if message, _ := payload["error"].(string); !strings.Contains(message, "API 返回错误") {
		t.Fatalf("error=%v", payload["error"])
	}
}

func TestTestTypeSafeSurfacesTransportError(t *testing.T) {
	// 关闭后的地址必然连接失败：走“连接失败”分支而非状态码分支。
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := server.URL
	server.Close()

	code, payload := callTestTypeSafe(t, fmt.Sprintf(`{"base_url":%q,"api_key":"ts-key"}`, closedURL))
	if code != http.StatusOK || payload["success"] != false {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	if message, _ := payload["error"].(string); !strings.Contains(message, "连接失败") {
		t.Fatalf("error=%v", payload["error"])
	}
}
