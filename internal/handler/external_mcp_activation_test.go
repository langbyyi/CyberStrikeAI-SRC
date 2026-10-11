package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
)

func TestMCPEditPreservesStoppedState(t *testing.T) {
	router, h, path := setupTestRouter()
	defer cleanupTestConfig(path)
	defer h.manager.StopAll()
	var calls atomic.Int64
	called := make(chan struct{}, 16)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case called <- struct{}{}:
		default:
		}
		http.Error(w, "test endpoint", 503)
	}))
	defer endpoint.Close()
	cfg := config.ExternalMCPServerConfig{Type: "http", URL: endpoint.URL, Description: "before"}
	h.config.ExternalMCP.Servers["stopped"] = cfg
	if err := h.manager.AddOrUpdateConfig("stopped", cfg); err != nil {
		t.Fatal(err)
	}
	request := func(method, url string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, url, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", method, url, w.Code, w.Body)
		}
		return w
	}
	request("POST", "/api/external-mcp/stopped/stop", nil)
	// Shape emitted by the edit UI: enable omitted, descriptive metadata changed.
	body, _ := json.Marshal(map[string]any{"config": map[string]any{"type": "http", "url": endpoint.URL, "description": "after"}})
	request("PUT", "/api/external-mcp/stopped", body)
	if h.manager.GetConfigs()["stopped"].ExternalMCPEnable {
		t.Fatal("metadata edit enabled a stopped MCP")
	}
	persisted, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ExternalMCP.Servers["stopped"].ExternalMCPEnable {
		t.Fatal("stop state lost on config reload")
	}
	select {
	case <-called:
		t.Fatal("metadata edit initiated a connection")
	case <-time.After(100 * time.Millisecond):
	}
	if calls.Load() != 0 {
		t.Fatal("stopped edit started external work")
	}
	request("POST", "/api/external-mcp/stopped/start", nil)
	select {
	case <-called:
	case <-time.After(3 * time.Second):
		t.Fatal("explicit Start did not connect")
	}
	if !h.manager.GetConfigs()["stopped"].ExternalMCPEnable {
		t.Fatal("explicit Start stayed disabled")
	}
	response := request("GET", "/api/external-mcp/stopped", nil)
	var server ExternalMCPResponse
	if err := json.Unmarshal(response.Body.Bytes(), &server); err != nil {
		t.Fatal(err)
	}
	if server.Config.Disabled {
		t.Fatal("Start left a stale disabled field in the edit response")
	}
	// Round-trip the actual GET payload just as the UI does, removing enable.
	encoded, _ := json.Marshal(server.Config)
	var edit map[string]any
	_ = json.Unmarshal(encoded, &edit)
	delete(edit, "external_mcp_enable")
	edit["description"] = "after explicit start"
	body, _ = json.Marshal(map[string]any{"config": edit})
	request("PUT", "/api/external-mcp/stopped", body)
	if !h.manager.GetConfigs()["stopped"].ExternalMCPEnable {
		t.Fatal("edit after Start stopped the MCP")
	}
	persisted, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.ExternalMCP.Servers["stopped"].ExternalMCPEnable {
		t.Fatal("explicit Start not persisted")
	}
}

func TestMCPRequestActivationPresence(t *testing.T) {
	for _, tc := range []struct {
		name, fields           string
		previous, exists, want bool
	}{
		{"new default", "", false, false, true},
		{"stopped edit", "", false, true, false},
		{"running edit", "", true, true, true},
		{"explicit enable", `,"external_mcp_enable":true`, false, true, true},
		{"explicit stop", `,"external_mcp_enable":false`, true, true, false},
		{"explicit disabled", `,"disabled":true`, true, true, false},
		{"explicit enabled official", `,"disabled":false`, false, true, true},
		{"disabled wins", `,"disabled":true,"external_mcp_enable":true`, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r AddOrUpdateExternalMCPRequest
			if err := json.Unmarshal([]byte(`{"config":{"description":"edit"`+tc.fields+`}}`), &r); err != nil {
				t.Fatal(err)
			}
			if got := r.activation(tc.previous, tc.exists); got != tc.want {
				t.Fatalf("activation=%v want=%v", got, tc.want)
			}
		})
	}
}
