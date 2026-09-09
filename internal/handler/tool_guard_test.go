package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/toolguard"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newToolGuardTestHandler(t *testing.T) *ConfigHandler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("# keep this comment\nserver:\n  port: 8123\napproval:\n  tool_approval:\n    tool_whitelist: [read_file]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := toolguard.NewManager(toolguard.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return &ConfigHandler{configPath: path, config: &config.Config{}, toolGuard: manager}
}

func toolGuardRequest(t *testing.T, handler gin.HandlerFunc, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/tool-guard", bytes.NewReader(data))
	c.Request.Header.Set("Content-Type", "application/json")
	handler(c)
	return w
}

func TestToolGuardSavePersistsAndAppliesWithoutChangingHITL(t *testing.T) {
	h := newToolGuardTestHandler(t)
	cfg := toolguard.DefaultConfig()
	cfg.Rules[0].Message = "识别到 {match}，禁止攻击政府网站，请检查目标。"
	w := toolGuardRequest(t, h.UpdateToolGuard, cfg)
	if w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	loaded, err := config.Load(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.EffectiveToolGuard(), cfg) || !reflect.DeepEqual(h.toolGuard.Config(), cfg) {
		t.Fatal("saved and effective policies differ")
	}
	if loaded.Server.Port != 8123 || !reflect.DeepEqual(loaded.Approval.ToolApproval.ToolWhitelist, []string{"read_file"}) {
		t.Fatal("unrelated configuration was changed")
	}
	info, _ := os.Stat(h.configPath)
	data, _ := os.ReadFile(h.configPath)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("file permissions were lost")
	}
	if !strings.Contains(string(data), "# keep this comment") {
		t.Fatal("comments were lost")
	}
	match := h.toolGuard.Check("scan", map[string]interface{}{"target": "agency.gov.cn"})
	if match == nil || !strings.Contains(match.Message, "agency.gov.cn") {
		t.Fatalf("updated message not applied: %+v", match)
	}
	cfg.Enabled = false
	w = toolGuardRequest(t, h.UpdateToolGuard, cfg)
	if w.Code != http.StatusOK || h.toolGuard.Check("scan", map[string]interface{}{"target": "agency.gov"}) != nil {
		t.Fatal("explicitly disabling protection did not apply")
	}
}

func TestToolGuardInvalidAndFailedSaveKeepEffectivePolicy(t *testing.T) {
	h := newToolGuardTestHandler(t)
	before, _ := os.ReadFile(h.configPath)
	cfg := toolguard.DefaultConfig()
	cfg.Enabled = false
	cfg.Rules[0].Pattern = "["
	for _, body := range []interface{}{cfg, map[string]interface{}{}, nil, map[string]interface{}{"enabled": false, "rules": nil}} {
		w := toolGuardRequest(t, h.UpdateToolGuard, body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid update accepted: %d %s", w.Code, w.Body.String())
		}
	}
	after, _ := os.ReadFile(h.configPath)
	if !bytes.Equal(before, after) || !h.toolGuard.Config().Enabled {
		t.Fatal("invalid input changed protection")
	}
	h.configPath = filepath.Join(t.TempDir(), "missing", "config.yaml")
	cfg = toolguard.DefaultConfig()
	cfg.Enabled = false
	w := toolGuardRequest(t, h.UpdateToolGuard, cfg)
	if w.Code != http.StatusInternalServerError || !h.toolGuard.Config().Enabled || h.config.ToolGuard != nil {
		t.Fatal("failed persistence changed live configuration")
	}
}

func TestToolGuardDryRunUsesUnsavedPolicyWithoutMutation(t *testing.T) {
	h := newToolGuardTestHandler(t)
	cfg := toolguard.DefaultConfig()
	cfg.Rules[0].Pattern = "example\\.org"
	w := toolGuardRequest(t, h.TestToolGuard, map[string]interface{}{
		"config": cfg, "toolName": "scan", "arguments": map[string]interface{}{"target": "example.org"},
	})
	var got struct {
		Blocked bool             `json:"blocked"`
		Match   *toolguard.Match `json:"match"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || !got.Blocked || got.Match == nil || got.Match.MatchedText != "example.org" {
		t.Fatalf("dry run failed: %s", w.Body.String())
	}
	if !reflect.DeepEqual(h.toolGuard.Config(), toolguard.DefaultConfig()) || h.config.ToolGuard != nil {
		t.Fatal("dry run changed live configuration")
	}
	w = toolGuardRequest(t, h.TestToolGuard, map[string]interface{}{"config": cfg, "arguments": []string{"example.org"}})
	if w.Code != http.StatusBadRequest {
		t.Fatal("non-object tool arguments accepted")
	}
}

func TestToolGuardRoutesEnforceConfigurationPermissions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		method, path, permission, scope string
		want                            int
	}{
		{"GET", "/api/tool-guard", "tasks:read", database.RBACScopeAll, 403},
		{"PUT", "/api/tool-guard", "tasks:write", database.RBACScopeAll, 403},
		{"GET", "/api/tool-guard", "config:read", database.RBACScopeAll, 200},
		{"POST", "/api/tool-guard/test", "config:read", database.RBACScopeAll, 200},
		{"PUT", "/api/tool-guard", "config:write", database.RBACScopeAll, 200},
		{"PUT", "/api/tool-guard", "config:write", database.RBACScopeOwn, 403},
	} {
		t.Run(tc.method+tc.permission+tc.scope, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set(security.ContextSessionKey, security.Session{UserID: "test", Permissions: map[string]bool{tc.permission: true}, Scope: tc.scope})
			})
			r.Use(security.RBACMiddleware(&database.DB{}))
			r.Handle(tc.method, tc.path, func(c *gin.Context) { c.Status(200) })
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestToolGuardConcurrentOtherSettingsSavePreservesPolicy(t *testing.T) {
	h := newToolGuardTestHandler(t)
	external := &ExternalMCPHandler{configPath: h.configPath, config: h.config, logger: zap.NewNop()}
	cfg := toolguard.DefaultConfig()
	cfg.Rules[0].Message = "持久化策略 {match}"
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for _, save := range []func() error{func() error { return h.saveToolGuardConfig(cfg) }, external.saveConfig} {
		wg.Add(1)
		go func(save func() error) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := save(); err != nil {
					errors <- err
					return
				}
			}
		}(save)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	loaded, err := config.Load(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.EffectiveToolGuard(), cfg) {
		t.Fatal("another settings save overwrote the tool guard policy")
	}
}
