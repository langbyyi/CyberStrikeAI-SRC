package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newHitlAuditPromptTestHandler(t *testing.T, cfg *config.Config) *ConfigHandler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("hitl:\n  audit_agent_prompt: \"\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return NewConfigHandler(path, cfg, nil, nil, nil, nil, nil, zap.NewNop())
}

func TestGetConfigResolvesBuiltinAuditAgentPromptWhenEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newHitlAuditPromptTestHandler(t, &config.Config{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.GetConfig(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var body struct {
		Hitl struct {
			AuditAgentPrompt string `json:"audit_agent_prompt"`
		} `json:"hitl"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got, want := body.Hitl.AuditAgentPrompt, config.DefaultHitlAuditAgentPrompt(); got != want {
		t.Fatal("empty audit_agent_prompt must be returned as the built-in default")
	}
}

func TestGetConfigReturnsCustomAuditAgentPromptWhenSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Hitl: config.HitlConfig{AuditAgentPrompt: "custom prompt"}}
	h := newHitlAuditPromptTestHandler(t, cfg)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.GetConfig(c)

	var body struct {
		Hitl struct {
			AuditAgentPrompt string `json:"audit_agent_prompt"`
		} `json:"hitl"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Hitl.AuditAgentPrompt != "custom prompt" {
		t.Fatalf("audit_agent_prompt = %q, want custom prompt", body.Hitl.AuditAgentPrompt)
	}
}

func TestUpdateConfigAuditAgentPrompt(t *testing.T) {
	gin.SetMode(gin.TestMode)

	put := func(t *testing.T, h *ConfigHandler, prompt string) {
		t.Helper()
		body := `{"hitl":{"audit_agent_prompt":` + jsonString(prompt) + `}}`
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		h.UpdateConfig(c)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
	}

	t.Run("empty clears custom prompt back to default", func(t *testing.T) {
		h := newHitlAuditPromptTestHandler(t, &config.Config{Hitl: config.HitlConfig{AuditAgentPrompt: "custom"}})
		put(t, h, "")
		if h.config.Hitl.AuditAgentPrompt != "" {
			t.Fatalf("audit_agent_prompt = %q, want empty (default)", h.config.Hitl.AuditAgentPrompt)
		}
	})

	t.Run("default text is treated as not customized", func(t *testing.T) {
		h := newHitlAuditPromptTestHandler(t, &config.Config{})
		put(t, h, config.DefaultHitlAuditAgentPrompt())
		if h.config.Hitl.AuditAgentPrompt != "" {
			t.Fatalf("audit_agent_prompt = %q, want empty (default)", h.config.Hitl.AuditAgentPrompt)
		}
	})

	t.Run("custom prompt is persisted", func(t *testing.T) {
		h := newHitlAuditPromptTestHandler(t, &config.Config{})
		put(t, h, "my custom prompt")
		if h.config.Hitl.AuditAgentPrompt != "my custom prompt" {
			t.Fatalf("audit_agent_prompt = %q, want my custom prompt", h.config.Hitl.AuditAgentPrompt)
		}
	})
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}