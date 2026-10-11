package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestConfigResponseMasksSecretsAndSavePreservesThem(t *testing.T) {
	cfg := &config.Config{
		OpenAI: config.OpenAIConfig{APIKey: "test-only-main", BaseURL: "http://127.0.0.1", Model: "test"},
		AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{
			"first":  {Name: "first", APIKey: "test-only-first", BaseURL: "http://127.0.0.1"},
			"second": {Name: "second", APIKey: "test-only-second", BaseURL: "http://127.0.0.1"},
		}},
		Robots: config.RobotsConfig{Wecom: config.RobotWecomConfig{Token: "test-only-token", Secret: "test-only-secret", EncodingAESKey: "test-only-aes"}},
	}
	h := &ConfigHandler{config: cfg, logger: zap.NewNop()}
	r := gin.New()
	r.GET("/config", h.GetConfig)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/config", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "test-only-") {
		t.Fatal("response contains a saved secret")
	}
	if cfg.OpenAI.APIKey != "test-only-main" || cfg.AI.Channels["first"].APIKey != "test-only-first" {
		t.Fatal("GET mutated live secrets")
	}
	var req UpdateConfigRequest
	if err := json.Unmarshal(w.Body.Bytes(), &req); err != nil {
		t.Fatal(err)
	}
	if err := restoreConfigRequestSecrets(&req, cfg); err != nil {
		t.Fatal(err)
	}
	if req.OpenAI.APIKey != cfg.OpenAI.APIKey || req.AI.Channels["second"].APIKey != cfg.AI.Channels["second"].APIKey || req.Robots.Wecom.Secret != cfg.Robots.Wecom.Secret {
		t.Fatal("unchanged save lost secret")
	}
	req.OpenAI.APIKey = "test-only-replacement"
	if err := restoreConfigRequestSecrets(&req, cfg); err != nil {
		t.Fatal(err)
	}
	if req.OpenAI.APIKey != "test-only-replacement" {
		t.Fatal("explicit replacement was ignored")
	}
	req.OpenAI.APIKey = ""
	if err := restoreConfigRequestSecrets(&req, cfg); err != nil {
		t.Fatal(err)
	}
	if req.OpenAI.APIKey != "" {
		t.Fatal("explicit clearing was ignored")
	}
	// Changing the default channel must not copy the old default's secret into it.
	req.OpenAI.APIKey = maskedSecret
	req.AI.DefaultChannel = "second"
	if err := restoreConfigRequestSecrets(&req, cfg); err != nil {
		t.Fatal(err)
	}
	if req.OpenAI.APIKey != "test-only-second" {
		t.Fatal("default channel change selected the old main key")
	}
}

func TestModelListUsesSavedChannelSecretWithoutEcho(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer test-only-upstream" {
			t.Error("masked key reached upstream")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"test-model"}]}`))
	}))
	defer srv.Close()
	h := &ConfigHandler{config: &config.Config{AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{"saved": {APIKey: "test-only-upstream", BaseURL: srv.URL}}}}}
	r := gin.New()
	r.POST("/models", h.ListModels)
	w := httptest.NewRecorder()
	raw, _ := json.Marshal(ListModelsRequest{BaseURL: srv.URL, APIKey: maskedSecret, ChannelID: "saved"})
	req := httptest.NewRequest(http.MethodPost, "/models", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || requests != 1 || strings.Contains(w.Body.String(), "test-only-upstream") {
		t.Fatalf("model request: %d requests=%d", w.Code, requests)
	}
}

func TestMaskedProbeUsesSelectedChannelAndRejectsAmbiguousKey(t *testing.T) {
	h := &ConfigHandler{config: &config.Config{AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{
		"one": {APIKey: "test-one", BaseURL: "http://127.0.0.1"},
		"two": {APIKey: "test-two", BaseURL: "http://127.0.0.1"},
	}}}}
	if key, err := h.resolveProbeSecret(maskedSecret, "two", "http://127.0.0.1", ""); err != nil || key != "test-two" {
		t.Fatalf("selected resolution failed: %v", err)
	}
	if _, err := h.resolveProbeSecret(maskedSecret, "", "http://127.0.0.1", ""); err == nil {
		t.Fatal("ambiguous key was selected")
	}
	if _, err := h.resolveProbeSecret(maskedSecret, "missing", "http://127.0.0.1", ""); err == nil {
		t.Fatal("missing channel accepted")
	}
	if key, err := h.resolveProbeSecret("test-new", "missing", "http://127.0.0.1", ""); err != nil || key != "test-new" {
		t.Fatal("new credential rejected")
	}
}

func TestConfigMaskCannotBeSavedAsNewChannelCredential(t *testing.T) {
	cfg := &config.Config{}
	req := UpdateConfigRequest{AI: &config.AIConfig{Channels: map[string]config.AIChannelConfig{"new": {APIKey: maskedSecret}}}}
	if restoreConfigRequestSecrets(&req, cfg) == nil {
		t.Fatal("mask accepted for new channel")
	}
}
