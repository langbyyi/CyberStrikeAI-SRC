package handler

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	"gopkg.in/yaml.v3"
)

func newConfigDoc() *yaml.Node {
	return &yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}},
	}
}

// supports_vision 是模型能力声明：必须能被写进 config.yaml（openai 段与 AI 通道各一份），
// 也要在关闭时从 YAML 里移除，避免留下 "supports_vision: false" 噪声。
func TestUpdateConfigWritesSupportsVision(t *testing.T) {
	doc := newConfigDoc()
	updateOpenAIConfig(doc, config.OpenAIConfig{
		Provider:       "openai",
		APIKey:         "sk-test",
		BaseURL:        "https://example.com/v1",
		Model:          "qwen-vl-max",
		SupportsVision: true,
	})
	updateAIConfig(doc, config.AIConfig{
		DefaultChannel: "default",
		Channels: map[string]config.AIChannelConfig{
			"default": {
				Name:           "Default",
				APIKey:         "sk-test",
				BaseURL:        "https://example.com/v1",
				Model:          "qwen-vl-max",
				SupportsVision: true,
			},
		},
	})

	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var loaded config.Config
	if err := yaml.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("parse written config: %v\n%s", err, raw)
	}
	if !loaded.OpenAI.SupportsVision {
		t.Errorf("openai.supports_vision not persisted:\n%s", raw)
	}
	ch, ok := loaded.AI.Channels["default"]
	if !ok {
		t.Fatalf("default channel missing:\n%s", raw)
	}
	if !ch.SupportsVision {
		t.Errorf("ai.channels.default.supports_vision not persisted:\n%s", raw)
	}
	if !ch.ToOpenAIConfig().SupportsVision {
		t.Error("channel flag lost when resolving back to OpenAIConfig")
	}

	// 关闭后应从 YAML 中移除
	doc2 := newConfigDoc()
	updateOpenAIConfig(doc2, config.OpenAIConfig{Model: "gpt-4"})
	updateAIConfig(doc2, config.AIConfig{
		DefaultChannel: "default",
		Channels:       map[string]config.AIChannelConfig{"default": {Model: "gpt-4"}},
	})
	raw2, err := yaml.Marshal(doc2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw2), "supports_vision") {
		t.Errorf("disabled flag should be removed from YAML:\n%s", raw2)
	}
}
