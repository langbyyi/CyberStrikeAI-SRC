package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/multiagent"

	"github.com/disintegration/imaging"
	"go.uber.org/zap"
)

// 端到端载荷校验：handler 编码出的 base64 必须是**可解码图片**，而不是被截断/损坏的字节。
func TestBuildTurnImagesProducesDecodablePayload(t *testing.T) {
	dir := t.TempDir()
	png := filepath.Join(dir, "shot.png")
	if err := imaging.Save(imaging.New(64, 32, color.RGBA{B: 200, A: 255}), png); err != nil {
		t.Fatal(err)
	}

	images := buildTurnImages([]string{png}, zap.NewNop())
	if len(images) != 1 {
		t.Fatalf("want 1 image, got %d", len(images))
	}
	raw, err := base64.StdEncoding.DecodeString(images[0].Base64)
	if err != nil {
		t.Fatalf("base64 payload undecodable: %v", err)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("payload is not a decodable image: %v", err)
	}
	if format != "png" || cfg.Width != 64 || cfg.Height != 32 {
		t.Fatalf("decoded %s %dx%d, want png 64x32", format, cfg.Width, cfg.Height)
	}
	if images[0].MIMEType != "image/png" {
		t.Errorf("mime = %q, want image/png", images[0].MIMEType)
	}

	// 经 ctx 传给 runner 后仍保持同一载荷（含 MIME 与 detail 默认值）
	ctx := multiagent.WithTurnImages(context.Background(), images)
	carried := multiagent.TurnImagesFromContext(ctx)
	if len(carried) != 1 || carried[0].Base64 != images[0].Base64 {
		t.Fatalf("ctx round-trip lost payload: %+v", carried)
	}
	if carried[0].Detail != "auto" {
		t.Errorf("detail = %q, want auto", carried[0].Detail)
	}
}

func TestBuildTurnImagesFiltersAndEncodes(t *testing.T) {
	dir := t.TempDir()
	png := filepath.Join(dir, "shot.png")
	if err := imaging.Save(imaging.New(64, 32, color.RGBA{R: 9, G: 9, B: 9, A: 255}), png); err != nil {
		t.Fatal(err)
	}
	txt := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(txt, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	images := buildTurnImages([]string{png, txt, filepath.Join(dir, "missing.png")}, zap.NewNop())
	if len(images) != 1 {
		t.Fatalf("want 1 image (png only), got %d: %+v", len(images), images)
	}
	if images[0].Base64 == "" || images[0].MIMEType != "image/png" {
		t.Errorf("image payload incomplete: %+v", images[0])
	}
	if images[0].Path != png {
		t.Errorf("path = %q, want %q", images[0].Path, png)
	}
	if images[0].Detail != "auto" {
		t.Errorf("detail = %q, want auto", images[0].Detail)
	}
	if got := buildTurnImages(nil, zap.NewNop()); len(got) != 0 {
		t.Errorf("nil paths should yield no images, got %+v", got)
	}
}

func TestAICChannelSupportsVision(t *testing.T) {
	cfg := &config.Config{OpenAI: config.OpenAIConfig{Model: "qwen-vl-max", SupportsVision: true}}
	h := &AgentHandler{config: cfg}
	if !h.aiChannelSupportsVision("") {
		t.Error("legacy openai section flag should apply when no channel is configured")
	}

	ch := config.AIChannelConfig{Model: "deepseek-chat"}
	cfg.AI = config.AIConfig{DefaultChannel: "main", Channels: map[string]config.AIChannelConfig{"main": ch}}
	if h.aiChannelSupportsVision("main") {
		t.Error("channel without supports_vision must stay text-only")
	}
	ch.SupportsVision = true
	cfg.AI.Channels["main"] = ch
	if !h.aiChannelSupportsVision("main") {
		t.Error("channel-level flag not honoured")
	}
	if (&AgentHandler{}).aiChannelSupportsVision("main") {
		t.Error("nil config should report false")
	}
}

func TestWithTurnImagesRespectsChannelCapability(t *testing.T) {
	prep := &multiAgentPrepared{TurnImages: []multiagent.TurnImage{{Base64: "AAAA", MIMEType: "image/png"}}}
	ctx := context.Background()

	textOnly := &config.Config{OpenAI: config.OpenAIConfig{Model: "deepseek-chat"}}
	if got := (&AgentHandler{}).withTurnImages(ctx, textOnly, prep); multiagent.TurnImagesFromContext(got) != nil {
		t.Error("text-only channel must not carry images")
	}

	vision := &config.Config{OpenAI: config.OpenAIConfig{Model: "qwen-vl-max", SupportsVision: true}}
	got := (&AgentHandler{}).withTurnImages(ctx, vision, prep)
	if images := multiagent.TurnImagesFromContext(got); len(images) != 1 {
		t.Fatalf("want 1 image in ctx, got %d", len(images))
	}

	// 无图片 / 空配置时不应改变 ctx
	if got := (&AgentHandler{}).withTurnImages(ctx, vision, &multiAgentPrepared{}); got != ctx {
		t.Error("no images should leave ctx untouched")
	}
	if got := (&AgentHandler{}).withTurnImages(ctx, nil, prep); got != ctx {
		t.Error("nil run config should leave ctx untouched")
	}
}
