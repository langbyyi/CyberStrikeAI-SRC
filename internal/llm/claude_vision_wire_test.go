package llm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/schema"
)

// 离线验证「原生图片直发」在 Claude(Anthropic Messages) 协议下的线上报文形状：
// 路径、鉴权头、图片块（base64 source）与文本块都必须符合 Anthropic 规范——
// 真实端点对不合规的报文会返回 400 解析错误，而不是业务错误。
func TestClaudeAgenticWireShapeCarriesImageBlock(t *testing.T) {
	type capturedRequest struct {
		path         string
		apiKey       string
		anthropicVer string
		contentType  string
		body         map[string]any
	}
	captured := make(chan capturedRequest, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		captured <- capturedRequest{
			path:         r.URL.Path,
			apiKey:       r.Header.Get("x-api-key"),
			anthropicVer: r.Header.Get("anthropic-version"),
			contentType:  r.Header.Get("Content-Type"),
			body:         body,
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"step-5-preview","content":[{"type":"text","text":"左上角红色圆形，右下角蓝色方形"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":12}}`))
	}))
	defer server.Close()

	oa := config.OpenAIConfig{
		Provider: "claude",
		APIKey:   "synthetic-key",
		BaseURL:  server.URL,
		Model:    "step-5-preview",
	}
	mdl, err := NewClaudeAgenticModel(context.Background(), oa, server.Client(), 128, nil)
	if err != nil {
		t.Fatalf("claude agentic model: %v", err)
	}

	payload := tinyPNGBase64(t)
	resp, err := mdl.Generate(context.Background(), []*schema.AgenticMessage{{
		Role: schema.AgenticRoleTypeUser,
		ContentBlocks: []*schema.ContentBlock{
			schema.NewContentBlock(&schema.UserInputText{Text: "左上角和右下角分别是什么形状与颜色？"}),
			schema.NewContentBlock(&schema.UserInputImage{
				Base64Data: payload,
				MIMEType:   "image/png",
				Detail:     schema.ImageURLDetailAuto,
			}),
		},
	}})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	content, _ := AgenticText(resp)
	if !strings.Contains(content, "红色") {
		t.Errorf("model reply not surfaced: %q", content)
	}

	got := <-captured
	if got.path != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", got.path)
	}
	if got.apiKey != "synthetic-key" {
		t.Errorf("x-api-key = %q", got.apiKey)
	}
	if strings.TrimSpace(got.anthropicVer) == "" {
		t.Error("anthropic-version header missing")
	}
	if !strings.Contains(got.contentType, "application/json") {
		t.Errorf("content-type = %q", got.contentType)
	}

	msgs, _ := got.body["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("messages = %v", got.body["messages"])
	}
	msg, _ := msgs[0].(map[string]any)
	blocks, _ := msg["content"].([]any)
	if len(blocks) != 2 {
		t.Fatalf("content blocks = %v, want image + text", msg["content"])
	}
	var imageBlock, textBlock map[string]any
	for _, raw := range blocks {
		block, _ := raw.(map[string]any)
		switch block["type"] {
		case "image":
			imageBlock = block
		case "text":
			textBlock = block
		}
	}
	if imageBlock == nil {
		t.Fatalf("no image block in wire body: %v", blocks)
	}
	source, _ := imageBlock["source"].(map[string]any)
	if source["type"] != "base64" {
		t.Errorf("image source type = %v, want base64", source["type"])
	}
	if source["media_type"] != "image/png" {
		t.Errorf("image media_type = %v", source["media_type"])
	}
	if data, _ := source["data"].(string); data != payload {
		t.Errorf("image payload mismatch: got %d chars, want %d", len(data), len(payload))
	}
	if textBlock == nil || !strings.Contains(textBlock["text"].(string), "形状") {
		t.Errorf("text block missing: %v", blocks)
	}
}

// tinyPNGBase64 生成一张 8x8 的 PNG（红/蓝对角），仅用于报文形状断言。
func tinyPNGBase64(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: color.White}, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(0, 0, 4, 4), &image.Uniform{C: color.RGBA{R: 255, A: 255}}, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(4, 4, 8, 8), &image.Uniform{C: color.RGBA{B: 255, A: 255}}, image.Point{}, draw.Src)
	var buf strings.Builder
	enc := base64.NewEncoder(base64.StdEncoding, &stringWriter{&buf})
	if err := png.Encode(enc, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	_ = enc.Close()
	return buf.String()
}

type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
