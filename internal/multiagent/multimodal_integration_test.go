package multiagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/color"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"

	"github.com/disintegration/imaging"
	"go.uber.org/zap"
)

// 端到端（到 provider 请求体）验证多模态接线：
//   - 通道声明 supports_vision：本轮图片必须出现在发给模型的请求里，且系统提示为原生图片段；
//   - 未声明：请求里不得出现图片，系统提示保持文本通道语义（纯文本主模型的兼容保证）。
//
// 模型侧用 httptest 假服务器，只断言请求体，不打真实 API。
func TestSingleAgentSendsImagesOnlyWhenChannelSupportsVision(t *testing.T) {
	dir := t.TempDir()
	imagePath := filepath.Join(dir, "shot.png")
	if err := imaging.Save(imaging.New(32, 16, color.RGBA{R: 240, G: 10, B: 10, A: 255}), imagePath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.StdEncoding.EncodeToString(raw)

	run := func(t *testing.T, supportsVision bool, withImages bool) string {
		t.Helper()
		captured := make(chan string, 4)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			data, _ := json.Marshal(body["messages"])
			captured <- string(data)
			// runner 默认走流式：必须按 stream 标志回 SSE，否则客户端解析为空并重试到超时
			if stream, _ := body["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, sseChunkStream)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"synthetic","object":"chat.completion","model":"synthetic","choices":[{"index":0,"message":{"role":"assistant","content":"看到红色的图。"},"finish_reason":"stop"}]}`)
		}))
		defer server.Close()

		db, err := database.NewDB(filepath.Join(t.TempDir(), "multimodal.db"), zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		conv, err := db.CreateConversation("synthetic", database.ConversationCreateMeta{})
		if err != nil {
			t.Fatal(err)
		}

		cfg := &config.Config{OpenAI: config.OpenAIConfig{
			Provider:       "openai",
			APIKey:         "synthetic-test-key",
			BaseURL:        server.URL + "/v1",
			Model:          "synthetic-model",
			SupportsVision: supportsVision,
		}}
		cfg.MultiAgent.EinoSkills.Disable = true
		mcpServer := mcp.NewServerWithStorage(zap.NewNop(), db)
		ag := agent.NewAgent(&cfg.OpenAI, &cfg.Agent, mcpServer, nil, zap.NewNop(), 10)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if withImages {
			ctx = WithTurnImages(ctx, []TurnImage{{Path: imagePath, Base64: payload, MIMEType: "image/png"}})
		}
		if _, err := RunEinoSingleChatModelAgent(ctx, cfg, &cfg.MultiAgent, ag, db, zap.NewNop(), conv.ID, "", "看这张图", nil, nil, nil, nil, ""); err != nil {
			t.Fatalf("run single agent: %v", err)
		}
		select {
		case body := <-captured:
			return body
		case <-time.After(5 * time.Second):
			t.Fatal("model was never called")
			return ""
		}
	}

	t.Run("vision channel receives the image", func(t *testing.T) {
		body := run(t, true, true)
		if !strings.Contains(body, "data:image/png;base64,") {
			t.Fatalf("request body has no image data url: %s", truncateForLog(body))
		}
		if !strings.Contains(body, payload[:64]) {
			t.Fatalf("request body does not carry the exact payload: %s", truncateForLog(body))
		}
		if !strings.Contains(body, "图片输入") {
			t.Errorf("native vision channel should get the image-input prompt section: %s", truncateForLog(body))
		}
		if strings.Contains(body, "analyze_image") {
			t.Errorf("native vision channel must not be told to use the out-of-band tool: %s", truncateForLog(body))
		}
	})

	t.Run("text-only channel neither sends nor claims images", func(t *testing.T) {
		body := run(t, false, false)
		if strings.Contains(body, "data:image/png;base64,") {
			t.Fatalf("text-only channel must not receive image payloads: %s", truncateForLog(body))
		}
		if strings.Contains(body, "图片输入") {
			t.Errorf("text-only channel must not claim native image input: %s", truncateForLog(body))
		}
	})
}

func truncateForLog(s string) string {
	if len(s) > 1200 {
		return s[:1200] + "...(truncated)"
	}
	return s
}

// sseChunkStream 是假模型的流式响应（OpenAI 兼容 SSE）：一行首包 + 一行 stop + [DONE]。
const sseChunkStream = `data: {"id":"synthetic","object":"chat.completion.chunk","model":"synthetic","choices":[{"index":0,"delta":{"role":"assistant","content":"看到红色的图。"},"finish_reason":null}]}

data: {"id":"synthetic","object":"chat.completion.chunk","model":"synthetic","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]

`
