package handler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/openai"

	"go.uber.org/zap"
)

// TestCreateProgressCallback_ConcurrentToolEvents 回归 issue #142：并行 tool 回调不得 concurrent map panic。
func TestCreateProgressCallback_ConcurrentToolEvents(t *testing.T) {
	logger := zap.NewNop()
	h := &AgentHandler{
		logger: logger,
		config: &config.Config{},
	}
	cb := h.createProgressCallback(context.Background(), nil, "conv-race-test", "", nil)

	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers * 2)
	for i := 0; i < workers; i++ {
		i := i
		go func() {
			defer wg.Done()
			toolCallID := fmt.Sprintf("tc-%d", i)
			cb("tool_call", "calling skill", map[string]interface{}{
				"toolCallId":   toolCallID,
				"toolName":     "skill",
				"argumentsObj": map[string]interface{}{"skill_name": "demo-skill"},
			})
		}()
		go func() {
			defer wg.Done()
			toolCallID := fmt.Sprintf("tc-%d", i)
			cb("tool_result", "skill done", map[string]interface{}{
				"toolCallId": toolCallID,
				"toolName":   "skill",
				"success":    true,
			})
		}()
	}
	wg.Wait()
}

// TestCreateProgressCallback_FlushesReasoningOnDone 流式推理聚合须在 done/response 时落库，刷新后可回放。
func TestCreateProgressCallback_FlushesReasoningOnDone(t *testing.T) {
	tmp := t.TempDir()
	db, err := database.NewDB(filepath.Join(tmp, "test.sqlite"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer os.RemoveAll(tmp)

	conv, err := db.CreateConversation("test", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	asst, err := db.AddMessage(conv.ID, "assistant", "处理中...", nil)
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}

	h := &AgentHandler{logger: zap.NewNop(), db: db}
	cb := h.createProgressCallback(context.Background(), nil, conv.ID, asst.ID, nil)

	streamID := "eino-reasoning-test-1"
	cb("reasoning_chain_stream_start", " ", map[string]interface{}{
		"streamId": streamID,
		"source":   "eino",
	})
	cb("reasoning_chain_stream_delta", "step one", openai.WithSSEAccumulated(map[string]interface{}{
		"streamId": streamID,
	}, "step one"))
	cb("done", "", map[string]interface{}{"conversationId": conv.ID})

	details, err := db.GetProcessDetails(asst.ID)
	if err != nil {
		t.Fatalf("GetProcessDetails: %v", err)
	}
	found := false
	for _, d := range details {
		if d.EventType == "reasoning_chain" && d.Message == "step one" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected reasoning_chain persisted on done, got %+v", details)
	}
}

func TestEnrichProgressEventData(t *testing.T) {
	t.Run("fills ids", func(t *testing.T) {
		out := enrichProgressEventData(map[string]interface{}{"source": "eino"}, "conv-1", "msg-1")
		m, ok := out.(map[string]interface{})
		if !ok {
			t.Fatalf("expected map, got %T", out)
		}
		if m["conversationId"] != "conv-1" || m["messageId"] != "msg-1" {
			t.Fatalf("unexpected enrichment: %+v", m)
		}
	})
	t.Run("preserves existing ids", func(t *testing.T) {
		out := enrichProgressEventData(map[string]interface{}{
			"conversationId": "keep-conv",
			"messageId":      "keep-msg",
		}, "conv-1", "msg-1")
		m := out.(map[string]interface{})
		if m["conversationId"] != "keep-conv" || m["messageId"] != "keep-msg" {
			t.Fatalf("should not overwrite existing ids: %+v", m)
		}
	})
}
