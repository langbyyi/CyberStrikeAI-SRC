package multiagent

import (
	"context"
	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTaskSpecificationReachesDelegatedDescription(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "spec.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c, err := db.CreateConversation("synthetic", database.ConversationCreateMeta{TestingSpecification: &database.TestingSpecification{Content: "MANDATORY_TASK_RULE"}})
	if err != nil {
		t.Fatal(err)
	}
	extra, block, err := taskSpecificationContext(db, c.ID, "workspace")
	if err != nil || !strings.Contains(extra, "MANDATORY_TASK_RULE") {
		t.Fatalf("context: %s, %v", extra, err)
	}
	mw := newAgenticTaskContextEnrichMiddleware("", nil, -1, block)
	if mw == nil {
		t.Fatal("disabling history must not disable mandatory task rules")
	}
	enricher := mw.(*agenticTaskContextEnrichMiddleware)
	result := enricher.enrichTaskDescription(`{"description":"Check the target"}`)
	if !strings.Contains(result, "MANDATORY_TASK_RULE") {
		t.Fatal("delegated task dropped rules")
	}
	deduped, _, err := taskSpecificationContext(db, c.ID, extra)
	if err != nil || strings.Count(deduped, "MANDATORY_TASK_RULE") != 1 {
		t.Fatal("duplicated specification")
	}
	if _, _, err := taskSpecificationContext(db, "missing-conversation", ""); err == nil {
		t.Fatal("missing snapshot must fail closed")
	}
}

func TestSingleAgentModelReceivesTestingSpecification(t *testing.T) {
	captured := make(chan string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		data, _ := json.Marshal(body["messages"])
		captured <- string(data)
		if stream, _ := body["stream"].(bool); stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"synthetic\",\"object\":\"chat.completion.chunk\",\"model\":\"synthetic\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Specification received.\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"synthetic\",\"object\":\"chat.completion.chunk\",\"model\":\"synthetic\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
		} else {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"synthetic","object":"chat.completion","model":"synthetic","choices":[{"index":0,"message":{"role":"assistant","content":"Specification received."},"finish_reason":"stop"}]}`)
		}
	}))
	defer server.Close()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "model-spec.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conv, err := db.CreateConversation("synthetic", database.ConversationCreateMeta{TestingSpecification: &database.TestingSpecification{Content: "MODEL_VISIBLE_RULE_ONLY_APP_EXAMPLE_TEST"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{OpenAI: config.OpenAIConfig{Provider: "openai", APIKey: "synthetic-test-key", BaseURL: server.URL + "/v1", Model: "synthetic-model"}}
	cfg.MultiAgent.EinoSkills.Disable = true
	mcpServer := mcp.NewServerWithStorage(zap.NewNop(), db)
	ag := agent.NewAgent(&cfg.OpenAI, &cfg.Agent, mcpServer, nil, zap.NewNop(), 10)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := RunEinoSingleChatModelAgent(ctx, cfg, &cfg.MultiAgent, ag, db, zap.NewNop(), conv.ID, "", "Summarize the rules", nil, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	request := <-captured
	if result == nil || !strings.Contains(request, "MODEL_VISIBLE_RULE_ONLY_APP_EXAMPLE_TEST") {
		t.Fatalf("model did not receive task specification: %s", request)
	}
}
