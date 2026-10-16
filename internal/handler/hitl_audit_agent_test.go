package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cyberstrike-ai/internal/config"

	"go.uber.org/zap"
)

func newAuditStubHandler(baseURL string) *AgentHandler {
	return &AgentHandler{
		config: &config.Config{OpenAI: config.OpenAIConfig{APIKey: "test-key", BaseURL: baseURL, Model: "audit-model"}},
		logger: zap.NewNop(),
	}
}

// 引擎抖动不该把一类操作判死：首次失败后重试，第二次成功即按裁决结果返回。
func TestAuditAgentReviewRetriesEngineFailureThenDecides(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"upstream unavailable"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"decision\":\"approve\",\"comment\":\"改的是自建账号，最小化验证\"}"}}]}`))
	}))
	defer server.Close()

	h := newAuditStubHandler(server.URL)
	decision := h.auditAgentReview(context.Background(), "http-framework-test", map[string]interface{}{"arguments": `{"method":"POST"}`})

	if decision.Decision != "approve" {
		t.Fatalf("decision=%s comment=%s", decision.Decision, decision.Comment)
	}
	if decision.Failure {
		t.Fatal("recovered attempt must not be flagged as engine failure")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("attempts=%d, want 2", got)
	}
}

// 持续失败时按"引擎不可用"返回，而不是伪装成策略拒绝：
// 文案必须说明这不是对本次操作的裁决，也不代表该类操作被封禁。
func TestAuditAgentReviewMarksPersistentEngineFailureAsNonPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	h := newAuditStubHandler(server.URL)
	decision := h.auditAgentReview(context.Background(), "exec", map[string]interface{}{"arguments": `{"command":"id"}`})

	if decision.Decision != "reject" || !decision.Failure {
		t.Fatalf("decision=%s failure=%v", decision.Decision, decision.Failure)
	}
	for _, want := range []string{"审批引擎不可用", "非策略裁决", "重试"} {
		if !strings.Contains(decision.Comment, want) {
			t.Fatalf("comment=%q must mention %q", decision.Comment, want)
		}
	}
}

func TestParseAuditAgentLLMContentApprove(t *testing.T) {
	d, err := parseAuditAgentLLMContent(`{"decision":"approve","comment":"与任务一致"}`)
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != "approve" || d.Comment != "与任务一致" {
		t.Fatalf("unexpected %+v", d)
	}
}

func TestParseAuditAgentLLMContentReject(t *testing.T) {
	d, err := parseAuditAgentLLMContent("```json\n{\"decision\":\"reject\",\"comment\":\"风险过高\"}\n```")
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != "reject" {
		t.Fatalf("expected reject, got %s", d.Decision)
	}
}

func TestParseAuditAgentLLMContentInvalid(t *testing.T) {
	_, err := parseAuditAgentLLMContent(`{"decision":"maybe"}`)
	if err == nil {
		t.Fatal("expected error for invalid decision")
	}
}

func TestParseAuditAgentLLMContentProseWrapped(t *testing.T) {
	d, err := parseAuditAgentLLMContent("好的，裁决如下：\n```json\n{\"decision\":\"approve\",\"comment\":\"只读 ls\"}\n```\n以上。")
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != "approve" {
		t.Fatalf("expected approve, got %s", d.Decision)
	}
}

func TestParseAuditAgentLLMContentChineseDecision(t *testing.T) {
	d, err := parseAuditAgentLLMContent(`{"decision":"通过","comment":"风险低"}`)
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != "approve" {
		t.Fatalf("expected approve, got %s", d.Decision)
	}
}

func TestBuildAuditAgentReviewInputHasSingleApprovalContract(t *testing.T) {
	s := buildAuditAgentReviewInput("execute", map[string]interface{}{
		"arguments": `{"command":"pwd"}`,
	})
	if strings.Contains(s, "hitlMode") {
		t.Fatalf("legacy approval mode leaked into input: %s", s)
	}
	if !strings.Contains(s, "execute") {
		t.Fatalf("unexpected input: %s", s)
	}
}

func TestBuildAuditAgentReviewInput(t *testing.T) {
	s := buildAuditAgentReviewInput("nmap", map[string]interface{}{
		"arguments":   `{"target":"10.0.0.1"}`,
		"userMessage": "扫描内网",
	})
	if s == "" {
		t.Fatal("expected non-empty input")
	}
	if !strings.Contains(s, "nmap") || !strings.Contains(s, "10.0.0.1") || !strings.Contains(s, "扫描内网") {
		t.Fatalf("unexpected input: %s", s)
	}
}

func TestAuditAgentReviewTypeSafeMissingAPIKey(t *testing.T) {
	h := &AgentHandler{config: &config.Config{Hitl: config.HitlConfig{AuditBackend: "typesafe"}}}
	d := h.auditAgentReview(context.Background(), "exec", nil)
	if d.Decision != "reject" {
		t.Fatalf("decision=%s", d.Decision)
	}
	if !strings.Contains(d.Comment, "TypeSafe API Key") {
		t.Fatalf("comment=%s", d.Comment)
	}
}

func TestHitlAuditEngineInfoTypeSafe(t *testing.T) {
	h := &AgentHandler{config: &config.Config{
		OpenAI: config.OpenAIConfig{Model: "gpt-4o"},
		Hitl:   config.HitlConfig{AuditBackend: "typesafe"},
	}}
	backend, model := h.hitlAuditEngineInfo()
	if backend != config.HitlAuditBackendTypeSafe {
		t.Fatalf("backend=%q", backend)
	}
	if model != config.TypeSafeDefaultModel {
		t.Fatalf("model=%q, want %s", model, config.TypeSafeDefaultModel)
	}
}

func TestHitlAuditEngineInfoOpenAIInheritsMainModel(t *testing.T) {
	h := &AgentHandler{config: &config.Config{
		OpenAI: config.OpenAIConfig{Model: "gpt-4o-mini"},
		Hitl:   config.HitlConfig{AuditBackend: "openai"},
	}}
	backend, model := h.hitlAuditEngineInfo()
	if backend != config.HitlAuditBackendOpenAI {
		t.Fatalf("backend=%q", backend)
	}
	if model != "gpt-4o-mini" {
		t.Fatalf("model=%q", model)
	}
}
