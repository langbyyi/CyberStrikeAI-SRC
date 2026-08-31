package handler

import (
	"strings"
	"testing"
)

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
