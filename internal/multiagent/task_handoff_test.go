package multiagent

import (
	"encoding/json"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestExtractTargetFromText(t *testing.T) {
	t.Parallel()
	if got := ExtractTargetFromText("请测 https://vuln.example.com/app/login 授权范围全站"); got != "https://vuln.example.com/app/login" {
		t.Fatalf("url got %q", got)
	}
	if got := ExtractTargetFromText("目标 10.0.0.8:8080"); !strings.Contains(got, "10.0.0.8") {
		t.Fatalf("ip got %q", got)
	}
}

func TestCorrectSubagentRouting_VerifyExploit(t *testing.T) {
	t.Parallel()
	got, changed := CorrectSubagentRouting("请 verify 该 SQL 注入并可 exploit", "recon")
	if !changed || got != "vulnerability-triage" {
		t.Fatalf("got=%q changed=%v", got, changed)
	}
	got2, ch2 := CorrectSubagentRouting("继续 recon 子域", "recon")
	if ch2 || got2 != "recon" {
		t.Fatalf("recon should stay, got=%q ch=%v", got2, ch2)
	}
}

func TestEnrichTaskArguments_BackfillAndEvidence(t *testing.T) {
	t.Parallel()
	conv := "test-task-handoff-1"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.RecordTool(SummarizeToolResult("sqlmap", `{"url":"https://t/x"}`, "Parameter id appears injectable\nerror_sig=SQL syntax"))

	mw := config.MultiAgentEinoMiddlewareConfig{}
	// defaults: boost on, require target, evidence k=5
	args := `{"subagent_type":"recon","description":"verify 登录页注入是否可利用"}`
	// supplement carries target
	sup := "\n\n## 用户历史输入\n[第1轮] 授权测试 https://target.example/login"
	enriched, reject := EnrichTaskArguments(args, sup, "### asset/login\nbody: cookie=abc", conv, &mw)
	if reject != "" {
		t.Fatalf("unexpected reject: %s", reject)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(enriched), &raw); err != nil {
		t.Fatal(err)
	}
	desc := raw["description"].(string)
	if !strings.Contains(desc, "https://target.example/login") {
		t.Fatalf("target backfill missing: %s", desc)
	}
	if !strings.Contains(desc, "sqlmap") {
		t.Fatalf("tool evidence missing: %s", desc)
	}
	if !strings.Contains(desc, "asset/login") {
		t.Fatalf("fact body missing: %s", desc)
	}
	// routing corrected
	if raw["subagent_type"] != "vulnerability-triage" {
		t.Fatalf("subagent_type=%v want vulnerability-triage", raw["subagent_type"])
	}
}

func TestEnrichTaskArguments_RejectMissingTarget(t *testing.T) {
	t.Parallel()
	mw := config.MultiAgentEinoMiddlewareConfig{}
	_, reject := EnrichTaskArguments(
		`{"subagent_type":"recon","description":"随便扫一下"}`,
		"", "", "c2", &mw,
	)
	if reject == "" || !strings.Contains(reject, "缺 target") {
		t.Fatalf("expected reject, got %q", reject)
	}
}

func TestFormatToolEvidenceBlock(t *testing.T) {
	t.Parallel()
	block := FormatToolEvidenceBlock([]ToolEvidenceEntry{
		{ToolName: "nuclei", StatusHint: "interesting", Length: 120, Summary: "cve-hit"},
	})
	if !strings.Contains(block, "nuclei") || !strings.Contains(block, "cve-hit") {
		t.Fatalf("block=%s", block)
	}
}

func TestShouldContinueCoverage(t *testing.T) {
	t.Parallel()
	conv := "cov-test-1"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.UpsertCoverage(CoverageItem{Path: "sqli.id", Status: "open", Priority: "P0"})
	cont, reason, open := st.ShouldContinue()
	if !cont || len(open) != 1 {
		t.Fatalf("cont=%v open=%d reason=%s", cont, len(open), reason)
	}
	st.UpsertCoverage(CoverageItem{Path: "sqli.id", Status: "done", Priority: "P0"})
	cont2, _, open2 := st.ShouldContinue()
	if cont2 || len(open2) != 0 {
		t.Fatalf("after done cont=%v open=%d", cont2, len(open2))
	}
}
