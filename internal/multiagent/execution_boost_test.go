package multiagent

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp/builtin"
)

func TestMergeAlwaysVisibleToolNamesWithBoost_IncludesHuntingCore(t *testing.T) {
	t.Parallel()
	merged := mergeAlwaysVisibleToolNamesWithBoost([]string{"read_file"}, true)
	required := []string{
		"http-framework-test",
		"exec", "execute-python-script", "jwt-analyzer", "dnslog", "skill",
		builtin.ToolRecordVulnerability, builtin.ToolRecordVulnerabilityCandidate,
		builtin.ToolUpsertProjectFact, builtin.ToolUpsertExecutionCoverage,
		builtin.ToolLogicProbeDiff,
		"read_file",
	}
	set := map[string]struct{}{}
	for _, n := range merged {
		set[strings.ToLower(n)] = struct{}{}
	}
	for _, want := range required {
		if _, ok := set[strings.ToLower(want)]; !ok {
			t.Fatalf("missing always_visible tool %q in merged=%v", want, merged)
		}
	}
}

func TestMergeAlwaysVisibleToolNamesWithBoost_DisabledSkipsHuntingOnly(t *testing.T) {
	t.Parallel()
	merged := mergeAlwaysVisibleToolNamesWithBoost(nil, false)
	set := map[string]struct{}{}
	for _, n := range merged {
		set[strings.ToLower(n)] = struct{}{}
	}
	// builtins still present
	if _, ok := set[builtin.ToolRecordVulnerability]; !ok {
		t.Fatal("builtin tools should always merge")
	}
	// hunting-only tools should not appear when boost off (unless they are builtins)
	if _, ok := set["http-framework-test"]; ok {
		t.Fatal("hunting-only tool should not be in default merge when boost disabled")
	}
}

func TestMergeReductionClearExclude_HuntingDefaults(t *testing.T) {
	t.Parallel()
	excl := mergeReductionClearExclude(nil, true)
	need := []string{"http-framework-test", "execute-python-script", "jwt-analyzer", "dnslog", "task"}
	set := map[string]struct{}{}
	for _, n := range excl {
		set[strings.ToLower(n)] = struct{}{}
	}
	for _, w := range need {
		if _, ok := set[strings.ToLower(w)]; !ok {
			t.Fatalf("missing reduction clear exclude %q", w)
		}
	}
}

func TestExecutionBoostConfigDefaults(t *testing.T) {
	t.Parallel()
	var mw config.MultiAgentEinoMiddlewareConfig
	if !mw.ExecutionBoostEffective() {
		t.Fatal("default execution_boost should be true")
	}
	if !mw.SkillRouterEffective() {
		t.Fatal("default skill router should follow boost")
	}
	if mw.TaskEvidenceKEffective() != 5 {
		t.Fatalf("default task evidence k = %d want 5", mw.TaskEvidenceKEffective())
	}
	if mw.StructuredSummaryMaxRunesEffective() != 1200 {
		t.Fatalf("default structured_summary_max_runes = %d want 1200", mw.StructuredSummaryMaxRunesEffective())
	}
	if !mw.FinalizeGateEffective() {
		t.Fatal("default finalize_gate should follow boost (true)")
	}
	off := false
	mw.ExecutionBoost = &off
	if mw.ExecutionBoostEffective() {
		t.Fatal("execution_boost=false should disable")
	}
	if mw.FinalizeGateEffective() {
		t.Fatal("finalize_gate should follow boost when nil")
	}
	// src_hunter_runtime.enable overrides
	on := true
	mw.SrcHunterRuntime.Enable = &on
	if !mw.ExecutionBoostEffective() {
		t.Fatal("src_hunter_runtime.enable=true should win")
	}
	// explicit finalize off
	fg := false
	mw.FinalizeGateEnable = &fg
	if mw.FinalizeGateEffective() {
		t.Fatal("finalize_gate_enable=false should disable")
	}
	// structured summary budget
	mw.StructuredSummaryMaxRunes = 900
	if mw.StructuredSummaryMaxRunesEffective() != 900 {
		t.Fatalf("got %d", mw.StructuredSummaryMaxRunesEffective())
	}
	mw.StructuredSummaryMaxRunes = -5
	if mw.StructuredSummaryMaxRunesEffective() != 1200 {
		t.Fatal("negative budget must clamp to default 1200")
	}
	mw.StructuredSummaryMaxRunes = 99999
	if mw.StructuredSummaryMaxRunesEffective() != 8000 {
		t.Fatalf("upper clamp want 8000 got %d", mw.StructuredSummaryMaxRunesEffective())
	}
	// SkillRouter TopK clamp
	mw.SkillRouterTopK = 100
	if mw.SkillRouterTopKEffective() != 10 {
		t.Fatalf("topk clamp got %d", mw.SkillRouterTopKEffective())
	}
}

func TestMergeAlwaysVisible_DedupConfigured(t *testing.T) {
	t.Parallel()
	merged := mergeAlwaysVisibleToolNamesWithBoost([]string{"sqlmap", "SQLMAP", "read_file"}, true)
	count := 0
	for _, n := range merged {
		if strings.EqualFold(n, "sqlmap") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("sqlmap should appear once after dedup, count=%d merged=%v", count, merged)
	}
}

func TestSummarizationInstructionPreservesGuardFields(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"open_hypotheses", "almost_signals", "dead_ends", "auth_coverage"} {
		if !strings.Contains(einoSummarizeUserInstruction, field) {
			t.Fatalf("summarization instruction missing forced field %q", field)
		}
	}
	if !strings.Contains(einoSummarizeUserInstruction, "禁止把未完成") && !strings.Contains(einoSummarizeUserInstruction, "禁止写「无洞收工」") {
		t.Fatal("summarization instruction should forbid collapsing unfinished work into no-vuln")
	}
}
