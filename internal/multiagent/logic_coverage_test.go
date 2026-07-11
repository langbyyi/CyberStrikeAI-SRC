package multiagent

import (
	"strings"
	"testing"
)

func TestAllLogicCoverageClassesPresent(t *testing.T) {
	t.Parallel()
	want := []string{
		LogicClassWorkflowSkip, LogicClassParamTamper, LogicClassRace,
		LogicClassIDORHoriz, LogicClassStateTamper, LogicClassCouponAbuse, LogicClassAuthStepSkip,
	}
	if len(AllLogicCoverageClasses) < len(want) {
		t.Fatalf("classes=%v", AllLogicCoverageClasses)
	}
	for _, w := range want {
		if !IsLogicCoverageClass(w) {
			t.Fatalf("IsLogicCoverageClass(%q)=false", w)
		}
	}
}

func TestHeuristicLogicCoverage_CheckoutEntry(t *testing.T) {
	t.Parallel()
	items := HeuristicLogicCoverageItems(
		"https://Shop.Example:443/api/checkout",
		`{"price":"1","coupon":"SAVE"}`,
		`{"order_id":1,"total":0}`,
	)
	if len(items) == 0 {
		t.Fatal("expected logic open items")
	}
	for _, it := range items {
		if it.Status != "open" {
			t.Fatalf("status=%s", it.Status)
		}
		// Heuristic items are P2 by default — they must not block finalize.
		if it.Priority != "P2" {
			t.Fatalf("priority=%s path=%s want P2", it.Priority, it.Path)
		}
		if !strings.HasPrefix(it.Path, "logic.") {
			t.Fatalf("path=%s", it.Path)
		}
		// default port stripped via target segment
		if strings.Contains(it.Path, "443") {
			t.Fatalf("port in path: %s", it.Path)
		}
	}
}

func TestLogicCoverage_GateBlocksThenDoneReleases(t *testing.T) {
	t.Parallel()
	conv := "test-logic-gate-entry"
	ResetConversationExecutionStateForTest(conv)
	upserted := AutoUpsertLogicCoverageFromToolSignals(conv, "http-framework-test",
		`{"url":"https://pay.example/checkout","data":"price=0.01&coupon=X"}`,
		`{"status":"ok","price":0.01}`,
	)
	if len(upserted) == 0 {
		t.Fatal("expected auto logic coverage")
	}
	st := GetConversationExecutionState(conv)

	// Heuristic logic coverage is P2 and must NOT block finalize.
	for _, it := range upserted {
		if it.Priority != "P2" {
			t.Fatalf("heuristic logic should be P2, got %s", it.Priority)
		}
	}
	_, blockedP2 := ApplyFinalizeGate(conv, "扫描完成，未发现漏洞。")
	if blockedP2 {
		t.Fatal("P2 heuristic items must not block finalize")
	}

	// Promote one item to P1 to verify the gate still works for real open paths.
	promoted := upserted[0]
	promoted.Priority = "P1"
	st.UpsertCoverage(promoted)
	out, blocked := ApplyFinalizeGate(conv, "扫描完成，未发现漏洞。")
	if !blocked {
		t.Fatal("finalize should block with open P1")
	}
	if !strings.Contains(out, "finalize_gate_blocked") {
		t.Fatalf("missing gate: %s", out)
	}
	// Close all open P0/P1
	cont, _, open := st.ShouldContinue()
	if !cont || len(open) == 0 {
		t.Fatalf("should continue with open P1 cont=%v open=%d", cont, len(open))
	}
	for _, it := range open {
		it.Status = "done"
		st.UpsertCoverage(it)
	}
	_, blocked2 := ApplyFinalizeGate(conv, "测试完成，未发现漏洞。")
	if blocked2 {
		t.Fatal("after done, gate should not block")
	}
}

func TestEstimateLogicCoveragePriorityTable(t *testing.T) {
	t.Parallel()
	// All heuristic logic classes are P2 — LLM must test first, then promote.
	for _, cls := range AllLogicCoverageClasses {
		if got := EstimateLogicCoveragePriority(cls); got != "P2" {
			t.Fatalf("%s heuristic → P2, got %s", cls, got)
		}
	}
}

func TestL1LogicCandidate_CoverageClass(t *testing.T) {
	t.Parallel()
	conv := "test-l1-logic-cand"
	ResetConversationExecutionStateForTest(conv)
	item := AutoUpsertCoverageFromCandidate(conv,
		"https://shop.example/order/1",
		"price",
		"param_tamper",
		"business_logic",
		"medium",
		"price=0 accepted; total dropped — invariant break",
	)
	if item.Status != "open" {
		t.Fatalf("status=%s", item.Status)
	}
	if !strings.Contains(item.Path, "logic.") {
		t.Fatalf("expected logic path, got %s", item.Path)
	}
	if !strings.Contains(item.Path, LogicClassParamTamper) {
		t.Fatalf("path should include class: %s", item.Path)
	}
	// Heuristic param_tamper defaults to P2 — LLM must test first, then promote.
	if item.Priority != "P2" {
		t.Fatalf("heuristic param_tamper should be P2, got %s", item.Priority)
	}
	// P2 items should NOT block finalize.
	cont, _, open := GetConversationExecutionState(conv).ShouldContinue()
	if cont {
		t.Fatalf("P2 heuristic item should not trigger should_continue: open=%+v", open)
	}
}

func TestNucleiCVEDoesNotAutoLogicCoverage(t *testing.T) {
	t.Parallel()
	conv := "test-nuclei-no-logic"
	ResetConversationExecutionStateForTest(conv)
	got := AutoUpsertLogicCoverageFromToolSignals(conv, "nuclei",
		`{"target":"https://x"}`,
		`[CVE-2021-44228] log4j\n[cve-2023-1] foo`,
	)
	if len(got) != 0 {
		t.Fatalf("nuclei CVE-only should not open logic coverage: %v", got)
	}
}
