package multiagent

import (
	"strings"
	"testing"
)

func TestBuildIdentityGapHint_OpenIDORNoDualAuth(t *testing.T) {
	t.Parallel()
	conv := "test-identity-gap"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.UpsertCoverage(CoverageItem{
		Path:     CoveragePathFromLogic("https://t/order/1", LogicClassIDORHoriz, "order_id"),
		Status:   "open",
		Priority: "P1",
		Note:     "user_id swap",
	})
	hint := BuildIdentityGapHint(st)
	if hint == "" {
		t.Fatal("expected identity gap hint")
	}
	if !strings.Contains(hint, "identity_gap") {
		t.Fatalf("marker missing: %s", hint)
	}
	if !strings.Contains(hint, "水平越权") && !strings.Contains(hint, "跨账号") {
		t.Fatalf("copy missing horizontal scope: %s", hint)
	}
	if IdentityGapImpliesWholeTrackSkip(hint) {
		t.Fatalf("must not claim whole logic track unusable: %s", hint)
	}
	// After dual auth recorded → no hint
	st.MarkAuthProbe(true, true)
	if BuildIdentityGapHint(st) != "" {
		t.Fatal("dual auth should clear gap")
	}
}

func TestApplyFinalizeGate_AppendsIdentityGap(t *testing.T) {
	t.Parallel()
	conv := "test-finalize-identity-gap"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path:     "logic.idor_horizontal.target:shop.example",
		Status:   "open",
		Priority: "P1",
	})
	// Wrap-up triggers gate + identity gap
	out, blocked := ApplyFinalizeGate(conv, "未发现漏洞，可以结束。")
	if !blocked {
		t.Fatal("should block")
	}
	if !strings.Contains(out, "identity_gap") {
		t.Fatalf("expected identity_gap in: %s", out)
	}
	// Idempotent
	out2, _ := ApplyFinalizeGate(conv, out)
	if strings.Count(out2, "identity_gap") != 1 {
		t.Fatalf("should not duplicate identity_gap: count=%d", strings.Count(out2, "identity_gap"))
	}
}

func TestAppendIdentityGap_NoIDORNoHint(t *testing.T) {
	t.Parallel()
	conv := "test-no-idor-gap"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path: "cand.sqli.param:id", Status: "open", Priority: "P0",
	})
	if BuildIdentityGapHint(GetConversationExecutionState(conv)) != "" {
		t.Fatal("non-idor should not gap")
	}
}

// Production path: ApplyFinalizeGateToRunResult must surface identity_gap even when
// response is not wrap-up phrasing (blocked=false). Regression for early-return bug.
func TestApplyFinalizeGateToRunResult_IdentityGapWhenNotBlocked(t *testing.T) {
	t.Parallel()
	conv := "test-runresult-identity-gap-noblock"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path:     "logic.idor_horizontal.target:api.example",
		Status:   "open",
		Priority: "P1",
		Note:     "need dual account",
	})
	// Non-wrap-up final text → blocked=false, but identity_gap must still land on Response.
	rr := &RunResult{Response: "本轮已核对订单详情接口，建议下一轮补充第二账号对比。"}
	out := ApplyFinalizeGateToRunResult(rr, conv, nil)
	if out == nil {
		t.Fatal("nil out")
	}
	if !strings.Contains(out.Response, "identity_gap") {
		t.Fatalf("production RunResult path must keep identity_gap when blocked=false, got: %s", out.Response)
	}
	if !strings.Contains(out.Response, "本轮已核对") {
		t.Fatalf("original text must be preserved: %s", out.Response)
	}
	// With dual auth recorded, gap must not appear
	ResetConversationExecutionStateForTest(conv + "-dual")
	st := GetConversationExecutionState(conv + "-dual")
	st.UpsertCoverage(CoverageItem{
		Path: "logic.idor_horizontal.target:x", Status: "open", Priority: "P1",
	})
	st.MarkAuthProbe(true, true)
	rr2 := &RunResult{Response: "继续测试中，暂无结论。"}
	out2 := ApplyFinalizeGateToRunResult(rr2, conv+"-dual", nil)
	if strings.Contains(out2.Response, "identity_gap") {
		t.Fatalf("dual auth should suppress identity_gap: %s", out2.Response)
	}
}
