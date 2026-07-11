package multiagent

import (
	"strings"
	"testing"
)

// R5: payment/checkout → business classes, NOT forced idor_horizontal.
func TestHeuristic_PaymentCheckout_BusinessNotOnlyIDOR(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		url  string
		args string
	}{
		{"pay_create", "https://shop.example/api/pay/create", `{"method":"POST","body":"amount=9.9"}`},
		{"checkout", "https://shop.example/checkout", `{"price":"1","quantity":2}`},
		{"order_amount", "https://pay.example/order", `amount=0.01&out_trade_no=T1`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			items := HeuristicLogicCoverageItems(tc.url, tc.args, `{"ok":true}`)
			if len(items) == 0 {
				t.Fatal("expected business coverage")
			}
			var hasBiz, hasIDOR bool
			for _, it := range items {
				if it.Status != "open" {
					t.Fatalf("status=%s", it.Status)
				}
				// Heuristic items are P2 by default.
				if it.Priority != "P2" {
					t.Fatalf("priority=%s path=%s want P2", it.Priority, it.Path)
				}
				p := it.Path
				if strings.Contains(p, LogicClassParamTamper) ||
					strings.Contains(p, LogicClassWorkflowSkip) ||
					strings.Contains(p, LogicClassCouponAbuse) ||
					strings.Contains(p, LogicClassRace) ||
					strings.Contains(p, LogicClassStateTamper) {
					hasBiz = true
				}
				if strings.Contains(p, LogicClassIDORHoriz) {
					hasIDOR = true
				}
			}
			if !hasBiz {
				t.Fatalf("expected business class open, got %+v", items)
			}
			if hasIDOR {
				t.Fatalf("payment entry must not force idor_horizontal, got %+v", items)
			}
		})
	}
}

func TestRouteSkills_PayCreateAmount_BusinessLogicTop(t *testing.T) {
	t.Parallel()
	res := RouteSkills(SkillRouterInput{
		ToolName:  "http-framework-test",
		Arguments: `{"method":"POST","url":"https://t/api/pay/create","data":"amount=1&out_trade_no=x"}`,
		Output:    `{"code":0,"pay_url":"..."}`,
		TopK:      3,
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "tips " + skillDir + " price payment workflow race"
		},
	})
	if len(res.Skills) == 0 {
		t.Fatal("no skills")
	}
	if res.Skills[0] != "business-logic-vulnerabilities" {
		// must at least be in Top and preferably first
		if !containsSkill(res.Skills, "business-logic-vulnerabilities") {
			t.Fatalf("pay/create must include business-logic, got %v", res.Skills)
		}
		t.Fatalf("pay/create amount should Top1 business-logic, got %v", res.Skills)
	}
}

func TestRouteSkills_CVEOnly_StillNotBusinessTop1(t *testing.T) {
	t.Parallel()
	res := RouteSkills(SkillRouterInput{
		ToolName:  "nuclei",
		Arguments: `{"target":"https://scan.example"}`,
		Output:    "[CVE-2021-44228] log4j\n[cve-2023-44487] http2\nnuclei-templates cves/",
		TopK:      3,
		SkillTipsLoader: func(_, d string, _ int) string {
			return "tips " + d
		},
	})
	if len(res.Skills) > 0 && res.Skills[0] == "business-logic-vulnerabilities" {
		t.Fatalf("CVE-only must not Top1 business-logic: %v", res.Skills)
	}
}

func TestLogicProbe_DescriptionBusinessFirst(t *testing.T) {
	t.Parallel()
	d := LogicProbeToolDescription
	for _, kw := range []string{"支付", "param_tamper", "step_skip", "parallel", "金额", "流程"} {
		if !strings.Contains(d, kw) {
			t.Fatalf("description missing %q: %s", kw, d)
		}
	}
	// identity optional, not required
	if strings.Contains(d, "auth_a 必填") || strings.Contains(strings.ToLower(d), "auth required") {
		t.Fatal("auth must not be required")
	}
	if !strings.Contains(d, "可选") && !strings.Contains(d, LogicProbeRecommendedOrder) {
		t.Fatal("should mention optional dual-account and recommended order")
	}
	if DefaultLogicProbeMode != LogicProbeModeParamTamper {
		t.Fatalf("default mode=%s want param_tamper", DefaultLogicProbeMode)
	}
	if NormalizeLogicProbeMode("") != LogicProbeModeParamTamper {
		t.Fatal("empty mode → param_tamper")
	}
	// required fields: only url in validate
	if msg := ValidateLogicProbeRequest(LogicProbeRequest{URL: "http://x", Mode: ""}); msg != "" {
		t.Fatalf("empty mode with url should pass validate, got %q", msg)
	}
	hint := NextHintForLogicProbe(LogicProbeModeParamTamper, false)
	if !strings.Contains(hint, "金额") && !strings.Contains(hint, "服务端") {
		t.Fatalf("next_hint should be business invariant oriented: %s", hint)
	}
}

func TestFinalize_BusinessParamTamperBlocksWrapUp(t *testing.T) {
	t.Parallel()
	conv := "test-r5-param-tamper-gate"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path:     CoveragePathFromLogic("https://pay.example/checkout", LogicClassParamTamper, "amount"),
		Status:   "open",
		Priority: "P0",
		Note:     "client amount",
	})
	out, blocked := ApplyFinalizeGate(conv, "扫描完成，未发现漏洞。")
	if !blocked {
		t.Fatal("param_tamper open must block wrap-up")
	}
	if !strings.Contains(out, "finalize_gate_blocked") {
		t.Fatalf("missing gate: %s", out)
	}
	if IdentityGapImpliesWholeTrackSkip(out) {
		t.Fatal("must not imply whole track skip")
	}
}

func TestFinalize_NoDualAuth_BusinessOpen_NoWholeTrackSkip(t *testing.T) {
	t.Parallel()
	conv := "test-r5-business-no-dual"
	ResetConversationExecutionStateForTest(conv)
	st := GetConversationExecutionState(conv)
	st.UpsertCoverage(CoverageItem{
		Path: "logic.param_tamper.param:amount.t:pay.example", Status: "open", Priority: "P0",
	})
	// No idor → no identity_gap; business still blocks wrap-up
	out, blocked := ApplyFinalizeGate(conv, "测试完成，无漏洞。")
	if !blocked {
		t.Fatal("business open should block")
	}
	if strings.Contains(out, "无法测逻辑") || strings.Contains(out, "逻辑全跳过") {
		t.Fatalf("forbidden whole-track skip copy: %s", out)
	}
	if strings.Contains(out, "identity_gap") {
		t.Fatalf("business-only should not force identity_gap: %s", out)
	}
	// Explicit: gap text itself must not over-claim
	if IdentityGapImpliesWholeTrackSkip(IdentityGapFinalizeHint) {
		t.Fatal("IdentityGapFinalizeHint must not claim whole logic track unusable")
	}
}

func TestFinalize_NoDualAuth_OnlyIDOR_IdentityGapOK(t *testing.T) {
	t.Parallel()
	conv := "test-r5-idor-only-gap"
	ResetConversationExecutionStateForTest(conv)
	GetConversationExecutionState(conv).UpsertCoverage(CoverageItem{
		Path: "logic.idor_horizontal.target:api.example", Status: "open", Priority: "P1",
	})
	hint := BuildIdentityGapHint(GetConversationExecutionState(conv))
	if hint == "" {
		t.Fatal("expected identity gap for open idor without dual auth")
	}
	if !strings.Contains(hint, "水平越权") && !strings.Contains(hint, "跨账号") {
		t.Fatalf("should mention horizontal only: %s", hint)
	}
	if !strings.Contains(hint, "不依赖双账号") && !strings.Contains(hint, "param_tamper") {
		t.Fatalf("should still encourage business tests: %s", hint)
	}
	if IdentityGapImpliesWholeTrackSkip(hint) {
		t.Fatal("gap must not imply whole track skip")
	}
}

func TestL1PaymentCandidate_BusinessCoverage(t *testing.T) {
	t.Parallel()
	conv := "test-r5-l1-payment"
	ResetConversationExecutionStateForTest(conv)
	item := AutoUpsertCoverageFromCandidate(conv,
		"https://shop.example/api/pay/create",
		"amount",
		"param_tamper",
		"business_logic",
		"high",
		"amount=0.01 still creates paid order — server trusted client price",
	)
	if item.Status != "open" {
		t.Fatalf("status=%s", item.Status)
	}
	if !strings.Contains(item.Path, "logic.") || !strings.Contains(item.Path, LogicClassParamTamper) {
		t.Fatalf("path=%s", item.Path)
	}
	if item.Priority != "P2" {
		t.Fatalf("heuristic payment candidate → P2, got %s", item.Priority)
	}
	// P2 heuristic items must not block finalize; only promoted/confirmed P0/P1 do.
	cont, _, open := GetConversationExecutionState(conv).ShouldContinue()
	if cont || len(open) != 0 {
		t.Fatalf("P2 heuristic must not keep should_continue: cont=%v open=%+v", cont, open)
	}
}

func TestPreferBusinessLogicFirstPass_InExtract(t *testing.T) {
	t.Parallel()
	md := "---\nname: business-logic\n---\n\n# Intro\n" +
		"## Price manipulation\nTest price and amount client-side.\n" +
		"## Workflow skip\nSkip payment confirm.\n" +
		"## Race\nParallel coupon redeem.\n" +
		"## IDOR only section far away\nuser_id swap\n"
	out := extractSkillTips(md, 2000)
	if !strings.Contains(out, "Business/Backend Logic Track") && !strings.Contains(out, "first-pass") {
		// preferBusinessLogicFirstPass prefix
		if !strings.Contains(strings.ToLower(out), "price") {
			t.Fatalf("expected payment-oriented tips: %s", out)
		}
	}
}
