package multiagent

import (
	"strings"
	"testing"
)

func TestEvaluateFinalizeContinuationForOpenCoverage(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	state := GetConversationExecutionState("conversation-a")
	state.UpsertCoverage(CoverageItem{
		Path:     "auth.login",
		Status:   "open",
		Priority: "P0",
		Note:     "needs differential verification",
	})

	decision := EvaluateFinalizeContinuation(state, "测试完成，未发现漏洞。")
	if !decision.Blocked {
		t.Fatal("open P0 coverage should block finalization")
	}
	if decision.Reason == "" || !strings.Contains(decision.Instruction, "auth.login") {
		t.Fatalf("decision = %#v, want reason and open coverage in instruction", decision)
	}
	if strings.Contains(decision.Instruction, "测试完成，未发现漏洞") {
		t.Fatal("internal continuation instruction must not contain the assistant response")
	}
	if strings.Contains(decision.Instruction, "finalize_gate_blocked") ||
		strings.Contains(decision.Instruction, "框架门闩") {
		t.Fatalf("continuation instruction leaks legacy marker: %q", decision.Instruction)
	}
}

func TestEvaluateFinalizeContinuationForShallowExecution(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	state := GetConversationExecutionState("conversation-a")
	decision := EvaluateFinalizeContinuation(state, "扫描完成，未发现安全问题。")

	if !decision.Blocked || decision.Kind != "depth_force" {
		t.Fatalf("decision = %#v, want depth_force block", decision)
	}
	if !strings.Contains(decision.Instruction, "真实验证") {
		t.Fatalf("instruction = %q, want verification direction", decision.Instruction)
	}
	if strings.Contains(decision.Instruction, "depth_force_blocked") {
		t.Fatalf("continuation instruction leaks legacy marker: %q", decision.Instruction)
	}
}

func TestEvaluateFinalizeContinuationAllowsNonWrapUpResponse(t *testing.T) {
	state := GetConversationExecutionState("conversation-a")
	decision := EvaluateFinalizeContinuation(state, "我已确认登录接口存在参数差异，下面给出复现步骤。")
	if decision.Blocked {
		t.Fatalf("decision = %#v, want allowed final response", decision)
	}
}

func TestFinalizeContinuationAttemptBound(t *testing.T) {
	blocked := FinalizeContinuationDecision{Blocked: true, Instruction: "continue"}
	for attempt := 0; attempt < MaxFinalizeContinuationsPerRun; attempt++ {
		if !ShouldStartFinalizeContinuation(blocked, attempt) {
			t.Fatalf("attempt %d should continue", attempt)
		}
	}
	if ShouldStartFinalizeContinuation(blocked, MaxFinalizeContinuationsPerRun) {
		t.Fatal("continuation must stop at configured bound")
	}
	if ShouldStartFinalizeContinuation(FinalizeContinuationDecision{}, 0) {
		t.Fatal("unblocked response must not continue")
	}
}

func TestFinalizeContinuationLimitNoticeIsUserFacing(t *testing.T) {
	notice := FinalizeContinuationLimitNotice("coverage_open")
	if strings.Contains(notice, "finalize_gate_blocked") ||
		strings.Contains(notice, "depth_force_blocked") ||
		strings.Contains(notice, "框架门闩") {
		t.Fatalf("notice leaks internal gate marker: %q", notice)
	}
	if !strings.Contains(notice, "未闭环") {
		t.Fatalf("notice = %q, want honest limitation", notice)
	}
}
