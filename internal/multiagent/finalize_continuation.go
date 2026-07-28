package multiagent

import (
	"fmt"
	"strings"
)

const MaxFinalizeContinuationsPerRun = 2

type FinalizeContinuationDecision struct {
	Blocked     bool
	Kind        string
	Reason      string
	Instruction string
}

func EvaluateFinalizeContinuation(state *ConversationExecutionState, response string) FinalizeContinuationDecision {
	response = strings.TrimSpace(response)
	if response == "" || state == nil {
		return FinalizeContinuationDecision{}
	}

	var kinds []string
	var reasons []string
	var instructions []string

	if blocked, reason := CoverageShouldBlockFinalize(state, response); blocked {
		_, _, open := state.ShouldContinue()
		var instruction strings.Builder
		instruction.WriteString(finalizeContinuationInstruction(FinalizeGateInstruction))
		instruction.WriteString(fmt.Sprintf("reason=%s\n", reason))
		for _, item := range open {
			instruction.WriteString(fmt.Sprintf("- path=%s priority=%s status=%s note=%s\n",
				item.Path, item.Priority, item.Status, truncateRunes(item.Note, 80)))
		}
		kinds = append(kinds, "coverage")
		reasons = append(reasons, reason)
		instructions = append(instructions, instruction.String())
	}

	if blocked, reason := SurfaceRecordShouldBlockFinalize(state, response); blocked {
		kinds = append(kinds, "surface_record")
		reasons = append(reasons, reason)
		instructions = append(instructions, finalizeContinuationInstruction(SurfaceRecordGateInstruction)+fmt.Sprintf("reason=%s\n", reason))
	}

	if len(instructions) == 0 {
		if blocked, reason := DepthShouldBlockFinalize(state, response); blocked {
			kinds = append(kinds, "depth_force")
			reasons = append(reasons, reason)
			instructions = append(instructions, finalizeContinuationInstruction(DepthForceInstruction)+fmt.Sprintf(
				"reason=%s total_tools=%d verification_tools=%d\n",
				reason, state.TotalToolCount(), state.VerificationToolCount()))
		}
	}

	if len(instructions) == 0 {
		return FinalizeContinuationDecision{}
	}
	return FinalizeContinuationDecision{
		Blocked:     true,
		Kind:        strings.Join(kinds, "+"),
		Reason:      strings.Join(reasons, ";"),
		Instruction: strings.Join(instructions, "\n"),
	}
}

func finalizeContinuationInstruction(instruction string) string {
	replacer := strings.NewReplacer(
		"## [finalize_gate_blocked] 框架门闩（非用户消息）", "## 执行续测要求",
		"## [surface_record_blocked] 框架门闩（非用户消息）", "## 攻击面记录要求",
		"## [depth_force_blocked] 框架深度门闩（非用户消息）", "## 验证深度要求",
	)
	return replacer.Replace(instruction)
}

func ShouldStartFinalizeContinuation(decision FinalizeContinuationDecision, completedContinuations int) bool {
	return decision.Blocked &&
		strings.TrimSpace(decision.Instruction) != "" &&
		completedContinuations >= 0 &&
		completedContinuations < MaxFinalizeContinuationsPerRun
}

func FinalizeContinuationLimitNotice(reason string) string {
	_ = reason
	return "\n\n> 自动续测已达到本次执行上限，但仍有验证项未闭环。以上结论仅覆盖已经完成的验证，不能视为目标不存在其他风险。"
}
