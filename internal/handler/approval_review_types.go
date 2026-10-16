package handler

// hitlDecision is the internal audit-model response. The unified approval
// coordinator accepts only approve/reject and never applies argument edits.
type hitlDecision struct {
	Decision string
	Comment  string
	// Failure 标记"审批引擎不可用"，而非策略裁决。调用方据此区分
	// "审计 Agent 判定拒绝"与"引擎故障导致本次未执行"，后者不该让
	// 整类操作在会话内被封禁。
	Failure bool
}
