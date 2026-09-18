package handler

import (
	"fmt"

	"cyberstrike-ai/internal/approval"
)

// Empty policy preserves the global defaults for queues created before this setting existed.
func validateBatchHITLPolicy(policy string) error {
	switch policy {
	case "", "off", "human", "audit_agent":
		return nil
	default:
		return fmt.Errorf("不支持的队列审批设置: %s", policy)
	}
}

// batchTaskPolicyOverride 将队列审批策略翻译为任务作用域审批覆盖：
// off=跳过审批；human / audit_agent=强制进入审批并指定审批人；
// 空=沿用全局审批配置（不覆盖）。统一审批架构不提供会话级改参，
// 上游 review_edit 选项不在本架构收录范围。
func batchTaskPolicyOverride(policy string) (approval.TaskPolicyOverride, bool) {
	switch policy {
	case "off":
		return approval.TaskPolicyOverride{Disabled: true}, true
	case "human":
		return approval.TaskPolicyOverride{RequireApproval: true, Reviewer: approval.ReviewerHuman}, true
	case "audit_agent":
		return approval.TaskPolicyOverride{RequireApproval: true, Reviewer: approval.ReviewerAgent}, true
	}
	return approval.TaskPolicyOverride{}, false
}
