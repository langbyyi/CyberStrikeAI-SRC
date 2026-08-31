package approval

import "time"

// Grant 是执行内核签发的执行凭证。opaque 设计：字段不导出，只能由
// Coordinator（内核）铸造；包外既不能伪造也不能篡改，消费方通过方法
// 只读取必要信息或在 ctx 中透传。凭证与 Invocation 的 canonical 参数
// hash 绑定，单次审批单生命周期内使用，带过期时间。
type Grant struct {
	approvalID     string
	invocationID   string
	invocationHash string
	toolName       string
	arguments      map[string]any
	canonicalArgs  string
	policyIDs      []string
	expiresAt      *time.Time
}

// GrantSpec 是内核铸造凭证的入参。
type GrantSpec struct {
	ApprovalID     string
	InvocationID   string
	InvocationHash string
	ToolName       string
	Arguments      map[string]any
	PolicyIDs      []string
	ExpiresAt      *time.Time
}

func newGrant(spec GrantSpec) Grant {
	arguments, err := cloneArguments(spec.Arguments)
	if err != nil {
		arguments = map[string]any{}
	}

	return Grant{
		approvalID:     spec.ApprovalID,
		invocationID:   spec.InvocationID,
		invocationHash: spec.InvocationHash,
		toolName:       spec.ToolName,
		arguments:      arguments,
		policyIDs:      append([]string(nil), spec.PolicyIDs...),
		canonicalArgs:  CanonicalArguments(arguments),
		expiresAt:      cloneTime(spec.ExpiresAt),
	}
}

// NewGrantForTesting 仅供 *_test.go 构造凭证（外部包的 ctx 复用 / 执行侧复核
// 测试）。生产代码必须经 Coordinator 铸造；架构守护测试会拒绝任何生产引用。
func NewGrantForTesting(spec GrantSpec) Grant { return newGrant(spec) }

// IsEmpty 报告是否为"无审批记录"的直通凭证（allow 决策不落审批单）。
func (g Grant) IsEmpty() bool { return g.approvalID == "" }

func (g Grant) ApprovalID() string     { return g.approvalID }
func (g Grant) InvocationID() string   { return g.invocationID }
func (g Grant) InvocationHash() string { return g.invocationHash }
func (g Grant) ToolName() string       { return g.toolName }

// Arguments 返回冻结参数。消费方只读，不得修改：内核在 Authorize 时已做
// JSON 深拷贝隔离，凭证内是授权时点参数的权威副本。
func (g Grant) Arguments() map[string]any {
	cloned, err := cloneArguments(g.arguments)
	if err != nil {
		return map[string]any{}
	}
	return cloned
}

func (g Grant) PolicyIDs() []string   { return append([]string(nil), g.policyIDs...) }
func (g Grant) ExpiresAt() *time.Time { return cloneTime(g.expiresAt) }

// Expired 报告凭证在给定时刻是否已过期。
func (g Grant) Expired(now time.Time) bool {
	return g.expiresAt != nil && !now.Before(*g.expiresAt)
}

// AuthorizesToolCall 复核凭证能否用于本次工具调用：非空、工具名一致、未过期、
// canonical 参数一致。这是执行侧防"凭证挪用到不同参数调用"的最后防线。
func (g Grant) AuthorizesToolCall(toolName string, args map[string]any, now time.Time) bool {
	if g.IsEmpty() || g.toolName != toolName || g.Expired(now) {
		return false
	}
	return g.canonicalArgs != "" && g.canonicalArgs == CanonicalArguments(args)
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// MatchesInvocation 复核凭证与 Invocation 的绑定关系（eino 拦截层复用 grant 时用）。
// policyIDs 传 nil 时按凭证自身记录的命中策略复核。
func (g Grant) MatchesInvocation(invocation Invocation, policyIDs []string, now time.Time) bool {
	if g.IsEmpty() || g.invocationID == "" || g.invocationID != invocation.ID {
		return false
	}
	if g.toolName != "" && g.toolName != invocation.ToolName {
		return false
	}
	if g.Expired(now) {
		return false
	}
	if policyIDs == nil {
		policyIDs = g.policyIDs
	}
	return g.invocationHash != "" && g.invocationHash == InvocationHash(invocation, policyIDs)
}
