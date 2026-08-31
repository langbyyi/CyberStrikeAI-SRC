package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/c2"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

type c2ApprovalCoordinator interface {
	Authorize(context.Context, approval.Invocation) (approval.Grant, error)
	Claim(context.Context, approval.Grant, string) error
	Complete(context.Context, approval.Grant, approval.ExecutionResult) error
}

// C2HITLBridge adapts C2 tasks to the unified approval coordinator.
type C2HITLBridge struct {
	coordinator c2ApprovalCoordinator
	logger      *zap.Logger
	getConvID   func() string
	// grants 保存"已审批通过、待执行"的凭证：任务到达终态时由 CompleteTask
	// 回写真实执行结果，取代旧的"审批通过即 Complete"失真语义。
	grants sync.Map // taskID -> approval.Grant
}

func NewC2ApprovalBridge(coordinator c2ApprovalCoordinator, logger *zap.Logger) *C2HITLBridge {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &C2HITLBridge{
		coordinator: coordinator, logger: logger, getConvID: func() string { return "" },
	}
}

// c2GrantMatchesRequest 校验 MCP 层授予的 grant 确实对应本任务：
// 工具名、过期时间，以及 grant 参数中携带的 session_id / task_type 与当前
// 请求一致。关键字段缺失或不同一律视为不匹配（fail-closed）——无法证明
// 凭证对应该任务时不得复用，防止同 ctx 内其他 C2 任务免费搭车。
func c2GrantMatchesRequest(grant approval.Grant, req c2.HITLApprovalRequest) bool {
	if grant.IsEmpty() || grant.ToolName() != c2.MCPToolC2Task || grant.Expired(time.Now().UTC()) {
		return false
	}
	grantSession := stringArg(grant.Arguments(), "session_id")
	if grantSession == "" || grantSession != strings.TrimSpace(req.SessionID) {
		return false
	}
	grantTaskType := stringArg(grant.Arguments(), "task_type")
	if grantTaskType == "" || grantTaskType != strings.TrimSpace(req.TaskType) {
		return false
	}
	return true
}

func stringArg(arguments map[string]any, key string) string {
	if arguments == nil {
		return ""
	}
	value, ok := arguments[key]
	if !ok || value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

// SetConversationIDGetter 设置获取当前对话 ID 的函数
func (b *C2HITLBridge) SetConversationIDGetter(fn func() string) {
	b.getConvID = fn
}

// RequestApproval delegates policy evaluation and review to the same
// coordinator used by MCP and agent tools. A grant already attached by the MCP
// guard is reused, preventing a second prompt for the same tool invocation.
func (b *C2HITLBridge) RequestApproval(ctx context.Context, req c2.HITLApprovalRequest) error {
	if grant, ok := approval.GrantFromContext(ctx); ok && c2GrantMatchesRequest(grant, req) {
		if !approval.TransferExecutionOwnership(ctx) {
			return errors.New("C2 approval execution ownership is unavailable")
		}
		b.grants.Store(req.TaskID, grant)
		return nil
	}
	if b == nil || b.coordinator == nil {
		return fmt.Errorf("C2 approval coordinator is unavailable")
	}
	convID := req.ConversationID
	if convID == "" {
		convID = b.getConvID()
	}
	requesterID := "system:c2"
	if principal, ok := authctx.PrincipalFromContext(ctx); ok {
		requesterID = principal.UserID
	}
	var payload any
	if strings.TrimSpace(req.PayloadJSON) != "" {
		if err := json.Unmarshal([]byte(req.PayloadJSON), &payload); err != nil {
			return fmt.Errorf("decode C2 approval payload: %w", err)
		}
	}
	arguments := map[string]any{
		"task_id": req.TaskID, "session_id": req.SessionID, "task_type": req.TaskType,
		"payload": payload, "source": req.Source, "reason": req.Reason,
	}
	grant, err := b.coordinator.Authorize(ctx, approval.Invocation{
		ID: req.TaskID, Source: "c2_task", ConversationID: strings.TrimSpace(convID),
		RequesterUserID: requesterID, ToolName: c2.MCPToolC2Task, ToolCallID: req.TaskID,
		Arguments: arguments,
	})
	if err != nil {
		return err
	}
	if grant.IsEmpty() {
		return nil
	}
	if err := b.coordinator.Claim(ctx, grant, req.TaskID); err != nil {
		return err
	}
	// 审批通过≠执行完成：保留凭证，任务终态时由 CompleteTask 回写真实结果。
	b.grants.Store(req.TaskID, grant)
	return nil
}

// CompleteTask 在 C2 任务到达终态时回写真实执行结果到审批单与台账。
// 无审批记录的任务（allow 直通）没有凭证，无需回写；进程重启后遗留的
// 凭证由审批单的 CancelUnrecoverable 统一清理。
func (b *C2HITLBridge) CompleteTask(taskID string, success bool, summary string) {
	if b == nil {
		return
	}
	value, ok := b.grants.LoadAndDelete(taskID)
	if !ok {
		return
	}
	grant := value.(approval.Grant)
	if err := b.coordinator.Complete(context.Background(), grant, approval.ExecutionResult{
		ExecutionID: taskID, Success: success, Summary: summary, CompletedAt: time.Now().UTC(),
	}); err != nil {
		b.logger.Warn("C2 任务执行结果回写审批单失败",
			zap.String("task_id", taskID), zap.Error(err))
	}
}

// C2HooksConfig 配置 C2 Manager 的 Hooks
type C2HooksConfig struct {
	DB                *database.DB
	Logger            *zap.Logger
	AttackChainRecord func(session *database.C2Session, phase string, description string)
	VulnRecord        func(session *database.C2Session, title string, severity string)
	// OnTaskFinal 在任务到达终态（success/failed/cancelled）时回调，
	// 用于审批单执行结果回写。
	OnTaskFinal func(task *database.C2Task, sessionID string)
}

// taskStatusSummary 生成台账/审批单用的执行结果摘要。
func taskStatusSummary(task *database.C2Task) string {
	return fmt.Sprintf("C2 task %s (%s) finished with status %s", task.ID, task.TaskType, task.Status)
}

// SetupC2Hooks 设置 C2 Manager 的业务钩子
func SetupC2Hooks(cfg *C2HooksConfig) c2.Hooks {
	return c2.Hooks{
		OnSessionFirstSeen: func(session *database.C2Session) {
			// 新会话上线
			cfg.Logger.Info("C2 Session first seen",
				zap.String("session_id", session.ID),
				zap.String("hostname", session.Hostname),
				zap.String("os", session.OS),
				zap.String("arch", session.Arch),
			)

			// 记录漏洞（初始访问点）
			if cfg.VulnRecord != nil {
				cfg.VulnRecord(session, fmt.Sprintf("C2 Session Established: %s@%s", session.Username, session.Hostname), "high")
			}

			// 记录攻击链（Initial Access）
			if cfg.AttackChainRecord != nil {
				cfg.AttackChainRecord(session, "initial-access", fmt.Sprintf("Implant beacon from %s/%s", session.Hostname, session.InternalIP))
			}
		},
		OnTaskCompleted: func(task *database.C2Task, sessionID string) {
			// 任务完成
			cfg.Logger.Debug("C2 Task completed",
				zap.String("task_id", task.ID),
				zap.String("task_type", task.TaskType),
				zap.String("status", task.Status),
			)

			// 终态回调：审批单/台账回写真实执行结果。
			if cfg.OnTaskFinal != nil {
				cfg.OnTaskFinal(task, sessionID)
			}

			// 根据任务类型记录攻击链
			if cfg.AttackChainRecord != nil {
				session, _ := cfg.DB.GetC2Session(sessionID)
				if session != nil {
					phase := taskToAttackPhase(task.TaskType)
					if phase != "" {
						cfg.AttackChainRecord(session, phase, fmt.Sprintf("Task %s: %s", task.TaskType, task.Status))
					}
				}
			}
		},
	}
}

// taskToAttackPhase 将任务类型映射到 ATT&CK 阶段
func taskToAttackPhase(taskType string) string {
	switch taskType {
	case "exec", "shell":
		return "execution"
	case "upload":
		return "persistence"
	case "download":
		return "exfiltration"
	case "screenshot":
		return "collection"
	case "kill_proc":
		return "impact"
	case "port_fwd", "socks_start":
		return "lateral-movement"
	case "load_assembly":
		return "defense-evasion"
	case "persist":
		return "persistence"
	case "self_delete":
		return "defense-evasion"
	default:
		return "execution"
	}
}

// SetupC2HITLBridgeWithAgent 设置 HITL 桥接器
// 这个函数将由 App 调用，注入必要的依赖
func SetupC2HITLBridgeWithAgent(coordinator *approval.Coordinator, logger *zap.Logger) c2.HITLBridge {
	return NewC2ApprovalBridge(coordinator, logger)
}
