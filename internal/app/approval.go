package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/handler"
	"cyberstrike-ai/internal/mcp"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

func buildApprovalCoordinator(cfg *config.Config, db *database.DB, agentHandler *handler.AgentHandler, humanReviewer *approval.HumanReviewBroker, logger *zap.Logger) (*approval.Coordinator, *approval.GlobalRuntime, error) {
	store := approval.NewSQLiteStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		return nil, nil, err
	}
	if migrated, err := approval.MigrateLegacyHITL(context.Background(), db); err != nil {
		return nil, nil, err
	} else if migrated.Requests > 0 {
		logger.Info("migrated legacy approval history", zap.Int64("requests", migrated.Requests))
	}
	if cancelled, err := store.CancelUnrecoverable(context.Background(), time.Now().UTC()); err != nil {
		logger.Warn("取消重启后不可恢复的审批失败", zap.Error(err))
	} else if cancelled > 0 {
		logger.Info("已取消重启后不可恢复的审批", zap.Int64("count", cancelled))
	}
	defaults, err := approval.LoadBundledDangerRules()
	if err != nil {
		return nil, nil, err
	}
	if seeded, err := store.SeedDefaultRules(context.Background(), defaults); err != nil {
		return nil, nil, err
	} else if seeded > 0 {
		logger.Info("seeded default danger rules", zap.Int("count", seeded))
	}
	storedRules, err := store.ListApprovalRules(context.Background())
	if err != nil {
		return nil, nil, err
	}
	globalRuntime, err := approval.NewGlobalRuntime(globalApprovalConfigFromAppConfig(cfg), storedRules)
	if err != nil {
		return nil, nil, err
	}
	coordinator := approval.NewCoordinator(approval.CoordinatorOptions{
		Evaluator: globalRuntime,
		Config:    globalApprovalConfigFromAppConfig(cfg), Store: store,
		AgentReviewer: handler.NewApprovalAgentReviewer(agentHandler),
		HumanReviewer: humanReviewer,
		Timeout:       time.Duration(cfg.Approval.TimeoutSecondsEffective()) * time.Second,
		Ledger:        store,
	})
	return coordinator, globalRuntime, nil
}

func globalApprovalConfigFromAppConfig(cfg *config.Config) approval.Config {
	if cfg == nil {
		return approval.NormalizeConfig(approval.Config{})
	}
	toolEnabled := cfg.Approval.ToolApproval.EnabledEffective(false)
	dangerEnabled := cfg.Approval.DangerousAction.EnabledEffective(true)
	whitelist := cfg.Approval.ToolApproval.ToolWhitelist
	reviewer := strings.TrimSpace(cfg.Approval.Reviewer)
	if reviewer == "" {
		reviewer = approval.ReviewerHuman
	}
	return approval.NormalizeConfig(approval.Config{
		Reviewer: reviewer, TimeoutSeconds: cfg.Approval.TimeoutSecondsEffective(),
		ToolApproval:    approval.TriggerConfig{Enabled: toolEnabled, ToolWhitelist: whitelist},
		DangerousAction: approval.TriggerConfig{Enabled: dangerEnabled},
	})
}
func approvalInvocationGuard(coordinator *approval.Coordinator, source string) mcp.InvocationGuard {
	if coordinator == nil {
		return nil
	}
	return func(ctx context.Context, toolName string, args map[string]interface{}) (context.Context, map[string]interface{}, error) {
		if grant, ok := approval.GrantFromContext(ctx); ok && grant.AuthorizesToolCall(toolName, args, time.Now().UTC()) {
			return ctx, grant.Arguments(), nil
		}
		requesterID := "system"
		if principal, ok := authctx.PrincipalFromContext(ctx); ok {
			requesterID = principal.UserID
		}
		invocation := approval.Invocation{
			ID: uuid.NewString(), Source: source, ConversationID: mcp.MCPConversationIDFromContext(ctx),
			ProjectID: mcp.MCPProjectIDFromContext(ctx), RequesterUserID: requesterID,
			ToolName: toolName, ToolCallID: mcp.MCPExecutionIDFromContext(ctx), Arguments: args,
		}
		grant, err := coordinator.Authorize(ctx, invocation)
		if err != nil {
			if errors.Is(err, approval.ErrApprovalRejected) {
				return nil, nil, err
			}
			return nil, nil, err
		}
		if grant.IsEmpty() {
			return ctx, grant.Arguments(), nil
		}
		executionID := mcp.MCPExecutionIDFromContext(ctx)
		if executionID == "" {
			executionID = uuid.NewString()
		}
		if err := coordinator.Claim(ctx, grant, executionID); err != nil {
			return nil, nil, err
		}
		approvedCtx := approval.WithExecutionOwnership(approval.WithGrant(ctx, grant))
		approvedCtx = mcp.WithInvocationCompletion(approvedCtx, func(completionCtx context.Context, _ string, _ map[string]interface{}, result *mcp.ToolResult, runErr error) {
			if approval.ExecutionOwnershipTransferred(completionCtx) {
				return
			}
			success := runErr == nil && result != nil && !result.IsError
			summary := ""
			if runErr != nil {
				summary = runErr.Error()
			} else if result != nil {
				summary = mcp.ToolResultPlainText(result)
			}
			_ = coordinator.Complete(completionCtx, grant, approval.ExecutionResult{
				ExecutionID: executionID, Success: success, Summary: summary, CompletedAt: time.Now().UTC(),
			})
		})
		return approvedCtx, grant.Arguments(), nil
	}
}
