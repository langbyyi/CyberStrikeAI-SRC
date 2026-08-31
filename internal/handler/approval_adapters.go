package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/multiagent"

	"github.com/google/uuid"
)

type approvalAgentReviewer struct{ handler *AgentHandler }

func NewApprovalAgentReviewer(handler *AgentHandler) approval.Reviewer {
	return &approvalAgentReviewer{handler: handler}
}

func (r *approvalAgentReviewer) Review(ctx context.Context, request approval.ReviewRequest) (approval.ReviewDecision, error) {
	if r == nil || r.handler == nil {
		return approval.ReviewDecision{}, errors.New("approval agent reviewer is unavailable")
	}
	payload := approvalReviewPayload(request)
	// 注入用户声明与中断后继续说明：
	// 审计 Agent 必须看到"用户让它做什么"才能区分攻击测试与真实破坏，
	// 否则只剩光秃秃的命令参数，任何删除类操作都会被保守拒绝。
	if r.handler != nil {
		r.handler.enrichHitlApprovalPayload(request.Invocation.ConversationID, request.Invocation.AssistantMessageID, payload)
	}
	decision := r.handler.auditAgentReview(ctx, request.Invocation.ToolName, payload)
	return approval.ReviewDecision{
		Decision: decision.Decision, Comment: decision.Comment,
		ActorType: "agent", ActorID: "audit-model",
	}, nil
}

func approvalReviewPayload(request approval.ReviewRequest) map[string]interface{} {
	payload := map[string]interface{}{
		"source": request.Invocation.Source, "approvalId": "", "toolName": request.Invocation.ToolName,
		"argumentsObj": request.Invocation.Arguments, "riskLevel": request.Assessment.RiskLevel,
		"findings": request.Assessment.TriggerFindings,
	}
	if request.Approval != nil {
		payload["approvalId"] = request.Approval.ID
	}
	return payload
}

func (h *AgentHandler) withApprovalToolInterceptor(ctx context.Context, conversationID, assistantMessageID string) context.Context {
	if h == nil || h.approvalCoordinator == nil {
		return ctx
	}
	return multiagent.WithApprovalToolInterceptor(ctx, func(callCtx context.Context, toolName, arguments string) (context.Context, string, error) {
		args := map[string]interface{}{}
		if arguments != "" {
			if err := json.Unmarshal([]byte(arguments), &args); err != nil {
				return nil, arguments, fmt.Errorf("decode approval tool arguments: %w", err)
			}
		}
		requesterID := "system"
		if principal, ok := authctx.PrincipalFromContext(callCtx); ok {
			requesterID = principal.UserID
		}
		invocation := approval.Invocation{
			ID: uuid.NewString(), Source: "eino_middleware", ConversationID: conversationID,
			AssistantMessageID: assistantMessageID, RequesterUserID: requesterID,
			ToolName: toolName, Arguments: args,
		}
		grant, err := h.approvalCoordinator.Authorize(callCtx, invocation)
		if err != nil {
			if errors.Is(err, approval.ErrApprovalRejected) {
				return nil, arguments, multiagent.NewHumanRejectError(err.Error())
			}
			return nil, arguments, err
		}
		frozen := approval.CanonicalArguments(grant.Arguments())
		if grant.IsEmpty() {
			return nil, frozen, nil
		}
		executionID := "eino_" + uuid.NewString()
		if err := h.approvalCoordinator.Claim(callCtx, grant, executionID); err != nil {
			return nil, arguments, err
		}
		approvedCtx := approval.WithGrant(callCtx, grant)
		approvedCtx = approval.WithExecutionFinalizer(approvedCtx, func(finalizeCtx context.Context, result approval.ExecutionResult) error {
			result.ExecutionID = executionID
			return h.approvalCoordinator.Complete(finalizeCtx, grant, result)
		})
		return approvedCtx, frozen, nil
	})
}
