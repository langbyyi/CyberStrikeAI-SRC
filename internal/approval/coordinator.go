package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrApprovalRejected    = errors.New("approval rejected")
	ErrApprovalExpired     = errors.New("approval expired")
	ErrReviewerUnavailable = errors.New("approval reviewer unavailable")
)

type CoordinatorOptions struct {
	Evaluator interface {
		Evaluate(context.Context, Invocation) (Assessment, error)
	}
	Config        Config
	Store         Store
	AgentReviewer Reviewer
	HumanReviewer Reviewer
	Timeout       time.Duration
	Now           func() time.Time
	// Ledger 是可选的决策台账（append-only 审计流）。
	Ledger Ledger
}

type Coordinator struct {
	evaluator interface {
		Evaluate(context.Context, Invocation) (Assessment, error)
	}
	config        Config
	store         Store
	agentReviewer Reviewer
	humanReviewer Reviewer
	timeout       time.Duration
	now           func() time.Time
	ledger        Ledger
}

func NewCoordinator(options CoordinatorOptions) *Coordinator {
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	return &Coordinator{
		evaluator: options.Evaluator, config: NormalizeConfig(options.Config),
		store: options.Store, agentReviewer: options.AgentReviewer,
		humanReviewer: options.HumanReviewer, timeout: timeout, now: now, ledger: options.Ledger,
	}
}

func (c *Coordinator) Authorize(ctx context.Context, invocation Invocation) (Grant, error) {
	if err := validateInvocation(invocation); err != nil {
		return Grant{}, err
	}
	var assessment Assessment
	var err error
	if c.evaluator == nil {
		return Grant{}, errors.New("approval evaluator is unavailable")
	}
	assessment, err = c.evaluator.Evaluate(ctx, invocation)
	if err != nil {
		return Grant{}, fmt.Errorf("evaluate approval policies: %w", err)
	}
	hash := InvocationHash(invocation, assessment.PolicyIDs)
	arguments, err := cloneArguments(invocation.Arguments)
	if err != nil {
		return Grant{}, err
	}
	grant := newGrant(GrantSpec{
		InvocationID: invocation.ID, InvocationHash: hash, ToolName: invocation.ToolName,
		Arguments: arguments, PolicyIDs: assessment.PolicyIDs,
	})
	if !assessment.RequiresApproval {
		c.appendDecisionEvent(ctx, invocation, assessment, hash, "", EnforcementAllow, "system", "coordinator", "")
		return grant, nil
	}
	if c.store == nil {
		return Grant{}, errors.New("approval store is unavailable")
	}

	now := c.now().UTC()
	expiresAt := now.Add(c.currentTimeout())
	reviewer := c.currentConfig().Reviewer
	status, stage := initialReviewState(reviewer)
	request := &Request{
		ID: "apr_" + uuid.NewString(), InvocationID: invocation.ID, InvocationHash: hash,
		Source: invocation.Source, ConversationID: invocation.ConversationID,
		MessageID: invocation.AssistantMessageID, ProjectID: invocation.ProjectID,
		RequesterUserID: invocation.RequesterUserID, ToolName: invocation.ToolName,
		ToolCallID: invocation.ToolCallID, Arguments: arguments, RiskLevel: assessment.RiskLevel,
		TriggerSources: assessmentTriggerSources(assessment), MatchedPolicies: assessment.PolicyIDs,
		Reviewer: reviewer, Stage: stage, Status: status,
		ExpiresAt: &expiresAt, CreatedAt: now, UpdatedAt: now,
	}
	if err := c.store.CreateRequest(ctx, request); err != nil {
		return Grant{}, err
	}
	finalDecision, err := c.review(ctx, invocation, assessment, request)
	if err != nil {
		if errors.Is(err, ErrApprovalRejected) {
			c.appendDecisionEvent(ctx, invocation, assessment, hash, request.ID, EnforcementDeny,
				finalDecision.ActorType, finalDecision.ActorID, finalDecision.Comment)
		} else if errors.Is(err, ErrApprovalExpired) {
			c.appendDecisionEvent(ctx, invocation, assessment, hash, request.ID, EnforcementDeny,
				"system", "coordinator", "approval expired")
		}
		return Grant{}, err
	}
	grant.approvalID = request.ID
	grant.expiresAt = &expiresAt
	c.appendDecisionEvent(ctx, invocation, assessment, hash, request.ID, EnforcementAllow,
		finalDecision.ActorType, finalDecision.ActorID, finalDecision.Comment)
	return grant, nil
}

func (c *Coordinator) Claim(ctx context.Context, grant Grant, executionID string) error {
	if grant.IsEmpty() {
		return nil
	}
	if grant.Expired(c.now().UTC()) {
		return ErrApprovalExpired
	}
	if strings.TrimSpace(executionID) == "" {
		return errors.New("execution id is required")
	}
	// 防御深度：领取前复核存储侧哈希，防止 grant 错配到另一张审批单后仍被消费。
	stored, err := c.store.GetRequest(ctx, grant.ApprovalID())
	if err != nil {
		return err
	}
	if stored.InvocationHash != grant.InvocationHash() || stored.Status != StatusApproved {
		return fmt.Errorf("%w: grant does not match approval %s", ErrStateConflict, grant.ApprovalID())
	}
	if err := c.store.Claim(ctx, grant.ApprovalID(), executionID); err != nil {
		return err
	}
	return nil
}

func (c *Coordinator) Complete(ctx context.Context, grant Grant, result ExecutionResult) error {
	if grant.IsEmpty() {
		return nil
	}
	if err := c.store.Complete(ctx, grant.ApprovalID(), result); err != nil {
		return err
	}
	if c.ledger != nil {
		_ = c.ledger.Append(ctx, LedgerEvent{
			ID: "apl_" + uuid.NewString(), EventType: LedgerEventExecution,
			InvocationID: grant.InvocationID(), ApprovalID: grant.ApprovalID(),
			ToolName: grant.ToolName(), ArgsHash: grant.InvocationHash(),
			Success: &result.Success, Summary: result.Summary, CreatedAt: c.now().UTC(),
		})
	}
	return nil
}

func (c *Coordinator) review(ctx context.Context, invocation Invocation, assessment Assessment, request *Request) (ReviewDecision, error) {
	reviewRequest := ReviewRequest{Approval: request, Invocation: invocation, Assessment: assessment}
	reviewer := c.humanReviewer
	if request.Reviewer == ReviewerAgent {
		reviewer = c.agentReviewer
	}
	decision, err := c.callReviewer(ctx, reviewer, reviewRequest)
	if err != nil {
		if errors.Is(err, ErrApprovalExpired) {
			expired := ReviewDecision{Decision: ReviewerReject, ActorType: "system", ActorID: "coordinator", Comment: err.Error()}
			if recordErr := c.record(ctx, request, expired, request.Status, StatusExpired, StageTerminal); recordErr != nil {
				return expired, recordErr
			}
			return expired, ErrApprovalExpired
		}
		sysDecision, rejectErr := c.rejectReviewerFailure(ctx, request, err)
		return sysDecision, rejectErr
	}
	if decision.Decision == ReviewerApprove {
		return decision, c.record(ctx, request, decision, request.Status, StatusApproved, StageApproved)
	}
	if err := c.record(ctx, request, decision, request.Status, StatusRejected, StageTerminal); err != nil {
		return decision, err
	}
	return decision, ErrApprovalRejected
}

func (c *Coordinator) currentConfig() Config {
	if provider, ok := c.evaluator.(interface{ Config() Config }); ok {
		return provider.Config()
	}
	return c.config
}

func (c *Coordinator) currentTimeout() time.Duration {
	if _, ok := c.evaluator.(interface{ Config() Config }); ok {
		return time.Duration(c.currentConfig().TimeoutSeconds) * time.Second
	}
	return c.timeout
}

func (c *Coordinator) callReviewer(ctx context.Context, reviewer Reviewer, request ReviewRequest) (ReviewDecision, error) {
	if reviewer == nil {
		return ReviewDecision{}, ErrReviewerUnavailable
	}
	decision, err := reviewer.Review(ctx, request)
	if err != nil {
		return ReviewDecision{}, err
	}
	if decision.ActorType == "" {
		return ReviewDecision{}, errors.New("reviewer actor type is required")
	}
	switch decision.Decision {
	case ReviewerApprove, ReviewerReject:
		return decision, nil
	default:
		return ReviewDecision{}, fmt.Errorf("invalid reviewer decision %q", decision.Decision)
	}
}

func (c *Coordinator) rejectReviewerFailure(ctx context.Context, request *Request, cause error) (ReviewDecision, error) {
	decision := ReviewDecision{Decision: ReviewerReject, ActorType: "system", ActorID: "coordinator", Comment: cause.Error()}
	if err := c.record(ctx, request, decision, request.Status, StatusRejected, StageTerminal); err != nil {
		return decision, err
	}
	return decision, fmt.Errorf("%w: %v", ErrApprovalRejected, cause)
}

// appendDecisionEvent 尽力而为地写台账：审批单状态机（store）是强一致权威，
// 台账是补充的统一审计视图；台账写入失败不阻断工具调用（避免 fail-crippled），
// 但实现方应保证自身可靠（SQLite WAL）。
func (c *Coordinator) appendDecisionEvent(ctx context.Context, invocation Invocation, assessment Assessment, hash, approvalID, enforcement, actorType, actorID, comment string) {
	if c.ledger == nil {
		return
	}
	event := LedgerEvent{
		ID: "apl_" + uuid.NewString(), EventType: LedgerEventDecision,
		InvocationID: invocation.ID, ApprovalID: approvalID,
		Source: invocation.Source, ConversationID: invocation.ConversationID,
		ProjectID: invocation.ProjectID, RequesterUserID: invocation.RequesterUserID,
		ToolName: invocation.ToolName, ToolCallID: invocation.ToolCallID,
		Enforcement: enforcement, Reviewer: c.currentConfig().Reviewer,
		RiskLevel: assessment.RiskLevel, ArgsHash: hash,
		ActorType: actorType, ActorID: actorID,
		MatchedRules: triggerFindingRuleIDs(assessment.TriggerFindings), Comment: comment,
		CreatedAt: c.now().UTC(),
	}
	_ = c.ledger.Append(ctx, event)
}

func triggerFindingRuleIDs(findings []TriggerFinding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.Source == "" {
			continue
		}
		id := finding.Source
		if finding.RuleID != "" {
			id += ":" + finding.RuleID
		}
		ids = append(ids, id)
	}
	return sortedUnique(ids)
}

func (c *Coordinator) record(ctx context.Context, request *Request, decision ReviewDecision, from, to, nextStage string) error {
	record := DecisionRecord{
		ID: "apd_" + uuid.NewString(), ApprovalID: request.ID, Stage: request.Stage,
		ActorType: decision.ActorType, ActorID: decision.ActorID, Decision: decision.Decision,
		Comment: decision.Comment, Metadata: decision.Metadata, CreatedAt: c.now().UTC(),
	}
	if err := c.store.RecordDecision(ctx, record, from, to, nextStage); err != nil {
		return err
	}
	request.Status, request.Stage = to, nextStage
	return nil
}

func initialReviewState(reviewer string) (string, string) {
	if reviewer == ReviewerHuman {
		return StatusPendingHuman, StageHumanReview
	}
	return StatusPendingAgent, StageAgentReview
}

func assessmentTriggerSources(assessment Assessment) []string {
	return sortedUnique(assessment.TriggerSources)
}

func validateInvocation(invocation Invocation) error {
	if strings.TrimSpace(invocation.ID) == "" || strings.TrimSpace(invocation.Source) == "" ||
		strings.TrimSpace(invocation.RequesterUserID) == "" || strings.TrimSpace(invocation.ToolName) == "" {
		return errors.New("approval invocation is incomplete")
	}
	if CanonicalArguments(invocation.Arguments) == "" {
		return errors.New("approval invocation arguments are not JSON-compatible")
	}
	return nil
}

func cloneArguments(arguments map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(arguments)
	if err != nil {
		return nil, errors.New("approval invocation arguments are not JSON-compatible")
	}
	cloned := make(map[string]any)
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil, err
	}
	return cloned, nil
}
