package approval

import (
	"context"
	"fmt"
	"strings"
)

// TriggerFinding explains why one trigger requires the shared approval flow.
type TriggerFinding struct {
	Source    string         `json:"source"`
	RuleID    string         `json:"ruleId,omitempty"`
	PolicyID  string         `json:"policyId,omitempty"`
	RiskLevel string         `json:"riskLevel,omitempty"`
	Message   string         `json:"message,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type TriggerResult struct {
	Matched   bool
	RiskLevel string
	Findings  []TriggerFinding
	PolicyIDs []string
}

type Trigger interface {
	Name() string
	Evaluate(context.Context, Invocation) (TriggerResult, error)
}

type Evaluator struct{ triggers []Trigger }

func NewEvaluator(triggers ...Trigger) *Evaluator {
	return &Evaluator{triggers: append([]Trigger(nil), triggers...)}
}

func (e *Evaluator) Evaluate(ctx context.Context, invocation Invocation) (Assessment, error) {
	assessment := Assessment{RiskLevel: RiskNone}
	for _, trigger := range e.triggers {
		if trigger == nil {
			continue
		}
		result, err := trigger.Evaluate(ctx, invocation)
		if err != nil {
			return Assessment{}, fmt.Errorf("evaluate %s trigger: %w", trigger.Name(), err)
		}
		if !result.Matched {
			continue
		}
		assessment.RequiresApproval = true
		assessment.TriggerSources = append(assessment.TriggerSources, trigger.Name())
		if riskRank(result.RiskLevel) > riskRank(assessment.RiskLevel) {
			assessment.RiskLevel = result.RiskLevel
		}
		for _, finding := range result.Findings {
			if finding.Source == "" {
				finding.Source = trigger.Name()
			}
			assessment.TriggerFindings = append(assessment.TriggerFindings, finding)
		}
		assessment.PolicyIDs = append(assessment.PolicyIDs, result.PolicyIDs...)
	}
	assessment.TriggerSources = sortedUnique(assessment.TriggerSources)
	assessment.PolicyIDs = sortedUnique(assessment.PolicyIDs)
	return assessment, nil
}

type ToolApprovalTrigger struct {
	enabled   bool
	whitelist map[string]struct{}
}

func NewToolApprovalTrigger(config TriggerConfig) *ToolApprovalTrigger {
	config = NormalizeConfig(Config{ToolApproval: config}).ToolApproval
	return &ToolApprovalTrigger{enabled: config.Enabled, whitelist: normalizedSet(config.ToolWhitelist)}
}

func (t *ToolApprovalTrigger) Name() string { return PolicyTypeToolApproval }

func (t *ToolApprovalTrigger) Evaluate(_ context.Context, invocation Invocation) (TriggerResult, error) {
	if t == nil || !t.enabled {
		return TriggerResult{}, nil
	}
	if _, ok := t.whitelist[strings.ToLower(strings.TrimSpace(invocation.ToolName))]; ok {
		return TriggerResult{}, nil
	}
	return TriggerResult{
		Matched: true, RiskLevel: RiskMedium,
		Findings:  []TriggerFinding{{Source: PolicyTypeToolApproval, RuleID: "not_allowlisted", RiskLevel: RiskMedium, Message: "tool is not in the global approval whitelist"}},
		PolicyIDs: []string{"tool_approval"},
	}, nil
}

// DangerTrigger adapts the existing global danger-rule matcher to the shared
// trigger contract. Rule risk is display metadata and never selects a reviewer.
type DangerTrigger struct {
	enabled bool
	policy  *DangerousActionPolicy
}

func NewDangerTrigger(enabled bool, loader *RuleLoader) *DangerTrigger {
	return &DangerTrigger{enabled: enabled, policy: NewDangerousActionPolicy(enabled, loader)}
}

func (t *DangerTrigger) Name() string { return PolicyTypeDangerousAction }

func (t *DangerTrigger) Evaluate(ctx context.Context, invocation Invocation) (TriggerResult, error) {
	if t == nil || !t.enabled {
		return TriggerResult{}, nil
	}
	assessment, err := t.policy.Evaluate(ctx, invocation)
	if err != nil {
		return TriggerResult{}, err
	}
	return assessment, nil
}
