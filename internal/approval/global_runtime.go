package approval

import (
	"context"
	"sync"
)

// GlobalRuntime owns the single approval-policy snapshot for one deployment.
// Project and conversation values never select or modify this snapshot.
type GlobalRuntime struct {
	mu        sync.RWMutex
	config    Config
	rules     []Rule
	extra     []Trigger
	evaluator *Evaluator
}

func NewGlobalRuntime(config Config, rules []Rule, extraTriggers ...Trigger) (*GlobalRuntime, error) {
	runtime := &GlobalRuntime{}
	if err := runtime.Update(config, rules, extraTriggers...); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (r *GlobalRuntime) Evaluate(ctx context.Context, invocation Invocation) (Assessment, error) {
	r.mu.RLock()
	evaluator := r.evaluator
	r.mu.RUnlock()
	return evaluator.Evaluate(ctx, invocation)
}

func (r *GlobalRuntime) Config() Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	config := r.config
	config.ToolApproval.ToolWhitelist = append([]string(nil), config.ToolApproval.ToolWhitelist...)
	return config
}

func (r *GlobalRuntime) Rules() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Rule(nil), r.rules...)
}

// Update validates and compiles a complete snapshot before publishing it.
// extraTriggers 附加在内置触发器之后（如敏感 HTTP 强制审批触发器），由
// runtime 持有并在后续热更新（规则发布、策略变更）中自动保留，调用方
// 用两参 Update 不会把附加触发器静默丢掉。
func (r *GlobalRuntime) Update(config Config, rules []Rule, extraTriggers ...Trigger) error {
	config = NormalizeConfig(config)
	loader, err := NewRuleLoader(rules)
	if err != nil {
		return err
	}
	r.mu.RLock()
	extra := r.extra
	if len(extraTriggers) > 0 {
		extra = extraTriggers
	}
	r.mu.RUnlock()
	triggers := append([]Trigger{
		NewToolApprovalTrigger(config.ToolApproval),
		NewDangerTrigger(config.DangerousAction.Enabled, loader),
	}, extra...)
	evaluator := NewEvaluator(triggers...)
	r.mu.Lock()
	r.config = config
	r.rules = append([]Rule(nil), rules...)
	r.extra = extra
	r.evaluator = evaluator
	r.mu.Unlock()
	return nil
}
