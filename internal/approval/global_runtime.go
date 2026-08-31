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
	evaluator *Evaluator
}

func NewGlobalRuntime(config Config, rules []Rule) (*GlobalRuntime, error) {
	runtime := &GlobalRuntime{}
	if err := runtime.Update(config, rules); err != nil {
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
func (r *GlobalRuntime) Update(config Config, rules []Rule) error {
	config = NormalizeConfig(config)
	loader, err := NewRuleLoader(rules)
	if err != nil {
		return err
	}
	evaluator := NewEvaluator(
		NewToolApprovalTrigger(config.ToolApproval),
		NewDangerTrigger(config.DangerousAction.Enabled, loader),
	)
	r.mu.Lock()
	r.config = config
	r.rules = append([]Rule(nil), rules...)
	r.evaluator = evaluator
	r.mu.Unlock()
	return nil
}
