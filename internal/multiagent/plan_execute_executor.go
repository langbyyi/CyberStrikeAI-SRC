package multiagent

import (
	"context"
	"fmt"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/prebuilt/planexecute"
)

// newPlanExecuteExecutor builds the Plan-Execute Executor as an Eino ChatModelAgent.
//
// Eino's planexecute.Config accepts any adk.Agent as Executor; this implementation
// keeps the official Executor contract (Plan/UserInput/ExecutedSteps session keys
// and ExecutedStepSessionKey output) while using ChatModelAgentConfig.Handlers so
// the executor can run the same ADK middleware stack as Deep/Supervisor. As of
// Eino v0.9.12/v0.10.0-alpha.10, planexecute.NewExecutor still does not expose a
// Handlers field, so this custom Executor is the best-practice extension point
// that preserves middleware without forking the whole planexecute loop.
func newPlanExecuteExecutor(ctx context.Context, cfg *planexecute.ExecutorConfig, handlers []adk.ChatModelAgentMiddleware) (adk.Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("plan_execute: ExecutorConfig 为空")
	}
	if cfg.Model == nil {
		return nil, fmt.Errorf("plan_execute: Executor Model 为空")
	}
	genInputFn := cfg.GenInputFn
	if genInputFn == nil {
		genInputFn = planExecuteDefaultGenExecutorInput
	}
	genInput := func(ctx context.Context, instruction string, _ *adk.AgentInput) ([]adk.Message, error) {
		plan, ok := adk.GetSessionValue(ctx, planexecute.PlanSessionKey)
		if !ok {
			return nil, fmt.Errorf("plan_execute executor: session value %q missing (possible session corruption)", planexecute.PlanSessionKey)
		}
		plan_, ok := plan.(planexecute.Plan)
		if !ok {
			return nil, fmt.Errorf("plan_execute executor: session value %q has invalid type %T", planexecute.PlanSessionKey, plan)
		}

		userInput, ok := adk.GetSessionValue(ctx, planexecute.UserInputSessionKey)
		if !ok {
			return nil, fmt.Errorf("plan_execute executor: session value %q missing (possible session corruption)", planexecute.UserInputSessionKey)
		}
		userInput_, ok := userInput.([]adk.Message)
		if !ok {
			return nil, fmt.Errorf("plan_execute executor: session value %q has invalid type %T", planexecute.UserInputSessionKey, userInput)
		}

		var executedSteps_ []planexecute.ExecutedStep
		executedStep, ok := adk.GetSessionValue(ctx, planexecute.ExecutedStepsSessionKey)
		if ok {
			executedSteps_, ok = executedStep.([]planexecute.ExecutedStep)
			if !ok {
				return nil, fmt.Errorf("plan_execute executor: session value %q has invalid type %T", planexecute.ExecutedStepsSessionKey, executedStep)
			}
		}

		in := &planexecute.ExecutionContext{
			UserInput:     userInput_,
			Plan:          plan_,
			ExecutedSteps: executedSteps_,
		}
		return genInputFn(ctx, in)
	}

	agentCfg := &adk.ChatModelAgentConfig{
		Name:          "executor",
		Description:   "an executor agent",
		Model:         cfg.Model,
		ToolsConfig:   cfg.ToolsConfig,
		GenModelInput: genInput,
		MaxIterations: cfg.MaxIterations,
		OutputKey:     planexecute.ExecutedStepSessionKey,
	}
	if len(handlers) > 0 {
		agentCfg.Handlers = handlers
	}
	return adk.NewChatModelAgent(ctx, agentCfg)
}

// planExecuteDefaultGenExecutorInput 对齐 Eino planexecute.defaultGenExecutorInputFn（包外不可引用默认实现）。
func planExecuteDefaultGenExecutorInput(ctx context.Context, in *planexecute.ExecutionContext) ([]adk.Message, error) {
	planContent, err := in.Plan.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return planexecute.ExecutorPrompt.Format(ctx, map[string]any{
		"input":          planExecuteFormatInput(in.UserInput),
		"plan":           string(planContent),
		"executed_steps": planExecuteFormatExecutedSteps(in.ExecutedSteps, nil, nil),
		"step":           in.Plan.FirstStep(),
	})
}
