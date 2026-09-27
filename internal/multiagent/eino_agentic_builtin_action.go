package multiagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// 本文件让 Eino 内置动作（transfer_to_agent）在 AgenticMessage 主路径上真正可用。
//
// Eino v0.9.14 的官方 transferToAgent 通过 adk.SendToolGenAction 写
// typedState[*schema.Message]，而 Agentic 主路径的 state 是
// typedState[*schema.AgenticMessage]，因此委派必然失败。这里在工具中间件层
// 接管 transfer_to_agent，改用反射写当前实时 state（sendADKToolGenAction）。
//
// exit 不在此处接管：本分支的完成协议用自有 einoAgenticExitTool 走
// ReturnDirectly（见 eino_completion_contract.go），与官方实现语义等价。

func isAgenticTransferTool(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), adk.TransferToAgentToolName)
}

// agenticTransferToolMiddleware 拦截 transfer_to_agent 并写入当前 react state 的
// ToolGenActions，返回官方同款成功文案。挂在工具中间件链最内侧（审批/RBAC 之后），
// 因此被 HITL 拒绝的 transfer 不会走到这里。
func agenticTransferToolMiddleware() compose.ToolMiddleware {
	return compose.ToolMiddleware{
		Invokable: func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
				if input != nil && isAgenticTransferTool(input.Name) {
					result, err := invokeAgenticTransferTool(ctx, input.Arguments)
					if err != nil {
						return nil, err
					}
					return &compose.ToolOutput{Result: result}, nil
				}
				return next(ctx, input)
			}
		},
	}
}

// withEinoAgenticTransferTool 在工具配置里追加 transfer_to_agent 接管中间件。
// 只对注册了 transfer 工具的代理（supervisor 主代理）有意义。
func withEinoAgenticTransferTool(cfg adk.ToolsConfig) adk.ToolsConfig {
	middlewares := append([]compose.ToolMiddleware(nil), cfg.ToolsNodeConfig.ToolCallMiddlewares...)
	middlewares = append(middlewares, agenticTransferToolMiddleware())
	cfg.ToolsNodeConfig.ToolCallMiddlewares = middlewares
	return cfg
}

func invokeAgenticTransferTool(ctx context.Context, argumentsInJSON string) (string, error) {
	var params struct {
		AgentName string `json:"agent_name"`
	}
	argumentsInJSON = strings.TrimSpace(argumentsInJSON)
	if argumentsInJSON == "" {
		argumentsInJSON = "{}"
	}
	if err := json.Unmarshal([]byte(argumentsInJSON), &params); err != nil {
		return "", err
	}
	if strings.TrimSpace(params.AgentName) == "" {
		return "", fmt.Errorf("transfer_to_agent requires agent_name")
	}
	if err := sendADKToolGenAction(ctx, adk.TransferToAgentToolName, adk.NewTransferToAgentAction(params.AgentName)); err != nil {
		return "", err
	}
	return fmt.Sprintf("successfully transferred to agent [%s]", params.AgentName), nil
}

// einoTypedSubAgentRegistrar 是 TypedChatModelAgent 的 typed 子代理注册接口。
// Eino 只导出 classic 版 adk.OnSubAgents（[]adk.Agent），故此处用局部接口断言。
type einoTypedSubAgentRegistrar interface {
	OnSetSubAgents(context.Context, []adk.TypedAgent[*schema.AgenticMessage]) error
}

// bindAgenticSupervisorSubAgents 把 typed 子代理注册进 typed 监督者。
//
// supervisor.New → adk.SetSubAgents 走 classic Agent 接口 + 类型断言，
// 而本分支监督者是经 classic 适配层包装的 TypedChatModelAgent[*schema.AgenticMessage]，
// 命不中 adk.OnSubAgents，子代理从未注册进 ChatModelAgent——transfer_to_agent
// 既不进 tools 索引、也没有交接指令，supervisor 委派整体失效（调 transfer 报
// "tool transfer_to_agent not found in toolsNode indexes"）。这里按 typed 接口补注册。
//
// 只注册子代理列表，不调用子代理的 OnSetAsSubAgent：子代理回合结束后的返回路径由
// supervisor.New 的 AgentWithDeterministicTransferTo 包装负责，额外给子代理挂
// parent transfer 工具会改变其工具集与提示，属于不必要的放大。
//
// 若将来 Eino 让 classic OnSubAgents 在 typed 主路径上也生效，supervisor.New 会二次注册
// 并报 "agent's sub-agents has already been set"（不会静默）：此时删掉本 helper 即可。
func bindAgenticSupervisorSubAgents(
	ctx context.Context,
	logger *zap.Logger,
	supervisorAgent adk.TypedAgent[*schema.AgenticMessage],
	subAgents []adk.TypedAgent[*schema.AgenticMessage],
) error {
	if supervisorAgent == nil || len(subAgents) == 0 {
		return nil
	}
	registrar, ok := supervisorAgent.(einoTypedSubAgentRegistrar)
	if !ok {
		// 只可能出现在 Eino 改动该方法签名的场景：降级为既有行为（不委派），
		// 不因此中断整轮对话。
		if logger != nil {
			logger.Warn("supervisor agentic typed 子代理注册接口不可用，本次不注册子代理",
				zap.String("agent", supervisorAgent.Name(ctx)),
				zap.String("agent_type", fmt.Sprintf("%T", supervisorAgent)),
			)
		}
		return nil
	}
	if err := registrar.OnSetSubAgents(ctx, subAgents); err != nil {
		return fmt.Errorf("supervisor agentic 子代理注册: %w", err)
	}
	return nil
}
