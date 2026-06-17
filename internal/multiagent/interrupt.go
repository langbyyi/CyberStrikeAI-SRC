package multiagent

import "errors"

// ErrInterruptContinue 作为 context.CancelCause 使用：用户选择「中断并继续」且当前无进行中的 MCP 工具时，
// 取消当前推理/流式输出，并在同一会话任务内携带用户补充说明自动续跑下一轮（类似 Hermes 式人机回合）。
var ErrInterruptContinue = errors.New("agent interrupt: continue with user-supplied context")

// ErrTransientRetryContinue 表示 Run 因 429/网络等临时错误结束，应由 handler 落库轨迹后
// loadHistoryFromAgentTrace 再开下一轮 Run（与 ErrInterruptContinue 同级的「分段续跑」语义）。
var ErrTransientRetryContinue = errors.New("agent transient: retry after persisting trace")

// ErrEmptyResponseContinue 表示 Eino ADK 会话正常结束但未捕获到助手正文，应由 handler 落库轨迹后
// loadHistoryFromAgentTrace 再开下一轮 Run（与 ErrInterruptContinue / ErrTransientRetryContinue 同级）。
var ErrEmptyResponseContinue = errors.New("agent empty response: continue after persisting trace")
