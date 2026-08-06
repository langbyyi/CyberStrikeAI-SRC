# Eino 多代理改造说明（DeepAgent）

本文档记录 **Eino 单代理（ADK）** 与 **多 Agent（CloudWeGo Eino `adk/prebuilt`）** 的改造范围、进度与后续事项。原生 ReAct 执行路径已移除。

## 总体结论

- **改造已可用于生产试验**：流式对话、MCP 工具桥接、配置开关、前端模式切换均已落地。
- **入口策略**：**单代理** 走 `/api/eino-agent/stream`；多代理走 `/api/multi-agent/stream`，请求体 **`orchestration`** 指定编排。模式定位按 Eino ADK 最佳实践区分：**Deep** 适合复杂安全测试与 task 子代理协作；**Plan-Execute** 适合目标明确的规划 → 执行 → 重规划闭环；**Supervisor** 适合多个专业子代理动态分派的专家路由场景。机器人默认 `robot_default_agent_mode: eino_single`；批量队列默认 `eino_single`，多代理模式需 `multi_agent.enabled`。

## 已完成项

| 项 | 说明 |
|----|------|
| 依赖与代理 | `go.mod` 直接依赖 `github.com/cloudwego/eino`、`eino-ext/.../openai`；`go.mod` 注释与 `scripts/bootstrap-go.sh` 指导 **GOPROXY**（如 `https://goproxy.cn,direct`）。 |
| 配置 | `config.yaml` → `agent.max_iterations` 为全局 ReAct 上限（主/子代理统一）；`multi_agent`：`enabled`、`robot_use_multi_agent`、`sub_agents`（含可选 `bind_role`）、`eino_skills`、`eino_middleware` 等；结构体见 `internal/config/config.go`。 |
| Markdown 子代理 / 主代理 | 在 `agents_dir` 下放 `*.md`。**子代理**：供 Deep `task` 与 `supervisor` `transfer`。**主代理（按模式分离）**：`orchestrator.md`（或 `kind: orchestrator` 的**单个**其他 .md）→ **Deep**；固定名 `orchestrator-plan-execute.md` → **plan_execute**；固定名 `orchestrator-supervisor.md` → **supervisor**。正文优先于 YAML：`multi_agent.orchestrator_instruction`、`orchestrator_instruction_plan_execute`、`orchestrator_instruction_supervisor`；plan_execute / supervisor **不会**回退到 Deep 的 `orchestrator_instruction`。皆空时 plan_execute / supervisor 使用代码内置默认提示。管理：**Agents → Agent管理**；API：`/api/multi-agent/markdown-agents*`。 |
| MCP 桥 | `internal/einomcp`：`ToolsFromDefinitions` + 会话 ID 持有者，执行走 `Agent.ExecuteMCPToolForConversation`。 |
| 编排 | `internal/multiagent/runner.go`：`deep.New` + 子 `ChatModelAgent` + `adk.NewRunner`（`EnableStreaming: true`，可选 `CheckPointStore`），事件映射为现有 SSE `tool_call` / `response_delta` 等。 |
| HTTP | `POST /api/multi-agent`（非流式）、`POST /api/multi-agent/stream`（SSE）；路由**常注册**，是否可用由运行时 `multi_agent.enabled` 决定（流式未启用时 SSE 内 `error` + `done`）。 |
| 会话准备 | `internal/handler/multi_agent_prepare.go`：`prepareMultiAgentSession`（含 **WebShell** `CreateConversationWithWebshell`、工具白名单与单代理一致）。 |
| 单 Agent | `internal/agent` 为 MCP/工具层（`ToolsForRole`、`ExecuteMCPToolForConversation`）；单代理编排走 `RunEinoSingleChatModelAgent`（`/api/eino-agent*`）。 |
| 前端 | 主聊天 / WebShell：**Eino 单代理**（`/api/eino-agent/stream`）与 **Deep / Plan-Execute / Supervisor**（`/api/multi-agent/stream` + `orchestration`）；`multi_agent.enabled` 控制多代理选项是否展示。 |
| 流式兼容 | Eino 单/多代理与 Web UI 共用 `handleStreamEvent`：`conversation`、`progress`、`response_start` / `response_delta`、`thinking` / `thinking_stream_*`、`tool_*`、`response`、`done` 等。 |
| 批量任务 | 队列 `agentMode` 为 `deep` / `plan_execute` / `supervisor` 时子任务带对应 `orchestration` 调用 `RunDeepAgent`；旧值 `multi` 与「`agentMode` 为空且 `batch_use_multi_agent: true`」均按 `deep`。 |
| 配置 API | `GET /api/config` 返回 `multi_agent: { enabled, robot_use_multi_agent, sub_agent_count }`；`PUT /api/config` 可更新 `enabled`、`robot_use_multi_agent`（不覆盖 `sub_agents`）。 |
| OpenAPI | 多代理路径说明已更新（流式未启用为 SSE 错误事件）。 |
| 机器人 | `ProcessMessageForRobot` 按 `robot_default_agent_mode`（默认 `eino_single`）调用 `RunEinoSingleChatModelAgent` 或 `RunDeepAgent`。 |
| 预置编排 | 聊天 / WebShell：`POST /api/multi-agent*` 请求体 `orchestration`：`deep` \| `plan_execute` \| `supervisor`（缺省 `deep`）。`deep` 使用 task 子代理协作；`plan_execute` 不构建 YAML/Markdown 子代理；`plan_execute_loop_max_iterations` 仍来自配置；`supervisor` 至少需一个子代理，只有一个子代理时会提示其专家路由空间有限。 |
| Eino 中间件 | `multi_agent.eino_middleware`（可选）：`patchtoolcalls`（默认开）、`toolsearch`（按阈值拆分 MCP 工具列表）、`plantask`（需 `eino_skills`）、`reduction`（大工具输出截断/落盘）、`checkpoint_dir`（Runner 断点）、`deep_output_key` / `deep_model_retry_max_retries` / `task_tool_description_prefix`（Deep 与 supervisor 主代理共享其中模型重试与 OutputKey）。**`plan_execute`**：Executor 使用 Eino 官方允许的自定义 `adk.ChatModelAgent`，保持官方 Plan/UserInput/ExecutedSteps session contract，同时挂载与 Deep/Supervisor 主代理同源的 middleware（patch → reduction → toolsearch → plantask → filesystem → skill → summarization tail）。Planner/Replanner 仅 summarization tail + prompt 预算截断，不跑 MCP 工具链。当前 Eino 官方 `planexecute.NewExecutor` 尚未暴露 Handlers 字段，因此该自定义 Executor 是保留 middleware 的对齐实现。 |

## 进行中 / 待办（ backlog ）

| 优先级 | 项 | 说明 |
|--------|----|------|
| P3 | **观测与计费** | Eino 事件可进一步打结构化日志 / trace id，便于排障。 |
| P3 | **测试** | 增加 `internal/multiagent` 与 einomcp 的集成测试（mock model 或录屏回放）。 |

## 关键文件索引

- `internal/multiagent/runner.go` — DeepAgent / plan_execute / supervisor 组装与事件循环  
- `internal/multiagent/eino_orchestration.go` — PlanExecute 根节点与 Executor 中间件栈（`buildPlanExecuteExecutorHandlers`）  
- `internal/handler/multi_agent.go` — SSE 与（同步）HTTP  
- `internal/handler/multi_agent_prepare.go` — 会话准备（含 WebShell）  
- `internal/einomcp/` — MCP → Eino Tool  
- `config.yaml` — `multi_agent` 示例块  
- `web/static/js/chat.js` — 模式选择与 stream URL  
- `web/static/js/webshell.js` — WebShell AI 流式 URL 与主聊天模式对齐  
- `web/static/js/settings.js` — 多代理标量保存  

## 版本记录

| 日期 | 说明 |
|------|------|
| 2026-03-22 | 首版：Eino DeepAgent + stream + 前端开关 + GOPROXY 脚本。 |
| 2026-03-22 | 补充：进度文档、`prepareMultiAgentSession` 抽取、WebShell 后端对齐、`POST /api/multi-agent`、OpenAPI `/api/multi-agent*` 条目。 |
| 2026-03-22 | 路由常注册、流式未启用 SSE 错误、`robot_use_multi_agent`、设置页持久化、WebShell/机器人多代理、`bind_role` 子代理 Skills/tools。 |
| 2026-03-22 | `tool_result.toolCallId`、`ReasoningContent`→思考流、`batch_use_multi_agent` 与批量队列 Eino 执行。 |
| 2026-03-22 | 流式工具事件：按稳定签名去重，避免每 chunk 刷屏与「未知工具」；最终回复去重相同段落；内置调度显示为 `task`。 |
| 2026-03-22 | `agents/*.md` 子代理定义、`agents_dir`、合并进 `RunDeepAgent`、前端 Agents 菜单与 CRUD API。 |
| 2026-03-22 | `orchestrator.md` / `kind: orchestrator` 主代理、列表主/子标记、与 `orchestrator_instruction` 优先级。 |
| 2026-04-19 | 主聊天「对话模式」：原生 ReAct 与 Deep / Plan-Execute / Supervisor；`POST /api/multi-agent*` 请求体 `orchestration` 与界面一致；`config.yaml` / 设置页不再维护预置编排字段（机器人/批量默认 `deep`）。 |
| 2026-04-21 | 移除角色 `skills` 与 `/api/roles/skills/list`；`bind_role` 仅继承 tools；Skills 仅通过 Eino `skill` 工具按需加载。 |
| 2026-07-06 | **最佳实践对齐**：Deep / Plan-Execute / Supervisor 改为中性适用场景描述；Supervisor 标为专家路由特定场景并收紧 transfer/exit 约束；plan_execute Executor 明确为遵循官方 session contract 的自定义 ChatModelAgent，保留 middleware 并补类型保护。 |
| 2026-07-02 | **plan_execute Executor 中间件对齐**：`ExecPreMiddlewares` 与 Deep 主代理同源；`buildPlanExecuteExecutorHandlers` + 回归测试；文档更正。 |
| 2026-06-02 | **移除原生 ReAct**：删除 `/api/agent-loop*` 执行入口与 `AgentLoopWithProgress`；统一 Eino ADK（单代理 `/api/eino-agent*`，多代理 `/api/multi-agent*`）；任务 cancel/tasks API 保留。 |
