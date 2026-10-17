# CyberStrikeAI-SRC 二开特性

> 当前分支：**v1.7.24-src**
> 基于 [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) 官方主线，聚焦**授权 SRC / 漏洞挖掘**方向：在官方完整平台之上做定向增强（可复现强制、SRC 报告、FOFA 多引擎、漏洞全生命周期、Tavily 联网搜索），并剔除压制 agent 自主性的治理层。

## 特性总览

| # | 特性 | 一句话 | 关键代码 |
| --- | --- | --- | --- |
| 1 | 可复现强制 | 无工具探测证据的漏洞禁止落库 | `internal/app/vulnerability_tools.go` |
| 2 | SRC 漏洞报告 | 9 个 SRC 字段 + 3 套导出模板 | `internal/handler/vulnerability_report.go` |
| 3 | FOFA 多引擎 | fofa/quake/shodan/zoomeye 原生协议 + 双通道 | `internal/fofaruntime/` |
| 4 | 漏洞全生命周期 | record/list/get/update/delete 五工具 | `internal/app/vulnerability_tools.go` |
| 5 | Skills / Roles | 79 Skill + 18 角色 | `skills/` `roles/` |
| 6 | ddddocr | 验证码/滑块 OCR | `tools/ddddocr.yaml` |
| 7 | issue#2 修复 | 孤儿 tool 消息规范化防网关 400 | `internal/multiagent/orphan_tool_pruner_middleware.go` |
| 8 | Tavily 联网搜索 | Agent 可用的 web_search 工具 | `internal/app/web_search_tool.go` |
| 9 | Eino 显式完成协议 | 过程说明不再被误判为最终回复 | `internal/multiagent/eino_completion_contract.go` |
| 10 | 红队工具箱 | msfconsole / frida / evil-winrm / aircrack-ng 等工具 YAML | `tools/*.yaml` |
| 11 | 多模态图片输入 | 对标 Codex/Claude Code：上传图片与 `read_file` 图片原生直发；纯文本主模型走旁路 | `internal/vision/native.go` `internal/multiagent/turn_images.go` `internal/multiagent/eino_skills.go` |
| 12 | 运行中输入排队 + 执行中引导 | 对标 Codex：运行中输入=排队卡片（立即/编辑/删除，结束自动发出），「立即」= TurnLoop 安全点注入指示 | `web/static/js/chat.js` `internal/multiagent/eino_turn_loop_runtime.go` `internal/handler/agent.go` |

## 核心二开（相对官方）

### 1. 可复现强制（防编造漏洞）
官方 `record_vulnerability` 仅在 prompt 提示"可复现"，无强制。本分支在落库前校验：**本会话必须对该漏洞目标完成过真实工具探测**（`tool_executions` 表 status=completed，且目标 host 出现在某次非管理类工具的参数/输出中），否则拒绝记录。
- 实现：`internal/app/vulnerability_tools.go` → `reproducibleEvidenceExists`；`internal/database/monitor.go` → `CompletedProbeEvidenceForConversation`
- 测试：`TestReproducibleEvidenceExists`（无执行拒 / 已探测放行 / 未测目标拒 / 仅 record 工具拒 / 未完成拒）

### 2. SRC 漏洞报告（字段 + 模板 + 导出选模板）
- **数据模型**：`Vulnerability` 补 9 个 SRC 字段——`category / auth_required / test_account / test_password / vuln_urls / network_segment / developer / poc_script / tool_call_id`（含 DB 列 + 迁移）
- **报告模板**：导出支持 `generic / enterprise_src / edusrc` 三套，导出时 `c.Query("template")` 选择；三套共用五块结构骨架，仅块内标签措辞皮肤不同（风险等级/漏洞等级/严重程度）
- **五块结构**（对齐 SRC 漏洞报告写作规范，结构化 markdown 非通篇正文）：标题行 = 漏洞标题原文 + `目标网站URL：`行；`一、漏洞摘要【必填】`（描述正文 + 文末等级/类型两行，类型含 SRC 分类括注）；`二、受影响资产【必填】`（基本信息表 + 漏洞地址代码块）；`三、复现流程【必填】`（前置条件 → 复现步骤 → 证据 → 一键验证脚本，空小节自动省略）；`四、危害与实证【必填】`；`五、修复建议【选填】`（含复测说明，内容全空时整块省略）
- **基本信息表**：漏洞类型、SRC 分类、目标系统/接口、认证要求、测试账号、测试密码（明文，供 SRC 审核复现）、网段、开发者、状态、漏洞 ID（等级在摘要文末两行、漏洞地址独立代码块，不重复进表）
- **文件名**：`{漏洞标题}_{ID 前 8 位}.md`（标题行 + 短 ID 保唯一）；录入写法纪律（量化标题、第一人称、线性流水整包、截图占位、危害×实证绑定、定级判据、匿名闸/认钥闸/不写清单）由 `skills/pentest-output-standards` 统一约束

### 3. FOFA 多引擎 agent 工具（原生协议）
官方仅有 FOFA HTTP handler，agent 无空间测绘工具。本分支新增：
- `internal/fofaruntime/`：搜索 runtime，**原生支持 fofa / quake / shodan / zoomeye 协议**（`SearchByProvider` 分发：fofa=qbase64+key GET、quake=POST+X-QuakeToken、shodan=GET /shodan/host/search、zoomeye=POST+API-KEY）+ 自然语言转语法
- `internal/app/fofa_tool.go`：`fofa_search` MCP 工具（provider 多引擎 + `natural_language` 参数）
- 配置：`config.yaml` 的 `fofa/zoomeye/quake/shodan` 段（`base_url` + `api_key`），或环境变量 `FOFA_API_KEY / ZOOMEYE_API_KEY / QUAKE_API_KEY / SHODAN_API_KEY`
- 测试：5 个 wire 协议断言（各引擎无协议串扰）

**1.7.11 增强**：
- **路径自动补齐**：`base_url` 只填域名/中转地址时，后端按引擎自动追加默认 API 路径（`ensureSearchPath`，各引擎独立补齐、互不串扰）
- **多端点 fallback**：`fofa.endpoints` 逐端点独立鉴权（`auth_mode` key/bearer + `verify_ssl`），主端点失败自动切换 `fallback_base_urls`
- **size/total 语义归一化**：中转站（无 `total` 键、`size`=总匹配数）与官方 API（`size`=返回条数）字段语义自动归一，前端「共 N 条」计数正确
- **双通道同源**：HTTP handler（`/api/fofa/search`、`/api/fofa/parse`）与 MCP `fofa_search` 共用同一 runtime（`SearchByProvider`），输出结构一致；HTTP 侧权限 `fofa:execute`，MCP 侧 `asset:read`

### 4. 漏洞全生命周期
官方仅 record/list/get。本分支补全 **record / list / get / update / delete** 五工具，update 支持全部 9 个 SRC 字段部分更新。
- 测试：`TestVulnerabilityLifecycle`（record 成功 / 无证据拒 / 缺必填拒 / update / delete）

### 5. Skills / Roles
- **79 个 Skill**（官方 v1.7.18 为 23 个）：新增 SRC 细分漏洞方法 playbook 包（sqli / xss / ssrf / idor / jwt / 命令注入 / 越权 / 业务逻辑 / OAuth 等 OWASP 全类型，部分含 SCENARIOS.md 与 references/），v1.7.18-src 又新增 CI/CD、云、容器、fastjson / shiro / spring、应急响应、内网、log4shell、移动、网络渗透、安全代码审计、安全自动化、安全意识、漏洞评估等 15 个方向包并扩写注入三件套，`unlimited-attack-scope` 改写为 `authorized-attack-scope`
- **18 个角色**（官方 v1.7.18 为 13 个）：渗透 / CTF / API / Web 应用扫描 / 信息收集 / 后渗透 / EDUSRC / 企业 SRC 等，含完整 `user_prompt` + 工具白名单（已清死工具引用、补齐 web_search）

### 6. ddddocr 验证码识别
`tools/ddddocr.yaml`（自动发现）：OCR 文字验证码 / 点选检测 / 滑块缺口定位，用于登录爆破、密码重置、注册绕过等场景。内联 Python 实现，运行时依赖 venv 中安装 `ddddocr`。

### 7. issue#2 修复（orphan tool 消息规范化）
移植自 v1.6.52-src commit 7251738：`orphan_tool_pruner_middleware` 规范化 assistant(tool_calls)/tool 消息回合——删孤儿/失序/重复 tool 消息 + **对缺失 result 补取消占位**，消除火山方舟 Coding Plan 等网关在"工具返回 → 下一次模型调用"节点的偶发 400。挂载于 `eino_chat_model_tail_middleware.go`，位于 summarization/reduction/tool_search 之后、ChatModel 调用之前。

### 8. 通用联网搜索（Tavily）
`websearch` 配置段 + `web_search` MCP 工具（Agent 可用）：Tavily API 驱动，`enabled: false` 可整体关闭；支持 `TAVILY_API_KEY` 环境变量与自定义 `base_url`、`max_results`、`timeout_seconds`。授权 `asset:read`。

### 9. Eino 显式完成协议

Eino single、deep、supervisor 只有在根 Agent 的内部 `exit(final_result=...)` 工具真实执行并返回后才允许最终化；计划和进度正文继续实时显示，但保持 `commentary`，不会触发“最终回复检查通过”。Plan-Execute 使用框架的确定性完成事件。缺少完成信号时从已有模型轨迹最多自动续跑一次（其余 finalization 阻塞原因最多两次，见 `internal/handler/finalization_auto_continue.go` 的 `finalizationMissingSignalAutoContinueMaxAttempts` / `finalizationAutoContinueMaxAttempts`），不重放已完成的工具调用；`use of closed network connection`、`net.ErrClosed` 和 `io.ErrUnexpectedEOF` 纳入当前模型调用的瞬时网络重试。该协议不修改 MCP 工具、RBAC、HITL、Tool Search、迭代预算或执行证据策略，漏洞挖掘与子 Agent 执行能力保持原路径。

### 10. 多模态图片输入（对标 Codex / Claude Code）

官方只有旁路方案：图片一律经独立 VL 模型转文字（`analyze_image`），主模型永远看不到图。本分支补上主流的**图片作为一等内容在 agent 循环内流转**，由通道能力位 `supports_vision` 单向开关：

- **用户上传图片**：按上限裁剪（长边 ≤1568px、JPEG q88、单图 ≤4MB、单轮 ≤10 张且总量 ≤12MB）后作为图片内容块随本轮消息直发主模型；图片只存在于本轮请求，历史仍只存路径，后续轮次不重复计费
- **`read_file` 读磁盘图片**：打开 eino ADK filesystem 的 `UseMultiModalRead`，`read_file` 变成 EnhancedInvokableTool，图片作为**工具结果图片块**返回给模型（与 Codex/Claude Code 的 read 行为一致）；纯文本通道保持原纯文本 `read_file`
- **外部 MCP 图片结果**：先落盘 `tmp/mcp-images/`（7 天）并在结果里给路径，模型按需 `read_file` 取图（不再把图片字节 `%v` 字符串化灌进上下文）
- **安全缝隙修复**：多模态工具走 compose 的独立中间件通道（`ToolMiddleware.EnhancedInvokable`），只实现 `Invokable` 的中间件对其不生效——若不处理，`read_file` 变 enhanced 后会绕过 RBAC / 统一审批 / 输出守卫 / 错误恢复。新增 `withEnhancedToolMiddlewares`（`internal/multiagent/enhanced_tool_middleware.go`）：把结构化结果投影为文本喂给既有中间件，中间件放行且未改写则返回原始结构化结果（图片保留），被改写（拒绝/审批拦截）则只返回文本
- **存储与预算核查修复（本轮自查发现）**：①`last_react_input` 模型视角轨迹会落库并在续跑时回灌，含 base64 图片会撑大数据库与每轮请求体——`cloneADKMessagesForTrace` 统一剥离二进制为占位；②自建 token counter 只取文本部分，图片对软预算/摘要触发不可见——新增 `imagePartsTokenSurcharge`（每图按保守 1600 token 计入）；③轨迹剥离同时覆盖历史遗留的 `Message.MultiContent` 字段
- **旁路降级**：`supports_vision` 关闭时维持官方行为（只给路径 + `analyze_image` 识图），提示词也切换为 `## 图片分析`；`analyze_image` 工具与 `vision` 段配置保持不变（兼容既有部署）
- **清理旧设计**：原生路径下不再注入 `## 图片分析`，也不再出现「不要用 read_file 读二进制图片」这类旧指引；`analyze_image` 的工具描述改为「仅主模型不能读图时使用」
- **上下文清理空壳图片修复（2026-10-17，实测复现）**：eino 的 agentic 版上下文清理在重建工具结果时只保留媒体块 `URL`、丢弃 base64 载荷（`reduction` 的 `toolResultToOutputParts`），而本分支图片一律以 base64 输入（URL 恒为空），清理后留下**空壳图片块**；下一次 ChatModel 直接以 `image message part must have url or base64 data` 终止整个会话（线上实例实测：`read_file` 多模态读取滑块验证码截图后，下一轮即失败，`node path: [node_1, ChatModel]`）。新增 `agenticEmptyMediaPartSanitizerMiddleware`（`internal/multiagent/eino_agentic_chat_model_tail_middleware.go`，挂在 tail 链 orphan pruner 之后、模型视角 trace 之前，即 reduction 之后、每次模型调用前），把无 URL 且无载荷的图片/音频/视频/文件块降级为文本占位：清理语义（旧工具结果出上下文）不变，工具调用关系与文本保持原样。经典 `schema.Message` 路径实测 clear 后保留载荷，无需对称处理
- **改动点**：`internal/vision/native.go`（上传图编码）、`internal/multiagent/turn_images.go`（ctx 承载 + 带图 user 消息，避免改 12 处 runner 签名）、`internal/multiagent/eino_skills.go`（`UseMultiModalRead` 门控 + `WrapEnhancedInvokableToolCall` 保留参数绑定与文本裁剪语义）、`internal/multiagent/enhanced_tool_middleware.go`（中间件多模态通道映射）、`internal/multiagent/eino_agentic_message.go`（图片块双向映射 + 工具结果图片占位，避免 base64 进文本通道）、`internal/handler/multi_agent_prepare.go`（按通道能力位收集）、`internal/project/vision_image_prompt.go`（两套提示分流）、`web/static/js/chat-images.js`（已发图片缩略图 + 灯箱）
- **配置/UI**：`ai.channels.<id>.supports_vision` / `openai.supports_vision`（默认 false，行为不变）；系统设置 → AI 通道勾选「主模型支持图片输入（多模态）」
- 文档：`docs/zh-CN/VISION.md`；测试：`internal/vision/native_test.go`、`internal/multiagent/turn_images_test.go`、`internal/multiagent/eino_multimodal_read_test.go`（断言 read_file 仅在能力位开启时返回图片块）、`internal/mcp/image_content_test.go`、`internal/handler/chat_turn_images_test.go`、`internal/handler/config_vision_flag_test.go`、`internal/project/vision_image_prompt_test.go`、`internal/multiagent/enhanced_tool_middleware_test.go`（断言中间件链同时覆盖两条通道）、`internal/multiagent/multimodal_parts_test.go`（图片计入预算 + 轨迹不含 base64）、`internal/handler/chat_turn_images_test.go`（编码载荷可解码为真图片）、`internal/multiagent/eino_agentic_media_sanitizer_test.go`（清理空壳图片降级，含 reduction→清洗端到端）、`web/tests/chat-attachment-thumbs.test.cjs`

### 11. 运行中输入排队 + 执行中引导（对标 Codex）

官方与同步前本分支的行为：会话已有任务在跑时，前端 `sendMessage` 直接弹「当前会话已有任务正在执行」，后端各入口以 `ErrTaskAlreadyRunning` 拒绝 —— 用户只能等或整轮停止。本分支改为 **Codex 式排队**：运行中按 Enter 不打断当前任务，消息落到输入框上方的队列卡片，任务结束后自动按序发出；需要立刻影响当前任务时点卡片上的「立即」，走**执行中引导**（TurnLoop 安全点注入）。

- **排队（前端，主路径）**：`chat.js` 队列模块（`enqueueChatMessage` / `renderChatQueue` / `chatQueueSendNow` / `drainChatQueueIfIdle` 等）。运行中发送 → 入队并清空输入，卡片支持「立即 / 编辑（行内）/ 删除」，队列按会话隔离并写入 `localStorage`（切会话各自装载，不串会话）；输入框占位符在有排队时切为「继续输入以排队后续修改」；任务结束由 `updateChatPrimaryActionState` 触发 `drainChatQueueIfIdle` 逐条发出。不发附件（附件需完整会话准备流程，仍提示等待）
- **执行中引导（后端，卡片「立即」= `POST /api/agent-loop/steer`）**：`{conversationId, message}`。200 = 已入队；404 `no_active_task`；409 `steer_unsupported`（workflow/批量等无 TurnLoop 安全点的运行时，明确拒绝而非静默中断任务）；403 沿用 `agentConversationAllowed`。受理后用户指示同时进入 `hitlCognition` 作为审批授权范围补充声明。实现：`PushUserSteerWithTrace` / `formatUserSteerPrompt` / `EinoTurnLoopItemKindUserSteer`（`eino_turn_loop_runtime.go`）、`AgentTurnLoopSteerRegistrar`（`eino_native_cancel.go`）、hook 绑定与 `user_steer` 进度事件（`eino_turn_loop_iterator_starter.go`，经 `createProgressCallback` 落 process_details + SSE + taskEventBus）、`BindAgentTurnLoopSteer` / `SteerRunningTask` 三态（`handler/task_manager.go`）
- **抢占参数的两条依据（区分「已证实」与「保守选择」）**：
  - **升级超时必须远长于单步合法耗时（已证实，有判别性回归测试）**：`WithPreemptTimeout` 超时后升级为立即中止。沿用「中断并继续」的 3 秒实测把 30 秒的 exec 打断重跑（真机事件时间线可查），故引导取 `einoTurnLoopSteerPreemptTimeout = 60min`（= 配置上限 `tool_timeout_minutes`），正常情况下工具轮/模型调用一结束就命中安全点完成切换，升级只用于运行真正挂死。注意该配置若被设为 0（不限）或大于 60，长时间工具仍可能在升级点被中止——需要更宽窗口时调大常量。`TestEinoTurnLoopUserSteerDoesNotAbortRunningTool` 把该超时改回 3 秒即失败。
  - **带 `WithRecursive()` 是保守选择（未逐项隔离）**：ADK 只在 `WithPreemptTimeout` 里附带递归传播；本项目 TurnLoop 的根 agent 是 adapter 包装、真实安全点在内层，带递归更稳妥。但「递归 vs 超时升级」哪个是引导送达的决定因素**没有隔离验证**：真机首版（无超时、无递归）引导丢失，第二版（3 秒超时 + 递归）送达，而第二版已被证明触发了升级路径，故更可能由升级而非递归起决定作用；单测里换回无递归的 `WithPreempt` 也能通过（`TestEinoTurnLoopUserSteerReachesDescendantSafePoint` 只锁定「生产装配下引导能进模型输入」，不判别递归）。保留递归无额外副作用——不触发升级就不会有立即中止级联。
- **停止不再弹「中断并继续」弹窗（旧实现已整体废弃）**：`cancelActiveTask` / `cancelProgressTask` 直接 `performHardCancelProgressTask` 停止。超集弹窗 `#user-interrupt-modal` 及其四个处理器（`openUserInterruptModal` / `closeUserInterruptModal` / `submitUserInterruptContinue` / `submitUserInterruptHardCancel`）、`userInterruptModalPending` / `__monitorInterruptContext` 上下文、9 个 `tasks.interrupt*` i18n 键、2 条 rbac-guards 权限包装、以及早已无人引用的 `tasks.userInterruptTimelineTitle` **全部删除**（它在两个按钮都可被更清楚的入口替代后只剩余度）。监控页针对**单次工具调用**的「终止」改走专用弹窗 `#mcp-tool-abort-modal`（单用途：只掐这一个工具、说明可选、本轮推理继续），并统一到**一条**后端路径 `POST /api/monitor/execution/:id/cancel`：它自己反查会话后调用与对话侧相同的 `cancelToolContinueAfter`（含 Eino execute 终止），解析不到会话时还有内/外部 MCP 仅凭 executionId 的兜底——这条比经 `/api/agent-loop/cancel{continueAfter}` 更完备，故前端删除了 `requestCancelWithContinue` 及其分叉逻辑（`web/tests/monitor-tool-terminate.test.cjs` 锁定）。后端 `CancelAgentLoop` 的 `continueAfter` 分支**保留但 UI 不再调用**（公开 API 且 OpenAPI 有记录）；若要彻底删除，需连带移除 `SetInterruptContinueNote` / `CancelTask(ErrInterruptContinue)` / `PushInterruptContinue*` 整条中断并继续子系统与运行循环抢占机制，属独立大改，未纳入本次范围
- **CI 覆盖修正（两类空跑）**：`.github/workflows/self-update.yml` 的前端步骤原为 `node --test web/static/js/*.test.cjs`，匹配 0 文件且 exit 0（本分支测试实际在 `web/tests/`，官方测试迁移时漏改）；`paths` 触发范围也少了 css/i18n/templates/tests。同时 `go test -race` 列表缺 `./internal/multiagent`，本次引导的 3 个核心 Go 用例不在 CI 里跑——已一并补上（列表 + paths）。
- **已知边界**：运行起始的极短窗口内 TurnLoop 尚未挂载，队列「立即」会退化为 409 并留在队列（不丢消息）
- **测试**：`internal/multiagent/eino_turn_loop_steer_tool_test.go`（工具执行期间引导能切换轮次、**引导不掐断正在跑的工具**、引导升级超时常量下限、与「中断并继续」对照）、`eino_turn_loop_runtime_test.go`、`eino_turn_loop_iterator_starter_test.go`（hook 绑定 + `user_steer` 事件 + 拒绝时不写时间线）、`internal/handler/agent_steer_test.go`、`internal/handler/task_manager_steer_test.go`、`web/tests/chat-queued-followup.test.cjs`（入队/持久化/会话隔离/立即/回退/自动发出/按钮态/占位符/403 权限提示）、`web/tests/monitor-tool-terminate.test.cjs`（停止不弹窗、单次工具终止单一后端路径、旧弹窗不复活）

### 12. 危险操作审批：按「同意 + 理由」自主裁决（不再按逐次声明）

**问题（线上实测，2026-10-15~16）**：审计 Agent 判 R1 拒绝后，该操作在会话里再也测不了，**用户明确同意也不生效**。三个会话（`099ce374` / `650479e6` / `26e41de5`）对 `resetPassword` 类接口跨 8 小时 11 次全拒，同一批日志里同接口的 GET 探测全部放行。执行 Agent 的自述是根因的直接证据：「审批意见只是 `approval rejected`，没有"需用户授权"这一句，因此我不能把它当成已授权」。

**根因（信息断链，不是规则配错）**：

- **拒绝理由被丢弃**：`coordinator.go` 的 R1 分支 `return decision, ErrApprovalRejected` 丢掉了 `decision.Comment`，下游 `approval_adapters.go` 只能把哨兵串成「审批意见：approval rejected」。`hitl_toolsearch_compat.go` 的逃生话术（「若审批意见表明需要用户授权…获得同意后重新发起即可通过」）因此**永不触发**——模型看不到"请确认是否授权"这句。（`rejectReviewerFailure` 那条路径本来就带 reason，只有正常 R1 漏了。）
- **同意不跨轮**：`hitlCognitionState` 是任务级内存、每轮 `StartTask` 重建，用户上一轮说的"同意"到下一轮就消失；测试规范也从未进过审批 payload。
- **判据错位**：提示词要求"userMessage 必须明确提及该类操作"，并明文「最小化验证…同样属于敏感危险操作」——把最该放行的形态（动自建/不存在对象）判死，与执行 Agent 系统提示词「授权范围内所有操作直接执行，包括改密码绕过」直接冲突。
- **引擎故障=终身封禁**：LLM 调用失败 / 无响应 / 响应无法解析三条路径一律终态 reject（现场 `apr_02b37f82` 即"响应无法解析，保守拒绝"）。
- **拒绝来源误述**：审计拒绝一律表述为 `rejected by user`，模型误判为"用户否决"，转而向用户申诉一件用户从未做过的事。

**改动**：

- **理由回传**：`coordinator.go` 新增 `RejectionReason` / `rejectError`，R1 以 `fmt.Errorf("%w: %s", ErrApprovalRejected, decision.Comment)` 返回；`approval_adapters.go` 用 `RejectionReason` 还原干净理由再构造软结果。这是整条闭环的钥匙。
- **同意跨轮可见**：新增 `database.ConversationUserDeclarations(conversationID, anchorMessageID, limit)`（与 `GetTurnUserMessage` 同处，按 `(created_at,rowid)` 定锚、**锚点比较放在 SQL 内做列对列比较**——Go 侧绑参与列值类型不一致时同秒消息会全部命中）。`hitl_context.go` 改为「会话级用户声明 + 任务级内存尾」合并去重（上限 20 条 / 8KB）。
- **授权基线入 payload**：新增 `testingSpecification` 字段，用 `GetConversationTestingSpecification` 自己格式化——**不能**直接复用 `ConversationTestingSpecificationBlock`，那段文案是给执行 Agent 的（"规范不授予额外权限，不得绕过审批"），会让审计 Agent 把声明基线又原样否掉。
- **判据重写**（`config.go` 审计提示词）：按「超范围 → 用户明确同意 → 有可检验理由 → 否则拒绝」排序；同意长期有效、不再逐次追问；**删除**「最小化验证同样属于敏感危险操作」；明确"写"本身不是拦截理由。**同意不得外推**：一次同意只覆盖该条消息点名的接口/对象/操作类别，换接口、换对象、换类别即视为未获同意（回落 A2/R1）；「继续」「都行」一类笼统回应不构成新同意。避免一次授权把整类操作永久打开。另修四处口径：① **R2 必须有声明可指**——userMessage / testingSpecification 都没给出范围时不得凭印象判超范围（R2 是唯一不可被同意覆盖的档位，允许凭印象判 R2 等于换条路重开死锁）；② A2 的三条理由（对象自建或不存在、单次有界、可回滚）是**累加**而非任一，且"命名像真实账号（admin/root/system）不算明显不存在"；③ 不再谎称 userMessage 是"本会话全部用户发言"——如实写明只保留最近若干条、更早轮次与超长消息会被截断丢弃（否则审计 Agent 会因窗口外的同意不可见而**确信**"用户从未同意"，正是原 bug 那种虚假确定性）；④ 消歧「写计划任务」——原文在危险清单与放行清单里同名，两张清单同时命中；现收窄为危险侧"改动在役主机的计划任务/开机项配置"、放行侧"对目标主机写计划任务做持久化"（与 Jev 的 `config_tamper` 分界一致）。
- **TypeSafe/Jev 通道对齐**（`internal/hitl/jev.go`）：原实现只有 4 条破坏性 Noul + 1 条 pentest + 1 个 decision Choice，**没有任何"同意"输入**，且破坏性 Noul 分支无条件先行——所以把默认提示词当 operatorPolicy 下发也修不了（换汤不换药）。新增 3 个轴：`out_of_authorized_scope`（超范围，对同意免疫）、`unjustified_probe`（无理由试探）、`authorization_basis`（consent / justified / none 标签），并让 `DecideJev` 按与提示词**完全相同的顺序**裁决：超范围/组织策略 → 同意 → 有理由 → 破坏性轴 → 无理由试探 → 默认放行。阈值：标签置信 ≥0.75 才采信；"有理由"只压得住 0.85 以下的破坏分——openai 后端读得到理由原文，Jev 只有一个标签，不该让它盖过"几乎必定破坏"的信号（自建对象改密 Jev 通常给 0.6~0.8，真实账号 0.9+，按此分档）。`BuildJevState` 的字段白名单同步补 `testingSpecification`。两条后端因此对同一调用同向结论，不会因换后端而改变"同意能不能解封"。
- **解封路径写进拒绝返回**（`hitl_toolsearch_compat.go` 的 `HitlRejectToolResult`）：把「首次被拒不是终态」、重发**是可选的**（「不要因为这一次被拒就偏离主线任务」）、授权路径、补理由路径（证明什么 / 依据哪次实测 / 动哪个对象 / 怎么回滚）、禁止换工具绕过，全部放进**工具结果**。**不写进执行 Agent 的常驻系统提示词**——那段每轮都加载，是永久上下文开销；而这些话只在被拒时才有意义。**授权提问不由审计侧强制**：审计 comment 只说清「实际操作 / 成功后的后果 / 命中规则」，不代主 Agent 索要授权；被拒后"还要不要执行该操作"由执行 Agent 自行拍板（自行拍板继续、或自行拍板不做），只有既属主线必需又自己定不下来时才在收尾时与其他结论一并提出交给用户。审计侧强制那句提问会逼模型在主线中途停下等授权。
- **引擎故障降级**：新增 `hitlAuditAttempts = 2` 重试一次；仍失败返回 `Failure: true` 的「审批引擎不可用（非策略裁决）」并落库 `metadata.auditFailure`，不再伪装成策略拒绝（`hitlDecision.Failure` → `approval_adapters.go`）。
- **规则层降噪**：`danger.http.destructive-path` / `danger.http.critical-identity-mutation` 加 `httpMethods` 写方法约束（`danger.http.critical-control-path` 保留 GET 拦截，控制面例外）。15 条真实记录里 13 条仅因 URL 含 `resetPassword` 入队，其中 7 条纯 GET。
- **与硬闸对齐**：硬闸 `sensitive_http_gate.go` 的清单比规则宽，差集内的操作会被硬闸直接 `IsError`、**不产生审批单**（无记录无出口）。已把 `truncate|drop|format|wipe|unlink|rmdir|kill|factory_reset|execpower*` 补进 `danger.script.destructive-http-operation`。
- **绕过补漏**：写方法藏进 shell 变量/for 列表（`-X "$m"`、`for m in PUT DELETE …`）时两层正则同时失明（`01ccf126` 实测 4 次）。硬闸新增 `sweptWriteMethods`，规则侧同步加 `(?:-X|--request)\s*.{0,2}\$|for \w+ in …(PUT|PATCH|DELETE)`——**长选项 `--request` 必须一起覆盖**，否则硬闸拦下而规则层不入队，就是"无审批单、无解封路径"的死路（该不变量已由 `internal/security/sensitive_http_gate_rule_alignment_test.go` 固化）；`execute` / `eino_fs::execute`（eino 文件系统执行通道）补进 `danger.script.*` 的 tools，之前它是一条无审计的执行通道。
- **规则覆盖语义等价绕过**（`danger-rules.json` 15 → 16 条）：甲方规范普遍要求"换名词 / 换方法 / 换参数名 / 命名变体一律同规则"，而 `clear`/`erase`/`discard`/`recycle`/`empty` 原来两层都不认，`_method=delete`、`op=rm` 这类伪装硬闸与规则层也都看不见。现 `danger.http.destructive-path` 补齐上述动词，并新增驼峰（`userDelete`）与分隔符（`user_delete`/`del-user`）变体；新增 `danger.http.destructive-verb-override`，从**参数体**（`url`/`data`）识别方法与参数名伪装——只认 DELETE/PUT/PATCH，避免把正常 `method=POST` 灌进队列；脚本通道同步。**同时补齐 http 侧死路**：`format`/`wipe`/`unlink` 原本"硬闸拦下但规则层不入队"（无审批单、无解封路径），现与硬闸同宽。命名变体收紧为"分隔符或驼峰边界"以免 `undelete` 这类词中子串误命中；而 `动词+小写词`（如 `/api/clearcache`、`?format=csv`）仍会命中——按"宁多入队、由审计放行"的安全侧取向有意保留。
- **执行侧不再因规范冲突停下来问用户**：`ConversationTestingSpecificationBlock` 的包装句删除「如存在冲突或歧义，先向用户说明」，冲突由执行 Agent 自行判定、不中断主线；导入的规范原文一字不动。授权提问同理不由审计侧强制（见上条）。
- **注入量有界**：`joinHitlUserDeclarations` 超限时丢最早的消息，并对"单条消息本身就超限"单独兜底截断——否则一次大段粘贴就能突破 8KB 上限撑爆审计请求。

**运维影响（升级必读）**：

- **危险规则默认值只插不改**：`SeedDefaultRules` 对已存在（或被 tombstone）的规则 `continue`，所以**本次规则调整不会自动更新已部署实例**——需在「人机协同 → 危险规则」页对已存在的对应规则做一次编辑保存（或删除后重启让其重新播种）。**本次受影响的是改过内容的两条：`danger.http.destructive-path`、`danger.script.destructive-http-operation`；新增的 `danger.http.destructive-verb-override` 会自动播种。**提示词默认值改动则即时生效，除非管理员此前把旧默认保存成了自定义提示词（`handler/config.go` 按"是否等于默认"判定是否落自定义），需要重存一次。
- **TypeSafe 后端判据在代码里，升级即生效**（不依赖提示词配置）。但注意两点：① 若管理员配置了自定义 `audit_agent_prompt`，它会作为 operatorPolicy 叠加，且**组织策略禁令与超范围同级、对同意免疫**——自定义策略里若有一刀切禁令（如"禁止一切命令执行"），"同意必放行"在该部署下不成立；② 判定命中组织策略或超范围时，`comment` 会明确写出是哪一项，便于排查。

**已知边界**：脚本通道（`exec` / `execute-python-script` / `execute`）的**只读**探测仍会进审批队列——判只读需要把方法推断下沉到规则层，而推断实现在 `internal/security`，`approval` 反向依赖会形成 import cycle；成本是一次审计调用与一条记录（新判据下会被 A2 放行），不影响可用性。脚本文件内容（`python3 x.py`）仍不参与匹配，需要 workspace 有界读取，未纳入本次。

**测试**：`internal/approval/coordinator_unified_test.go`（拒绝错误携带审批原文、非拒绝错误不误报）、`danger_rule_queue_regression_test.go`（真实记录形状的入队/放行对照）、`rule_verify_test.go`（只读降噪、硬闸对齐、通道纳管、方法变量化、命名变体、方法/参数伪装）、`internal/database/conversation_user_declarations_test.go`（跨轮可见、锚点截断、limit）、`internal/database/testing_specification_test.go`（规范块不得让执行 Agent 停下来问用户、规范原文仍须原样带入）、`internal/handler/hitl_context_test.go`（跨轮同意、测试规范入 payload 且不带执行侧免责文案）、`hitl_audit_agent_test.go`（httptest 桩：重试后成功、持续失败标记为非策略裁决）、`internal/security/sensitive_http_gate_method_sweep_test.go`（方法变量化拦截 + 只读不误伤）、`internal/security/sensitive_http_gate_rule_alignment_test.go`（跨层不变量：**硬闸拦下 ⇒ 规则层必须入队**，含 http 侧 `format`/`wipe`/`unlink` 死路，防"无审批单的死路"复发）、`internal/config/config_test.go`（提示词契约，含删除项不得复活）、`internal/multiagent/hitl_toolsearch_compat_test.go`（拒绝返回必须带「一次未通过不是终态 / 可检验的理由 / 变相绕过」——这两条规则的唯一下发渠道）、`internal/multiagent/approval_middleware_test.go`（审计拒绝文案不得出现 `rejected by user`）、`internal/hitl/jev_test.go`（TypeSafe 通道与提示词同向：同意解封 / 理由解封 / 超范围不可解封 / 组织策略不可解封 / 无理由试探拦下且 comment 不代索要授权 / 标签置信不足回落破坏轴 / 只读侦察不误伤）

### 13. 敏感 HTTP 判定并入统一审批（消除硬编码拒绝）（2026-10-18）

**问题（线上实测，shfft 验证码探测会话）**：`sensitive_http_gate`（07-15 `968bff31` 引入）在执行器里硬编码拒绝：命中即 `IsError` 返回 `[sensitive_http_gate] blocked`，且在规则层未命中的形态下**不产生审批单、不写审计、无解封路径**——Agent 重试只会反复撞墙。10-16 `86e0a23e` 给硬闸新增 `method:sweep` 后拦截面扩大，普通 Python 探测脚本开始成批撞上这条死路。

**误判根因**：`collectToolTextBlob` 把整个 args 的 JSON 兜底串拼进扫描文本，字面量 `\n` 让 `reMethodListLoop` 捕获组 `[^\n;|&]+` 跨行吞进后续代码——`post,cj=newsess()` 的函数名 `post` 被当成 for 列表里的写方法 → `method:sweep` 误拦（本地用原始命令复现与线上一致）。

**改动**：

- **判定并入统一审批**：新增 `security.SensitiveHTTPGateTrigger`（实现 `approval.Trigger`），挂进 `GlobalRuntime` 触发器链（extra triggers 由 runtime 持有，规则热更新两参 `Update` 自动保留）。命中 ⇒ `RequiresApproval` + finding（`RuleID=reason`），与危险规则走同一审批、同一留痕（审批单 + ledger + 决策审计），**不存在硬编码拒绝**。
- **删除执行器硬拒**：`executor.go` 的 gate 分支移除。覆盖依据：所有工具调用都过 `InvocationGuard`（`app.go` 内/外 MCP 各一处，eino 中间件另一路），授权统一由 `Coordinator.Authorize` 裁决；`DangerousInvocationGranted` 保留为 grant 语义的测试锚点。
- **误判根修**：sweep 判定只作用于原始字段文本（`collectToolTexts`：原始字段非空时 JSON 兜底串不再参与扫描，仅原始字段全空时整体兜底）；线上真实命令固化为回归用例。
- **不变量改写**：`sensitive_http_gate_rule_alignment_test.go` 由「硬闸拦下 ⇒ 规则层必须入队」改为「**判定命中 ⇒ GlobalRuntime 必入队且触发来源含 `sensitive_http_gate`**」——死路在结构上消失，不再依赖规则层同宽（§12 该不变量就此取代）。
- **文案**：系统提示词与 `tool-execution-governance.md` 的「危险操作硬闸」改为「危险操作强制审批」——通用工具审批可关闭，危险操作强制审批不可关闭。

**语义变化**：原来被硬闸 `IsError` 拒死的调用现在会创建审批单：默认 reviewer（人工，超时 15 分钟）裁决，或 reviewer=audit_agent 时由审计 Agent 按 §12 判据（超范围 → 同意 → 有理由 → 拒绝）自主裁决；批准即以冻结参数执行，拒绝则模型收到审批人原文并可向用户请求授权（§12 闭环）。「同意+理由」自主裁决自此覆盖原硬闸全部分类。

**测试**：`go test ./...` 全量通过；security/approval/app/mcp/handler 逐包验证。

## 与官方版本及本仓库历史的关系（对照核实）

**对比基准与结论均经代码检索核实**（2026-09-09 复核，`git diff v1.7.18` 工作区全量对比）：

1. **官方 v1.7.18**（Ed1s0nZ/CyberStrikeAI，tag `v1.7.18`）：官方不含本分支的二开层组件（`internal/fofaruntime/`、`web_search_tool.go`、`vulnerability_report.go`、`sensitive_http_gate.go` 等对官方代码 0 命中）。本分支以官方为基座叠加二开增强。

2. **本仓库 v1.6.48-51-src 历史**：曾引入治理层 `execution_controller` / `skill_router` / `session_intent` / `depth_force` / `evidence_policy` / `semantic_outcome` / `tool_exec_governor` 等。**v1.7.11-src 将其全部移除**，回归官方精简形态；后续 `fofa.icu` 硬编码代理、启动注入 FOFA 环境变量、batch-delete 路由补注册、漏洞表缺失列补全等历史修复，也已被官方 v1.7.13~v1.7.16 同步吸收或由更通用的实现取代（多端点 `FofaConfig.Endpoints[]`、运行时直读 `FOFA_API_KEY` 等），不再构成现存差异。

**与官方 v1.7.18 的全量差异**（实测）：513 个文件变更——新增 180、修改 242、删除 72、重命名 19（+63,595/-18,191 行；工作区口径，数字随未提交改动微幅漂移）。要点：
- 新增 `internal/fofaruntime/` 四引擎 Go 原生运行时（fofa/quake/shodan/zoomeye，1315 行含测试）与旧域名自动迁移容错
- 新增 `web_search_tool.go`（Tavily）、`vulnerability_report.go`（SRC 报告导出 +3 测试）、`sensitive_http_gate.go`（硬闸）
- 漏洞链路强化：三要素/PoC prompt 重写、可复现门禁 host 边界匹配、转义归一化判定开关、SRC 扩展 DB 列
- multiagent：中断续跑携带模型可见轨迹、tool_search 常驻/非常驻分组注入、运行中摘要修正
- skills 新增 43 包（新增 62 个文件）、移除 demo / unlimited-attack-scope 2 包，现共 80 个；工具 YAML 官方 90 个 → 现 116 个（累计新增 33 个红队/信息收集向，其中 mimikatz / apktool / ettercap / medusa / proxychains / recon-ng / strace 7 个已移除）、5 个新角色（roles 补 web_search 17 处）
- 删除：官方宣传图、README_CN.md、SECURITY.md、英文文档目录 `docs/en-US/`（zh-CN 全量保留）、插件 dist 二进制、demo/unlimited-attack-scope 技能包、mcp-servers 与插件的冗余中英文 README

### v1.7.18 同步说明（2026-09-09）

官方 v1.7.17→v1.7.18 共 12 个提交：**11 个按提交语义镜像，1 个跳过**。

- **新增官方能力**：
  - `internal/toolguard/` 调用拦截（可配置规则，出厂内置政府域名保护，默认开启）：MCP 内置/外部两条调度路径均接入，与统一审批叠加——**先拦截后审批**（被规则禁止的调用不再进入审批队列），审批改参（review_edit）后按最终参数二次拦截；监控页新增「已拦截」状态与统计（`web/tests/tool-guard*.test.cjs`）
  - 诊断日志按日轮转 + 保留天数清理（`internal/logger/daily_writer.go`，`Logger.Close()` 为 SRC 补充以支持 Windows 句柄释放）
  - DeepSeek 配置归一/自动识别、AI 通道 reasoning 下拉刷新、Claude 模型摘要 token 上限、摘要模型错误透出、登录前与局部渲染刷新导航权限
- **跟随官方移除会话分组**：`group:*` 权限、分组 UI/后端（`handler/group.go` 等）、i18n 分组键全部清除，对话管理保留置顶/重命名/批量
- **跳过 `feat: persist hitl default config`**（21c6ad9b）：其目标是官方旧 `handler/hitl.go` 体系；本分支的统一审批（`internal/approval/`）已以 `approval:` 配置段持久化 reviewer/timeout/触发器，语义被取代
- 官方 v1.7.18 的 roles / tools 数量与 v1.7.17 一致（13 / 90），二开层 18 角色 / 116 工具 YAML 保持；skills 扩至 79 包（新增 15 方向包 + 扩写注入三件套，官方 demo 包继续不收录）

### v1.7.19 同步说明（2026-09-18）

官方 v1.7.18→v1.7.19 共 11 个提交：**9 个语义合并（含 2 个适配）+ 1 个 sudo 测试增强直接合入 + 2 个裁剪项官方动作已达成**。逐提交与本地二开层比对后按语义合并，非直接 merge。

- **新增官方能力（整体采纳）**：
  - `internal/processguard/` 进程隔离（Linux cgroup v2 / Windows Job Object）：`config.yaml` 新增 `security.process_isolation` 段，MCP 执行服务、外部管理器接入；配套 `.github/workflows/process-isolation.yml` CI
  - 任务进程生命周期（`internal/handler/task_lifecycle.go` + runlease）：任务启动/结束登记进程范围，任务取消时清理遗留子进程（`task_process_cleanup_test.go`）
  - Eino 跨中断轮次记忆（`internal/multiagent/eino_turn_history.go`）：TurnLoop GenInput 在纯提示词续跑时前置历史轮消息（官方修复 issue #121）；与本分支 `PushInterruptContinueWithTrace` 轨迹前置机制通过守卫函数协调（该守卫后因「执行中引导」加入同类 item 而更名为 `einoItemsCarryModelFacingTrace`）——轨迹已随 item 携带时跳过 history 前置，两套机制互不重复
  - SSE 错误规范化（`internal/openai/eino_sse_error.go`）：流式响应错误事件统一转结构化错误
  - 摘要模型守卫增强（`eino_summarize_model_guard.go`）
  - supervisor 退出优先 final_result（`eino_exit_fallback_test.go` 跟进）
- **适配合并**：
  - 启动 banner 多地址（官方 #307）：本分支 bannerHosts 为其超集（含优选出口 IPv4 + IPv6 括号），保留二开实现，官方测试并入 `startup_test.go`；`PrintStartupWebUI` 拆出 `printStartupWebUI(out, opts)` 可测缝
  - **批量任务审批策略（ac101d84）移植到统一审批**：官方基于已废弃的旧 `handler/hitl.go` 体系（HITLRequest / hitlManager / WithHITLToolInterceptor），本分支已替换为 `internal/approval/` 统一审批，直接合并产生 8 处编译错误。移植方案：新增 `approval.TaskPolicyOverride` 上下文覆盖（`internal/approval/context.go`）——`Disabled`（off 直通不落单）/ `RequireApproval`（human / audit_agent 强制审批）/ `Reviewer` 覆盖审批人，仅随请求 context 生效，**不修改 GlobalRuntime 全局快照**（守卫测试 `task_policy_override_test.go` 锁定该不变量）；`batch_queue_executor.go` 在任务级 context 注入 override 后挂接既有 `withApprovalToolInterceptor`。**review_edit 选项剔除**：统一审批架构中该概念已显式移除（前端守卫测试禁止该字符串），批量策略仅支持 inherit / off / human / audit_agent
- **sudo 测试增强（4d53717c）直接合入**：`shell_execute_stream_test.go` 以 mock sudo 替代对主机 sudo 策略的依赖（精确匹配 `sudo: a password is required` + exit code 校验 + 后续命令不得执行），fork 侧保留 `//go:build !windows` 构建标签与 NOPASSWD skip 前置；`.gitignore` 补 `/vendor/`（569513f3）已并入
- **裁剪策略已达成**：微信二维码更新（7f5c092e）与赞助内容移除（eca26f0e）——本分支更早已删除宣传 QR 图与 `README_CN.md`，官方动作与本分支现状一致，无需变更
- **文档/前端**：批量 HITL 策略下拉移除 review_edit 选项（`index.html` / `tasks.js` / 中英 i18n）；`config.example.yaml` 版本号 → `v1.7.19-src`；README 基线更新；裁剪策略继续执行（官方宣传 QR 图、`docs/en-US/tool-execution-governance.md` 等不入库）

### v1.7.21 同步说明（2026-10-07）

官方 v1.7.20→v1.7.21 共 5 个提交：**2 个直接合入（含 1 个版本号）+ 2 个整体采纳（存储清理含 3 处适配 + 俄语语言包含 1 处适配）+ 1 个裁剪项已达成**。逐提交与本地二开层比对后按语义合并，非直接 merge。

- **summarization token 上限重复修复（bbfcb871）直接合入**：`newEinoSummarizationModelOptions` 原先同时设置 `model.WithMaxTokens` 与 `einoopenai.WithMaxCompletionTokens`，部分网关会同时收到 `max_tokens` + `max_completion_tokens` 重复上限而拒绝；改为 Claude provider（Agentic）走 `model.WithMaxTokens`、其余仅 `WithMaxCompletionTokens`。默认 `summarization_output_reserve_tokens` 8192→40960（`config.example.yaml` 与 `DefaultSummarizationOutputReserveTokens` 同步）。涉及 5 个文件本地与官方 v1.7.20 零分歧，cherry-pick 干净落地；`eino_summarize_payload_test.go` 新增 wire 级断言（请求体只含 `max_completion_tokens`）。
- **运行时存储清理（470eb5ea）整体采纳（28 文件 +3356 行）**：新增 `internal/storage/` 分类保留策略清理器——agent 工作区 / 工具输出溢写 / C2 产物 / 对话上传件 / 工作流检查点 / 诊断日志七类运行时产物按保留天数清扫；设置页新增「存储清理」页签（预览默认、真删需 `dry_run=false` + `confirm=true` 双确认、活跃会话保护期、孤儿目录宽限回收、符号链接不跟随、删除先改名为 `.tmp-for-deletion` 可恢复残渣）；`storage:read/write` 权限仅授予管理员；`config.yaml` 新增 `storage` 段（`auto_clean` 默认关闭，升级不删既有数据）。顺带修复两个泄漏：DeleteConversation 磁盘残留 chat_uploads 文件（行已 ON DELETE CASCADE）、工作流检查点此前无任何删除路径。适配点：
  - `internal/security/rbac.go` 权限目录：本地是统一审批 `approval:*`（无官方 `hitl:read/write`），保留本地目录并在 `config:write` 后插入 `storage:read/write` 两项；`grantSystemRolePermissions` 将 `storage:` 前缀与 rbac/config/terminal/audit 一并排除在 operator 默认授权之外（管理员专属）。
  - `internal/handler/config.go`：`updateStorageConfig` yaml 回写与 `PUT /api/config` 的 storage 段合并逻辑直接合入；官方 `UpdateHitlDefaultConfig`（写 hitl 默认模式/审批人/超时）只被官方旧 `handler/hitl.go` 的 `/hitl/default-config` 路由调用，本分支统一审批由 `/api/approval-config`（`SaveGlobalApprovalConfig`）取代，**裁掉不收录**。
  - `internal/app/app.go`：App 结构体与构造字面量保留本地 approvalCoordinator / approvalHumanReviewer 字段，插入 `storageHandler`；清理器根目录复用本地既有的 `workspaceRoot` / `reductionRoot` / `plantaskBase` / `dbPath` 推导，与实际写入目录同源。
  - 前端 `web/static/js/storage.js`、`settings.js` 页签钩子、`index.html` 页签与面板、`style.css`、中英 i18n、`docs/zh-CN/configuration.md` 均直接落地；官方 `docs/en-US/configuration.md` 变更不跟进（本分支不收录英文文档目录）。顺带清掉 `style.css` 中 v1.7.18 同步误入库的一行孤立 `>>>>>>> 6ad9ea2d` 冲突标记残留。
- **俄语 UI 语言包（78973e84）整体采纳**：新增 `web/static/i18n/ru-RU.json`（4899 行）+ 语言切换器「Русский」项（`index.html` / `api-docs.html`）；`i18n.js` 增加 ru 浏览器语言探测、`ru-RU → [en-US, zh-CN]` 回退链（ru 激活时预载 en-US 资源）与 `window.uiLocale()` 统一 BCP 47 助手；`chat.js` / `monitor.js` / `vulnerability.js` / `audit.js` / `audit-datetime-picker.js` 的时间与日期格式化改走 `uiLocale()`（ru-RU 24 小时制）。适配点：官方 `hitl.js` 的 `hitlLocale()` 改造在本分支落不到原处——本地 hitl.js 已瘦身为 i18n/API 辅助（人机协同页逻辑分居 `approval-ui.js` / `approval-ui-model.js`），等价改动语义合并到 `approval-ui.js` 的 `approvalLocale()`（uiLocale 优先 + ru 分支）。ru-RU.json 基于官方键集，本分支二开键（审批页 / FOFA / websearch 等）未翻译，按回退链显示英文，与官方「未翻译回退英文」行为一致。
- **微信群二维码更新（e9b6e0d8）裁剪已达成**：本地早已删除宣传 QR 图与 `README_CN.md`，官方动作与本分支现状一致，无需变更。
- **版本号（82b0af10）**：`config.example.yaml` → `v1.7.21-src`，README 基线与本文件同步更新。
- 二开层完整保留：可复现强制、SRC 报告五块导出、FOFA 四引擎、漏洞全生命周期、bannerHosts、统一审批（`approval:*` 权限体系未动，存储清理权限独立成段）均未改动；本次新增 `internal/storage/` 七文件、`internal/handler/storage.go`、`internal/database/storage_activity.go`、`web/static/js/storage.js`、`web/static/i18n/ru-RU.json`，RBAC 目录净增 `storage:read/write` 两项权限。

### v1.7.22 同步说明（2026-10-11）

官方 v1.7.21→v1.7.22 共 29 个提交：**26 个 bug 清单修复语义合并（含工作流元数据确认修复 #345 与 1 个测试提交）+ 1 个手机端 UI（#344）整体采纳 + 1 个官方过程文档（裁剪）+ 1 个版本号**。规模为历次最大（119 文件 +10739 行），按文件三方合并（base=official-v1.7.21）+ 逐冲突语义消解，非直接 merge。

- **开源 bug 清单修复（17498368 记录范围 + 26 个 fix/test 提交）整体采纳**：C2（回调 host 校验、监听编辑与必填校验恢复、任务文件上传所有权校验、HTTP 会话逐会话鉴权、过期离线命令关闭 + TCP 派发串行化、信标终端态保留、payload 模板 shell 输出保留）、工作流（工具执行超时下推 `internal/mcp/execution_deadline.go`、节点/列表标签边界、校验与执行结果保留、元数据确认后恢复保存 #345）、批量任务（已完成队列展示失败结果、任务取消贯穿 final 事件、审批中断后取消标签保留）、知识库（索引错误保留与归因提示）、nmap（扫描类型选择时保留脚本参数）、资产（导出本地化 + 导入兼容、受限扫描目标与资产完成指令、列表徽章边界、对话标题对齐）、凭据脱敏（config/webshell/agent 保存掩码）、登录/角色输入校验与任务访问保护。
- **适配合并 3 处**：
  - **凭据脱敏（76da9894）**：官方新增 `config_secrets.go` 泛化掩码（按 `api_key/password/token/...` 键名递归）+ `restoreConfigRequestSecrets` 回填 + `resolveProbeSecret` 探活解析；GetConfig 冲突取「本分支 hitlCfg 审批回填 + 官方 `maskedConfigResponse` 包装」。适配点：`configSecretSnapshot` 官方字段清单缺本分支二开段，**补 `WebSearch`**——否则 websearch.api_key GET 返回 `********` 后保存回填直接 400（快照缺段报「没有已保存凭据」）；Approval/Agent/C2 段核实无密钥字段，无需扩展。
  - **robot/batch 终态化证据要求（079ba0d2）**：官方将 `decideAgentRunForDeliveryWithPolicy` 末参 `requireExecutionEvidence` true→false（无工具证据的纯文本/取消任务不再被 blocked 吞掉最终回复，配套 task_lifecycle/task_manager 取消终态保留）。本分支采纳官方语义于**循环后最终判定**（`finalizeRobotAgentSuccess`、batch 收尾两处，含 cleanup 重判定）；**循环内判定保留 `true`**（047a201e 的设计：喂 `tryAutoContinueAfterFinalization`，证据缺失先自动续跑最多两次再收尾，维持 SRC 证据压力）。官方新测试 `plain_text_finalization_test.go` 适配本分支 6 参签名（`mcpExecutionIDs`/`taskStatus` 传 `nil`）。
  - **默认提示词范围收敛（062fd30c）**：官方将「高强度扫描要求」（火力全开/2000+ 步/绝不提前结束）改写为「任务范围与执行深度」（以用户本轮目标为边界、403/404 如实报告不自动扩大、达目标即收尾、不以赏金数量替代完成条件）。**本分支保留 SRC 化提示词原文**——授权 SRC 场景的持续挖掘与「不因 404/空响应结束」是二开定位，且铁律一「只测用户指定目标、禁止旁站/C 段扩展」已覆盖官方修复的范围纪律意图（文档化分歧，与 v1.7.20「本分支提示原样保留」同一处理）。
- **手机端 UI（8e00147d #344）整体采纳**：新增 `web/static/css/mobile.css`（3628 行：底部导航/侧边抽屉/手势/触控与软键盘/安全区适配）、`api-docs-mobile.css`、`web/static/js/mobile-ui.js`（1270 行）、`web/static/site.webmanifest`（主屏启动配置）、`scripts/mobile-*.mjs|json`（官方移动端审计脚本）；i18n 三语言各 +20 键；`index.html`/`api-docs.html` 三方合并零冲突；大依赖延迟加载。
- **官方前端测试落位适配**：官方位于 `web/static/js/*.test.cjs` 的 18 个新测试迁至本分支 `web/tests/`（官方测试以仓库根相对路径读源码，迁移无需改引用）。4 处适配：`c2-listener-form` / `knowledge-index-error` / `asset-export-language` / `workflow-save` 读取源码统一 `\r\n→\n` 规范化（官方测试以 `\n` 锚点 vm 切片源码，Windows autocrlf 检出下 `indexOf('\n\n')` 失败返回 -1）；后两者的 `__dirname` 相对路径对齐本分支 `web/static` 布局（js 与 vendor 路径）。官方对 `web/static/js/workflow-package-ui.test.cjs` 的两例新增测试（导入结果措辞/重复包确认语义）并入本分支迁移副本。
- **裁剪**：官方 `docs/bug-sheet-review.md` / `docs/bug-sheet-status.md`（官方 bug 清单过程文档）不入库；官方旧 HITL 体系新测试 `internal/handler/hitl_task_cancel_integration_test.go`（依赖本分支已移除的 `NewHITLManager`）裁剪——取消终态语义由 task_lifecycle/task_manager（已合入）+ 统一审批覆盖。`internal/security/nmap_argument_order_test.go` 按本分支惯例补 `//go:build !windows`（其依赖的 `setupTestExecutor` 在带同标签的本分支 executor_test.go 中）。
- **版本号（762f798a）**：`config.example.yaml` → `v1.7.22-src`，README 基线与本文件同步更新。
- 二开层完整保留：可复现强制、SRC 报告五块导出、FOFA 四引擎、漏洞全生命周期、统一审批、SRC 化默认提示词、18 角色 / 116 工具 YAML / 79 Skills 均未改动；`finalizationBlockedMessage` 新增官方 `workflow_rejected` 直出分支，与分支既有缺完成信号分支共存（生产端 `workflow_integration.go` 随 C 类文件落地）。

### v1.7.23 同步说明（2026-10-11）

官方 v1.7.22→v1.7.23 共 41 个提交：**应用内自更新（PR #346 + #347 恢复修复）整体采纳（默认源改指本仓库）+ 漏洞复测（PR #348）整体采纳（审批继承适配统一审批）+ 登录密码可见切换 + MCP 修复两处**；裁剪官方 CHANGELOG / README_CN / docs/feature 过程文档 / docs/en-US。34 个分歧文件三方合并，15 个含冲突逐处语义消解，非直接 merge。

- **应用内自更新（cb8bc6b8…e80668b2 + a3edab47 恢复修复）整体采纳**：新增 `internal/update/`（20 文件：adopt/apply/build/binary/lock（Unix flock + Windows）/paths/recovery_evidence/replace/rollback_pending/update/version）+ `internal/handler/update.go` + `cmd/server/update_cli.go` + `web/static/js/update.js`（设置页「系统更新」控制台：状态/预览/采纳/重启看门狗/中断回滚恢复）+ `update:read/update:apply` 权限与 `/system/update` 路由（进程级变更，assigned/own 会话不可触发）+ `.github/workflows/self-update.yml`。**适配点（安全关键）**：`DefaultRepoURL` 官方默认 `AIPentest/CyberStrikeAI.git` → **`https://github.com/langbyyi/CyberStrikeAI-SRC.git`**（官方注释明示 fork 改这一个值；不改则用户一键更新会拉官方主线、丢失整个 SRC 二开层），守卫测试同步；`upgrade.sh` 官方重构（resolve_repo：git 工作区同步 / `--repo` / 环境变量 / 内置兜底）落地，内置兜底 `DEFAULT_GITHUB_REPO` 同改本仓库；`.gitignore` 补 `.update-*` 运行时产物；run.sh 自动生成 config.yaml 行为随官方落地（README 契约测试 `TestReadmeQuickStartDocumentsAutomaticConfigCreation` 本分支 README 原文已覆盖）。
- **漏洞复测（6a673649 PR #348）整体采纳**：漏洞列表一键创建独立复测对话——`internal/database/vulnerability_retest.go`（快照式复制消息、`vulnerability_retests` 分支表、占位符 `{{vulnerability_id}}/{{conversation_id}}/{{source_conversation_id}}` 解析）、`internal/handler/vulnerability_retest.go`（权限链：漏洞读写 + 源对话读 + 项目范围 + 源运行中 409）、`update_vulnerability_status` MCP 工具（fixed/confirmed 状态 + 复测证据 append-only 落 `retest_log` 列）、`Vulnerability.RetestLog` 字段与 SELECT/Scan 全链补列、复测会话的 MCP `get_vulnerability` 授权走 `canAccessVulnerabilityForRetest`（源记录 + 项目边界）。**审批继承适配**：官方 `CreateVulnerabilityRetest` 的 `hitl_conversation_configs` 行复制带 sqlite_master 守卫，本分支无该表时空转——统一审批为全局 `approval:*` 配置，策略天然生效；官方 handler 测试剔除 `NewHITLManager` 依赖段（源会话配置预置与继承断言），保留权限流 403/409、占位符解析、PendingPrompt 持久化、GetConversation 恢复覆盖。
- **登录密码可见切换（d590cdd7）**：登录输入框内可达性切换按钮（`auth.js`/`index.html`/i18n/`password-feedback.test.cjs` 迁移副本并入官方新增断言）。
- **MCP 修复**：外部 MCP start/stop 激活标志一致（ff50af02）、stop 状态保留 + 恢复证据先验证后变更（fab7e603）。
- **官方测试落位适配**：4 个新前端测试迁 `web/tests/`；`permission-gate-state`/`router-hash-form` 的 `__dirname` 路径对齐（后者 docs 断言剔除 en-US 条目）；`update-ui` 构建时间日期断言放宽为 M/D/Y 与 Y/M/D 两序皆可（官方按 en-US CI 写死 M/D/YYYY，zh-CN 环境 `toLocaleDateString` 输出 Y/M/D——测试侧放宽，运行时零改动）；3 个 X 类官方测试（chat-scroll-refresh / hitl-approval-ui / hitl-conversation-isolation）的官方修改并入本分支迁移副本——缓存版本号断言泛化采纳，hitl.js 默认配置流新契约断言不采纳（本分支 hitl.js 已瘦身，流程由统一审批取代）。
- **裁剪**：`CHANGELOG.md`（官方版本账本，本分支以 git log + SRC二开.md 记录）、`README_CN.md`（更早已裁）、`docs/feature/login-password-eye.md` / `docs/feature/self-update-recovery-fixes.md`（官方过程文档）、`docs/en-US/{deployment,developer-guide,rbac}.md`（英文文档目录更早已裁）；`README.md` 保留本分支版本（官方对 README 的自更新描述不入库）。
- **版本号（8ce62813）**：`config.example.yaml` → `v1.7.23-src`（并采纳官方对 version 字段的「一键更新后同步 config.yaml 版本号」注释）。
- 二开层完整保留：可复现强制、SRC 报告五块导出、FOFA 四引擎、漏洞五工具生命周期（与官方 `update_vulnerability_status` 并存）、统一审批（`approval:*` 目录未动，仅新增 `update:read/apply`）、SRC 化默认提示词、18 角色 / 116 工具 YAML / 79 Skills 均未改动。

**同步后审计（2026-10-11，三方合并探测法全量扫描 v1.7.21→v1.7.23 全部 209 个官方变更文件）**：

- **149 个文件与官方 v1.7.23 完全一致（UPTODATE）、0 个可干净重放的遗漏（GAP）**；23 个 DIVERGED 全部为有意分歧（SRC 扩展列/五工具、默认源改指本仓库、提示词保留、审批体系差异、版本号后缀），逐项以官方新增行覆盖率核对——除有意替换的 6 行（官方默认仓库地址 ×2、版本号、hitl 测试依赖、日期断言、`__dirname` 路径适配）外，官方增量 100% 在位。
- **修复两处 v1.7.23 合并残留**：
  - `internal/database/database.go` 的 `migrateVulnerabilitiesConversationFK` 中 `copyRows` 的 INSERT 列表因合并拼接出现 `evidence, impact, recommendation, retest_notes` 四列重复（SQLite 容忍重复列且两侧取值相同、功能无异常，但属脏 SQL），已去重并规整为「官方列块 + 本分支 SRC 列块 + retest_log」单份顺序。
  - `web/tests/chat-scroll-refresh.test.cjs` 补最后一处官方泛化断言（`style.css?v=[A-Za-z0-9._-]+`，原残留字面 `20260907` 锚点）。
- 官方 `main` 分支在 v1.7.23 之后有 8 个未发版提交（SQLite 启动时表/列对账 `7f8dab4e` 及过程文档），**属下一版本范围，本次不跟**；发布后再评估。
- 官方 98de0859「同时间戳消息收尾」修复落点在官方旧 `handler/hitl.go`（本分支已裁），等价语义由本分支统一审批 `approval` 包承担：`MigrateLegacyHITL`（每次启动幂等迁移遗留 HITL 历史）+ `CancelUnrecoverable`（启动时将不可恢复的 pending/approved 审批置 cancelled，「process restarted」）已覆盖官方修复意图；消息排序本分支全链为 `ORDER BY created_at, rowid`（官方修复的正是该 tie-breaker 语义），无缺口。

### v1.7.24 同步说明（2026-10-16）

官方 v1.7.23→v1.7.24 共 82 个提交（含 5 个 PR 合并）：**声明式 Schema 启动对账（7f8dab4e 等 F0-F3 全套）整体采纳并做 SRC 扩展列适配 + 项目续跑（#361）整体采纳 + 黑board 上下文记忆与压缩检查点（#355）整体采纳 + Token 用量监控（#354）整体采纳 + 移动端项目 UI 修复（#360）整体采纳 + SQLite 并发锁等待加固（#362）直接合入 + 攻击链节点实证与上下文摘要 + 工具拦截乐观并发 + REST 空列表/404 语义 + 手工漏洞独立创建 + RBAC 角色会话定点吊销 + 任务超时归类**；裁剪官方过程文档 12 份；非直接 merge，按文件三方合并（base=official-v1.7.23）。

- **声明式 Schema 启动对账（v1.7.24 头号变更）整体采纳 + SRC 适配**：官方把逐表 `migrateXxxTable()` 增量迁移整体替换为声明式 schema——新增 `internal/database/schemas/application.sql`（51 表 + 89 索引，`CREATE TABLE`/`CREATE INDEX` 全集）与 `schemas/knowledge.sql`，`internal/database/schema_reconcile.go` 的 `reconcileSchema()` 在启动时对照参考库补齐缺表/缺列/缺索引（保留额外列与数据、事务内全有或全无），`schema_legacy.go` 保留漏洞外键语义重建（动态保留旧库额外列）。`database.go` 从 1800+ 行瘦身为 277 行：`initTables()` 只剩 `reconcileSchema(applicationSchema)` + 数据回填 + 外键语义迁移。**SRC 适配（关键，缺则新建库丢列）**：本分支 9 个 SRC 漏洞列（`category / auth_required / test_account / test_password / vuln_urls / network_segment / developer / poc_script / tool_call_id`）、`projects.testing_specification_json`、两张测试规范表（`conversation_testing_specifications` / `batch_testing_specifications`）均补进 `application.sql`；`initTestingSpecifications()` 保留为启动钩子（触发器创建与存量冻结回填属行为迁移，非结构声明）。
- **项目续跑（#361）整体采纳**：新增 `internal/project/resume.go`、`internal/projectprompt/resume.go`、`internal/project/workspace_inventory.go`（工作文件候选清单，最多 4000 字符预算）、`internal/project/blackboard_refresh.go`；`fact_index_*` 预算与续接补充纳入同一索引预算；文件事实与索引链接重构（`fact_body_links.go` / `fact_index_links.go`）。
- **黑board 上下文记忆 + 压缩检查点（#355）整体采纳**：`internal/multiagent/eino_context_checkpoint.go`（压缩时自动存 tentative note，每会话/代理一条，不替代已确认事实）、`internal/agent/generated_context.go` 与 `internal/multiagent/eino_generated_context.go`（系统生成摘要标注来源，不计入原始用户意图）、按会话 scoped memory；配置新增 `project.context_checkpoints`（默认 true）。
- **Token 用量监控（#354）整体采纳**：新增 `internal/database/model_token_usage.go`（结构化聚合表 + 回填）、`internal/openai/eino_usage_normalizer.go`、`internal/multiagent/eino_run_usage_accumulator.go`；前端新增 `web/static/js/token-usage.js` + 设置页 Token 明细与看板缓存命中率；`web/static/js/attack-chain-context.js`（压缩摘要与证据线索卡片）。
- **移动端项目页修复（#360）整体采纳**：`mobile.css` 表头遮挡、横向滚动至末行、事实列可读性；官方新增 `scripts/project-mobile-layout.test.cjs`（Playwright 离线回归）一并入库。
- **SQLite 并发加固（#362）直接合入**：`internal/database` 事务锁等待边界 + 资产 upsert 忙等重试（`transaction_lock_test.go` 覆盖）。
- **工具拦截乐观并发（#351）直接合入**：`tool_guard` 规则保存带 `If-Match` 版本号，陈旧保存返回 `tool_guard_conflict` 且保留草稿；`internal/handler/tool_guard.go` 与前端 `tool-guard.js` 同步；官方测试 72 行新增并入 `web/tests/tool-guard.test.cjs`（36 项全通过）。
- **REST 语义归一（9f111a13）直接合入**：`DELETE /api/c2/profiles/:id`、`DELETE /api/webshell/connections/:id` 不存在返回 404 与固定文案；`GET /api/vulnerabilities`、`GET /api/batch-tasks` 空结果由 `null` 改 `[]`；`docs/zh-CN/api-reference.md` 新增「删除与空列表响应约定」一节。
- **手工漏洞独立创建（a8321c4b）直接合入**：允许无对话的独立漏洞录入并校验关联；前端 `vulnerability.js` 的会话 ID 裁剪与空值提交，官方测试迁址 `web/tests/vulnerability-create.test.cjs`。
- **RBAC 角色会话定点吊销（088d6da3）直接合入**：角色权限/范围变更仅吊销受影响角色会话（`RevokeRoleSessions`，替代全量 `RevokeAllSessions`），`UpdateRole`/`DeleteRole` 加 `roleMu` 串行化 + 权限快照比对。
- **任务超时归类（5ff781bd）直接合入**：新增 `internal/handler/task_deadline.go`，区分任务级 deadline 与子操作超时（子操作超时不再误杀整个任务）。
- **攻击链实证与摘要**：`internal/attackchain/node_evidence.go`（节点对照真实工具调用核验）、`context_summary.go`（压缩摘要进攻击链上下文）；前端 `chat.js` 的 `renderAttackChain` 采纳官方上下文卡片渲染，**本分支 async 签名保留**（ELK 按需加载依赖 await），官方防串台重构（`beginAttackChainRequest` / `isCurrentAttackChainRequest`）随之落地。
- **适配合并**：
  - `go.mod`：官方 eino 系列升级全采纳（`eino v0.9.14→v0.9.21`、`agenticclaude v0.1.3→v0.1.7`、`agenticopenai v0.2.1→v0.2.4`、`acl/openai` 新伪版本、`openai-go/v3 v3.35.0→v3.44.0`），其余依赖取本分支较新版本（gin 1.12.0 / zap 1.28.0 / x/crypto 0.54.0 等），`go mod tidy` 归一。
  - `web/static/i18n/{zh-CN,en-US}.json`：官方新增键并入，同时补 `hitl.reviewerManual`（并入的官方代码引用）；官方 41 个 HITL 前端键按本分支精简策略跳过（统一审批无人机协同页语义）。
  - `web/templates/index.html`：脚本区取并集——官方新增 `attack-chain-context.js` / `token-usage.js`，本分支保留 `chat-images.js` / `approval-ui*.js`；样式与脚本缓存版本号统一到官方新值。
  - `internal/handler/hitl.go` / `hitl_logs.go`：官方把建表交给声明式 schema，`EnsureSchema` 只留 `backfillHitlReviewers`；本分支这两个文件早已裁撤（统一审批取代），对应 reviewer 默认值改动落在 `application.sql`。
  - 官方 X 类 5 个测试（chat-scroll-refresh / hitl-approval-ui / tool-guard / turn-duration-refresh / update-ui）增量并入本分支 `web/tests/` 迁移副本：monitor 缓存版本号断言更新、`reviewer TEXT` 断言改指 `application.sql`、tool-guard 乐观并发 2 用例、`cacheWriteTokens` 断言、update-ui alias 正则泛化。
  - `internal/project/workspace_inventory_test.go`：官方 e21ac52b 已做文件名可移植化，本分支补 symlink 不可用时的 `t.Skipf` 守卫（Windows 本地无 `SeCreateSymbolicLinkPrivilege` 时官方 CI 之外会失败，官方 CI runner 有该特权）。
- **裁剪**：官方过程文档 12 份——`docs/feature/{rest-error-empty-results,russian-layout-overflow,task-timeout-classification,tool-guard-conflict-detection}.md`、`docs/feature/startup-schema-reconcile/`（6 份）、`docs/fixes/{P-026-role-session-revocation,manual-vulnerability-create}.md`（本分支以 git log + 本文件记录，不收录过程文档）；`docs/en-US/{api-reference,rbac}.md` 等英文文档目录不收录。
- **版本号（4ca8b7d3）**：`config.example.yaml` → `v1.7.24-src`（并采纳官方 `project.context_checkpoints` 注释与 `fact_index` 预算说明）。
- 合并后审计（165 个官方变更文件三方探测）：**104 个与官方 v1.7.24 完全一致（UPTODATE）、28 个官方增量干净并入（UPDATED）、8 个 DIVERGED 全部为有意分歧（版本号/`go.mod` 依赖策略/`go.sum`/SRC 列 schema/`chat.js` 本分支队列与 async 签名/`style.css` 并集/`index.html` 并集）、25 个裁剪或迁址**，0 个遗漏。
- 二开层完整保留：可复现强制、SRC 报告五块导出、FOFA 四引擎、漏洞五工具生命周期（与官方 `update_vulnerability_status` 并存）、统一审批（`approval:*` 目录未动，批量任务策略覆盖不变量保持）、SRC 化默认提示词、18 角色 / 116 工具 YAML / 79 Skills、前端资源按需加载与多模态图片直发均未改动。

### 跟进官方 v1.7.24 未发版修复：FOFA region 返回字段（2026-10-17）

官方 v1.7.24 发布后有 12 个提交，其中唯一代码修复 `0c0d4a53`「use supported FOFA region return field and preserve asset location」直接命中本分支招牌特性，已完整跟进；其余 11 个为文档（含官方 process journal 清理与双语翻译，本分支不收录）。

- **问题**：FOFA 官方 API 的返回字段清单里没有 `province`（该值以 `region` 导出）。本分支 FOFA 默认字段、Web 端默认值与两套预设都在用 `province`，请求会因字段不受支持而失败——空间测绘主链路受影响。
- **修复**（逐文件跟进官方）：
  - `internal/handler/fofa.go`：默认字段 `province` → `region`；`req.Fields` 改用 `strings.TrimSpace` 判空（纯空白也走默认）；fofa 分支在调用 runtime 前先过 `normalizeFofaFields`。
  - 新增 `internal/handler/fofa_fields.go`：`normalizeFofaFields` 将旧表单/旧客户端传来的 legacy 别名 `province` 归一为 `region`，同时去重去空；按本分支包结构补入 `splitAndCleanCSV` 辅助（与 `internal/fofaruntime` 同名实现一致）。
  - 新增 `internal/handler/fofa_fields_test.go`（官方原样）：契约式上游 mock——对不支持的字段直接返 400，覆盖默认/空白默认/legacy 表单/别名去重/规范 region 五个子用例；已通过。
  - 前端：`web/static/js/info-collect.js`（默认字段 + 「Web 常用」「情报增强」两套预设改用 `region`/`asn`/`org`，并补 legacy 字段串的 provider 切换守卫）、`web/static/js/assets.js`（`fofaResultToAsset` 的省份来源改为 `region` 优先、保留 `province` 与 quake 的 `location.province_cn` 兜底）、`web/templates/index.html`（`#fofa-fields` 默认值）。
  - `tools/fofa_search.yaml`：字段清单同步为 `country,region,city,...,asn,org`。
  - 测试迁址：`web/static/js/fofa-fields.test.cjs` → `web/tests/fofa-fields.test.cjs`（`__dirname` 路径适配）。7 项通过，含 region/province/quake 三来源 × 对象/数组两种行格式的导入落省断言。
- **兼容**：旧客户端传 `province` 由后端归一，无需改动；已有保存的旧字段串在前端切换 provider 时会被重置为受支持默认值。
- 验证：`go test ./internal/... ./cmd/...` 全过；前端 `web/tests/` **407/407** 通过（新增 7 项）。

### v1.7.20 同步说明（2026-09-27）

官方 v1.7.19→v1.7.20 共 4 个提交：**2 个直接合入（含 1 个版本号）+ 1 个适配合并 + 1 个语义合并到统一审批**；另顺带收口一处官方同源的 supervisor 委派失效。逐提交与本地二开层比对后按语义合并，非直接 merge。

- **项目预览任务统计图标（8da3c8c5）直接合入**：`projects.js` 的刷新箭头 path 换成闭合圆环（`<circle r=8>`），`.project-folder-preview-stats svg` 由 15px 改 16px 并加 `overflow: visible`，官方断言并入 `web/tests/project-folder-preview.test.cjs`。
- **Eino exit/transfer 在 AgenticMessage state 上工作（3aa92746）适配合并**：
  - 官方问题：Eino v0.9.14 的 `adk.ExitTool` / `transfer_to_agent` 通过 `SendToolGenAction` 写 `typedState[*schema.Message]`，Agentic 主路径的 state 是 `typedState[*schema.AgenticMessage]`，`compose.ProcessState[*adk.State]` 取不到而失效。官方方案是新增反射式状态访问 + `agenticCompatibleExitTool` + 拦截 exit/transfer 的工具中间件。
  - **本分支不替换 exit 实现**：二开层早已用自有 `einoAgenticExitTool`（ReturnDirectly + 显式完成协议，见 `eino_completion_contract.go` 注释）解决同一问题，替换会改动已验证的完成协议与 `einoCompletionTracker` 判定，风险大于收益。
  - **采纳反射式 helper**（`internal/multiagent/eino_agentic_react_state.go`）：`mutateADKReactState` 以 `ProcessState[any]` 取最内层 react state，`clearADKReturnDirectly` 借反射清 `ReturnDirectlyToolCallID` / `HasReturnDirectly` / `ReturnDirectlyEvent`。本分支 `hitlClearReturnDirectlyIfTransfer` 原先直接 `compose.ProcessState[*adk.State]`，在 Agentic 主路径上类型不匹配、错误被 `_ =` 吞掉——即该守卫一直是静默 no-op；改后经典与 Agentic 两种 state 都真正生效（`eino_agentic_react_state_test.go` 两种形状各一条断言）。注意 `transfer_to_agent` 属 HITL 内置免审批元工具（`HitlExemptMetaTools`），该守卫当前是防御性路径而非必经路径。
  - **修复 supervisor 委派失效（官方同源既有缺陷，本次一并收口）**：官方 transfer 拦截中间件的前提是 `transfer_to_agent` 已在 tools 索引里，而上游 supervisor 走 `supervisor.New → adk.SetSubAgents`（classic `[]adk.Agent` 接口），本分支监督者是经 classic 适配层包装的 `TypedChatModelAgent[*schema.AgenticMessage]`，命不中 `adk.OnSubAgents`，子代理从未注册进 ChatModelAgent —— transfer 工具与交接指令都不存在，委派整体失效（实测报 `tool transfer_to_agent not found in toolsNode indexes`，子代理 0 次调用）。修法：`bindAgenticSupervisorSubAgents`（`eino_agentic_builtin_action.go`）在包装成 classic 前按 typed 接口 `OnSetSubAgents` 补注册；同一文件新增 `agenticTransferToolMiddleware`（挂在工具中间件链最内侧、审批之后）接管 `transfer_to_agent`，用反射写当前实时 state（`sendADKToolGenAction`），替代只会写经典 Message state 的官方实现。只注册子代理、不给子代理挂 parent transfer，返回路径继续由 `supervisor.New` 的 `AgentWithDeterministicTransferTo` 负责。回归测试 `eino_supervisor_transfer_test.go` 覆盖去程/回程动作事件、子代理真实被调用、完成信号与边界（未注册时不委派）。
  - 该修复带来的一处提示词叠加：Eino 在注册子代理后会自行追加官方交接指令（含子代理名 + 描述，并要求“移交时只输出函数调用”），与本分支 supervisor 提示里“在助手正文写交接包”的要求并存；本分支提示原样保留（路由策略与交接包要求仍以它为准），实际委派质量建议在真实任务里观察。
- **TypeSafe Jev 作为 HITL 审计后端（38b96ec6）语义合并到统一审批**：
  - 新增 `internal/typesafe/client.go`（TypeSafe System One 客户端：noul/choice 问题、答案解析、APIError）与 `internal/hitl/jev.go`（内置破坏性问题集 + 组织策略 overlay、state 裁剪、`DecideJev` 代码侧裁定：破坏性 noul 与组织策略 noul 优先于渗透 payload noul，破坏分阈值 0.55），官方测试原样入库。
  - `HitlConfig.AuditBackend` + `EffectiveAuditBackend` / `TypeSafeConfigEffective` / `JevOperatorPolicy`：本分支只有统一审批一种模式，故 `JevOperatorPolicy` 不带 mode 参数；内置默认提示词与 Jev 问题语义重复，返回空串不写入 state。
  - `auditAgentReview` 顶部按后端分派，新增 `auditAgentReviewTypeSafe`（Key 必填且不继承主模型密钥、90s 超时、失败保守拒绝）。
  - **引擎信息的落库方式适配**：官方把 `auditBackend` / `auditModel` 塞进旧 `handler/hitl.go` 的 pending interrupt payload，本分支统一审批没有该字段。改用决定记录自带的 `metadata`（`approval_decisions.metadata_json` 已存在）：`approvalAgentReviewer.Review` 在裁决时写入 `{auditBackend, auditModel}`，`/api/approvals` 原样返回 `decisions[].metadata`，前端 `ApprovalUIModel.auditEngineFromDecision` 优先读 metadata、无 metadata 的老记录回退备注特征（`破坏分` / `choice=` / `TypeSafe`）识别。**无数据库结构变更**。
  - 配置读写：`/api/config` 暴露并归一化 `hitl.audit_backend`，配置回写 yaml 同步该键；新增 `POST /api/config/test-typesafe`（最小 Noul 连通性验证）与对应 OpenAPI 条目、路由注册。
  - 前端：设置页新增「审批引擎」下拉——选 Jev 时隐藏 OpenAI 提供商与「获取列表」，替换三个占位提示并显示 Jev/策略提示；人机协同页顶部显示当前引擎，审计日志在「审批方」列下与详情里标注该次裁决引擎；中英 i18n 与亮/暗主题样式齐备。
  - **裁剪**：官方审查编辑模式（review_edit）相关文案与键不收录（统一审批无该概念，`web/tests/approval-policy-ui.test.cjs` 守卫禁止该字符串出现在审批运行时文件）；官方 `hitl.strategyHintJev` 对应的人机协同页「审计策略」页签本分支已不存在，等价提示落在设置页策略框下方（`settings.hitl.auditPromptTypeSafeHint`）。
- **版本号（a89f21b4）**：`config.example.yaml` → `v1.7.20-src`，README 基线与本文件同步更新。
- **官方文件级映射与裁剪（39 个文件逐项核对：下列为需适配/裁剪项，末尾为可直接落地项）**：
  - 官方 `internal/handler/hitl.go`（pending payload 附 auditBackend/auditModel + `hitlDefaultConfigResponse`）、`hitl_logs.go`（日志行附引擎）在本分支不存在：统一审批的待审/日志数据来自 `/api/approvals`，引擎改由**决定记录 metadata**（日志）与 `/api/approval-config` 新增字段（当前引擎，复用 `approval:read`，不额外放开 `config:read`）提供，页面级引擎行因此对纯审批人也可用；官方“待审条目自带引擎”差异点已由页面级引擎行覆盖。
  - 官方 `internal/handler/hitl_audit_backend.go` / `hitl_audit_backend_test.go`：`hitlAuditEngineInfo` 并入 `hitl_audit_agent.go`（并导出 `AuditEngineInfo` 供审批页注入）；`stringifyHitlJSON` / `inferHitlAuditBackendFromComment` / `hitlAuditBackendFromRecord` 属展示逻辑，落到前端纯模块 `approval-ui-model.js`（`auditEngineFromDecision`）并由 `web/tests/approval-ui-model.test.cjs` 覆盖。
  - 官方 `internal/config/hitl_prompt_test.go` 的 `TestJevOperatorPolicySkipsDefaultPrompt` 并入本分支 `internal/config/config_test.go`。
  - 官方 `web/static/js/chat.js` 的改动含输入框侧栏审计模型标签（`currentHitlAuditEngineLabel()`）；本分支聊天侧栏已无该入口，故只保留 `/api/config` → `window.csaiHitlAuditBackend/Model` 的桥接（供人机协同页与日志展示）。
  - 官方 `docs/en-US/*`（configuration / hitl-best-practices）改动不跟进：本分支不收录英文文档目录，等价内容分别落在 `docs/zh-CN/configuration.md` 与 `docs/zh-CN/hitl-best-practices.md`。
  - 官方 `docs/zh-CN/MULTI_AGENT_EINO.md` 的变更行已补入（2026-09-27 两行：状态对齐 + supervisor 委派修复）。
  - 官方 `internal/multiagent/eino_agentic_chat_model_agent.go`（`replaceClassicExitTool` + 全局挂载内置动作中间件）**不跟进**：本分支不替换 exit、中间件只在 supervisor 分支挂载（见上条「本分支不替换 exit 实现」）。
  - 官方新文件 `internal/multiagent/eino_agentic_builtin_action_test.go` **不逐字跟进**：其 `ExitTool` / `agenticCompatibleExitTool` 用例建立在本分支不采用的 exit 实现上；等价行为由本分支 `eino_agentic_react_state_test.go`（反射状态读写）与 `eino_supervisor_transfer_test.go`（中间件接管 + 委派 e2e）覆盖。
  - 官方 `web/static/js/hitl.js` 中的人机协同页逻辑在本分支分居两处：页面/待审/日志在 `web/static/js/approval-ui.js`（纯逻辑在 `approval-ui-model.js`），i18n 与 API 辅助留在 `hitl.js`；对应断言并入 `web/tests/hitl-approval-ui.test.cjs`。
  - **可直接落地项**（无适配分歧）：`internal/app/app.go`（test-typesafe 路由）、`internal/config/config.go`、`internal/config/config_test.go`、`internal/handler/config.go`（TestTypeSafe / UpdateConfig / yaml 回写）、`internal/handler/hitl_audit_agent.go`、`internal/handler/hitl_audit_agent_test.go`、`internal/handler/openapi.go`、`internal/hitl/jev.go` 与 `jev_test.go`、`internal/typesafe/client.go` 与 `client_test.go`、`internal/multiagent/eino_agentic_react_state.go`、`internal/multiagent/hitl_middleware.go`、`internal/multiagent/runner.go`、`web/static/css/style.css`、`web/static/i18n/zh-CN.json` 与 `en-US.json`、`web/static/js/i18n.js`、`web/static/js/projects.js` 与其测试、`web/static/js/settings.js`、`web/templates/index.html`。
- 二开层完整保留：可复现强制、SRC 报告五块导出、FOFA 四引擎、漏洞全生命周期、bannerHosts、统一审批（工作流 / 批量任务 / MCP 双路径接入）、18 角色 / 116 工具 YAML / 79 Skills 均未改动；本次新增 `internal/typesafe/`、`internal/hitl/jev.go`，以及 multiagent 侧的 `eino_agentic_react_state.go`、`eino_agentic_builtin_action.go`（含各自测试与 `eino_supervisor_transfer_test.go`），并修正 `clearADKReturnDirectly` 的 Agentic 路径；`internal/handler/approval_decide_test.go` 另补两条引擎字段测试。
**本分支的硬门**：可复现强制（#1）+ 敏感接口硬闸（`sensitive_http_gate`，防不可逆写操作）。

## 部署

```bash
./run.sh                                    # 官方启动脚本（Go 1.25+）
# 首次启动服务端会自动从 config.example.yaml 生成 config.yaml，填入模型/API 配置后重启即可
```

- 空间测绘：`fofa/zoomeye/quake/shodan` 段填 `api_key`（高级字段见 `config.example.yaml` 的 `fofa` 段）
- 联网搜索：`websearch.api_key`（Tavily）
- 版本号：`config.yaml` 的 `version` 字段，前端展示

## 与官方合并

本分支以官方发布标签为基座，二开均为叠加层（漏洞/报告/FOFA/技能/Tavily）+ 治理层剔除。官方后续升级按提交语义合并执行核心，二开层独立维护。

- 仓库：`https://github.com/langbyyi/CyberStrikeAI-SRC`
- 升级：`./upgrade.sh`（默认拉取本仓库最新 release，保留 `config.yaml` / `data/` / `venv/` / `tools/` / `roles/` / `skills/`）
