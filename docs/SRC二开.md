# CyberStrikeAI-SRC 二开特性

> 当前分支：**v1.7.20-src**
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
  - Eino 跨中断轮次记忆（`internal/multiagent/eino_turn_history.go`）：TurnLoop GenInput 在纯提示词续跑时前置历史轮消息（官方修复 issue #121）；与本分支 `PushInterruptContinueWithTrace` 轨迹前置机制通过 `einoItemsCarryInterruptTrace` 守卫协调——轨迹已随 item 携带时跳过 history 前置，两套机制互不重复
  - SSE 错误规范化（`internal/openai/eino_sse_error.go`）：流式响应错误事件统一转结构化错误
  - 摘要模型守卫增强（`eino_summarize_model_guard.go`）
  - supervisor 退出优先 final_result（`eino_exit_fallback_test.go` 跟进）
- **适配合并**：
  - 启动 banner 多地址（官方 #307）：本分支 bannerHosts 为其超集（含优选出口 IPv4 + IPv6 括号），保留二开实现，官方测试并入 `startup_test.go`；`PrintStartupWebUI` 拆出 `printStartupWebUI(out, opts)` 可测缝
  - **批量任务审批策略（ac101d84）移植到统一审批**：官方基于已废弃的旧 `handler/hitl.go` 体系（HITLRequest / hitlManager / WithHITLToolInterceptor），本分支已替换为 `internal/approval/` 统一审批，直接合并产生 8 处编译错误。移植方案：新增 `approval.TaskPolicyOverride` 上下文覆盖（`internal/approval/context.go`）——`Disabled`（off 直通不落单）/ `RequireApproval`（human / audit_agent 强制审批）/ `Reviewer` 覆盖审批人，仅随请求 context 生效，**不修改 GlobalRuntime 全局快照**（守卫测试 `task_policy_override_test.go` 锁定该不变量）；`batch_queue_executor.go` 在任务级 context 注入 override 后挂接既有 `withApprovalToolInterceptor`。**review_edit 选项剔除**：统一审批架构中该概念已显式移除（前端守卫测试禁止该字符串），批量策略仅支持 inherit / off / human / audit_agent
- **sudo 测试增强（4d53717c）直接合入**：`shell_execute_stream_test.go` 以 mock sudo 替代对主机 sudo 策略的依赖（精确匹配 `sudo: a password is required` + exit code 校验 + 后续命令不得执行），fork 侧保留 `//go:build !windows` 构建标签与 NOPASSWD skip 前置；`.gitignore` 补 `/vendor/`（569513f3）已并入
- **裁剪策略已达成**：微信二维码更新（7f5c092e）与赞助内容移除（eca26f0e）——本分支更早已删除宣传 QR 图与 `README_CN.md`，官方动作与本分支现状一致，无需变更
- **文档/前端**：批量 HITL 策略下拉移除 review_edit 选项（`index.html` / `tasks.js` / 中英 i18n）；`config.example.yaml` 版本号 → `v1.7.19-src`；README 基线更新；裁剪策略继续执行（官方宣传 QR 图、`docs/en-US/tool-execution-governance.md` 等不入库）

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
cp config.example.yaml config.yaml          # 填入模型/API 配置后运行
```

- 空间测绘：`fofa/zoomeye/quake/shodan` 段填 `api_key`（高级字段见 `config.example.yaml` 的 `fofa` 段）
- 联网搜索：`websearch.api_key`（Tavily）
- 版本号：`config.yaml` 的 `version` 字段，前端展示

## 与官方合并

本分支以官方发布标签为基座，二开均为叠加层（漏洞/报告/FOFA/技能/Tavily）+ 治理层剔除。官方后续升级按提交语义合并执行核心，二开层独立维护。

- 仓库：`https://github.com/langbyyi/CyberStrikeAI-SRC`
- 升级：`./upgrade.sh`（默认拉取本仓库最新 release，保留 `config.yaml` / `data/` / `venv/` / `tools/` / `roles/` / `skills/`）
