# CyberStrikeAI-SRC 二开特性

> 当前分支：**v1.7.19-src**
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
