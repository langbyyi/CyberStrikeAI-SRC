# CyberStrikeAI-SRC 二开特性

> 当前分支：**v1.7.17-src**
> 基于 [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) 官方主线，聚焦**授权 SRC / 漏洞挖掘**方向：在官方完整平台之上做定向增强（可复现强制、SRC 报告、FOFA 多引擎、漏洞全生命周期、Tavily 联网搜索），并剔除压制 agent 自主性的治理层。

## 特性总览

| # | 特性 | 一句话 | 关键代码 |
| --- | --- | --- | --- |
| 1 | 可复现强制 | 无工具探测证据的漏洞禁止落库 | `internal/app/vulnerability_tools.go` |
| 2 | SRC 漏洞报告 | 9 个 SRC 字段 + 3 套导出模板 | `internal/handler/vulnerability_report.go` |
| 3 | FOFA 多引擎 | fofa/quake/shodan/zoomeye 原生协议 + 双通道 | `internal/fofaruntime/` |
| 4 | 漏洞全生命周期 | record/list/get/update/delete 五工具 | `internal/app/vulnerability_tools.go` |
| 5 | Skills / Roles | 64 Skill + 15 角色 | `skills/` `roles/` |
| 6 | ddddocr | 验证码/滑块 OCR | `tools/ddddocr.yaml` |
| 7 | issue#2 修复 | 孤儿 tool 消息规范化防网关 400 | `internal/multiagent/orphan_tool_pruner_middleware.go` |
| 8 | Tavily 联网搜索 | Agent 可用的 web_search 工具 | `internal/app/web_search_tool.go` |
| 9 | Eino 显式完成协议 | 过程说明不再被误判为最终回复 | `internal/multiagent/eino_completion_contract.go` |

## 核心二开（相对官方）

### 1. 可复现强制（防编造漏洞）
官方 `record_vulnerability` 仅在 prompt 提示"可复现"，无强制。本分支在落库前校验：**本会话必须对该漏洞目标完成过真实工具探测**（`tool_executions` 表 status=completed，且目标 host 出现在某次非管理类工具的参数/输出中），否则拒绝记录。
- 实现：`internal/app/vulnerability_tools.go` → `reproducibleEvidenceExists`；`internal/database/monitor.go` → `CompletedProbeEvidenceForConversation`
- 测试：`TestReproducibleEvidenceExists`（无执行拒 / 已探测放行 / 未测目标拒 / 仅 record 工具拒 / 未完成拒）

### 2. SRC 漏洞报告（字段 + 模板 + 导出选模板）
- **数据模型**：`Vulnerability` 补 9 个 SRC 字段——`category / auth_required / test_account / test_password / vuln_urls / network_segment / developer / poc_script / tool_call_id`（含 DB 列 + 迁移）
- **报告模板**：导出支持 `generic / enterprise_src / edusrc` 三套，导出时 `c.Query("template")` 选择；基本信息表字段统一，仅措辞皮肤不同（风险等级/漏洞等级/严重程度）
- **基本信息表**：漏洞类型、SRC 分类、风险等级、目标系统/接口、漏洞地址（多行）、认证要求、测试账号、测试密码（明文，供 SRC 审核复现）、网段、状态、漏洞 ID；正文含描述、前置条件、复现步骤、证据/PoC、一键复现脚本、实际影响、修复建议、复测说明

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
- **64 个 Skill**（官方 v1.7.17 为 23 个）：新增 SRC 细分漏洞方法 playbook 包（sqli / xss / ssrf / idor / jwt / 命令注入 / 越权 / 业务逻辑 / OAuth 等 OWASP 全类型，部分含 SCENARIOS.md 与 references/），`unlimited-attack-scope` 改写为 `authorized-attack-scope`，移除官方 demo 包
- **15 个角色**：渗透 / CTF / API / Web 应用扫描 / 信息收集 / 后渗透 / EDUSRC / 企业 SRC 等，含完整 `user_prompt` + 工具白名单（已清死工具引用、补齐 web_search）

### 6. ddddocr 验证码识别
`tools/ddddocr.yaml`（自动发现）：OCR 文字验证码 / 点选检测 / 滑块缺口定位，用于登录爆破、密码重置、注册绕过等场景。

### 7. issue#2 修复（orphan tool 消息规范化）
移植自 v1.6.52-src commit 7251738：`orphan_tool_pruner_middleware` 规范化 assistant(tool_calls)/tool 消息回合——删孤儿/失序/重复 tool 消息 + **对缺失 result 补取消占位**，消除火山方舟 Coding Plan 等网关在"工具返回 → 下一次模型调用"节点的偶发 400。挂载于 `eino_chat_model_tail_middleware.go`，位于 summarization/reduction/tool_search 之后、ChatModel 调用之前。

### 8. 通用联网搜索（Tavily）
`websearch` 配置段 + `web_search` MCP 工具（Agent 可用）：Tavily API 驱动，`enabled: false` 可整体关闭；支持 `TAVILY_API_KEY` 环境变量与自定义 `base_url`、`max_results`、`timeout_seconds`。授权 `asset:read`。

### 9. Eino 显式完成协议

Eino single、deep、supervisor 只有在根 Agent 的内部 `exit(final_result=...)` 工具真实执行并返回后才允许最终化；计划和进度正文继续实时显示，但保持 `commentary`，不会触发“最终回复检查通过”。Plan-Execute 使用框架的确定性完成事件。缺少完成信号时从已有模型轨迹最多续跑两次，不重放已完成的工具调用；`use of closed network connection`、`net.ErrClosed` 和 `io.ErrUnexpectedEOF` 纳入当前模型调用的瞬时网络重试。该协议不修改 MCP 工具、RBAC、HITL、Tool Search、迭代预算或执行证据策略，漏洞挖掘与子 Agent 执行能力保持原路径。

## 与官方版本及本仓库历史的关系（对照核实）

**对比基准与结论均经代码检索核实**（2026-08-25，`git diff v1.7.17 HEAD`）：

1. **官方 v1.7.17**（Ed1s0nZ/CyberStrikeAI，tag `v1.7.17`）：官方不含本分支的二开层组件（`internal/fofaruntime/`、`web_search_tool.go`、`vulnerability_report.go`、`sensitive_http_gate.go` 等对官方代码 0 命中）。本分支以官方为基座叠加二开增强。

2. **本仓库 v1.6.48-51-src 历史**：曾引入治理层 `execution_controller` / `skill_router` / `session_intent` / `depth_force` / `evidence_policy` / `semantic_outcome` / `tool_exec_governor` 等。**v1.7.11-src 将其全部移除**，回归官方精简形态；后续 `fofa.icu` 硬编码代理、启动注入 FOFA 环境变量、batch-delete 路由补注册、漏洞表缺失列补全等历史修复，也已被官方 v1.7.13~v1.7.16 同步吸收或由更通用的实现取代（多端点 `FofaConfig.Endpoints[]`、运行时直读 `FOFA_API_KEY` 等），不再构成现存差异。

**与官方 v1.7.17 的全量差异**（实测）：314 个文件变更——新增 122、修改 159、删除 32、重命名 1（+34605/-3832 行）。要点：
- 新增 `internal/fofaruntime/` 四引擎 Go 原生运行时（fofa/quake/shodan/zoomeye，1616 行含测试）与旧域名自动迁移容错
- 新增 `web_search_tool.go`（Tavily）、`vulnerability_report.go`（SRC 报告导出 +3 测试）、`sensitive_http_gate.go`（硬闸）
- 漏洞链路强化：三要素/PoC prompt 重写、可复现门禁 host 边界匹配、转义归一化判定开关、SRC 扩展 DB 列
- multiagent：中断续跑携带模型可见轨迹、tool_search 常驻/非常驻分组注入、运行中摘要修正
- skills 净增 45 包（62 文件）、33 个新工具 yaml、5 个新角色（roles 补 web_search 17 处）
- 删除：官方宣传图、README_CN.md、SECURITY.md、插件 dist 二进制、demo/unlimited-attack-scope 技能包

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
