<div align="center">
  <img src="images/logo.png" alt="CyberStrikeAI-SRC" width="160">
</div>

# CyberStrikeAI-SRC

> 基于 [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) 的二开分支，专注**授权 SRC 漏洞挖掘**方向。

## 这是什么

[CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) 是一个 **AI 原生安全测试平台**（Go 实现）：通过 MCP 协议与 AI Agent，把自然语言指令编排成端到端的安全测试流程——从侦察、扫描、漏洞挖掘、攻击链分析到结果可视化，提供可审计、可追溯、可协作的测试环境。

本仓库是其**二开分支**，在完整平台能力之上，专注 SRC 漏洞挖掘方向做定向增强。

### 核心能力

- **AI 决策引擎**：兼容 OpenAI 协议（GPT / Claude / DeepSeek / GLM 等）
- **90+ 内置工具**：覆盖完整 kill chain（nmap、masscan、sqlmap、nuclei、subfinder、fofa_search 等）
- **智能编排（CloudWeGo Eino ADK）**：单代理模式，支持上下文摘要、检查点续跑、瞬态重试
- **角色化测试**：渗透 / CTF / EDUSRC / 企业 SRC 等 15 个预设角色，按场景定制提示与工具集
- **Skills 技能库**：47 个漏洞方法 Skill，覆盖注入 / 上传 / 越权 / IDOR / 业务逻辑 / OAuth 等 OWASP 全类型
- **漏洞全生命周期**：record / list / get / update / delete，5 工具齐全
- **知识库（RAG）**：向量检索 + 自动索引
- **Web UI、审计日志、SQLite 持久化**；批量任务、会话分组、人机协同（HITL）

> 界面预览、插件、完整配置与工具清单请参阅官方仓库；本 README 侧重本分支的**差异与 SRC 定位**。

## SRC 方向的增强

- **可复现强制**：`record_vulnerability` 落库前校验本会话对该目标的真实完成工具探测证据，杜绝编造/不可复现漏洞入库。
- **SRC 漏洞报告**：补 9 个 SRC 提交必备字段（category / auth_required / test_account / test_password / vuln_urls / network_segment / developer / poc_script / tool_call_id），支持 `enterprise_src` / `edusrc` / `generic` 三套模板，**导出时选模板**。
- **FOFA 多引擎 agent 工具**：`fofa_search` MCP 工具原生支持 fofa / quake / shodan / zoomeye 四引擎协议 + 自然语言转查询语法（官方仅有 HTTP handler，agent 无法调）。
- **ddddocr 验证码识别**：OCR 文字验证码 / 点选定位 / 滑块缺口，配合登录爆破等场景。
- **提示词 SRC 化**：四条铁律 + 分级记录 + 攻击面优先级 + 利用链 + 赏金心态，针对授权 SRC 场景优化。
- **orphan tool 消息规范化**：修复工具返回后偶发网关 400（移植自 v1.6.52-src）。
- **剔除治理层**：移除 execution_controller / skill_router / session_intent / coverage / finalization / depth_force / evidence_policy 等 ~20 个控制层，释放 agent 链式挖掘自主性。保留可复现 + 敏感接口两道硬门。
- **浏览器交互式挖洞**：`browser-assisted-hunting` skill 提供双账号越权对比 / DOM XSS 渲染取证 / 验证码登录 / 前端隐藏功能绕过打法，`external_mcp` 一段配置接入 Playwright 官方 MCP（示例见 config.example.yaml），浏览器工具调用同样计入可复现证据链。
- **弱模型报告净化**：双重转义的字面换行写库前统一还原（已含真实换行的字段跳过、Windows 路径与凭据字段保护），导出文件名分类前缀去重，复现步骤强制 Step 1 起步。

## 已同步官方更新

- **v1.7.14-src（对应官方 v1.7.14）**：Eino 框架升级 v0.9.14 + Agentic 模型组件（`agenticopenai`），单代理 / Deep / Supervisor / plan_execute Executor 全线切到 Agentic typed agent；模型韧性运营化——原生 retry（429/5xx/网络抖动/空流自动退避）+ failover 备用通道（`model_failover_channels`，主渠道限流不再断跑）；1259 行 run loop 巨石拆为 40+ 单一职责组件；run 级 token 用量核算（`eino_usage_summary` 时间线）；上下文超限单次激进压缩续跑；设置页暴露 retry/failover 参数。
- **v1.7.13-src（对应官方 v1.7.13）**：HITL 审计 Agent 默认放行基调（攻击性 payload 必放行、仅不可逆破坏 reject、规则编号可追溯）；`upsert_project_fact` / `get_project_fact` 进免审批白名单；流式重复 tool_call index 恢复；项目对话刷新续流 / 工具状态恢复 / HITL 卡死重启；Agent 任务进度列表（plantask + 悬浮进度 UI）；Quake `code` 字符串容错；官方 21 个方法论 skill 更新。
- 更早版本：平台 RBAC、机器人接入、工作流包导入导出、资产管理、ZoomEye/Quake/Shodan 多源测绘、工具后台执行、会话角色保存、AI 通道等均已包含。

## 快速开始

### 环境要求

- Go 1.25+、Python 3.10+
- 一个 OpenAI 兼容的模型 API（GPT / Claude / DeepSeek / GLM 等）

### 安装与启动

```bash
git clone https://github.com/langbyyi/CyberStrikeAI-SRC && cd CyberStrikeAI-SRC
cp config.example.yaml config.yaml   # 编辑配置（模型/FOFA/API Key 等）
./run.sh
```

`run.sh` 会自动校验环境、拉取依赖、编译并启动服务。默认 HTTP，访问 **http://127.0.0.1:8080/**；HTTPS 用 `./run.sh --https`。

### 首次配置

1. **登录**：首次启动控制台打印随机初始管理员密码；改密码运行 `./cyberstrike-ai --reset-admin-password`
2. **配置模型**：编辑 `config.yaml` 的 `ai.channels` 段
3. **FOFA 多引擎**：`config.yaml` 的 `fofa` / `zoomeye` / `quake` / `shodan` 段（api_key 或环境变量）

更多配置见 `config.example.yaml`。
