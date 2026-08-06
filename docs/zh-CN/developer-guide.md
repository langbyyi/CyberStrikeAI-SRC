# 开发者指南

本文面向二次开发者，说明项目结构、启动方式、主要扩展点和开发习惯。

## 项目结构

```text
cmd/server/              Web 服务入口
internal/app/            应用组装、路由注册、MCP 工具注册
internal/handler/        HTTP Handler
internal/database/       SQLite 数据访问
internal/security/       认证、限流、Shell 执行
internal/mcp/            MCP Server、外部 MCP 管理
internal/multiagent/     Eino 单代理、多代理、中间件
internal/workflow/       工作流运行时
internal/knowledge/      知识库索引与检索
internal/c2/             内置 C2
internal/project/        项目事实黑板
web/static/              前端 JS/CSS/资源
web/templates/           HTML 模板
tools/                   命令工具 YAML
roles/                   角色 YAML
agents/                  多代理 Markdown 定义
skills/                  Agent Skills
docs/                    项目文档
```

## 启动开发环境

```bash
go run ./cmd/server --config config.yaml
```

前端是静态页面，模板在 `web/templates/`，JS/CSS 在 `web/static/`。修改后刷新浏览器即可验证，多数场景不需要单独前端构建。

## 路由

路由集中在 `internal/app/app.go` 的 `registerRoutes` 中。新增业务接口通常需要：

1. 在 `internal/handler/` 增加 Handler。
2. 在 `internal/database/` 增加必要的数据访问。
3. 在 `internal/app/app.go` 构造并注册路由。
4. 如需对外文档，更新 `internal/handler/openapi.go`。
5. 如需前端调用，更新 `web/static/js/`。

## 数据库

默认 SQLite。新增表或字段时：

- 将迁移逻辑放到数据库初始化或对应模块迁移函数。
- 保持向后兼容，避免破坏已有 `data/conversations.db`。
- 添加针对迁移和核心查询的单测。

## 新增工具

命令工具优先通过 `tools/*.yaml` 增加，不必改 Go 代码。需要 Go 内置工具时：

- 在合适模块注册 MCP Tool。
- 定义清晰 `InputSchema`。
- 处理超时、错误、审计和 HITL 上下文。
- 避免把高风险操作默认免审批。

工具 YAML 规则见 `tools/README.md`。

## 新增角色

角色通过 `roles/*.yaml` 管理。常见字段包括名称、描述、系统提示词和工具列表。角色应遵循最小工具集原则，不要把所有工具默认交给专用角色。

## 新增子代理

多代理子 Agent 放在 `agents/*.md`。Front matter 示例：

```yaml
---
name: Vulnerability Triage
id: vulnerability-triage
description: 对漏洞线索进行验证、定级和修复建议整理
tools:
  - nmap
  - nuclei
bind_role: 综合漏洞扫描
max_iterations: 200
---
```

正文是系统提示词。主代理可使用固定文件名或 `kind: orchestrator`。

## 新增 Skill

Skill 放在 `skills/<name>/SKILL.md`。用于提供专题能力、流程说明或附属资料。详见 [Skills 指南](skills-guide.md)。

## 前端开发

前端代码按功能拆分在 `web/static/js/`。新增页面或模块时：

- 复用现有 `apiFetch`、modal、通知、i18n 工具。
- 同步更新 `web/static/i18n/zh-CN.json` 和 `en-US.json`。
- 避免把敏感 Key 放到前端。
- 高风险按钮要有确认和清晰状态反馈。

i18n 规范见 [前端国际化方案](frontend-i18n.md)。

## OpenAPI

`internal/handler/openapi.go` 维护内置 OpenAPI 输出。新增公开接口后建议同步补：

- path
- method
- summary/description
- requestBody
- responses
- security

这样 `/api-docs` 才能反映最新接口。

## 开发习惯

- 优先保持现有模块边界。
- 大模型、外部 API、文件系统、Shell 相关改动必须考虑超时和错误路径。
- 高风险能力要接入 HITL 或至少有清晰审计。
- 代码变更后运行相关包单测。

## 新增业务模块的完整配方

不要只加一个 Handler。完整模块通常要考虑：

1. 数据模型：是否需要 SQLite 表和迁移。
2. Handler：HTTP 参数、错误码、分页、过滤。
3. Audit：管理动作是否要审计。
4. Monitor：如果会执行长任务，是否要记录执行状态。
5. MCP：是否要暴露给 Agent。
6. HITL：MCP 工具是否有审批边界。
7. OpenAPI：是否更新 `/api/openapi/spec`。
8. Frontend：是否需要 i18n、状态、空态、错误提示。
9. Tests：数据库、handler、边界条件。
10. Docs：配置、使用、排错和安全影响。

少做其中一项，后面通常会以“用户看不懂”“Agent 调错”“接口没人会用”的形式返工。

## Handler 错误设计

建议错误响应保持：

```json
{
  "error": "machine_readable_code",
  "message": "给用户看的说明"
}
```

不要只返回 Go error 字符串。前端需要稳定字段，用户需要可操作建议，日志需要详细错误。

## 长任务设计

扫描、索引、批量任务、C2 等都可能长时间运行。设计时要回答：

- 是否能取消？
- 是否能查询进度？
- 失败后能否重试？
- 结果写在哪里？
- 页面刷新后状态是否还在？
- 是否会阻塞 HTTP 请求？

如果答案是否定的，应考虑接入任务表、事件流或监控模块。

## 测试优先级

最值得补测试的地方：

- 配置热应用。
- HITL 审批分支。
- Shell 超时和无输出。
- 外部 MCP 失败恢复。
- 知识库索引和检索后处理。
- WebShell 编码和系统识别。
- SQLite 迁移兼容。

这些地方比普通 getter/setter 更容易出现真实用户故障。
