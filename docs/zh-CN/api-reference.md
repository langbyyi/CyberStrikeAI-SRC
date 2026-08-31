# API 参考

CyberStrikeAI 内置 OpenAPI 规格和 API 文档页面。启动服务后访问：

```text
/api-docs
```

OpenAPI JSON：

```text
GET /api/openapi/spec
```

`/api/openapi/spec` 需要登录认证，避免未授权用户直接枚举接口结构。

> 说明：本文收录常用与集成关键的接口，**并非完整清单**。全部路由以 `internal/app/app.go` 的注册为准；本文未展开的端点在文末[其他端点](#其他端点)按组归纳。

## 认证

登录：

```http
POST /api/auth/login
Content-Type: application/json

{"password":"your-password"}
```

认证成功后，前端通常使用 Cookie 会话。外部客户端也可参考 OpenAPI 中的 Bearer Token 描述，按实际返回字段接入。

常用认证接口：

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/change-password`
- `GET /api/auth/validate`

## 对话与 Agent

单代理：

- `POST /api/eino-agent`
- `POST /api/eino-agent/stream`

多代理：

- `POST /api/multi-agent`
- `POST /api/multi-agent/stream`

多代理请求体通过 `orchestration` 指定：

- `deep`
- `plan_execute`
- `supervisor`

常用请求体字段：

| 字段 | 说明 |
| --- | --- |
| `message` | 用户消息，必填。 |
| `conversationId` | 继续已有对话；为空时创建新对话。 |
| `projectId` | 新对话绑定项目；为空时可跟随 `config.project.default_project_id`。 |
| `role` | 使用指定角色。 |
| `aiChannelId` | 选择 `ai.channels` 中的通道 ID；为空时使用 `ai.default_channel`。 |
| `reasoning` | 会话级推理覆盖，受通道 `reasoning.allow_client_reasoning` 控制。 |

对话管理：

- `POST /api/conversations`
- `GET /api/conversations`
- `GET /api/conversations/:id`
- `PUT /api/conversations/:id`
- `DELETE /api/conversations/:id`
- `POST /api/conversations/:id/delete-turn`
- `GET /api/messages/:id/process-details`

## 统一审批（HITL）

HITL 审批统一由以下接口提供：

- `GET /api/approvals`：分页查询审批单，支持 `conversationId`、`projectId`、`requesterUserId`、`status`、`q`、`decision`、`actorType`、`terminal`、`limit`（1-200，默认 50）、`offset` 筛选。
- `GET /api/approvals/ledger`：审批台账，支持 `invocationId`、`from`、`to` 和 `limit`；时间接受 RFC3339 或 Unix 秒。
- `GET /api/approvals/:id`：审批单详情（含决策记录）。
- `POST /api/approvals/:id/decision`：人工决策，请求体 `{"decision":"approve|reject","comment":"可选备注"}`，仅 `pending_human` 状态可决策（否则 409）。

读取接口需要 `approval:read`，决策接口需要 `approval:decide`。旧 `hitl:*` 权限不兼容统一审批接口。

危险操作规则与全局配置：

- `GET /api/approval-rules`：列出危险操作规则，需 `approval:read`。
- `POST /api/approval-rules`：发布规则，需 `approval:policy:write`。请求体字段为 `id`、`enabled`、`priority`、`riskLevel` 和 `matcher`。
- `DELETE /api/approval-rules`：删除危险操作规则，需 `approval:policy:write`，请求体为 `{"id":"规则 ID"}`。
- `GET /api/approval-config` / `PUT /api/approval-config`：读取或更新全局审批配置，分别需要 `approval:read` 和 `approval:policy:write`。

规则 `matcher` 支持：

- `tools`：工具名称列表。
- `httpMethods`：HTTP 方法列表。
- `pathPatterns`、`textPatterns`：RE2 正则列表。
- `argumentPatterns`：参数名到 RE2 正则列表的映射。
- `requireHttpTransport`：是否只匹配 HTTP 传输调用。

统一审批接口及上述请求/响应模型也已纳入服务端 `/openapi.json`。手写文档解释运行语义，OpenAPI 作为机器可读契约。

## 文件管理来源

文件管理页面和 `/api/chat-uploads` 列表接口会把对话相关文件按来源归类。底层目录仍使用项目 ID 或会话 ID 保持稳定，界面会优先显示项目名或对话标题，完整 ID 可在提示或路径中查看。

| 来源 | `source` | 典型目录 | 说明 | 可变更性 |
| --- | --- | --- | --- | --- |
| 工作目录 | `workspace` | `tmp/workspace/projects/<projectId>/...`、`tmp/workspace/conversations/<conversationId>/...` | Agent 执行任务时保存下载文件、分析脚本、中间结果和生成的 CSV/XLSX/Markdown 等。用户反馈“AI 生成的文件找不到”时，通常先看这里。 | 只读展示；支持复制路径、下载、导出。 |
| 会话产物 | `conversation_artifact` | `data/conversation_artifacts/<conversationId>/...` | 系统按会话归档的交付物或会话级产物，例如总结、报告、模型中间件生成的归档内容。 | 只读展示；支持复制路径、下载、导出。 |
| 工具输出 | `reduction` | `tmp/reduction/projects/<projectId>/...`、`tmp/reduction/conversations/<conversationId>/...` | 超长工具输出、扫描原文或被截断前落盘的结果缓存。适合回看完整工具输出。 | 只读展示；支持复制路径、下载、导出。 |
| 对话附件 | `upload` | `chat_uploads/<date>/<conversationId>/...` | 用户在对话或文件管理页手动上传的附件。需要让 AI 引用某文件时，可复制服务器绝对路径粘贴到对话中。 | 可上传、新建目录、编辑文本文件、重命名、删除、复制路径、下载、导出。 |

相关接口：

- `GET /api/chat-uploads`：按来源、项目、会话、文件名筛选文件。
- `GET /api/chat-uploads/path`：把文件管理中的相对路径或内部虚拟路径解析为服务器绝对路径，用于复制文件或目录路径。
- `GET /api/chat-uploads/download`：下载指定文件。
- `GET /api/chat-uploads/export`：导出当前筛选结果为 ZIP。
- `POST /api/chat-uploads`：上传到对话附件目录。

## 项目、漏洞、攻击链

项目：

- `GET /api/projects`
- `POST /api/projects`
- `GET /api/projects/:id`
- `PUT /api/projects/:id`
- `DELETE /api/projects/:id`
- `GET /api/projects/:id/facts`
- `POST /api/projects/:id/facts`
- `GET /api/projects/:id/fact-graph`

漏洞：

- `GET /api/vulnerabilities`
- `POST /api/vulnerabilities`
- `GET /api/vulnerabilities/:id`
- `PUT /api/vulnerabilities/:id`
- `DELETE /api/vulnerabilities/:id`
- `GET /api/vulnerabilities/export`

攻击链：

- `GET /api/attack-chain/:conversationId`
- `POST /api/attack-chain/:conversationId/regenerate`

## 信息收集（空间测绘搜索）

信息收集页的查询由后端代理到 FOFA / ZoomEye / Quake / Shodan，前端不接触 Key。需要 `fofa:execute` 权限。

- `POST /api/fofa/search`：空间测绘搜索。
- `POST /api/fofa/parse`：自然语言转搜索语法。

`/api/fofa/search` 请求体字段：

| 字段 | 说明 |
| --- | --- |
| `provider` | 数据源：`fofa`（默认）、`zoomeye`、`quake`、`shodan`。 |
| `query` | 对应引擎的搜索语法，必填。 |
| `size` | 返回条数上限（引擎相关，FOFA 最大 10000）。 |
| `page` | 页码，默认 1。 |
| `fields` | 返回字段（引擎相关，逗号分隔）。 |
| `full` | 是否返回完整字段。 |

`/api/fofa/parse` 请求体字段：

| 字段 | 说明 |
| --- | --- |
| `provider` | 目标引擎，同上。 |
| `text` | 自然语言查询，如 `公司名为示例且域名含 example 的主机`。 |

响应结构与 `/api-docs` 中的 OpenAPI 定义一致：`total` 为总匹配数，`size` 为实际返回条数，`results` 为结果数组。搜索接口的 MCP 版本为 `fofa_search` 工具（Agent 可调用，支持 `provider` / `natural_language` 参数，授权 `asset:read`）。

## 资产管理与批量导入

资产接口：

- `GET /api/assets`：分页查询资产；
- `GET /api/assets/selection`：按当前筛选条件解析跨页选择，最多返回 10000 条；
- `GET /api/assets/stats`：获取资产统计，`days` 仅支持 `7`、`30` 或 `90`；
- `POST /api/assets/import`：新增或去重更新资产，单次最多 100000 条；
- `POST /api/assets/scan-links`：批量记录扫描关联，单次最多 10000 条；
- `PUT /api/assets/bulk`：原子批量更新最多 10000 个资产；
- `PUT /api/assets/project-binding`：批量绑定项目，单次最多 10000 个资产 ID；
- `POST /api/assets/batch-delete`：原子批量删除最多 10000 个资产；
- `POST /api/assets/merge`：合并 2-100 个具有共同身份的重复资产；
- `PUT /api/assets/:id`：更新资产；
- `DELETE /api/assets/:id`：删除资产。

`GET /api/assets` 和 `GET /api/assets/selection` 使用相同的筛选与排序参数；`selection` 会忽略分页参数并返回全部匹配项（最多 10000 条）：

| 类别 | 参数 |
| --- | --- |
| 分页（仅列表） | `page`、`page_size`（最大 100） |
| 常用 | `q`、`status`、`project_id`、`risk_level`、`min_vulnerabilities`、`max_vulnerabilities` |
| 目标与来源 | `host`、`ip`、`domain`、`port`、`protocol`、`source`、`tag` |
| 责任与业务 | `responsible_person`、`department`、`business_system`、`environment`、`criticality` |
| 地理 | `country`、`province`、`city` |
| 扫描 | `scan_state=never|scanned`、`scan_overdue_days`、`last_scan_before`、`last_scan_after` |
| 发现时间 | `first_seen_before`、`first_seen_after`、`last_seen_before`、`last_seen_after` |
| 排序 | `sort_by`、`sort_order=asc|desc` |

时间参数接受 RFC3339 或 `YYYY-MM-DD`。`sort_by` 支持 `last_seen_at`、`last_scan_at`、`first_seen_at`、`created_at`、`updated_at`、`host`、`port`、`risk_level` 和 `vulnerability_count`。

`POST /api/assets/import` 接收 JSON，而不是 XLSX/CSV 文件。Web 端会在浏览器中解析模板、预览并转换为该请求格式：

```http
POST /api/assets/import
Authorization: Bearer <token>
Content-Type: application/json

{
  "source": "manual-import",
  "source_query": "asset-import-2026-07.xlsx",
  "assets": [
    {
      "host": "https://app.example.com:443",
      "domain": "app.example.com",
      "port": 443,
      "protocol": "https",
      "title": "Example App",
      "server": "nginx",
      "project_id": "<project-id>",
      "responsible_person": "Alice",
      "department": "Security",
      "business_system": "Customer Portal",
      "environment": "production",
      "criticality": "critical",
      "tags": ["production", "internet"],
      "status": "active"
    },
    {
      "ip": "192.0.2.10",
      "port": 22,
      "protocol": "ssh",
      "status": "active"
    }
  ]
}
```

请求规则：

- `assets` 必须包含 `1-100000` 条；
- 每条资产的 `host`、`ip`、`domain` 至少一项非空；
- `port` 范围为 `0-65535`；
- `status` 仅支持 `active` 或 `inactive`；
- `environment` 支持空值或 `production`、`staging`、`testing`、`development`、`other`；
- `criticality` 支持空值或 `critical`、`high`、`medium`、`low`；
- 标签最多 30 个，单个最多 64 个字符；
- `project_id` 非空时，调用者必须有权访问该项目；
- 需要 `asset:write` 权限；
- 服务端按“目标 + 端口 + 协议”去重，并在同一事务中处理本次请求。

成功响应：

```json
{
  "created": 120,
  "updated": 8,
  "skipped": 2
}
```

- `created`：新建数量；
- `updated`：命中去重键并合并更新的数量；
- `skipped`：空记录或因资源归属不可更新而跳过的数量。

字段校验失败返回 `400`，且响应 `error` 会包含出错资产的顺序。项目无权访问返回 `403`。批量导入的模板字段和 UI 操作见[资产管理指南](asset-management.md#从表格批量导入)。

批量编辑示例：

```http
PUT /api/assets/bulk
Content-Type: application/json

{
  "asset_ids": ["<asset-id-1>", "<asset-id-2>"],
  "responsible_person": "Alice",
  "department": "Security",
  "environment": "production",
  "criticality": "high",
  "add_tags": ["internet-facing"],
  "remove_tags": ["untriaged"]
}
```

批量字段均为可选；未提供的字段保持原值。`add_tags` 和 `remove_tags` 会在事务内去重处理。批量编辑、项目绑定和批量删除会先验证全部资产的可访问性，任一 ID 不存在或无权访问时整批失败。

重复资产合并示例：

```http
POST /api/assets/merge
Content-Type: application/json

{
  "asset_ids": ["<primary-id>", "<duplicate-id>"],
  "primary_id": "<primary-id>"
}
```

每个待删除记录必须与主资产共享域名、IP 或 Host。主资产已有字段优先，空字段从其他记录补齐，标签取并集；调用者需要更新主资产和删除其余资产的权限。

## 工具、MCP、配置

配置：

- `GET /api/config`
- `PUT /api/config`
- `POST /api/config/apply`
- `GET /api/config/tools`
- `GET /api/config/tools/:name/schema`
- `POST /api/config/test-openai`
- `POST /api/config/test-vision`
- `POST /api/config/list-models`

MCP：

- `POST /api/mcp`
- `GET /api/external-mcp`
- `PUT /api/external-mcp/:name`
- `POST /api/external-mcp/:name/start`
- `POST /api/external-mcp/:name/stop`
- `DELETE /api/external-mcp/:name`

## 知识库、Skills、角色、Agent

知识库：

- `GET /api/knowledge/categories`
- `GET /api/knowledge/items`
- `POST /api/knowledge/scan`
- `POST /api/knowledge/index`
- `POST /api/knowledge/search`

角色：

- `GET /api/roles`
- `POST /api/roles`
- `GET /api/roles/:name`
- `PUT /api/roles/:name`
- `DELETE /api/roles/:name`

Skills：

- `GET /api/skills`
- `POST /api/skills`
- `GET /api/skills/:name`
- `PUT /api/skills/:name`
- `DELETE /api/skills/:name`
- `GET /api/skills/:name/files`
- `GET /api/skills/:name/file`
- `PUT /api/skills/:name/file`

Markdown 子代理：

- `GET /api/multi-agent/markdown-agents`
- `POST /api/multi-agent/markdown-agents`
- `GET /api/multi-agent/markdown-agents/:filename`
- `PUT /api/multi-agent/markdown-agents/:filename`
- `DELETE /api/multi-agent/markdown-agents/:filename`

## 高风险能力

WebShell：

- `GET /api/webshell/connections`
- `POST /api/webshell/connections`
- `POST /api/webshell/exec`
- `POST /api/webshell/file`

C2：

- `GET /api/c2/listeners`
- `POST /api/c2/listeners`
- `GET /api/c2/sessions`
- `POST /api/c2/tasks`
- `POST /api/c2/payloads/build`

终端：

- `POST /api/terminal/run`
- `POST /api/terminal/run/stream`
- `GET /api/terminal/ws`

这些接口应只开放给可信管理员，并配合 HTTPS、强密码、网络隔离和审计。

## 其他端点

以下端点已在 `internal/app/app.go` 注册但未在前文展开。除标注"公开"的机器人回调（无需登录，受每 IP 每分钟 60 次速率限制）外，均需登录；权限依据 `internal/security/rbac_middleware.go`，"兼容"表示该路由接受多个等价权限。

注意：`assigned`/`own` 作用域的会话不能调用进程级全局变更接口（角色、Skills、外部 MCP、机器人、工作流定义与工作流包、知识库管理等），也不能访问 `/api/monitor/stats`、`/api/monitor/calls-timeline` 和 C2 Profile 的写操作。

### 机器人

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET/POST | `/api/robot/wecom` | 企业微信回调（GET 用于服务器验证） | 公开 |
| POST | `/api/robot/dingtalk` | 钉钉消息回调 | 公开 |
| POST | `/api/robot/lark` | 飞书消息回调 | 公开 |
| POST | `/api/robot/test` | 模拟机器人消息测试 | `robot:write` |
| POST | `/api/robot/wechat/qrcode` | 发起微信 iLink 扫码绑定 | `robot:write` |
| GET | `/api/robot/wechat/qrcode/status` | 查询扫码状态 | `robot:write` |
| POST | `/api/robot/wechat/qrcode/verify` | 校验扫码结果 | `robot:write` |
| GET | `/api/robot/wechat/status` | 查询微信绑定状态 | `robot:read` |
| POST | `/api/auth/robot-binding-code` | 创建机器人绑定码 | `auth:self` |
| GET | `/api/auth/robot-bindings` | 查看我的机器人绑定 | `auth:self` |
| DELETE | `/api/auth/robot-bindings/:id` | 删除我的机器人绑定 | `auth:self` |

### Agent Loop 与批量任务

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| POST | `/api/agent-loop/cancel` | 取消运行中的 Agent Loop | `tasks:write` |
| GET | `/api/agent-loop/tasks` | 运行中任务列表 | `tasks:read` |
| GET | `/api/agent-loop/tasks/completed` | 已完成任务列表 | `tasks:read` |
| GET | `/api/agent-loop/task-events` | 任务事件 SSE 流 | `tasks:read` |
| POST | `/api/batch-tasks` | 创建批量任务队列 | `tasks:write` |
| GET | `/api/batch-tasks`、`/api/batch-tasks/:queueId` | 查询队列列表/详情 | `tasks:read` |
| POST | `/api/batch-tasks/:queueId/start`、`.../rerun`、`.../pause` | 启动/重跑/暂停队列 | `tasks:write` |
| PUT | `/api/batch-tasks/:queueId/metadata`、`.../schedule`、`.../schedule-enabled` | 更新队列元数据/调度 | `tasks:write` |
| DELETE | `/api/batch-tasks/:queueId` | 删除队列 | `tasks:delete` |
| POST | `/api/batch-tasks/:queueId/tasks` | 追加子任务 | `tasks:write` |
| PUT | `/api/batch-tasks/:queueId/tasks/:taskId` | 更新子任务 | `tasks:write` |
| POST | `/api/batch-tasks/:queueId/tasks/:taskId/run` | 运行单个子任务 | `tasks:write` |
| DELETE | `/api/batch-tasks/:queueId/tasks/:taskId` | 删除子任务 | `tasks:delete` |

### 对话扩展与分组

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/api/usage/tokens` | Token 用量统计 | `dashboard:read` |
| GET | `/api/conversations/:id/token-usage` | 会话 Token 用量 | `chat:read` |
| GET | `/api/conversations/:id/plan-tasks` | 会话计划任务 | `chat:read` |
| GET | `/api/conversations/:id/results` | 会话完整结果聚合 | `chat:read` |
| PUT | `/api/conversations/:id/project` | 会话绑定/解绑项目 | `chat:write` |
| PUT | `/api/conversations/:id/pinned` | 置顶/取消置顶会话 | `chat:write` |
| GET | `/api/process-details/:id` | 单条执行过程详情 | `chat:read` |
| POST/GET | `/api/groups` | 创建/查询对话分组 | `group:write` / `group:read` |
| GET | `/api/groups/mappings` | 全部分组映射 | `group:read` |
| POST | `/api/groups/conversations` | 会话加入分组 | `group:write` |
| GET/PUT/DELETE | `/api/groups/:id` | 分组详情/更新/删除 | `group:read` / `group:write` / `group:delete` |
| PUT | `/api/groups/:id/pinned` | 置顶/取消置顶分组 | `group:write` |
| GET | `/api/groups/:id/conversations` | 分组内会话 | `group:read` |
| DELETE | `/api/groups/:id/conversations/:conversationId` | 会话移出分组 | `group:delete` |
| PUT | `/api/groups/:id/conversations/:conversationId/pinned` | 组内会话置顶 | `group:write` |

### 监控与通知

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/api/monitor` | 工具执行记录列表 | `monitor:read` |
| GET | `/api/monitor/execution/:id` | 执行详情 | `monitor:read` |
| GET | `/api/monitor/stats`、`/api/monitor/calls-timeline` | 进程级统计 | `monitor:read`（需 all 作用域） |
| POST | `/api/monitor/execution/:id/cancel` | 取消执行 | `monitor:write` |
| POST | `/api/monitor/executions/names` | 批量获取工具名 | `monitor:write` |
| DELETE | `/api/monitor/execution/:id` | 删除单条记录 | `monitor:delete` |
| DELETE | `/api/monitor/executions` | 批量删除记录 | `monitor:delete` |
| GET | `/api/notifications/summary` | 通知摘要 | `notification:read` |
| POST | `/api/notifications/read` | 标记通知已读 | `notification:write` |

### 审计日志

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/api/audit/meta`、`/api/audit/summary` | 审计元数据/摘要 | `audit:read` |
| GET | `/api/audit/logs`、`/api/audit/logs/export`、`/api/audit/logs/:id` | 查询/导出/详情 | `audit:read` |

### RBAC 管理

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/api/rbac/me` | 当前用户权限与作用域 | `auth:self` |
| GET | `/api/rbac/metadata`、`/api/rbac/users`、`/api/rbac/roles`、`/api/rbac/resource-assignments` | 查询 | `rbac:read` |
| POST/PUT/DELETE | `/api/rbac/users*`、`/api/rbac/roles*`、`/api/rbac/resource-assignments*` | 维护（无独立 delete 权限） | `rbac:write` |
| GET | `/api/rbac/resources` | 可分配资源枚举 | `rbac:write` |

### 工作流

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/api/workflows`、`/api/workflows/:id` | 工作流列表/详情 | `workflow:read` |
| POST | `/api/workflows` | 创建工作流 | `workflow:write` |
| PUT | `/api/workflows/:id` | 更新工作流 | `workflow:write` |
| DELETE | `/api/workflows/:id` | 删除工作流 | `workflow:delete` |
| POST | `/api/workflows/validate`、`/api/workflows/dry-run` | 校验/试运行 | `workflow:execute` |
| POST | `/api/workflows/generate-draft` | 生成工作流草稿 | `workflow:write` |
| GET | `/api/workflows/runs/pending`、`/api/workflows/runs/:runId`、`/api/workflows/runs/:runId/replay` | 运行查询/重放 | `workflow:read` |
| POST | `/api/workflows/runs/:runId/resume` | 恢复运行 | `workflow:execute` |
| GET | `/api/workflows/:id/package` | 导出工作流包 | `workflow:read` |
| POST/GET | `/api/workflow-package-inspections`、`/api/workflow-package-imports`（含 `/:id`） | 包检查/导入（读写均为写权限） | `workflow:write` |

### 前文分组的剩余端点

| 方法 | 路径 | 权限 |
| --- | --- | --- |
| GET | `/api/external-mcp/stats`、`/api/external-mcp/:name` | `mcp:read` |
| GET | `/api/knowledge/items/:id`、`/api/knowledge/index-status`、`/api/knowledge/retrieval-logs`、`/api/knowledge/stats` | `knowledge:read` |
| POST/PUT | `/api/knowledge/items`、`/api/knowledge/items/:id` | `knowledge:write` |
| DELETE | `/api/knowledge/items/:id`、`/api/knowledge/retrieval-logs/:id` | `knowledge:delete` |
| DELETE | `/api/vulnerabilities/batch` | `vulnerability:delete` |
| GET | `/api/vulnerabilities/filter-options`、`/api/vulnerabilities/stats` | `vulnerability:read` |
| GET/PUT | `/api/vulnerability-alerts/subscription` | `vulnerability:read`（仅修改本人订阅） |
| GET | `/api/projects/dashboard-summary`、`/api/projects/:id/stats`、`/api/projects/:id/conversations`、`/api/projects/:id/fact-edges` | `project:read` |
| POST | `/api/projects/:id/fact-edges`、`/api/projects/:id/promote-attack-chain/:conversationId`、`/api/projects/:id/facts/deprecate`、`/api/projects/:id/facts/restore` | `project:write` |
| PUT | `/api/projects/:id/facts/:factId` | `project:write` |
| DELETE | `/api/projects/:id/fact-edges/:edgeId`、`/api/projects/:id/facts/:factId` | `project:delete` |
| GET | `/api/webshell/connections/:id/ai-history`、`.../ai-conversations`、`.../state` | `webshell:read` |
| PUT | `/api/webshell/connections/:id`、`.../state` | `webshell:write` |
| DELETE | `/api/webshell/connections/:id` | `webshell:delete` |
| GET | `/api/chat-uploads/content` | `files:read` |
| POST | `/api/chat-uploads/mkdir` | `files:write` |
| PUT | `/api/chat-uploads/rename`、`/api/chat-uploads/content` | `files:write` |
| DELETE | `/api/chat-uploads` | `files:delete` |
| GET | `/api/skills/stats`、`/api/skills/:name/bound-roles` | `skills:read` |
| DELETE | `/api/skills/stats`、`/api/skills/:name/stats` | `skills:delete` |
| GET | `/api/c2/listeners/:id`、`/api/c2/sessions/:id`、`/api/c2/tasks`、`/api/c2/tasks/:id`、`/api/c2/tasks/:id/wait`、`/api/c2/tasks/:id/result-file`、`/api/c2/payloads/:id/download`、`/api/c2/events`、`/api/c2/events/stream`（SSE）、`/api/c2/files`、`/api/c2/profiles`、`/api/c2/profiles/:id` | `c2:read` |
| POST/PUT | `/api/c2/listeners/:id/start`、`.../stop`、`/api/c2/sessions/:id/sleep`、`.../note`、`/api/c2/sessions/:id/tasks`、`/api/c2/tasks/:id/cancel`、`/api/c2/payloads/oneliner`、`/api/c2/files/upload`、`/api/c2/profiles`、`/api/c2/profiles/:id` | `c2:write`（Profile 写操作需 all 作用域） |
| DELETE | `/api/c2/listeners/:id`、`/api/c2/sessions`、`/api/c2/sessions/:id`、`/api/c2/tasks`、`/api/c2/events`、`/api/c2/profiles/:id` | `c2:delete`（Profile 删除需 all 作用域） |

## 调用建议

- 优先使用 `/api-docs` 查看完整参数和响应结构。
- 流式接口使用 SSE，反向代理需关闭缓冲。
- 所有修改类接口都应处理 401、403、404、409、500。
- 外部集成建议创建最小权限网络路径，不要把 Web 管理面直接暴露到公网。

## 认证细节

认证中间件会按顺序提取 token：

1. `Authorization: Bearer <token>`
2. `Authorization: <token>`
3. 查询参数 `?token=<token>`（仅限 GET 请求，且仅用于 SSE 流或 WebSocket 升级连接）
4. Cookie `auth_token`

这意味着外部脚本最稳妥的方式是使用 `Authorization: Bearer`。查询参数只在 SSE/WebSocket 场景生效，且容易进入代理日志，不建议生产使用。

## SSE 客户端注意事项

`/api/eino-agent/stream` 和 `/api/multi-agent/stream` 是长连接。客户端应处理：

- 网络中断后不要盲目重放破坏性请求。
- 收到 `error` 事件后读取错误正文。
- 收到 `done` 才视为本轮结束。
- 代理层不能缓冲。
- 请求体中的 `conversationId` 决定是否接续已有对话。

## API 稳定性分层

| API 类型 | 稳定性 | 集成建议 |
| --- | --- | --- |
| `/api/auth/*` | 高 | 可直接集成 |
| `/api/eino-agent*` | 高 | 推荐外部对话入口 |
| `/api/openapi/spec` | 高 | 用于生成客户端 |
| `/api/assets/*` | 高 | 资产管理与批量导入 |
| `/api/config*` | 中 | 管理工具使用，谨慎自动化 |
| `/api/c2/*`、`/api/webshell/*` | 中 | 高风险，必须加权限边界 |
| 前端私有调用细节 | 低 | 不建议插件依赖 |

## Curl 示例

登录并提取 token 的返回字段可能随实现调整，建议先看 `/api-docs`。如果已有 token：

```bash
curl -k https://127.0.0.1:8080/api/conversations \
  -H "Authorization: Bearer <token>"
```

发送非流式单代理请求：

```bash
curl -k https://127.0.0.1:8080/api/eino-agent \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"message":"对 127.0.0.1 做授权的基础信息收集，先不要执行高风险操作"}'
```

## 源码锚点

- 路由：`internal/app/app.go`
- 认证：`internal/security/auth_middleware.go`
- OpenAPI：`internal/handler/openapi.go`
- 单代理：`internal/handler/eino_single_agent.go`
- 多代理：`internal/handler/multi_agent.go`
- 统一审批：`internal/handler/approval.go`
- 资产接口：`internal/handler/asset.go`
- 资产存储与去重：`internal/database/asset.go`
