# 审计与监控

CyberStrikeAI 有两类常用可观测数据：平台操作审计和工具执行监控。二者用途不同，建议同时开启。

## 平台审计

配置：

```yaml
audit:
  enabled: true
  retention_days: 15
  max_detail_bytes: 8192
  auth_failure_cooldown_seconds: 60
```

审计记录覆盖登录、配置、资源管理等平台操作。它不会完整记录对话正文，也不逐条记录所有工具调用正文。

接口：

- `GET /api/audit/meta`
- `GET /api/audit/summary`
- `GET /api/audit/logs`
- `GET /api/audit/logs/:id`
- `GET /api/audit/logs/export`

建议关注：

- 登录失败和异常来源 IP。
- 密码修改。
- 配置修改。
- 外部 MCP 增删改。
- C2/WebShell/知识库等高风险资源操作。

## 工具执行监控

配置：

```yaml
monitor:
  retention_days: 90
```

工具执行监控用于查看 MCP 工具调用、命令状态、耗时、取消和结果摘要。

接口：

- `GET /api/monitor`
- `GET /api/monitor/execution/:id`
- `POST /api/monitor/execution/:id/cancel`
- `DELETE /api/monitor/execution/:id`
- `DELETE /api/monitor/executions`
- `GET /api/monitor/stats`
- `GET /api/monitor/calls-timeline`
- `POST /api/monitor/executions/names`

## 通知摘要

接口：

- `GET /api/notifications/summary`
- `POST /api/notifications/read`

通知用于提示待处理事项、未读状态或运行中任务概况。具体展示取决于前端页面。

## HITL 日志

HITL 决策日志独立管理：

- `GET /api/hitl/pending`
- `GET /api/hitl/logs`
- `GET /api/hitl/logs/:id`
- `DELETE /api/hitl/logs`
- `POST /api/hitl/decision`
- `POST /api/hitl/dismiss`

建议将 HITL 日志与平台审计结合，用于复盘 Agent 为什么执行或没有执行某个工具。

## 保留策略

建议：

- 审计日志保留 15 到 90 天，按组织要求调整。
- 工具执行记录保留 30 到 180 天。
- C2、WebShell、上传附件和任务结果按项目周期单独清理。
- 导出日志时注意脱敏和访问权限。

## 运维巡检

每周检查：

- 是否有异常登录失败。
- 是否有未授权配置变更。
- 长时间运行或失败率高的工具。
- 外部 MCP 连接状态。
- 数据库文件大小和磁盘空间。

每次演练结束：

- 导出必要审计证据。
- 删除无用 WebShell/C2 会话和 payload。
- 清理上传附件和临时工作区。
- 归档报告、漏洞和项目事实。

## 审计和监控的边界

两者经常被混用，但语义不同：

- 审计回答“谁在平台上做了什么管理动作”。
- 监控回答“工具调用运行得怎么样”。
- HITL 日志回答“某个工具调用为什么被放行、修改或拒绝”。
- 对话过程详情回答“Agent 当时如何推理和串联步骤”。

一次安全复盘通常要把四类信息合在一起看。只看审计，会漏掉具体工具输出；只看监控，会漏掉谁修改了配置。

## 关键事件解释

建议重点关注这些事件类型：

| 事件 | 为什么重要 |
| --- | --- |
| 登录失败 | 暴力尝试、密码泄露或误配置 |
| 修改密码 | 所有旧 session 会被撤销，可能影响正在使用的人 |
| 更新配置 | 可能改变模型、工具、C2、知识库、审计策略 |
| 外部 MCP 变更 | 新工具可能拥有本机或远端执行能力 |
| C2 listener/task | 直接影响授权目标和网络暴露面 |
| WebShell 连接变更 | 可能引入真实业务系统执行通道 |
| HITL 拒绝 | 说明 Agent 或用户请求触达风险边界 |

## 日志保留不是越久越好

安全工具日志往往包含目标、漏洞、路径、命令输出和组织内部信息。保留时间应平衡复盘价值与泄露风险：

- 短期演练：15-30 天。
- 持续红队平台：90-180 天。
- 合规要求：按组织规范归档，但导出后应加密。

如果没有专门日志平台，不要无限期保留 SQLite 中的所有明细。

## 源码锚点

- 审计服务：`internal/audit/service.go`
- 审计脱敏：`internal/audit/sanitize.go`
- 审计保留：`internal/audit/retention.go`
- 审计接口：`internal/handler/audit.go`
- 监控 reconcile：`internal/monitor/reconcile.go`
- 监控接口：`internal/handler/monitor.go`
- HITL 日志：`internal/handler/hitl_logs.go`
