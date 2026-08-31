# 统一审批最佳实践

统一审批用于在 AI 执行工具前阻断敏感操作，并保留从规则命中、审批到真实执行结果的审计链。

## 架构与语义

- `tool_approval` 控制普通工具是否需要审批；白名单工具可直接放行。
- `dangerous_action` 控制命中危险规则的调用是否需要审批。
- 两个开关互相独立，但触发后进入同一个协调器，同一调用最多产生一张审批单。
- 审批方是全局共享的 `human` 或 `agent`，不为两种触发器分别配置。
- 裁决只有 `approve` 和 `reject`；审批不能改写工具参数。
- 通过后签发的 Grant 与工具名、规范化参数和规则版本精确绑定，只能领取一次。
- 会话 ID 和项目 ID 只用于 RBAC、筛选和导航，不参与策略解析。

## 配置

```yaml
approval:
  reviewer: human # human | agent
  timeout_seconds: 300
  tool_approval:
    enabled: false
    tool_whitelist: [read_file, ls, list_dir, glob, grep, tool_search]
  dangerous_action:
    enabled: true

hitl:
  audit_model:
    provider: ""
    base_url: ""
    api_key: ""
    model: ""
  retention_days: 90
  audit_agent_prompt: ""
```

`approval` 是审批行为的唯一权威配置。`hitl.audit_model` 只在 `reviewer: agent` 时提供审批模型，空字段继承主模型配置。

`approval.timeout_seconds` 是单张审批单从创建到失效的最长秒数，必须大于 0。超时会自动拒绝本次调用；超时后不能补批准。即使人工已经点击通过，工具在领取执行凭证前也会再次校验有效期。

## 人工审批流程

当 `approval.reviewer: human` 且任一触发器要求审批时：

1. 协调器冻结工具名称和完整参数，创建 `pending_human` 审批单并暂停原调用。
2. 具备 `approval:read` 权限的用户可在人机协同页面查看工具、参数、风险和触发来源。
3. 具备 `approval:decide` 权限的登录用户提交 `approve` 或 `reject`，备注可选。
4. 后端只接受仍处于 `pending_human`、未超时且存在在线等待任务的审批单；重复裁决、过期审批或进程重启后的孤立记录返回 `409`。
5. 通过后协调器签发一次性执行凭证；执行器领取成功后状态进入 `executing`，最终记录为 `succeeded` 或 `failed`。

人工决策通过 `POST /api/approvals/:id/decision` 提交。数据库记录是审计依据，在线 broker 只负责唤醒当前正在等待的调用；不能仅修改数据库状态来恢复或执行任务。

## 参数冻结与动态字段

审批凭证与工具名、规范化后的完整参数、调用 ID 和规则版本绑定。审批页面展示的参数就是被授权参数，人工或审计 Agent 都不能在批准时改写参数。

时间戳、nonce、请求 ID 等动态值也属于参数的一部分：

- 在审批前生成并保持不变，可以正常批准和执行。
- 审批后重新生成或修改，会导致参数摘要不一致，执行器拒绝使用原凭证。
- 必须在批准后生成的动态值，应先在工具契约中明确设计为非安全语义字段并经过独立安全评审；当前实现不会自动忽略任何名称类似时间戳的字段。

## 建议

- 初次上线使用 `reviewer: human`，只将明确只读工具加入白名单。
- 待审批量过大时可改用 `reviewer: agent`，但仍应保留危险规则开关。
- 规则发布前会在服务端编译校验；失败时保留上一份有效快照。
- 重启时尚未执行的审批会被取消，不允许凭旧授权继续执行。
- 工作流 checkpoint 是流程暂停机制，不是安全审批，两者不共享状态。

## 权限

- 读取审批单、配置和规则：`approval:read`
- 人工裁决：`approval:decide`
- 修改全局配置和危险规则：`approval:policy:write`

旧 `hitl:*` 权限不会自动获得统一审批的读取、裁决或策略修改权限。
