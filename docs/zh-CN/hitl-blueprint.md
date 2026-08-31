# 统一审批架构

> 本文档描述当前实现。详细决策记录见 `docs/superpowers/specs/2026-08-30-unified-approval-design.md`。

## 目标

在 AI 工具调用与真实执行之间建立唯一安全边界，防止敏感操作误伤系统，同时避免多套审批运行时产生竞态、重复审批或越权放行。

## 核心流程

```text
Invocation
    ↓
GlobalRuntime
    ├─ ToolApprovalTrigger
    └─ DangerTrigger
    ↓ union
Coordinator
    ↓
HumanReviewer | AgentReviewer
    ↓ approve / reject
exact single-use Grant
    ↓
execution owner (Eino / MCP / C2)
    ↓
real execution result + audit ledger
```

## 不变式

1. 策略只有全局层；项目和会话只是请求元数据。
2. 普通工具与危险操作有独立开关，但共用审批方、超时和状态机。
3. 同一 Invocation 最多创建一张审批单。
4. 人工和 Agent 只能返回 `approve` 或 `reject`。
5. 参数在授权时冻结；执行前复核工具名和 canonical arguments。
6. Grant 只能 Claim 一次；审批通过不等于执行完成。
7. C2 等异步调用显式接管 completion ownership，只由真实终态回写结果。
8. 规则编译、存储、审批方、Grant 复核或状态转移失败时一律 fail closed。
9. 工作流 checkpoint 使用工作流自身的暂停/恢复状态，不写入安全审批单。

## 运行时边界

- `internal/approval/GlobalRuntime`：持有全局配置和规则的原子快照。
- `internal/approval/Coordinator`：创建审批单、调用唯一审批方、签发和消费 Grant。
- `internal/handler`：提供全局配置、规则、待审批和裁决 API。
- Eino/MCP/C2 adapter：构造 Invocation，并在执行边界 Claim/Complete。
- SQLite：保存审批单、裁决、执行结果和只追加审计事件。历史表保留供升级读取，不再参与运行时策略。
