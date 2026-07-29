# Eino Single Evidence-Driven Convergence Design

## 1. 目标

优化 CyberStrikeAI 的 `eino_single` 执行流程，在不使用固定短轮次截断高价值测试的前提下：

- 根据证据进展自适应继续、换方向或结束；
- 给摘要调用提供独立超时与确定性降级；
- 区分工具执行失败、目标负结果、瞬态错误、策略拒绝和框架裁剪；
- 限制相同调用错误与相同失败假设的重复次数；
- 停滞后可靠生成正式报告，不把 planning 或内部指令当成最终回复；
- 原子管理 pending，消除裁剪结果先于工具调用事件到达造成的竞态；
- 阻止证据不足或被策略拒绝的发现通过更换漏洞类型升级为正式漏洞。

本设计只调整单代理执行流程及其共用的监控、证据和摘要辅助模块，不改变授权范围、安全工具能力或多代理编排语义。

## 2. 基准事实

真实会话 `de13e76b-d849-4213-8c09-466b5b1901eb` 提供以下基准：

- 总耗时约 39 分 24 秒；
- 132 次迭代、134 次过程工具调用；
- `execute` 75 次，`http-framework-test` 35 次；
- MCP 监控记录 125 次真实执行，其中成功 109、失败 16；
- 16 次失败包括 10 次可避免的调用错误、5 次目标/网络结果、1 次正确的质量门拒绝；
- `upsert_project_fact` 因 `links 须为数组` 连续失败 5 次；
- 第 103 轮工具结果返回后，摘要/下一模型阶段等待超过 150 秒，绕过 120 秒流空闲限制；
- 第 132 轮停滞门清空工具调用，ADK 将其误判为正常完成；
- 框架裁剪结果早于 run loop 登记 pending，结束时产生 `eino_pending_orphaned`；
- 最终回复是 planning 文本和 `identity_gap` 内部提示，不是正式报告；
- `ACAO: * + credentials` 和 JSONP callback 反射被错误升级为可利用 CORS/XSS。

这些事实同时构成本设计的回归测试场景。

## 3. 非目标

- 不把全局硬上限简单降低到 40～60 轮；
- 不以命令黑名单代替语义收敛；
- 不改变用户明确授权的目标范围；
- 不自动执行新的攻击动作；
- 不为单一案例创建特例域名、路径或 payload；
- 不重构与 `eino_single` 收敛无关的多代理模块。

## 4. 方案选择

### 4.1 固定缩短上限

优点是实现简单，缺点是会截断仍在产生高价值证据的任务，不能满足挖掘能力要求。

### 4.2 局部修补

分别修复摘要超时、pending 和最终回复，能够消除单个故障，但执行义务、coverage、停滞和重试仍会在不同模块中形成冲突。

### 4.3 证据驱动自适应收敛

采用此方案。建立统一的执行收敛 Module，以较小的 Interface 集中输出下一动作；工具结果分类、同错预算、pending 账本和正式收尾作为其内部或相邻 Module。该方案提供最高的 Locality 和 Leverage：修改一次收敛语义即可覆盖所有单代理工具路径和测试。

## 5. 架构

### 5.1 Execution Convergence Module

外部 Interface 接受已经归一化的执行事实，不接受原始日志文本：

- 当前阶段；
- 工具调用签名；
- 语义结果；
- 证据进展；
- coverage 变化；
- 记录义务变化；
- 已消耗的分支与全局低价值预算。

输出唯一的下一动作：

- `continue`：当前分支仍有证据进展；
- `pivot`：当前假设无进展，但仍有高优先级未覆盖面；
- `finalize`：没有足够理由继续探测；
- `finished`：正式报告已经生成或确定性降级已经完成。

阶段转换为：

```text
exploring ──无进展──> pivoting ──新证据──> exploring
    │                     │
    └──满足收尾条件────────┴──> finalizing ──报告完成──> finished
```

`finalizing` 是单向阶段；进入后不得恢复普通 probe。这样可以避免模型在“准备总结”和“再试一个路径”之间循环。

### 5.2 Semantic Outcome Module

语义结果类别及其处理：

| 类别 | 含义 | 收敛与监控处理 |
|---|---|---|
| `completed` | 工具基础设施正常完成 | 根据证据提取结果判断是否进展 |
| `target_negative` | 404、拒绝连接、稳定 WAF 拦截等 | 作为负证据关闭对应分支，不降低基础设施成功率 |
| `external_transient` | reset、429、5xx、网络超时 | 最多重试两次，之后转为 blocked coverage |
| `invocation_error` | 参数、Shell、文件、schema 错误 | 允许一次纠正，重复时阻断同类调用 |
| `policy_rejected` | 质量门或安全策略拒绝 | 不重试；记录拒绝证据指纹 |
| `framework_dropped` | 执行控制器主动裁剪 | 不计真实执行，不计 MCP 成功率 |

错误指纹至少包含归一化工具名、错误类别、稳定错误码或消息模板和 coverage 分支。它不得依赖时间戳、UUID、输出文件名或无关参数。

### 5.3 自适应预算

保留 `eino_single_execution.max_iterations=200` 作为异常硬上限。

- 当前假设连续 3 个 probe batch 没有证据进展：进入 `pivoting`；
- 全局连续 12 个低价值 probe：进入 `finalizing`；
- `invocation_error` 同一错误允许 1 次纠正；
- `external_transient` 同一假设允许 2 次尝试；
- 已有漏洞记录后，只为未闭环 P0/P1 coverage 或新出现的高价值证据继续；
- 新证据进展只恢复当前分支预算，不清空全局历史。

下列变化不刷新预算：

- 新的命令字符串但相同语义目标；
- 同类 SPA shell；
- 同类 404/405/410/412；
- 仅时间戳、请求 ID、Cookie、UUID 或 token 值变化；
- 重复落库、列表和状态管理调用；
- 同一拒绝证据改标题或漏洞类型。

### 5.4 Summary Deadline Module

摘要模型不再直接持有未包装的 `mainModel`。摘要调用使用独立的 `summarization_timeout_seconds`，默认 120 秒。

超时后：

1. 不对 deadline 进行摘要内部盲重试；
2. 从执行状态和最近完整工具回合生成确定性摘要；
3. 保留用户目标、确认事实、候选、正式漏洞、未闭环 P0/P1 coverage、失败尝试索引和最近工具轨迹；
4. 继续主流程，并产生可观测的 `summarization_fallback` 事件。

确定性摘要只压缩已有内容，不产生新的安全结论。

### 5.5 Pending Ledger Module

Interface：

- `Register(call)`：登记真实进入执行阶段的工具调用；
- `Resolve(callID, result)`：以真实或框架结果完成调用；
- `Drop(callID, reason)`：原子写入裁剪结果和 tombstone；
- `Flush(reason)`：仅用于任务取消、不可恢复错误或兼容性清理。

不再由中间件直接发 progress 后再通过独立通知清理 run loop map。`Drop` 必须在同一 Module 内完成状态变更和事件输出。

迟到的 `Register` 遇到 tombstone 时不得重新建立 pending。`eino_pending_orphaned` 只表示真正违反账本不变量，不再作为正常收尾路径。

### 5.6 Finalization Module

进入 `finalizing` 时：

1. 停止创建新的 probe；
2. 允许完成已经开始的结果处理、漏洞记录和项目事实写入；
3. 原子 Drop 尚未执行且被收敛策略裁剪的调用；
4. 使用无工具模型调用生成正式报告；
5. 无工具模型调用失败或超时时，使用确定性模板生成保底报告；
6. 将阶段更新为 `finished` 后才允许 run end。

正式报告必须区分：

- 已确认发现；
- 候选及证据缺口；
- 已覆盖攻击面；
- blocked/dead-end 分支；
- 网络或工具限制；
- 收尾原因。

最终回复清洗必须删除或拒绝以下内容：

- planning/reasoning；
- `framework_next_action`；
- `identity_gap`；
- `depth_force_next`；
- `SkillRouter`；
- 其它仅供 Agent 使用的内部提示。

若最后可用文本仍是行动计划或内部提示，视为没有最终报告，必须走无工具 Finalization Module 或确定性保底。

### 5.7 Evidence Policy Module

正式漏洞记录必须由当前会话已经观测到的工具证据支持。

- `policy_rejected` 的证据指纹写入拒绝记忆；
- 同一证据仅更换标题、严重级别或漏洞类型仍然拒绝；
- CORS 配置本身默认是加固项；`ACAO: *` 与 credentials 同时出现不能被解释为浏览器可携带凭证读取；
- JSONP callback 反射在只有 HTTP 响应时最多是候选信号；
- 正式 XSS 需要浏览器执行上下文或等价的客户端执行证据，并明确脚本实际运行的 origin；
- IDOR 需要对象标识和至少两个授权上下文的差分，缺少第二身份时保留候选或 blocked；
- 证据不足时自动降级为候选，不允许模型通过换类型绕过。

Evidence Policy Module 不负责主动测试，只判断已有证据是否满足落库等级。

### 5.8 监控语义

MCP 监控同时展示：

- 基础设施执行成功率；
- 各 Semantic Outcome 数量；
- 每个会话的真实执行、目标负结果、瞬态失败、调用错误、策略拒绝和框架裁剪；
- 同错预算拦截次数；
- 收敛阶段、收尾原因和摘要降级次数。

过程详情与 MCP 监控通过 conversation ID 和 tool call ID 关联。已完成执行也必须保留 conversation ID，不能只为 `running` 状态临时补充。

## 6. 数据流

```text
Model tool_calls
  → Execution Convergence.Preflight
    → allowed: Pending Ledger.Register → tool adapter → Semantic Outcome
      → Evidence extraction / Evidence Policy
      → Execution Convergence.Observe
      → Pending Ledger.Resolve
    → dropped: Pending Ledger.Drop
  → continue | pivot | finalize
  → Finalization（必要时）
```

摘要位于发送主模型之前，但使用相同的执行状态快照和独立 deadline。监控消费已经分类的 Semantic Outcome，不自行重新推断业务语义。

## 7. 错误处理

- 非法 OpenAI 工具消息继续由最终消息规范化 Module 处理；
- 摘要 timeout 转确定性摘要，不直接终止任务；
- 正式收尾模型 timeout 转确定性报告；
- pending 不一致记录错误事件并修复账本，但不得把 planning 当成最终结果；
- iteration hard limit 仍产生部分报告，并明确结束原因为硬上限；
- 用户取消立即停止，不额外启动 Finalization 模型调用；
- 数据库写入错误参与同错预算，重复失败后进入 blocked coverage。

## 8. 配置

在 `agent.eino_single_execution` 增加：

```yaml
summarization_timeout_seconds: 120
```

其它阈值先作为经过测试的执行策略常量，不新增大量配置项。只有真实部署证明需要跨环境调整时再扩展配置，避免把内部状态机复杂度暴露给用户。

## 9. 测试策略

### 9.1 Module 测试

- 新攻击面刷新当前分支预算；
- SPA shell、同类 404 和仅 volatile 字段变化不刷新预算；
- 3 个无进展 batch 触发 pivot；
- 12 个全局低价值 probe 触发 finalize；
- 新高价值证据能够从 pivot 回到 exploring；
- finalizing 后 probe 永远不再放行；
- 相同 schema 错误只允许一次纠正；
- 目标拒绝连接分类为 target_negative；
- 连接 reset 分类为 external_transient；
- 策略拒绝记忆阻止换类型重提。

### 9.2 Pending 测试

- Drop 先于迟到 Register 时不会重建 pending；
- 真实 Resolve 只发一个结果；
- 重复结果不产生重复完成事件；
- 正常 run end 时 pending 为零；
- 取消时 Flush 为每个 pending 产生一个明确结果。

### 9.3 摘要测试

- 摘要 Generate 超过 120 秒时被取消；
- deadline 不触发内部多次重试；
- 确定性摘要保留目标、事实、漏洞、coverage 和最近完整工具回合；
- 摘要降级后消息序列仍满足 OpenAI 工具协议。

### 9.4 正式收尾测试

- 停滞裁剪最后一个工具后进入 finalizing，而不是直接结束；
- 无工具最终调用成功时使用正式报告；
- 最终调用失败时使用确定性报告；
- planning 和内部提示不能成为最终回复；
- iteration limit 仍能返回明确的部分报告。

### 9.5 Evidence Policy 测试

- `ACAO: * + ACAC: true` 不构成凭证 CORS；
- 仅 JSONP callback 反射不能写正式 XSS；
- 浏览器执行证据满足时允许 XSS；
- 缺少双身份的 IDOR 只能候选或 blocked；
- CORS 拒绝后改成 XSS 但证据相同仍被阻断。

### 9.6 集成与回归

用真实会话的匿名化事件序列构建固定 fixture，验证：

- 没有 `eino_pending_orphaned`；
- 停滞后一定生成正式报告；
- 相同 `links 须为数组` 最多出现两次；
- 合法并行工具调用仍完整配对；
- 意图来源仍为 `rules_confident`；
- 高价值新证据能够延长局部探索；
- 最终回复不含内部指令。

## 10. 验收标准

- 保留 200 轮硬上限，但普通无进展任务能通过自适应策略提前收尾；
- 任何证据持续进展的任务不会因为固定短轮次被截断；
- 摘要单次最长 120 秒，并有确定性降级；
- 同一 invocation error 最多一次纠正；
- target negative 不再计入基础设施失败率；
- 停滞后不直接 run end；
- 正常结束时 pending 为零；
- 正式报告始终存在，且不泄露内部提示；
- 证据不足或被拒绝的 CORS/JSONP 样本不能升级为正式 XSS；
- 全量测试、静态检查和构建通过；
- 变更仅本地提交，不推送。

## 11. 实施顺序

1. 引入 Semantic Outcome 与同错预算；
2. 深化 Execution Convergence Module；
3. 替换 pending map 为 Pending Ledger；
4. 增加摘要 deadline 与确定性降级；
5. 增加 Finalization Module；
6. 增加 Evidence Policy；
7. 调整监控统计与 conversation 关联；
8. 使用真实会话 fixture 做集成回归。

每一步必须先写失败测试，再做最小实现，并保持现有 OpenAI 消息规范化、意图识别和瞬态重试测试通过。
