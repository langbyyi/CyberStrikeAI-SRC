# CyberStrikeAI Domain Context

本文只定义执行编排中需要跨模块共享的领域术语。实现、日志、测试和设计文档应使用这些名称，避免同一概念在不同文件中漂移。

## 执行收敛（Execution Convergence）

单次授权测试从探索走向可靠结束的过程。执行收敛不是简单达到迭代上限，而是根据证据进展、覆盖状态、记录义务和连续低价值结果，在 `exploring`、`pivoting`、`finalizing`、`finished` 阶段之间转换。

## 证据进展（Evidence Progress）

能够改变后续测试决策的新信息，仅包括：

- 新的有效攻击面；
- 有意义的状态码、响应结构、身份或业务流程差分；
- P0/P1 coverage 的推进或闭环；
- 记录义务的创建或解除；
- 漏洞从信号升级为候选或确认。

输出文本、时间戳、UUID、同类错误页、同类 SPA shell 或重复管理操作的变化不属于证据进展。

## 语义结果（Semantic Outcome）

工具调用完成后面向执行决策的结果类别。类别为 `completed`、`target_negative`、`external_transient`、`invocation_error`、`policy_rejected`、`framework_dropped`。语义结果区别于底层进程退出码；例如目标返回 404 或拒绝连接可以是有效负证据，而不是执行基础设施故障。

## 同错预算（Same-error Budget）

对同一工具、同一归一化错误和同一执行分支允许的纠正次数。参数、Shell、文件和 schema 错误最多纠正一次；网络类瞬态错误最多重试两次。预算用于阻止模型通过微调无关参数重复撞击同一失败。

## 正式收尾（Finalization）

执行收敛进入 `finalizing` 后的无工具阶段。正式收尾复核证据、区分确认发现与候选、说明 coverage 和停止原因，并生成用户可读报告。planning、reasoning 和 `framework_*` 等内部指令不得成为最终回复。

## Pending Ledger

单次运行内工具调用 ID 的一致性账本。账本原子处理登记、完成、裁剪和强制清理，并为已裁剪 ID 保留 tombstone，防止迟到的流事件重新制造 pending。

## 证据策略（Evidence Policy）

正式漏洞落库前对漏洞类型与已观测工具证据进行匹配的规则。证据策略可以将证据不足的发现降级为候选，也可以记忆被拒绝的证据指纹，禁止仅通过更换标题或漏洞类型绕过拒绝。
