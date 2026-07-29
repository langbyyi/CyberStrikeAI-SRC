# Eino Single Evidence-Driven Convergence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan.

**Goal:** 让 Eino 单代理在保持漏洞挖掘深度的前提下，依据证据进展自适应收敛，消除工具调用尾部竞态、摘要调用无界等待、同错重复消耗和内部控制文本泄露。

**Architecture:** 在现有 `ConversationExecutionState` 与 `ExecutionController` 上增加语义结果、证据进展、执行阶段和 pending ledger；中间件只负责分类与记账，运行循环负责阶段转换和正式收尾。模型摘要与最终收尾均有独立 deadline，超时或模型输出不合格时使用确定性降级，确保任何退出路径都返回可读报告。

**Tech Stack:** Go、CloudWeGo Eino ADK、Gin、SQLite

## Global Constraints

- 保留 `max_iterations=200` 作为硬上限，不用缩短固定时长代替自适应收敛。
- 分支连续 3 个无证据批次触发换路；全局累计 12 个低价值探测进入收尾。
- 同一调用错误只允许 1 次纠正；外部瞬态错误最多重试 2 次。
- 不改变合法安全测试能力；证据不足时降级为候选，不伪造正式漏洞。
- 所有生产变更先写失败测试，再做最小实现。
- 保留用户现有改动；完成后只做本地提交，不推送。

---

## Task 1: 语义结果分类与同错预算

**Files:**

- Create: `internal/multiagent/semantic_outcome.go`
- Create: `internal/multiagent/semantic_outcome_test.go`
- Modify: `internal/multiagent/execution_controller.go`
- Modify: `internal/multiagent/execution_controller_stagnation_test.go`
- Modify: `internal/multiagent/skill_router_middleware.go`
- Modify: `internal/multiagent/eino_single_execution_middleware.go`

**Step 1: 写失败测试**

覆盖 `completed`、`target_negative`、`external_transient`、`invocation_error`、`policy_rejected`、`framework_dropped`，并证明：

- SPA shell、稳定 404/405 和连接拒绝不会因响应文本变化被视为新证据。
- 同一 schema/参数错误换参数重试仍共享错误指纹，第二次纠正后被阻止。
- 网络 reset/429/5xx 只允许两次瞬态重试。
- 状态写工具也进入同错预算。

Run: `go test ./internal/multiagent -run 'Test(ClassifySemanticOutcome|ExecutionControllerSemanticBudget)'`

Expected: FAIL，缺少分类器和预算接口。

**Step 2: 最小实现**

新增：

```go
type SemanticOutcomeKind string

type SemanticOutcome struct {
    Kind             SemanticOutcomeKind
    Code             string
    Fingerprint      string
    EvidenceProgress bool
}

func ClassifySemanticOutcome(toolName, arguments, result string, isError bool) SemanticOutcome
```

分类器规范化时间戳、随机 ID、端口错误等易变片段；控制器以“工具 + 语义错误指纹”计数，不再仅按完整参数签名计数。中间件对普通探测和状态写统一记账。

**Step 3: 验证与提交**

Run: `go test ./internal/multiagent`

Commit: `fix: classify tool outcomes and bound repeated errors`

## Task 2: 证据进展与自适应执行阶段

**Files:**

- Modify: `internal/multiagent/execution_controller.go`
- Create: `internal/multiagent/execution_phase_test.go`
- Modify: `internal/multiagent/eino_single_execution_middleware.go`
- Modify: `internal/multiagent/execution_evidence.go`

**Step 1: 写失败测试**

证明：

- 仅结构化的新事实、身份差异、可复现行为或成功落库才重置证据停滞。
- 单分支 3 个无证据批次从 `exploring` 进入 `pivoting`。
- 换路后仍可继续不同分支，不会因一次 pivot 直接结束整个 ADK。
- 全局 12 个低价值探测进入 `finalizing`，并禁止新探测但允许收尾状态写。

Run: `go test ./internal/multiagent -run 'TestExecutionPhase'`

Expected: FAIL，缺少阶段机。

**Step 2: 最小实现**

新增 `exploring/pivoting/finalizing/finished` 阶段、低价值探测计数和显式 `MarkEvidenceProgress`。`AfterModelRewriteState` 在 pivot 时保留一个可继续的控制路径，不以清空所有 tool calls 作为收敛信号；finalizing 才禁止新探测。

**Step 3: 验证与提交**

Run: `go test ./internal/multiagent`

Commit: `fix: converge agent runs by evidence progress`

## Task 3: Pending Ledger 与工具调用竞态

**Files:**

- Create: `internal/multiagent/pending_ledger.go`
- Create: `internal/multiagent/pending_ledger_test.go`
- Modify: `internal/multiagent/execution_evidence.go`
- Modify: `internal/multiagent/eino_single_execution_middleware.go`
- Modify: `internal/multiagent/eino_adk_run_loop.go`
- Modify: `internal/multiagent/eino_pending_cleanup_test.go`

**Step 1: 写失败测试**

覆盖：

- `Drop` 先于 `Register` 时，tombstone 阻止迟到注册。
- `Resolve` 幂等，同一 call ID 只输出一个结果。
- run end 只清理真实未决调用，不为已 drop 调用产生 `eino_pending_orphaned`。

Run: `go test ./internal/multiagent -run 'TestPendingLedger|TestEinoPending'`

Expected: FAIL，缺少 ledger。

**Step 2: 最小实现**

实现并接入：

```go
type PendingLedger struct { /* guarded pending + tombstones */ }
func (l *PendingLedger) Register(call ToolCallSnapshot) bool
func (l *PendingLedger) Resolve(callID string) bool
func (l *PendingLedger) Drop(call ToolCallSnapshot, reason string) bool
func (l *PendingLedger) Flush(reason string) []ToolCallSnapshot
```

ledger 归属单次 conversation execution state；运行循环和 rewrite middleware 共用同一实例，替代两套时序不一致的局部状态。

**Step 3: 验证与提交**

Run: `go test ./internal/multiagent`

Commit: `fix: serialize pending tool call lifecycle`

## Task 4: 摘要 deadline 与确定性降级

**Files:**

- Modify: `internal/config/config.go`
- Modify: `config.example.yaml`
- Modify: `internal/multiagent/eino_summarize.go`
- Create: `internal/multiagent/eino_summarize_test.go`

**Step 1: 写失败测试**

用阻塞 fake model 验证摘要在配置 deadline 内退出，并返回包含关键用户目标、最近工具事实和未决约束的确定性摘要；deadline fallback 不再触发同一次摘要重试。

Run: `go test ./internal/multiagent -run 'TestSummarizationDeadline|TestDeterministicSummary'`

Expected: FAIL，缺少 deadline 包装和 fallback。

**Step 2: 最小实现**

增加 `summarization_timeout_seconds`，默认 120 秒。只包装 summarization model，超时返回本地生成的合法 assistant summary；保留最近完整工具轮次，裁剪旧的大型 tool output，不生成新事实。

**Step 3: 验证与提交**

Run: `go test ./internal/multiagent ./internal/config`

Commit: `fix: bound summarization latency with deterministic fallback`

## Task 5: 可靠正式收尾与内部文本清洗

**Files:**

- Create: `internal/multiagent/finalization.go`
- Create: `internal/multiagent/finalization_test.go`
- Modify: `internal/multiagent/eino_adk_run_loop.go`
- Modify: `internal/multiagent/eino_adk_runner.go`
- Modify: `internal/handler/eino_single_agent.go`
- Modify: `internal/multiagent/finalize_continuation.go`

**Step 1: 写失败测试**

验证 planning-only、`identity_gap`、`execution_stagnation`、pending cleanup 提示均不能成为最终用户回复；finalizing 时调用一次禁用工具的 finalizer；超时/空回复时返回包含“已验证事实、未确认候选、限制与下一步”的确定性报告。

Run: `go test ./internal/multiagent -run 'TestFinalization|TestSanitizeFinalResponse'`

Expected: FAIL。

**Step 2: 最小实现**

为 run args 注入 no-tool finalizer，并设置独立 deadline。所有终止路径统一经过 `FinalizeRunResult`；内部控制标记进入诊断事件，不进入用户正文。模型收尾失败时由 execution state 和 recent tools 生成报告。

**Step 3: 验证与提交**

Run: `go test ./internal/multiagent ./internal/handler`

Commit: `fix: guarantee clean evidence-based final reports`

## Task 6: 漏洞证据策略与拒绝记忆

**Files:**

- Create: `internal/multiagent/evidence_policy.go`
- Create: `internal/multiagent/evidence_policy_test.go`
- Modify: `internal/multiagent/eino_single_execution_middleware.go`
- Modify: `internal/multiagent/execution_evidence.go`

**Step 1: 写失败测试**

覆盖：

- 通配 ACAO 与 credentials 组合不自动构成可读取凭据的 CORS 漏洞。
- JSONP 参数反射没有浏览器源上下文证明时不能改类型落成 XSS。
- IDOR 必须有两个身份或等价授权差异证据。
- 同一证据被策略拒绝后，换漏洞类型再次提交仍被同一证据指纹阻止。

Run: `go test ./internal/multiagent -run 'TestEvidencePolicy'`

Expected: FAIL。

**Step 2: 最小实现**

在 `record_vulnerability` precheck 前构造证据指纹并执行策略。证据不足返回可操作的候选提示并写入 rejection memory；不修改底层通用漏洞工具的合法能力。

**Step 3: 验证与提交**

Run: `go test ./internal/multiagent`

Commit: `fix: require vulnerability-specific evidence before recording`

## Task 7: 监控语义与会话归属

**Files:**

- Modify: `internal/handler/monitor.go`
- Modify: `internal/handler/monitor_test.go`
- Modify: `internal/mcp/tool_execution.go`
- Modify: 对应 SQLite migration/schema 文件（以仓库实际结构为准）

**Step 1: 写失败测试**

验证 monitor 分开统计基础设施成功、目标否定、调用错误、瞬态失败、策略拒绝和 framework drop；completed execution 也能持久化/补齐 conversation ID。

Run: `go test ./internal/handler ./internal/mcp -run 'TestMonitor|TestToolExecution'`

Expected: FAIL。

**Step 2: 最小实现**

在执行记录中保存 semantic outcome；旧记录读取时按现有字段派生兼容值。会话补齐不再只处理 `running` 状态，避免完成记录归属为空。

**Step 3: 验证与提交**

Run: `go test ./internal/handler ./internal/mcp`

Commit: `fix: expose semantic tool outcomes in monitoring`

## Task 8: 真实会话回归、全量验证与本地提交

**Files:**

- Create: `internal/multiagent/testdata/session_de13_convergence.json`
- Create or modify: `internal/multiagent/eino_convergence_integration_test.go`
- Modify: `CONTEXT.md`（仅在实现后的术语与设计有偏差时）

**Step 1: 建立最小脱敏 fixture**

只保留会触发问题的事件序列：重复 SPA shell、状态写 schema error、策略拒绝后类型替换、stagnation、drop-before-register 和 planning-only final response。不得包含 bearer token、真实 cookie 或直接身份数据。

**Step 2: 集成回归**

断言：

- 不超过自适应预算即进入 finalizing。
- 不产生伪 XSS 正式记录。
- drop-before-register 后 pending 为零。
- 最终报告无内部控制文本且包含已验证事实。

Run: `go test ./internal/multiagent -run TestSessionDe13Convergence -count=1`

**Step 3: 全量验证**

Run:

```powershell
go test ./... -count=1
go vet ./...
git diff --check
git status --short
```

如仓库提供前端或额外构建脚本，再执行对应构建；失败必须区分本次回归与既有环境问题。

**Step 4: 最终本地提交**

检查 staged diff 不含密钥、真实会话凭据和无关文件后提交：

`git commit -m "fix: make agent execution evidence-driven and reliable"`

不得执行 `git push`。
