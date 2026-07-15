# Eino Single Agent 执行控制与决策义务设计

## 1. 背景

本设计以一次真实的 `eino_single` 单 ADK 执行记录作为样本，但解决的是项目级通用执行问题，不针对某个中间件、漏洞类型或目标编写特例。

样本任务的关键数据：

- 总时长 25.39 分钟，31 轮 Agent 迭代，118 次工具调用。
- 30 个工具批次中 29 个是并行批次，单批最多 7 个工具。
- 首次出现稳定、可复现、可报告的强证据后，约 24 分 16 秒才写入 L1 candidate。
- Agent 早期已将同一证据写入 project fact，说明问题不是证据识别失败，而是识别后无法约束下一动作。
- 收尾时 L1 与 4 个 coverage upsert 同批并发，其中一个 upsert 被硬断路器拒绝。
- 首轮同时加载多个宽泛 skill，其中一个输出约 73,411 字符，形成明显的上下文噪声。

当前已有的 structured summary、dead-tool、coverage、surface detection、finalize gate 和进程树终止能力继续保留。新设计将这些能力收敛到一个可验证的单 Agent 执行控制闭环。

## 2. 范围

### 2.1 本次实现

- 仅修改 `eino_single` 模式。
- 每个会话只处理用户明确委派的一个主目标。
- 修正模型输出的工具批次，保证决策、状态变更和探测之间的因果顺序。
- 增加通用的“决策义务”生命周期，先覆盖可报告强证据的及时落库。
- 统一 Agent 总截止时间、模型调用超时、工具超时、shell 空闲超时、取消传播与重试预算。
- 增加证据新颖度与停滞检测，防止同一假设无上限字典爆破。
- 限制 skill 加载数量和 Agent 可见内容体积。
- 为 curl/API 诊断提供执行决策摘要和状态事件。

### 2.2 不在本次范围

- Deep、Plan-Execute、Supervisor 和子 Agent 调度。
- 多目标、多资产或跨目标义务调度。
- 新的扫描器、PoC 或漏洞场景专用正则。
- 将执行状态持久化到新数据库表。本次仍使用会话内存状态和现有 process details 持久化。

## 3. 成功标准

1. 可报告强证据出现后，最迟下一次模型迭代完成 L1/L2，且在落库前不执行无关探测。
2. L1/L2、coverage upsert、project fact、skill 加载和 `should_continue_execution` 不与探测工具混合并发。
3. L1 成功后自动满足对应决策义务，并关闭该义务关联的发现型 coverage；不要求 Agent 手工补 upsert。
4. 重复的同一证据不会重开 `done/blocked` coverage；新证据指纹仍可生成新义务。
5. 连续 3 个探测批次或 12 次探测调用没有新证据时，下一轮必须换假设、标记 blocked 或收尾，不允许继续同类爆破。
6. 超时返回结构化原因、所属层级、已产生的部分输出和剩余重试预算；相同参数超时不会无限重试。
7. 用户停止、中断继续、Agent 总超时、模型超时、工具超时和 shell 空闲超时可被准确区分。
8. 回放样本事件时，L1 从第 31 轮前移到首次强证据后的下一轮，收尾 4 次 coverage upsert 不再出现。

## 4. 整体架构

```text
ChatModel 输出
  -> AfterModelRewriteState: 工具批次分类与重写
  -> Tool middleware: 执行前义务/重试/截止时间校验
  -> 真实工具执行
  -> 结构化 ToolOutcome + 部分输出
  -> 证据指纹与新颖度更新
  -> 创建/满足 DecisionObligation
  -> 关闭关联 coverage
  -> BeforeModelRewriteState: 向下一轮注入唯一、短促的框架指令
```

实现保持两道防线：

- `AfterModelRewriteState` 在工具节点执行前直接重写模型产生的 `ToolCalls`，这是主要因果顺序保障。Eino v0.9.12 已明确允许该 hook 修改并持久化模型响应状态。
- 现有 tool middleware 增加执行前检查作为防御性保障，防止续跑、恢复历史或框架差异绕过批次重写。

## 5. 会话主目标

`RunEinoSingleChatModelAgent` 启动时，从当前用户消息和现有会话上下文中提取主目标，经 `NormalizeCoverageTarget` 归一化后写入 `ConversationExecutionState.PrimaryTarget`。

规则：

- 首次提取成功后固定，后续工具输出中的其他 host 不会改写主目标。
- 工具参数有 URL/host 时必须与主目标一致；不一致的结果可记录为外部线索，但不生成本会话的探测义务。
- 如首次提取失败，使用第一个成功执行的网络工具参数补全；本设计不引入多目标分支。

## 6. 决策义务

### 6.1 数据模型

```go
type DecisionObligation struct {
    ID              string
    Kind            string // record_finding
    Target          string
    EvidenceHash    string
    EvidenceSummary string
    Priority        string // P0 | P1
    RequiredTools   []string
    LinkedCoverage  []string
    BoundToolCallID string
    Status          string // pending | satisfied | blocked
    CreatedAt       time.Time
    ResolvedAt      time.Time
    Resolution      string
}
```

`EvidenceHash` 使用“归一化主目标 + 信号种类集合 + 具体路径/资源集合 + 结果指纹”生成。同一工具结果中的多个相关强信号合并成一个 obligation，避免一次响应要求多次 L1。

### 6.2 创建

现有 `DetectSurfaceSignals` 改为通用证据适配器的第一个输入源，但 obligation 管理器本身不理解 CXF、Swagger、GraphQL 等场景名称，只接收：

```go
type ExecutionSignal struct {
    Class       string
    Target      string
    Resources   []string
    Reportable  bool
    Confidence  string
    Priority    string
    Summary     string
}
```

仅 `Reportable=true` 且 `Confidence=confirmed` 的信号创建 `record_finding` obligation。软 400、单个偶发状态码、空 404 或未复现扫描命中不会触发执行层硬门。

### 6.3 解析

当批次重写器允许 `record_vulnerability_candidate` 或 `record_vulnerability` 执行时，先把 obligation ID 与该次 ToolCall ID 绑定。执行前校验记录参数仍指向主目标，并至少引用 obligation 的一个资源或证据摘要；不匹配则拒绝执行并返回短促纠正，不能拿无关 L1 满足义务。

绑定的记录调用成功写入数据库后：

1. 解析当前主目标下最早、最高优先级的 pending `record_finding` obligation。
2. 记录实际 vulnerability ID 作为 resolution。
3. 将 obligation 关联的自动发现型 coverage 设为 `done`，note 写入 `resolved by L1/L2: <id>`。
4. L1 自身新建的 candidate coverage 不被关闭；它代表后续 L2 验证，仍按现有优先级规则决定是否阻塞收尾。

只有绑定 ToolCall ID 的成功结果可以解析 obligation。由于 pending obligation 会在生成后立即阻止其他探测，正常情况下同一时刻只会有一个待写的强证据义务，无需把内部 fingerprint 暴露给模型或加入工具 schema。

### 6.4 Coverage 终态

新增 `UpsertAutomaticCoverage`，自动检测器不再直接调用通用 `UpsertCoverage`。

- 自动 upsert 不得将 `done/blocked` 改回 `open/in_progress`。
- 显式 `upsert_execution_coverage` 保留人工重开能力。
- 自动 coverage 写入 obligation ID，便于精确关闭，不使用“关闭所有 surface”这类会话级布尔逻辑。

## 7. 工具批次治理

### 7.1 分类

```text
probe_readonly   HTTP 请求、侦察、手工验证、扫描器
long_running     重扫描、长脚本、显式后台任务
state_mutation   project fact、coverage upsert、skill 加载
decision         L1/L2 记录、should_continue_execution
unknown          尚未登记语义的新工具
```

工具名集中维护在单个纯函数中；带有明确写状态语义的内置工具必须显式列入后两类。未知工具不得假定只读，按 `unknown` 独占批次串行执行，并发出一次可观测事件，避免新接入的写工具绕过状态顺序。

### 7.2 `AfterModelRewriteState` 规则

1. 存在 pending `record_finding` obligation 时，只保留第一个 `record_vulnerability_candidate` 或 `record_vulnerability`。如模型未产生解析工具，清空所有其他 ToolCalls，让下一迭代收到短促纠正。
2. 批次内只要存在 `decision` 或 `state_mutation`，只保留一个最高优先级状态工具，移除其他状态工具和全部探测工具。
3. 纯 `probe_readonly` 批次最多保留 3 个调用。
4. `long_running` 每批最多一个，不与其他工具并发。
5. `skill` 属于状态修改：每轮最多加载一个，不与探测同批。
6. `unknown` 每批最多一个，不与其他工具并发。
7. 被移除的 ToolCalls 不生成伪造 tool result，避免孤儿消息。框架将重写摘要写入会话执行状态，下一次 `BeforeModelRewriteState` 注入一次性说明。

状态工具优先级：

```text
record_vulnerability / record_vulnerability_candidate
  > should_continue_execution
  > upsert_execution_coverage
  > upsert_project_fact
  > skill
```

### 7.3 执行前防御性检查

Tool middleware 再次检查：

- pending record obligation 下的非解析工具直接返回 `dependency_blocked`，不进入真实工具。
- 已标记 dead 的工具不再执行。
- 相同调用签名已用尽重试预算时不再执行。
- Agent 总截止时间剩余不足时，不启动不可在剩余时间内完成的工具。

## 8. 证据新颖度与停滞检测

### 8.1 调用签名

`CallSignature` 由工具名、HTTP method、归一化 URL/path、影响语义的 header、body/payload hash 和扫描范围参数组成。时间戳、输出路径和 tool call ID 不参与签名。

相同 URL 但不同 Accept、method 或 payload 属于不同假设；因此不使用简单 URL 去重。

### 8.2 结果指纹

`ResultFingerprint` 包含：

- 结构化 status/error code。
- HTTP 状态码、长度桶、响应标题/类型。
- 提取到的 endpoint、参数、资源和高价值信号集合。
- 标准化错误原因。

以下任一发生即视为新证据并重置停滞计数：

- 新资源/新参数/新路径。
- 新响应类或稳定差分。
- 信号从推测升级为可复现。
- 新 obligation 或已有 obligation 被满足。

### 8.3 停滞门

连续 3 个完成的探测批次或 12 次探测调用没有新证据时：

- 写入 `pivot_required` 一次性指令。
- 下一轮只接受一个明显不同的调用签名、一个 blocked/coverage 状态更新，或 `should_continue_execution`。
- 如下一轮仍是同假设的扩大字典，在执行前返回 `stagnation_blocked`。

停滞门不会因单次超时或单次 404 触发，也不会强制结束任务；它要求更换假设或明确关闭当前分支。

## 9. 截止时间树

### 9.1 原则

所有超时都从同一个 Agent run deadline 派生：

```text
Agent run deadline
  |- model call deadline
  |- tool call deadline
      |- connect timeout
      |- stream idle timeout
      `- shell process-tree termination deadline
```

子 deadline 的有效值始终为：

```text
min(会话剩余时间, 工具分类默认值, per-tool 覆盖, 调用方已有 deadline)
```

“中断并继续”可换新 cancel context，但必须保留原始绝对 run deadline，不得像当前实现一样每次重置 600 分钟。

### 9.2 默认值

| 层级 | 默认值 |
|---|---:|
| Agent 整轮 run | 120 分钟 |
| Agent 最大迭代 | 200 |
| 单次模型调用 | 300 秒 |
| 模型流无新 chunk | 120 秒 |
| decision/state 内置工具 | 30 秒 |
| 轻量 HTTP/侦察 | 120 秒 |
| 模板/字典扫描器 | 900 秒 |
| 利用类工具 | 1200 秒 |
| exec/execute 前台 wall-clock | 300 秒 |
| shell 无输出空闲 | 300 秒 |
| 进程树终止后强制回收宽限 | 5 秒 |

默认值保持现有重扫描的长时间能力，但将当前 3000 迭代和 600 分钟单段总超时收紧为可控上限。

### 9.3 结构化结果

内部不再仅通过文本正则推断超时。每次工具执行产生：

```go
type ToolOutcome struct {
    Code          string // ok, timeout, idle_timeout, cancelled, unavailable, config_error, dependency_blocked, stagnation_blocked
    TimeoutLayer  string // run, model, tool, connect, stream_idle, shell_idle, wall_clock
    Retryable     bool
    RetryLeft     int
    PartialOutput string
    Duration      time.Duration
}
```

`ToolOutcome` 存入会话状态和 process details，再渲染为简短的 Agent-facing 文本。保留 `classifyToolError` 仅作为无结构外部 MCP 结果的兼容降级路径。

### 9.4 部分输出

- Streamable tool 超时时保留已收到 chunks，末尾追加 timeout 结构块。
- Invokable tool 如已返回部分结果，同样保留；判定超时时检查 `ctx.Err()` 而不仅是 `err != nil`。
- shell 超时先终止进程组，最多等待 5 秒回收；仍未退出时强制 kill，不得无界等待 `<-done>`。

## 10. 重试预算

模型调用重试与工具重试分开计数。现有 Eino transient run retry 只处理模型/运行流短暂故障，不代替工具重试策略。

| 结果 | 同签名重试 |
|---|---:|
| unavailable / templates_missing / config_error | 0 |
| dependency_blocked / stagnation_blocked | 0 |
| timeout / idle_timeout | 0；只允许一次“范围已收窄”的新签名 |
| connect/target_unreachable | 1 次轻量连通性复核 |
| HTTP 429 | 1 次，遵循 Retry-After |
| HTTP 5xx / 外部 MCP 短暂失败 | 1 次，有界退避 |

“收窄范围”要求新调用的字典、目标路径数、线程数、severity/tags 或 timeout 参数有可观察的收缩；仅修改输出文件名不算新签名。

## 11. Skill 上下文治理

- 单轮最多一个新 skill。
- 手工 `skill` 工具与自动 skill router 共享同一个 loaded-skill 去重集合。
- skill router 在 `eino_single` 中默认 TopK 为 1。
- 完整 skill 输出仍可持久化，Agent-facing 内容最多 4,000 runes，超出部分用 persisted-output 引用。
- 已有通用方法论 skill 时，不再同轮加载另一个高重叠宽泛 skill。

## 12. 模型指令

长门闩改为状态驱动的短指令，每轮最多注入一个最高优先级指令。

Pending record 示例：

```text
[framework_next_action]
已有可复现强证据待记录。下一个并且唯一的工具调用必须是
record_vulnerability_candidate 或 record_vulnerability。
禁止与探测、coverage、fact 或 skill 并发。
evidence: <200 rune summary>
```

完成后不再反复注入该指令。真正的顺序保证来自 ToolCalls 重写和 tool precheck，而不是寄希望于提示词权重。

## 13. 可观测性

新增 process detail 事件：

- `execution_obligation_created`
- `execution_obligation_resolved`
- `tool_batch_rewritten`
- `tool_call_blocked`
- `tool_timeout`
- `execution_stagnation`
- `execution_budget_exhausted`

完成任务摘要增加：

```json
{
  "iterations": 31,
  "toolCallsPlanned": 118,
  "toolCallsExecuted": 80,
  "toolCallsDropped": 38,
  "timeouts": 2,
  "stagnationGates": 1,
  "obligationsCreated": 1,
  "obligationsPending": 0,
  "lastNewEvidenceAt": "..."
}
```

`GET /api/agent-loop/tasks/completed` 保留现有任务字段，并可选返回上述简短 `executionSummary`；完整事件仍通过现有 message process-details 接口读取。

## 14. 代码落点

### 新增

- `internal/multiagent/execution_controller.go`
  - obligation、primary target、新颖度、停滞与重试预算的纯状态逻辑。
- `internal/multiagent/eino_single_execution_middleware.go`
  - `BeforeModelRewriteState` 指令注入。
  - `AfterModelRewriteState` ToolCalls 重写。
- `internal/multiagent/tool_outcome.go`
  - 结构化 outcome、超时层级与兼容文本渲染。

### 修改

- `internal/multiagent/eino_single_runner.go`
  - 仅在 `eino_single` handlers 中挂载 execution middleware。
  - 初始化单主目标和 run budget。
- `internal/multiagent/skill_router_middleware.go`
  - tool precheck、结果新颖度和 obligation 创建。
- `internal/multiagent/tool_exec_governor.go`
  - 统一 deadline 解析、部分流输出和结构化 outcome。
- `internal/multiagent/execution_evidence.go`
  - 增加执行控制状态，移除会话级 `surfaceSignalSeen/vulnerabilityRecorded` 对决策的布尔依赖。
- `internal/multiagent/surface_discovery.go`
  - 只负责证据提取与自动 coverage，不再拥有独立长提示词门闩。
- `internal/multiagent/coverage_from_vuln.go`
  - obligation-linked coverage 关闭。
- `internal/app/vulnerability_tools.go`
  - DB 写入成功后解析 obligation。
- `internal/handler/eino_single_agent.go`
  - 用配置化 run deadline 替代硬编码 600 分钟，中断续跑保留绝对 deadline。
- `internal/security/executor.go`
  - 有界进程树回收和 timeout outcome。
- `internal/config/config.go`
  - 增加 run/model 超时字段；现有 per-tool timeout 覆盖继续兼容。
- `internal/handler/task_manager.go`
  - 完成任务时快照 execution summary。

不修改 `runner.go` 的 Deep 路径、Plan-Execute executor、Supervisor 和子 Agent 结构。

## 15. 配置

新增字段保持最小：

```yaml
agent:
  eino_single_execution:
    enabled: true
    max_iterations: 200
    run_timeout_minutes: 120
    model_call_timeout_seconds: 300
    model_stream_idle_timeout_seconds: 120

multi_agent:
  eino_middleware:
    skill_router_top_k: 1
    skill_router_max_runes: 4000
```

- `agent.eino_single_execution` 是新增的单 ADK 专属配置块，不复用全局 `agent.max_iterations`，避免改变 Deep、Plan-Execute、Supervisor 或子 Agent 行为。
- `enabled` 省略时默认 true；设为 false 时回滚 obligation、批次重写和停滞门，但保留原有超时和进程回收修正。
- 现有 `tool_exec_governor.per_tool_timeout_sec` 继续作为工具覆盖，但不能超过 run 剩余时间。

## 16. 测试设计

### 16.1 状态单测

- 同一证据指纹只创建一个 obligation。
- 新指纹会创建新 obligation。
- L1 只解析当前最早高优先级 pending obligation。
- 自动 coverage 不重开终态，显式 upsert 可重开。
- 停滞计数在新证据出现时重置。
- 不同调用签名的重试预算互不影响。

### 16.2 ADK middleware 单测

使用 Eino `ChatModelAgentState` 构造模型响应，验证：

- pending obligation + `record + 3 probes` 只保留 record。
- pending obligation + 纯 probes 清空 ToolCalls 并生成一次性纠正。
- `fact + coverage + probes` 只保留优先级最高的状态工具。
- 7 个 probes 被稳定截断为前 3 个。
- 被移除的 ToolCalls 不留孤儿 tool message。

### 16.3 超时单测

- Invokable 超时在 `err=nil` 但 `ctx.Err()!=nil` 时仍正确标记。
- Streamable 超时保留已收到 chunks。
- run deadline 永远压缩工具 deadline。
- 中断续跑不延长绝对 deadline。
- shell 终止后最多 5 秒强制回收。
- timeout 原参数重试被拒绝，收窄后的新签名允许一次。

### 16.4 单 Agent 集成测试

用 fake ChatModel 和 fake tools 验证完整闭环：

1. probe 返回可报告强证据。
2. 下一轮模型同时产生 L1 和多个 probes。
3. 只执行 L1。
4. L1 成功后 obligation 满足、关联 coverage 关闭。
5. 同一强证据再次出现不重开 coverage。
6. `should_continue_execution` 可正常收尾，无手工 surface upsert。

### 16.5 真实记录回放

将本次 359 个 process events 抽取为脱敏 fixture，只保留工具名、参数签名、结果指纹、批次和时序。回放断言：

- 首次强证据后下一轮解析 L1 obligation。
- 没有收尾 coverage upsert 风暴。
- 连续无新证据的字典分支触发 pivot。
- 计划 118 个工具时，实际执行数显著下降，且不损失已确认证据。

## 17. 实施顺序

1. 先引入纯状态的 execution controller、指纹和单测。
2. 接入 `eino_single` After/BeforeModel middleware，完成批次重写。
3. 接入 L1/L2 obligation 解析与 coverage 终态。
4. 统一 run/model/tool/shell deadline 和 ToolOutcome。
5. 增加停滞、重试和 skill 预算。
6. 增加 process events、completed task execution summary 和脱敏回放测试。
7. 运行 `go test ./internal/multiagent ./internal/app ./internal/handler ./internal/security`，再用 fake ChatModel 集成测试验证单 ADK 闭环。

## 18. 风险与降级

- **强信号误报导致阻断**：只对 confirmed + reportable 创建硬 obligation；其他信号仍是软提示。
- **严格串行增加迭代数**：只串行状态/决策工具，纯探测仍允许 3 并发。
- **超时损失证据**：流式和 shell 路径必须保留 partial output 后再返回 timeout outcome。
- **新门闩造成死循环**：所有 obligation 都可被成功工具解析；记录工具校验失败时保留 pending 并返回具体字段错误；不以自动 force-stop 伪装成成功。
- **回滚**：关闭 `agent.eino_single_execution.enabled` 即可恢复原 ToolCalls 执行方式；超时与进程回收修正独立保留。
