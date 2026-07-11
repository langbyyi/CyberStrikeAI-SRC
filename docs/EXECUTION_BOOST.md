# 挖洞执行增强（Execution Boost / src_hunter_runtime）

在**不修改系统提示词 / agents 作战长文**的前提下，通过运行时中间件、工具注册与配置默认提升 Agent 执行力。

## 一键开关

在 `config.yaml` 的 `multi_agent.eino_middleware` 下：

```yaml
execution_boost: true          # 默认 true；false 关闭增强
src_hunter_runtime:
  enable: true                 # 覆盖 execution_boost
  skill_router: true
  task_evidence_k: 5
skill_router_enable: true
structured_summary_max_runes: 1200   # 扫描器结构化摘要预算（第二轮）
finalize_gate_enable: true           # 收工半硬门闩（第二轮；默认跟随 boost）
task_require_target: true
```

**回滚**：`execution_boost: false` 或 `src_hunter_runtime.enable: false`，重启服务即可恢复增强前行为（L1/coverage 工具仍注册，但不注入 always_visible 默认集与 SkillRouter）。

---

## 第一节 · 第一轮能力

| 能力 | 配置键 | 行为 |
|------|--------|------|
| 核心工具常驻可见 | `execution_boost` | 合并 `sqlmap/nuclei/ffuf/katana/arjun/dalfox/http-framework-test/exec/execute-python-script/jwt-analyzer/dnslog/skill` 与漏洞/fact/coverage 内置工具到 always_visible |
| Skill 自动触达 | `skill_router_*` / `src_hunter_runtime.skill_router` | 工具结果后处理注入 Top1–3 skill 要点（去重+预算） |
| 上下文保全 | `reduction_clear_exclude` + summarization instruction | 默认 exclude 安全工具；摘要强制保留 open_hypotheses/almost_signals/dead_ends/auth_coverage |
| task 交接 | `task_evidence_k` / `task_require_target` | 附加用户目标、最近 K 次工具摘要、项目 fact 正文；缺 target 拒绝或回填；verify/exploit 纠正 subagent 路由 |
| L1 候选 | 工具 `record_vulnerability_candidate` | 差分/信号即可写 status=candidate；L2 `record_vulnerability` 门槛不变 |
| 硬拒绝粒度 | （代码） | key=`(conversation, target, type/category)`，同站不同类型不互伤 |
| 执行门闩（软） | `upsert/get_execution_coverage`、`should_continue_execution` | 会话 coverage + P0/P1 未闭环提示；关键工具自动 upsert |

### 第一轮关键日志

- `eino middleware: tool_search enabled|disabled`：`execution_boost`、`always_visible_merged`
- `skill_router injected`：注入了哪些 skill
- `task handoff enriched|rejected`：附加证据条数 / 缺 target
- `candidate vulnerability recorded` / `execution coverage upsert` / `should_continue_execution`

---

## 第二节 · 第二轮（结构性补强）

第一轮 always_visible / 软门闩在「角色未挂工具」「模型不调 should_continue」「大输出糊成一团」时仍会浅扫收工。第二轮在**仍不改 system prompt / agents 长文**的前提下补齐：

### 1. 角色 tools 对齐

默认挖洞角色（至少：`渗透测试`、`企业SRC渗透测试`、`EDUSRC渗透测试`、`Web应用扫描`，以及综合扫描/API/框架等常用角色）的 `tools:` 列表补齐与 `execution_boost` 一致的核心集：

- 扫描器：`sqlmap` `nuclei` `ffuf` `katana` `arjun` `dalfox` `http-framework-test`
- 执行：`exec` `execute-python-script` `jwt-analyzer` `dnslog` `skill`
- 漏洞/事实：`record_vulnerability` `record_vulnerability_candidate` `list_vulnerabilities` `get_vulnerability` 与 project fact 工具
- coverage：`upsert_execution_coverage` `get_execution_coverage` `should_continue_execution`

**只改 tools 列表，不改 user_prompt 长文。** 单测：`TestHuntingRolesToolsIncludeCoreSet`。

### 2. 收工半硬门闩（finalize gate）

问题：仅依赖模型调用 `should_continue_execution` 无效。

实现（方案 A）：在 eino_single / ADK run loop 组装最终 `RunResult.Response` 之后，若会话 coverage 仍有 **open/in_progress 的 P0/P1**，且助手文本匹配「无漏洞 / 测试完成 / 未发现」类收工话术，则**追加**框架块 `[finalize_gate_blocked]`，列出 open 项并要求继续验证或标 `blocked`。

- 纯函数：`ApplyFinalizeGate` / `ApplyFinalizeGateToRunResult`
- 不改 system prompt；日志字段：`finalize_gate_blocked`
- 配置：`finalize_gate_enable`（nil 跟随 `execution_boost`）

### 3. 安全工具结构化摘要（reduction 增强）

对 `sqlmap` / `nuclei` / `ffuf` / `http-framework-test` / `dalfox` / `execute-python-script` 等，在 tool 结果后处理中**置顶**固定结构短摘要：

```
status_hint / http_status / length / time_ms / error_sig / interesting_params / matched_payload / next_hint
```

- 预算：`structured_summary_max_runes`（默认 1200，建议 800–1500）
- 原文仍保留（过长可由既有 reduction 截断落盘）
- 日志字段：`tool_structured_summary`

### 4. SkillRouter 加强

- 参数名启发：`id` / `file` / `url` / `path` / `redirect` / `q` / `search` / `token` / `jwt` 等
- 无强信号时，对 web 入口类工具弱推 `recon-and-methodology` 或 `bug-bounty`（低权重，受 TopK/去重限制）
- skills 目录缺失时静默降级（不报错）

### 5. L1 → L2 与 coverage 联动

- 写入 `record_vulnerability_candidate` 时自动 upsert coverage（path≈target+param/type，status=open，priority 按类型/严重度估 P0/P1）
- 日志：`coverage_auto_from_candidate`
- L2 `record_vulnerability` 成功时尽力将匹配 coverage 标 `done`

### 第二轮关键日志

| 字段 | 含义 |
|------|------|
| `finalize_gate_blocked` | 收工话术被门闩拦截并改写/追加 |
| `tool_structured_summary` | 扫描器结果已置顶结构化摘要 |
| `coverage_auto_from_candidate` | L1 候选写入时自动 upsert coverage |

---

## 第三节 · 代码健全与回归

本轮把挖洞运行时当作**框架本体**做代码层健全：边界条件、配置一致性、热重载、并发安全、单测锁、可观测与失败降级。**不依赖真实 SRC/内网目标**，不要求本机长期跑服务。

### 1. 如何只跑单测验收

```bash
# 核心三包（无 CGO 时 sqlite 相关 Skip，不得红）
go test ./internal/multiagent/ ./internal/app/ ./internal/config/ -count=1
go build ./cmd/server/
```

Windows PowerShell：

```powershell
$env:CGO_ENABLED=0; go test ./internal/multiagent/ ./internal/app/ ./internal/config/ -count=1
go build ./cmd/server/
```

### 2. 默认即内核与 kill_switch

| 能力 | 默认 | 关闭方式 |
|------|------|----------|
| execution_boost 全家桶 | **开**（`Effective()` 在字段 nil 时为 true） | `execution_boost: false` 或 `src_hunter_runtime.enable: false` |
| SkillRouter | 跟随 boost | `skill_router_enable: false` 或 `src_hunter_runtime.skill_router: false` |
| finalize 半硬门闩 | 跟随 boost | `finalize_gate_enable: false` |
| 结构化摘要预算 | 1200 runes | `structured_summary_max_runes: N`（≤0→1200；>8000→8000） |

L1 candidate / coverage 工具在 boost 关闭后**仍注册**（热重载 `registerCoreSessionTools`），只是不再合并 always_visible 默认扫描器集、不注入 SkillRouter。

### 3. 关键日志字段（统一）

| 字段 | 含义 |
|------|------|
| `execution_boost` | tool_search / middleware 日志中的 boost 开关与 always_visible 合并规模 |
| `skill_router injected` | 本次工具结果注入的 skill 目录名列表 |
| `tool_structured_summary` | 扫描器结果已置顶结构化摘要 |
| `finalize_gate_blocked` | 收工话术被门闩改写/追加 |
| `coverage_auto_from_candidate` | L1 候选写入时自动 upsert coverage |

### 4. 代码契约（单测锁定）

- **finalize**：`CoverageShouldBlockFinalize` / `ApplyFinalizeGate`；ADK 正常结束与错误/部分结果出口均经 `maybeApplyFinalizeGate`；logger nil 安全
- **摘要顺序**：`summary → 原文 → skill block`（`ComposeToolResultWithBoostOrder`）
- **coverage**：path 规范化（host 小写、去默认端口）；priority 表（sqli/rce/auth→P0/P1，info→P2/P3）；`ShouldContinue` 仅计 open|in_progress 的 P0/P1
- **会话态**：`ConversationExecutionState` 方法均带 mutex；coverage / 会话 map 有 max entries 淘汰
- **角色 tools**：`TestHuntingRolesToolsIncludeCoreSet` + tools/*.yaml 存在性校验

### 5. 已知限制

1. finalize 门闩**改写最终助手文本**，不硬 kill 进程/会话；模型仍可在下一轮无视提示。
2. **无实网 / 无真 LLM 集成测试**；验收以纯函数与结构单测为准。
3. L2 `record_vulnerability` 证据门槛**不降低**；candidate 仅联动 coverage，不替代完整 PoC。

### 6. 禁改路径（回归自检）

```bash
git diff -- internal/agent/default_single_system_prompt.go agents/
```

应为空（或仅无关空白，本轮要求作战长文零改动）。

---

## 与系统提示词的边界

- **禁止改**：`internal/agent/default_single_system_prompt.go`、`agents/*.md` 作战长文、roles 长 `user_prompt` 文案
- **允许改**：summarization 压缩 instruction（框架摘要策略）、中间件、工具、配置默认、roles 的 **tools 列表**

验证未改提示词：

```bash
git diff -- internal/agent/default_single_system_prompt.go agents/
```

验证角色仅 tools 变更（抽样）：

```bash
git diff -- roles/
```

---

## 第四节 · 业务/后端缺陷轨（Business/Backend Logic Track）

**产品口径（R5 纠偏）**：目标是更多可利用的 **后端/业务实现缺陷**，不是「逻辑漏洞 = 越权」。  
水平/垂直越权仅为**子集**；**单身份即可推进**支付/流程/篡改/竞态。双号只用于 idor 类加测，**不是整轨入场条件**。

范围包括：支付金额/数量/折扣客户端篡改；流程跳步（未支付 confirm）；券/积分/邀请码滥用；竞态双花与重复回调；信任前端 `status`/`paid`/`role`；退款售后状态机；以及可选的越权。

第四轮落地闭环；**第五轮纠偏**权重与文案，避免模型只挖 IDOR。

### 1. 闭环（信号 → gate）

```text
支付/流程/业务 JSON 信号
    → 业务类 coverage open（param_tamper / workflow_skip / coupon_abuse / race / state_tamper …）
    → SkillRouter 高权重 business-logic（race 中权；idor 中低且需跨用户语境）
    → logic_probe_diff：param_tamper → step_skip → parallel →（有双号再）identity_diff
    → L1 candidate（业务不变量差分，无需双号）+ coverage
    → 仅扫 CVE「无洞收工」→ finalize 仍可挡（业务 open 未闭环）
```

| 环节 | 关键符号 / 工具 | 行为 |
|------|-----------------|------|
| Skill 路由 | `RouteSkills` | **高**：`business-logic-vulnerabilities`（amount/price/checkout/pay/callback…）；**中**：`race-condition`；**中低**：idor 仅明确 user_id/跨用户；CVE-only **不得** Top1 business-logic |
| 业务 coverage | `HeuristicLogicSignals` | **优先** `param_tamper` `workflow_skip` `coupon_abuse` `race` `state_tamper` `auth_step_skip`；`idor_horizontal` **仅**跨用户语境，支付入口不强制 idor |
| 差分探针 | `logic_probe_diff` | 默认 mode=`param_tamper`；主用途支付/流程/竞态；`identity_diff` **可选**；`next_hint` 偏业务不变量 |
| L1 | `record_vulnerability_candidate` | signal=业务不变量差分即可，**不要求双账号**；type 优先业务类 |
| 身份缺口 | `BuildIdentityGapHint` | **仅**提示跨账号/水平越权未测；**禁止**「无双号=逻辑无法测/整轨跳过」 |
| 门闩 | `ApplyFinalizeGate` | 业务 open P0/P1 挡「无洞」；与注入类同等 |

### 2. 单号 vs 双号

| 能力 | 单号 | 双号 |
|------|------|------|
| 金额/数量/券/跳步/竞态/状态篡改 | 可测（主路径） | 同左 |
| 水平越权 / 跨账号对象访问 | 深度不足（诚实提示） | `identity_diff` 加测 |

### 3. 默认开与紧急关闭

视为挖洞运行时本体，**默认开**，跟随 `execution_boost`。  
紧急关：`execution_boost: false` 或 `src_hunter_runtime.enable: false`。

### 4. 与扫描轨的关系

- nuclei/CVE 扫描轨不变；**业务 open 未完成**时不能只靠 CVE 列表收工。
- 支付入口 open 的是 param_tamper/workflow 等，不是「默认唯一 idor」。

### 5. 验收（仅代码层）

```bash
go test ./internal/multiagent/ ./internal/app/ ./internal/config/ -count=1
go build ./cmd/server/
```

重点：`TestHeuristic_PaymentCheckout_*`、`TestRouteSkills_PayCreateAmount_*`、`TestLogicProbe_DescriptionBusinessFirst`、`TestFinalize_BusinessParamTamper*`、`TestFinalize_NoDualAuth_BusinessOpen_*`、`TestL1PaymentCandidate_*`。

### 6. 关键日志

| 字段 | 含义 |
|------|------|
| `coverage_auto_from_logic` | 自动业务/逻辑 coverage |
| `logic_probe_diff` | 探针调用 |
| `identity_gap` | **仅**跨账号未测提示（非整轨取消） |

### 7. 已知限制

1. 无双号时 **仅**水平越权深度下降；支付/流程/竞态仍应继续。
2. 无实网 / 无真 LLM e2e；实网仍需业务接口与账号权限。
3. 门闩改写最终文本，非杀进程；L2 证据门槛不降。

### 8. 禁改

- 不改 `default_single_system_prompt.go`、`agents/*.md` 作战长文。

---

## 第五节 · 工具执行治理（Execution Plane）

**问题（现场日志坐实）**：`exec` 跑 `curl`（无 `--max-time`）对 TCP 半开连接无限等 → 框架 `parallelRunToolCall` 的 `wg.Wait()` 等它 → 整轮阻塞，下一轮 LLM 永不发起；因 0 个 tool_result 返回，连 30s 心跳都不打，UI 完全静默。

控制面（execution_boost / coverage / finalize_gate）已很厚，但**工具执行面欠债**。第五节从开发侧系统性治理，让「一个挂死工具拖死整轮」不再可能，失败可被模型据以换路。**不破坏控制面、不改 eino 框架源码、不改 MCP JSON 协议。**

### 1. 配置（tool_exec_governor）

在 `config.yaml` 的 `multi_agent.eino_middleware` 下：

```yaml
tool_exec_governor:
  enable: true              # nil/true=开；false 一键关闭全部治理（恢复原行为）
  max_concurrent: 5         # 每会话工具并发上限；0/负数=不限；钳制 [0,32]
  mcp_per_call_timeout_sec: 600   # MCP 工具默认 per-call 超时；负数=不限；钳制 [60,7200]
  inject_cmd_timeout: true  # 对 curl/wget 未指定超时时注入 --max-time 兜底
  max_wall_clock_sec: 300   # exec/execute 单次工具调用 wall-clock 总上限；负数=不限；钳制 [60,7200]
  per_tool_timeout_sec:     # per-tool 超时覆盖（秒）
    nmap: 600
    nuclei: 900
    sqlmap: 1800
```

### 2. 七项治理（中间件层统一，覆盖 execute + MCP 两条路径）

| 项 | 位置 | 行为 |
|----|------|------|
| 并发上限（P2-b） | `tool_exec_governor.go` concurrencyLimitMiddleware | 按会话信号量限制并行工具数（默认 5），避免一个慢工具饿死整批；`0=不限` |
| MCP per-call 超时（P2-a） | `tool_exec_governor.go` perCallTimeoutMiddleware | 按工具分档（scanner 900s / exploit 1800s / recon 走默认 600s），超时转 soft error 让图继续（nil error），模型可据 `error_code: timeout` 换路 |
| 命令层超时注入（P2-d） | `executor.go` maybeInjectCmdTimeout | `exec`/`execute` 跑 curl/wget 且未指定超时时注入 `--max-time 60 --connect-timeout 10`（直击现场卡死根因） |
| wall-clock 总上限（P2-e） | `executor.go` executeSystemCommand | `exec`/`execute` 单次工具调用总时长硬上限（默认 300s）。与 inactivity 互补：inactivity 防「卡死无输出」，wall-clock 防「持续有输出但整体极慢」的长脚本拖死整轮 |
| 路径预检（P1-c） | `executor.go` preflightToolPaths | nuclei 模板库 / ffuf 字典缺失时不启动子进程，直接返回结构化 soft error，避免空等超时 |
| 非流式 inactivity（P2-c） | `executor.go` combinedOutputCancellableWithInactivity | 非流式执行叠加无输出空闲兜底（默认 300s），与流式路径一致，消除「仅有首包输出后挂起」盲区 |
| 失败结构化（P1-a） | `tool_structured_summary.go` classifyToolError | error_code 枚举（templates_missing/target_unreachable/timeout/config_error）+ retryable + 动态 next_hint，取代裸首行启发式 |
| 心跳盲区（P0-a） | `eino_adk_run_loop.go` nextAgentEventWithContext | 工具在途时也启动 30s 心跳（kind=`adk_wait_tools_running`），补齐「整批在跑、0 result」静默盲区 |

中间件洋葱顺序（外→内）：`hitl → softRecovery → [并发上限 → per-call 超时] → executionBoost → 实际工具`。

### 3. 重工具默认参数收敛（P1-b，tools/*.yaml）

默认安全快失败，深挖靠显式参数（均可覆盖）：masscan 全端口→常用端口集；nuclei 加 `-timeout/-rate-limit/-c`；nikto 加 `-timeout/-maxtime`；dalfox 加 `--timeout/--delay`；ffuf 加 `-maxtime`（字典启动校验）；sqlmap level 默认 3→1 保守 + `--timeout/--threads`。

### 4. 默认值与回滚

- 治理全部**默认开** + 保守值（并发 5 允许合理并行、MCP 超时 600s > 正常扫描、命令注入仅在未指定时兜底、wall-clock 300s 兜底长跑脚本）。
- 一键回滚：`tool_exec_governor.enable: false`，重启即恢复增强前行为（与 execution_boost 回滚体验一致）。
- curl 注入可单独关：`inject_cmd_timeout: false`。
- wall-clock 可单独关或调大：`max_wall_clock_sec: -1` 关闭；`max_wall_clock_sec: 600` 调为 10 分钟（钳制 [60,7200]）。

### 5. 关键日志字段

| 字段 | 含义 |
|------|------|
| `tool_concurrency_acquire_waited` | 并发槽位等待时长（>0 说明触及上限） |
| `mcp_tool_per_call_timeout` | MCP 工具触发 per-call 超时（工具名/超时值） |
| `tool_structured_summary.error_code` | 失败分类（取代裸 error_sig 推断） |
| `adk_wait_tools_running` | 工具在途心跳（补盲区，区别于 adk_wait_after_tools） |
| `cmd_timeout_injected` | 命令层超时注入（curl/wget） |
| `exec_wall_clock_timeout` | exec/execute 触发 wall-clock 总上限；工具结果中同时带 `[error_code: timeout, retryable: true]` |

### 6. 验收（仅代码层）

```bash
$env:CGO_ENABLED=0; go test ./internal/multiagent/ ./internal/app/ ./internal/config/ ./internal/security/ -count=1
go build ./cmd/server/
```

重点：`TestMaybeInjectCmdTimeout` / `TestPreflightToolPaths` / `TestClassifyToolError_Patterns` / `TestResolveMCPToolTimeout` / `TestConcurrencyLimit_BlocksBeyondCap` / `TestPerCallTimeout_InvokableSoftError`。

### 7. 已知限制

1. 并发信号量按会话隔离，会话量累积时不主动回收（会话量可控，YAGNI）。
2. per-call 超时 Streamable 端缓冲整流（与 executionBoostStreamable 一致），非真流式超时。
3. 命令层超时注入为保守字符串替换，复杂管道/多 curl 仅覆盖简单情况。
4. 无实网 / 无真 LLM e2e；验收以纯函数与结构单测为准。
