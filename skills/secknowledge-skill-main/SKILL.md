---
name: secknowledge-skill
description: |
  Web+AI 安全测试知识库。融合 WooYun 88,636 案例 + 先知 L1-L4 方法论 + GAARM 150 风险
  + OWASP Top 10 (LLM/ASI/WSTG)。
  TRIGGER when 任务是实战安全测试：渗透测试、漏洞挖掘/利用、红队攻防、安全审计 (SAST/DAST)、
  CTF、AI/LLM 安全测试 (Prompt 注入/越狱/MCP/Agent/沙箱逃逸)。用户明确给出测试目标
  (URL/代码/模型/Agent 架构) 且意图是"测试/审计/挖漏洞/利用"。
  DO NOT trigger:
  - 安全概念讨论（"什么是 XSS"、"SQL 注入原理是什么"）→ 普通问答
  - 非安全性质的 code review / debug / 性能优化 → code-audit-skill 或其他
  - 修复语法错误 / 业务逻辑 bug → 普通编程协助
  - 纯 Web 白盒代码审计（Java/JS 深度审计）→ code-audit-skill
  - 仅引用 CVE 编号查文档 → WebSearch
---

# Web 和 AI 安全测试知识库

> 知识源: WooYun 88,636 漏洞 × 先知 5,600+ 文档 × GAARM 150 AI 风险 × OWASP
> 架构: SKILL.md（路由）→ references/（按场景加载）

## 触发条件

**触发条件（AND 组合）**：
1. 用户意图是**执行**安全测试（渗透/挖洞/利用/审计） — 非讨论/学习
2. 提供了**具体目标**：URL、接口、代码片段、模型/Agent 架构、MCP 配置 — 非抽象问题
3. 任务**涉及以下领域之一**：
   - Web: SQL 注入/XSS/命令执行/越权/文件上传/SSRF/反序列化/XXE/GraphQL/HTTP 走私
   - AI: Prompt 注入/越狱/MCP 投毒/Agent 滥用/RAG 投毒/沙箱逃逸/模型窃取
   - 绕过: WAF/内容过滤/Guard Rails 绕过

**不触发**（任一命中即路由到他处）：
- 概念讲解："什么是…"、"…原理"、"…怎么防御" → 普通问答
- 非安全代码审查："review 代码质量"、"优化性能" → 普通 code review
- 业务 bug：语法错误、空指针、业务逻辑错误（非安全逻辑）→ 普通 debug
- **深度白盒代码审计**（Source-Sink 污点传播、AST 分析）→ code-audit-skill
- 查 CVE 文档、工具文档 → WebSearch/Context7

**歧义处理**：目标和意图不明时，先问："目标是什么？你希望做渗透测试 / 代码审计 / 还是了解概念？"

## 行为准则（整个会话有效，不因对话长度放松）

1. ❗ **所有 Payload/CVE 编号/风险编号必须引用 reference 文件的具体章节** — 每次输出前自检。未在 reference 中的一律标注 "UNABLE TO CITE"，禁止编造。
2. ❗ **区分"漏洞假设"与"漏洞确认"** — 基于方法论推断的潜在风险 → 标注 `假设（需验证）`；有明确证据的 → 标注 `已确认（证据: …）`。禁止混淆。
3. ❗ **授权边界** — 任何利用步骤输出前必须确认是 CTF/授权渗透/本人环境。无授权上下文只输出分析，不输出可直接武器化的完整 Payload。

## 幻觉防护与来源引用

| 内容类型 | 正确输出 | 禁止输出 |
|---------|---------|---------|
| CVE 编号 | 引用具体 reference 文件和章节，或标 "UNABLE TO CITE — 建议 WebSearch 核实" | 编造 CVE-YYYY-NNNN |
| Payload | 从 `references/payloads.md` 或 `web-*.md` 引用具体章节 | 凭印象写 payload |
| GAARM 风险编号 | 引用 `references/gaarm-risk-matrix.md` | 自造编号 |
| OWASP 条目 | LLM01-10 / ASI01-10 / WSTG-* 引用 `testing-methodology.md §10.x` | 改写编号含义 |
| 工具/命令 | 仅使用在 reference 中出现过的，或明确标注 "通用命令（未在 reference 中核对）" | 伪造工具参数 |
| 无检索结果 | "UNABLE TO ASSESS：reference 未覆盖此场景，建议 WebSearch" | 凭经验推测作为结论 |

**标注分级**：
- `[引用]` — 来自 reference 具体章节（需带 file:section）
- `⚠️ 通用知识` — 未在本 Skill reference 中核对，仅作提示
- `💡 建议` — 方法论推理，非事实声明

## 输出约束

禁止输出：
- 开场白："让我来分析…" / "首先我们需要…" / "根据你的需求…"
- 工具调用描述："我将使用 Read 工具读取 XX"
- 已知信息复述（用户刚说的 URL、目标类型）
- 无来源引用的 Payload 或 CVE 编号
- 未经授权场景下的完整武器化链

输出限制：
- 单次回复 ≤ 3 个层次的建议（避免信息膨胀）
- Payload 示例 ≤ 5 条/漏洞类型（完整列表引用 reference）
- 使用表格/速查格式，禁止长段落叙述

## 工具优先级（本 Skill 自用）

| 操作 | 首选 | 降级条件 | 降级工具 |
|------|------|---------|---------|
| 读 reference | Read | Read 失败 | Bash cat |
| 搜索关键词/CVE | Grep (reference 内) | 连续 2 次未命中 | WebSearch |
| 代码审计目标 | 委派 code-audit-skill | — | — |

单次超时 ≠ 不可用，必须重试 1 次后才能降级。

## 使用流程

**Step 1: 目标分类 + reference 定位**
- 判断：Web / AI / Web+AI 混合 / 容器沙箱
- 定位：按"场景导航索引"找到对应 reference 文件

✅ Checkpoint: `Step 1 完成: 目标类型={X}, 已定位 reference={N} 个文件`

**Step 2: 按需加载 reference（精准定位）**
- 优先用 Grep 定位具体章节号，再 Read 该区域（避免全文件加载浪费 context）
- 需要全貌时加载完整文件（无 token 硬限制）
- 失败降级：Read 失败 → Bash cat；Grep 无命中 → 标注"UNABLE TO CITE"

✅ Checkpoint: `Step 2 完成: 已加载 {列表}，覆盖目标场景`

**Step 3: 按方法论输出测试思路（L1→L4）**
- L1 攻击面识别 → L2 假设构建 → L3 深度利用 → L4 防御反推
- 每条结论必须引用 reference 行号；无依据 → 标注并停止该线

✅ Checkpoint: `Step 3 完成: 输出 N 条假设, M 条已引用, K 条标注 UNABLE TO CITE`

**失败路径**：
- reference 文件缺失 → 输出"该场景 reference 缺失，建议补充"，不编造内容
- 目标模糊 → 触发歧义澄清问题，不猜测

## 场景导航索引

> 每行指向对应 reference。详细 Payload/案例/方法论全部在 reference 中，本 SKILL.md 不再展开。

### 核心方法论

| 场景 | reference |
|------|----------|
| L1-L4 思维金字塔 + WooYun 漏洞公式 + GAARM 映射 | `references/testing-methodology.md` |
| OWASP Top 10 映射（LLM/ASI/WSTG）| `testing-methodology.md §10.1-10.3` |
| GAARM 150 条风险编号 | `references/gaarm-risk-matrix.md` |

### Web 安全

| 场景 | reference |
|------|----------|
| SQL 注入 / XSS / 命令执行 / XXE / 反序列化 | `references/web-injection.md` |
| 越权 / 支付 / 密码重置 / 会话 / API 鉴权 | `references/web-logic-auth.md` |
| 文件上传 / 路径遍历 / SSRF | `references/web-file-infra.md` |
| CORS / GraphQL / HTTP 走私 / WebSocket / OAuth | `references/web-modern-protocols.md` |
| 供应链 / 云配置 / 容器 / CI/CD / 框架 CVE | `references/web-deployment-security.md` |

### AI/LLM 安全

| 场景 | reference |
|------|----------|
| Prompt 注入 / MCP 投毒 / Agent 滥用（GAARM 34 条）| `references/ai-app-security.md` |
| 越狱 / 幻觉 / 对抗样本 / 模型窃取（GAARM 42 条）| `references/ai-model-security.md` |
| System Prompt 泄露 / 数据窃取 / 推断（GAARM 32 条）| `references/ai-data-security.md` |
| 角色逃逸 / 权限失控 / 多 Agent 伪造（GAARM 23 条）| `references/ai-identity-security.md` |
| 沙箱逃逸 / 容器 / 供应链（GAARM 19 条）| `references/ai-baseline-security.md` |

### Payload 速查

| 场景 | reference |
|------|----------|
| Web Payload 索引（指向各专项文件）| `references/payloads.md §索引` |
| AI安全 Payload（Prompt注入/越狱/MCP/Agent）| `references/payloads.md §2-7` |
| 逃逸 Payload（cgroup/Docker/内核）| `references/payloads.md §8` |
| 持久化（.bashrc/crontab/SSH）| `references/payloads.md §9` |
| 反弹 Shell / 横向移动 | `references/payloads.md §10` |

## 零结果处理

| 情况 | 正确动作 |
|------|---------|
| Grep 未命中 reference | "UNABLE TO CITE: 该场景 {X} 未在 reference 中覆盖。建议 WebSearch 或补充 reference" |
| 用户给的 URL 无响应 | "UNABLE TO ASSESS: 目标不可达" — 不基于 URL 结构猜测漏洞 |
| 需要执行但无授权上下文 | "仅输出分析，不输出武器化链。如为授权测试，请明确授权范围" |
| reference 与用户场景部分匹配 | 引用已匹配部分 + 明确标注未覆盖部分为 "UNABLE TO CITE" |

## 与其他 Skill 的路由

| 用户诉求 | 正确路由 |
|---------|---------|
| 渗透测试 / 红队 / CTF / 挖洞 | **本 Skill** |
| Java/JS 深度白盒代码审计（Source-Sink）| code-audit-skill |
| Mirawork 平台专项测试 | mirawork-security-tester |
| WooYun 历史漏洞分析方法论 | wooyun-legacy |
| 先知社区研究方法论 | xianzhi-research |

---

*v2.0 | 知识源: WooYun 88,636 × 先知 5,600+ × GAARM 150 × OWASP LLM/ASI/WSTG*
