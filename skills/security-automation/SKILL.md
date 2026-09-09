---
name: security-automation
description: 安全自动化顶级专业技能：DevSecOps全流程集成、CI/CD安全管道、SAST/DAST/SCA/容器/IaC自动化扫描编排、安全工具链集成实战、攻防双视角自动化（红队打点/蓝队检测响应）、SOAR深度编排、Agentic AI安全自动化（LLM Agent编排扫描与响应）、大模型安全运营（AI告警降噪/剧本生成）、误报治理与质量保障、合规自动化（证据收集/报告）
metadata:
  version: 3.0.0
---

# 安全自动化深度技能（攻防双视角 + AI 原生自动化）

> **AI LOAD INSTRUCTION**: DevSecOps 与安全自动化专家方法论。聚焦流水线卡点选型→扫描工具链→策略即代码→漏洞生命周期→SOAR/Agentic 编排→误报治理。自动化结论保留原始证据，门槛对齐 pentest-verification。

## 概述

安全自动化是将安全能力嵌入 DevOps 与安全运营流程的核心实践。本技能系统化覆盖**代码提交→构建→测试→部署→运行**全生命周期安全自动化，同时站在**资深攻防专家双视角**：红队视角关注"自动化打点—攻击链验证—漏洞利用"，蓝队视角关注"自动检测—降噪—编排响应"。v3.0.0 在 v2.0.0 基础上新增 **SOAR 深度编排、Agentic AI 安全自动化、大模型安全运营（LLM 告警分析与降噪）、AI 辅助剧本生成、攻防双视角自动化、误报治理与质量保障、合规自动化（证据收集/报告）** 等高级维度，并给出与 Eino 技能系统的联动方式。

### 核心概念
- **安全左移（Shift-Left）**：将安全检测从生产阶段前置到需求/编码/构建阶段，缺陷修复成本随阶段后移指数上升
- **门禁（Quality Gate）**：扫描结果不达标即阻断流水线（硬门禁）或降级放行+风险登记（软门禁）
- **SAST/DAST/SCA/IAST**：静态/动态/软件成分/交互式应用安全测试，四类扫描互补覆盖
- **SBOM**：软件物料清单，供应链安全的可观测基础（CycloneDX/SPDX）
- **SOAR**：安全编排、自动化与响应，三要素=编排（连接工具）+自动化（执行逻辑）+响应（处置闭环）
- **剧本（Playbook）**：预定义响应流程，全自动/半自动（HITL 审批）/全手动三种模式
- **Agentic 自动化**：AI Agent 自主规划—决策—执行多步任务，区别于执行预编排剧本的 SOAR 与辅助分析的副驾（Copilot）
- **HITL（Human-in-the-loop）**：关键动作人工审批，Agentic 自动化安全的底线护栏
- **ATT&CK**：MITRE 攻击技战术知识库，红队模拟与蓝队检测映射的统一语言
- **误报治理**：通过验证、去重、关联、置信度阈值将"告警洪流"收敛为"可执行任务"

### 2025-2026 行业演进要点
- SOAR 已从独立产品**演进为 SIEM/XDR 原生能力**（Gartner Hype Cycle 确认），并与 SIEM 统一负载
- **自然语言剧本创建**与**自适应剧本**（运行期根据证据动态调整）取代静态线性剧本
- **Agentic SOC** 成为主流：D3 Morpheus（单一推理引擎+运行时生成剧本）、Palo Alto Cortex AgentiX（XSOAR 继任者）、Microsoft Security Copilot+Sentinel、CrowdStrike Charlotte AI、SentinelOne Purple AI 等
- **LLM 告警 Triage 实证**：源特定智能体编排 + 确定性过滤先行，低危告警全量自动 Triage，升级率可压至 ~3%，节省数千分析师小时
- **AI 红队三级进化**：脚本自动化（<2020）→ AI 决策赋能（2020-2024）→ 智能体协同（2024+，多智能体自主规划攻击路径）
- **Exploit-validated 结果**成为行业标准：只上报"已被利用验证"的漏洞，消除 90%+ 扫描噪声

## 一、DevSecOps 全流程与安全左移

### 1.1 安全左移模型
```
Plan阶段:   威胁建模(STRIDE) → 安全需求 → 安全设计评审 → 攻击面分析
Code阶段:   IDE安全插件 → Pre-commit Hook(密钥/格式) → 代码审计(SAST)
Build阶段:  SAST → SCA → 依赖漏洞 → 许可证合规 → 构建产物签名
Test阶段:   DAST → IAST → 渗透测试 → Fuzzing → API安全测试
Deploy阶段: 容器扫描 → IaC审计 → 配置合规 → 供应链校验(SBOM)
Run阶段:    RASP → WAF → 运行时监控(Falco) → 漏洞管理 → 自动化应急响应
```

### 1.2 安全管道架构（GitLab CI 示例）
```yaml
stages:
  - security-scan

sast:
  stage: security-scan
  image: semgrep/semgrep
  script:
    - semgrep --config=auto --json -o sast-results.json .
  artifacts:
    reports:
      sast: sast-results.json

dependency-scan:
  stage: security-scan
  image: aquasec/trivy
  script:
    - trivy fs --format json -o deps-results.json .

container-scan:
  stage: security-scan
  image: aquasec/trivy
  script:
    - trivy image --format json -o container-results.json $CI_REGISTRY_IMAGE

secret-scan:
  stage: security-scan
  image: zricethezav/gitleaks
  script:
    - gitleaks detect --source . --report-format json --report-path secrets.json

iac-scan:
  stage: security-scan
  image: bridgecrew/checkov
  script:
    - checkov -d terraform/ -o json > iac-results.json
```

### 1.3 全链路安全门禁（Gate）
```bash
# 门禁原则：扫描发现 X 级漏洞 → 阻断发布；Y 级漏洞 → 放行+缺陷登记+限时修复
# 示例：Semgrep 阻断严重级
if grep -q '"severity": "ERROR"' sast-results.json; then
  echo "检测到严重级SAST漏洞，阻断流水线"
  exit 1
fi

# 示例：Trivy 高危漏洞阈值阻断（支持 --exit-code --severity 直接内嵌）
trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed $IMAGE
```
- **硬门禁**：CRITICAL/HIGH 直断；**软门禁**：MEDIUM/LOW 放行但自动创建缺陷单并追踪 SLA
- 门禁参数建议统一由 `security-config` 仓库管理，扫描器只读配置，避免各团队自行放水

### 1.4 度量与指标
| 指标 | 含义 | 建议目标 |
|------|------|---------|
| 漏洞密度 | 每千行代码漏洞数 | 持续下降趋势 |
| MTTR | 平均修复时间（漏洞/告警） | 按 SLA 分级 |
| 修复率 | 周期内修复/新增 | ≥90% |
| 门禁拦截率 | 流水线被安全阻断比例 | 反映左移生效度 |
| 误报率 | 确认误报/总告警 | <30% 持续优化 |
| 覆盖率 | 扫描资产/全量资产 | ≥95% |

## 二、自动化扫描工具链

### 2.1 SAST（静态应用安全测试）
| 工具 | 语言 | 特点 |
|------|------|------|
| Semgrep | 多语言 | 规则灵活，自定义强，OSS 规则社区 |
| CodeQL | 多语言 | GitHub 集成，数据流/污点分析 |
| SonarQube | 多语言 | 代码质量+安全，质量门禁 |
| Bandit | Python | Python 专用 |
| Brakeman | Ruby | Rails 专用 |
| Gosec | Go | Go 专用 |
| ESLint Security / eslint-plugin-security | JS/TS | Node.js 安全 |
| Snyk Code / Fortify / Checkmarx | 商业 | 企业级，IDE/CI 全覆盖 |

**实战要点**：SAST 按团队细分规则集（新项目严/存量项目宽），结果按文件变更行（diff）过滤，只上报"本次改动引入"的问题，避免存量噪声淹没新问题。

### 2.2 DAST（动态应用安全测试）
| 工具 | 类型 | 特点 |
|------|------|------|
| OWASP ZAP | 开源 | CI/CD 集成，API 扫描，主动/被动模式 |
| Burp Suite CI | 商业 | 专业级，REST API 驱动 |
| Nuclei | 开源 | 模板驱动，YAML 模板生态丰富，扫描极快 |
| Nikto | 开源 | Web 服务器扫描 |
| Arachni | 开源 | 高覆盖 Web 扫描 |

### 2.3 SCA（软件成分分析）
| 工具 | 范围 | 特点 |
|------|------|------|
| Trivy | 全面 | 依赖/容器/IaC/密钥四合一 |
| Grype | 依赖/镜像 | 与 Syft SBOM 生成配套 |
| Snyk | 依赖 | 修复建议，PR 集成 |
| Dependabot / Renovate | 依赖 | 自动升级 PR |
| OWASP Dependency-Check | 依赖 | NVD 数据库 |
| OSV-Scanner | 依赖 | Google OSV 数据库 |

### 2.4 容器与 IaC 安全
| 工具 | 目标 | 特点 |
|------|------|------|
| Trivy | 镜像/依赖 | 多用途扫描，支持 SBOM 生成 |
| Hadolint | Dockerfile | Dockerfile Lint |
| Checkov | Terraform/K8s/云 | IaC 安全策略 1000+ |
| tfsec | Terraform | Terraform 安全 |
| kube-hunter | K8s | K8s 渗透测试 |
| OPA/Gatekeeper | K8s | 策略即代码（准入控制） |
| Kyverno | K8s | K8s 原生策略，无需 Rego |
| kube-bench | K8s | CIS Benchmark |

### 2.5 密钥泄露扫描与防护（Pre-commit + CI）
```bash
# gitleaks pre-commit hook（提交即拦截）
#!/bin/sh
gitleaks protect --staged
if [ $? -ne 0 ]; then
  echo "检测到密钥泄露，提交被拒绝"
  exit 1
fi
```
```yaml
# CI 全量扫描（含 Git 历史）
secret-scan:
  script:
    - gitleaks detect --source . --log-opts="--all"
    # 扫描所有 Git 历史，阻断合并请求
```
**补充**：定期（每周）对 Git 历史做深度回扫，防止已合入的密钥遗漏；检测到历史泄露时优先轮换密钥而非仅删提交。

### 2.6 供应链安全（SBOM/签名/来源）
```bash
# 生成 SBOM（CycloneDX 格式）
syft dir:. -o cyclonedx-json > sbom.json
# 或 trivy
trivy fs --format cyclonedx -o sbom.json .

# 校验 SBOM 与镜像签名
cosign verify $IMAGE --certificate-identity $IDENTITY --certificate-oidc-issuer $ISSUER

# 依赖投毒防护：锁定版本 + hash 校验（npm/pip 等）
# package-lock.json / poetry.lock 强制提交，CI 校验 lock 文件未篡改
```
供应链自动化还包括：镜像来源白名单、依赖策略（禁用已 EOL 版本）、内网镜像代理（阻断对上游的不可控拉取）。

## 三、合规即代码与策略引擎

### 3.1 OPA 策略示例
```rego
# K8s Pod 安全策略
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("容器 %v 不允许使用特权模式", [container.name])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("容器 %v 必须以非root运行", [container.name])
}
```

### 3.2 CIS Benchmark 自动化
```bash
# Docker CIS Benchmark
docker-bench-security

# K8s CIS Benchmark
kube-bench

# AWS CIS Benchmark
prowler --checks cis

# 云安全态势（GCP/Azure）
# scoutsuite / pacu 组合
```

### 3.3 策略引擎选型与进阶
| 引擎 | 语言 | 适用 |
|------|------|------|
| OPA/Gatekeeper | Rego | 云原生准入 + 通用策略 |
| Kyverno | YAML | K8s 原生，学习成本低 |
| Conftest | Rego | 通用配置测试（Dockerfile/Terraform/K8s 均可） |
| HashiCorp Sentinel | Sentinel | Terraform Enterprise 集成 |

```bash
# Conftest 测试任意配置
conftest test deployment.yaml -p policies/
```

### 3.4 策略生命周期管理
- 策略即代码：存放在独立 `security-policies` 仓库，走 MR 评审 + 单测（OPA 单元测试 `opa test`）
- 变更灰度：先在**告警模式**（audit）运行新策略，观察误报，再切换**强制模式**（enforce）
- 版本化与回滚：策略与集群/环境版本绑定，回滚策略如同回滚代码

## 四、漏洞管理自动化

### 4.1 漏洞管理闭环流程
```
1. 扫描发现 → 自动录入漏洞管理平台
2. 归一化 → 多扫描器结果统一格式（去重/去噪/合并同类）
3. 风险评估 → CVSS评分 × 资产权重 × 可利用性 = 优先级
4. 分配修复 → 按代码归属/资产负责人自动指派
5. 修复验证 → 自动复扫确认修复，闭环关闭
6. SLA跟踪 → 超时自动告警+升级
7. 定期报告 → 自动生成安全态势报告（周/月）
```

### 4.2 漏洞平台集成（DefectDojo 示例）
```bash
# 导入 Trivy 扫描结果
curl -X POST http://defectdojo/api/v2/import-scan/ \
  -H "Authorization: Token $TOKEN" \
  -F "scan_type=Trivy Scan" \
  -F "file=@trivy-results.json"

# 导入 Semgrep 结果
curl -X POST http://defectdojo/api/v2/import-scan/ \
  -H "Authorization: Token $TOKEN" \
  -F "scan_type=Semgrep JSON Report" \
  -F "file=@sast-results.json"
```

### 4.3 去重与聚合策略
- **多扫描器合并**：同一漏洞（如 XSS）在 SAST/DAST/人工验证中重复出现 → 以最高置信度证据为准合并，保留各来源证据链
- **指纹归一化**：CWE/CVE/资产(仓库:文件:行 / URL:参数) 三元组作为去重键
- **定期基线漂移检测**：同一资产连续 N 次扫描出现/消失的漏洞自动复核

### 4.4 SLA 与告警
```bash
# 示例：基于日期的 SLA 升级脚本（伪代码）
for vuln in open_vulnerabilities:
    if vuln.severity == "critical" and vuln.age_days > 7:
        escalate(vuln, to="安全负责人", notify="IM/邮件")
    elif vuln.severity == "high" and vuln.age_days > 14:
        escalate(vuln, to="部门负责人")
```

## 五、安全工具链集成实战（nuclei/SAST/DAST/漏洞管理平台联动）

### 5.1 扫描器→漏洞平台全链路联动
```
CI流水线/调度器
  ├─ Semgrep(SAST) ──┐
  ├─ Trivy(SCA/镜像) ─┤→ 结果归一化 → DefectDojo/ThreadFix → 指派修复 → 复扫验证
  ├─ Nuclei(DAST) ───┤
  └─ Checkov(IaC) ───┘        ↑
                        回归/去重/加噪
```

### 5.2 Nuclei 实战（模板驱动快速扫描）
```bash
# 单资产扫描
nuclei -u https://target.com -severity high,critical -jsonl -o nuclei.jsonl

# 资产列表批量扫描（并发控制，遵守授权）
nuclei -l targets.txt -c 20 -stats -jsonl -o nuclei.jsonl

# 指定模板分类
nuclei -u https://target.com -t cves/ -t exposures/ -t misconfiguration/

# 与漏洞平台联动：nuclei -jsonl 输出 → jq 提取 → 导入 DefectDojo
jq -c '{scan_type:"Nuclei Scan", ...}' nuclei.jsonl
```

### 5.3 结果归一化示例（Python 单文件）
```python
# 将 nuclei JSONL → DefectDojo 期望字段（示意）
import json, sys
out = []
for line in sys.stdin:
    d = json.loads(line)
    out.append({
        "title": d.get("info", {}).get("name", d.get("template-id")),
        "severity": d.get("info", {}).get("severity", "info"),
        "cwe": (d.get("info", {}).get("classification") or {}).get("cwe-id", []),
        "description": d.get("info", {}).get("description", ""),
        "matched_at": d.get("matched-at"),
        "tags": d.get("info", {}).get("tags", []),
    })
print(json.dumps(out, ensure_ascii=False, indent=2))
```

### 5.4 ZAP 自动化（DAST 入 CI）
```bash
# ZAP 全量扫描并出报告
docker run -t ghcr.io/zaproxy/zaproxy zap-baseline.py \
  -t https://target.com -r zap-report.html -J zap-report.json

# 结合 -x 导出 XML 供 DefectDojo "ZAP Scan" 类型导入
```

## 六、攻防双视角自动化

### 6.1 红队自动化打点（Red 视角）
```
资产收集(子域/端口/指纹)
  → 攻击面分析(ASM: 公网暴露/影子资产)
  → 自动化漏洞探测(nuclei/自动化工具)
  → 漏洞验证(exploit-validated: 起 PoC 确认可利用性)
  → 打点成功 → 建立据点 → 横向扩展
```
```bash
# 打点自动化示例（仅授权环境）
# 1) 子域枚举
subfinder -d target.com -all -silent | sort -u > subs.txt
# 2) 存活探测
httpx -l subs.txt -silent -title -status-code -tech-detect -o alive.txt
# 3) 指纹/资产测绘（httpx 探测技术栈，nuclei -tech-detect 亦可）
httpx -l alive.txt -tech-detect -silent | tee -a tech.txt
# 4) 定向漏洞验证
nuclei -l alive.txt -t cves/ -t exposures/ -severity critical,high
# 5) 结果入库 + 人工/LLM 研判 → 确认可利用目标
```
- 攻击面管理（ASM）自动化：持续发现**影子资产/新暴露面**，与 CMDB 资产库比对找出"未登记资产"
- 红队视角关键：自动化只做"广度"，**深度利用链仍依赖专家+LLM 辅助**（结合 fastjson-exploitation 等利用技能）

### 6.2 蓝队自动检测响应（Blue 视角）
```
检测(SIEM/EDR/NDR 规则+行为分析)
  → 告警聚合/降噪(去重/关联/LLM triage)
  → 自动化调查(资产上下文/威胁情报/TTP映射)
  → 自动化响应(隔离/封禁/撤销会话 —— 高危动作 HITL)
  → 复盘与检测工程(规则调优/新规则生成)
```
```bash
# 示例：EDR/SIEM 告警 → 自动化处置脚本（示意）
# 1) 提取 IOC
# 2) 威胁情报查询（VirusTotal/AbuseIPDB/MISP）
# 3) 命中规则 → 隔离主机 / 封禁 IP / 撤销 Token
# 4) 全自动动作需白名单+审批闸门
```

### 6.3 攻击模拟与纵深防御验证
```bash
# Atomic Red Team（红蓝共用检测验证）
git clone https://github.com/redcanaryco/atomic-red-team
# 执行单一 ATT&CK 技术（模拟 T1059.001 PowerShell）
powershell -ExecutionPolicy Bypass -File ./atomics/T1059.001/T1059.001.yaml  # 或对应执行脚本

# MITRE CALDERA（自主对抗模拟平台）
# 部署 server + agent，按操作计划自动化演练

# 商业替代：SafeBreach / AttackIQ / Picus —— 持续验证检测覆盖率
```
- **检测覆盖率度量**：用攻击模拟结果反向评估"哪些 TTP 未被检测"，驱动检测工程补齐
- 攻防演练自动化：红队工具链输出 ↔ 蓝队检测覆盖矩阵（ATT&CK Navigator 热力图）自动对比

### 6.4 红蓝联动闭环
```
红队自动化发现 → 证据包(复现步骤+PoC) → 漏洞平台登记
                              ↓
蓝队检测规则(以红队 TTP 为样本生成) → 攻击模拟验证 → 上线
                              ↓
复测闭环：下轮红队验证新规则是否拦截 → 覆盖率持续提升
```

## 七、SOAR 深度实践（剧本编排/案件管理）

### 7.1 SOAR 架构与能力演进
```
编排层(Orchestration): API 连接 SIEM/EDR/身份/邮件/防火墙/威胁情报
自动化层(Automation):  剧本执行引擎（全自动/半自动/手动）
响应层(Response):      案件管理、告警队列、处置动作、审计留痕
```
**2025-2026 演进**：SOAR 不再是独立孤岛，已内嵌进 SIEM/XDR（如 Splunk SOAR 与 ES 8.0 统一负载、Microsoft Sentinel 集成、Palo Alto Cortex AgentiX）；新增**自然语言剧本创建**与**提示驱动自动化**（Prompt-driven automation：直接向外部团队/工单系统推送处置请求）。

### 7.2 剧本编排（Playbook）
**剧本要素**：触发器（SIEM 告警/定时/Webhook）→ 条件分支 → 动作（查询/封禁/通知）→ 人工审批节点 → 超时与失败处理。

```yaml
# 暴力破解调查剧本（示意，YAML 化描述）
name: brute-force-investigation
trigger: SIEM 告警 "Multiple Failed Logins"
steps:
  - action: 查询来源IP威胁情报(AbuseIPDB/MISP)
  - action: 查询账号最近登录记录
  - action: 查询资产关键性(CMDB)
  - if: IP信誉=恶意 AND 账号=特权
    then: [隔离主机(HITL审批), 封禁IP, 禁用账号, 通知安全负责人]
  - else: [打标"预期行为", 关闭案件]
  - action: 生成案件报告与证据快照
```

### 7.3 案件管理（Case Management）
- 告警→案件自动关联（同源/同资产/同攻击链聚合为一个案件）
- 案件生命周期：新开→调查中→处置中→已关闭(含误报关闭原因分类)
- 证据留痕：每个动作记录操作者（人或 Agent）、时间、参数、结果 → 审计完整
- 关键实践：**误报关闭必须填写原因分类**（规则过宽/预期行为/环境变化），数据反哺规则调优

### 7.4 SIEM/XDR 集成要点
- 统一事件模型：OCSF（Open Cybersecurity Schema Framework）正在成为跨源标准化事实标准，早期归一化可大幅降低剧本复杂度
- 富化先行：剧本第一步统一做上下文富化（资产、用户、IP 信誉、关联事件），后续所有分支共用
- 限流与风暴保护：同一资产高频告警在剧本入口聚合，防止剧本被告警风暴打爆

### 7.5 自适应剧本（LLM 增强）
静态剧本的局限：对未知攻击形态无法响应。2026 趋势是**运行时生成剧本**：LLM 基于实时证据动态决策下一步（查什么、问什么、封什么），但必须在**规则边界+动作白名单+审批闸门**内执行，详见第八章。

## 八、Agentic AI 安全自动化（LLM Agent 编排扫描/响应）

### 8.1 Agentic 与自动化/副驾的本质区别
| 类型 | 谁决定下一步 | 代表 |
|------|------------|------|
| SOAR 自动化 | 人类预先编写剧本 | Splunk SOAR、XSOAR |
| Copilot 副驾 | 人类运行时决策，AI 辅助 | Microsoft Security Copilot |
| **Agentic** | **系统基于实时证据自主推理决策，在受控边界内行动** | D3 Morpheus、Cortex AgentiX、Torq HyperAgents |

### 8.2 LLM Agent 编排扫描（Red/蓝通用）
```
用户指令(自然语言) → Agent规划(拆解任务) → 工具调用(nuclei/子域/指纹/查漏洞库)
  → 结果分析 → 下一步决策(扩大范围/验证/跳过) → 输出结构化报告
```
```python
# Agent 工具调用示意（LangChain/CrewAI 风格）
from langchain.tools import tool

@tool
def run_nuclei(target: str, severity: str = "high") -> str:
    """对目标执行 nuclei 扫描，返回 JSONL 结果"""
    # 实际实现：subprocess 调用 nuclei，解析输出
    ...

@tool
def lookup_cve(cve_id: str) -> str:
    """查询 CVE 详情与 PoC 信息"""
    ...

# Agent 循环：plan → act → observe → re-plan
```

### 8.3 LLM Agent 编排响应（蓝队）
```
告警进入 → Agent调查(查日志/查资产/查威胁情报) → 形成结论(严重度+置信度)
  → 分级响应：
     低危/确定误报 → 自动关闭(附理由)
     中危 → 转人工队列(附调查摘要)
     高危 → 隔离/封禁(需HITL审批) + 生成报告
```
**成熟实践（2026 实证）**：Databricks 用 17 个**源特定 Triage Agent**（每个 Agent 只负责单一检测源）+ 共享威胁情报 Agent，低危告警全量自动 Triage，升级率 ~3.2%，30 天节省 6500+ 分析师小时。**单一通用 Agent 处理全量告警会退化为另一种噪声（升级率 50%），源特定 Agent 才是有效形态。**

### 8.4 Agent 架构模式
- **多智能体协作**：规划 Agent / 执行 Agent / 验证 Agent / 情报 Agent 分工，结果交叉复核
- **ReAct 循环**：Reasoning → Acting → Observation，每一步都有观察反馈
- **技能化**：把安全操作封装为 Skill/工具（如本技能集），Agent 按需加载，节省 token
- **记忆与上下文**：案件级记忆（跨会话续查）+ 知识库检索（RAG 检索 runbook/历史案件）

### 8.5 自主等级与 HITL（安全运营）
| 等级 | 行为 | 适用 |
|------|------|------|
| AL1 建议 | Agent 仅给建议，人执行 | 初期/高风险动作 |
| AL2 审批 | Agent 执行到关键动作停下等人审批 | 半自动（HITL） |
| AL3 授权内自动 | 白名单动作内自动执行 | 低危、高频、确定动作 |
| AL4 自主 | 全流程自主 | 受限环境（靶场/隔离网段） |

**红线**：封禁生产、隔离核心资产、禁用特权账号、外发数据等动作默认 AL2，白名单之外的 AL3/AL4 必须经安全委员会审批。

### 8.6 Agentic 安全自动化风险与边界
- **幻觉**：Agent 可能编造不存在的"发现"→ 强制**exploit-validated**（执行 PoC 验证后才算数），低置信度必须标注
- **提示注入**：外部输入（日志/网页/邮件）可诱导 Agent 执行恶意动作 → 工具输入做白名单/净化，敏感上下文不直接进 prompt
- **权限失控**：Agent 只应持最小权限的**服务账号**（API Key 隔离、网络策略限制），绝不能复用人类管理员凭据
- **动作可逆性**：优先可逆动作（撤销 Token>禁用账号>删数据），不可逆动作必须人工
- **审计留痕**：Agent 每一步推理与工具调用全量落日志，可回放、可追责
- **成本与延迟**：LLM 调用昂贵，规则先行过滤 90%+ 事件，LLM 只处理剩余 5%-10%

## 九、AI 大模型安全运营（LLM 分析告警/降噪/剧本生成）

### 9.1 LLM 告警分析与降噪（三层管道）
```
Layer1 规则过滤:  确定性规则滤掉 90-95% 明确良性事件(健康检查/CI账号/计划任务)
Layer2 LLM Triage: 富化后的告警 → LLM 结构化判定(benign/suspicious/malicious + 置信度 + 理由)
Layer3 分级响应:   高危自动遏制 / 中危转人工 / 低危记录趋势
```
```python
# LLM Triage 结构化输出（示意）
from pydantic import BaseModel
from enum import Enum

class Disposition(str, Enum):
    ESCALATE = "escalate"; MONITOR = "monitor"; CLOSE = "close"

class TriageResult(BaseModel):
    severity: str          # critical/high/medium/low/info
    disposition: Disposition
    confidence: float      # 0-1，低于阈值不自动动作
    reasoning: str         # 一段结论性理由
    recommended_actions: list[str]
    false_positive_indicators: list[str]  # 支撑"关闭"判定的证据
```
**富化是命脉**：用户角色、资产关键性、IP 信誉、24h 关联告警、是否业务时间——"垃圾进垃圾出"，LLM 需要上下文才能避免把 Tor 出口节点当普通外部 IP。

### 9.2 降噪的工程要点
- **置信度阈值化**：LLM 输出数值置信度，低于阈值只打标不动作；高阈值才自动关闭/升级
- **已知良性模式语料**：维护 CI/CD 服务账号、定时任务、扫描器自身流量等"已知良性"清单，提示词中显式声明"这些模式不应告警"
- **每日误报率看板**：`误报率=确认误报/总告警`，规则或 Agent 调优后回测
- **关闭原因分类**：误报关闭必须归因，反哺规则与提示词优化

### 9.3 AI 辅助剧本生成与优化
- **自然语言生成剧本**：`"帮我写一个：检测到异常登录后，查询威胁情报，若是恶意 IP 则禁用账号并通知"` → LLM 生成结构化剧本 → 人工评审 → 沙箱回放（用历史告警回测）→ 灰度上线
- **剧本优化**：用历史案件数据训练/提示优化分支条件；回放引擎评估剧本在历史数据上的"该拦截的没拦/该放行的误拦"
- **检测规则生成**：从确认的攻击事件（红队 TTP/事后复盘）自动生成 Sigma/YARA/查询规则草案

### 9.4 双模型架构与安全 LLM 选型
```
战略大脑(通用大模型): 威胁研判、攻击链推理、复杂决策
战术专家(安全微调模型): 日志语义解析、ATT&CK 技术识别、实时告警分类(毫秒级)
```
- 开源安全模型：Cisco Foundation-sec 系列（8B 级模型经 prompt tuning 可达超大模型性能）、微软安全专用模型（基于安全遥测训练）
- 本地化部署考虑：数据不出域（合规）、延迟、成本
- **RAG 知识库**：runbook、历史案件、威胁情报(MISP)、内部检测笔记 → 检索增强，降低幻觉

### 9.5 提示词与输出规范
- 始终要求**结构化输出**（JSON Schema/Pydantic），下游不用解析自由文本
- 系统提示词声明角色（"你是资深 SOC 分析师，进行一线 Triage"）与判定规则
- 上下文裁剪：只投喂富化摘要（几 KB），不投喂 10KB 原始日志
- 关键结论要求 Agent **引用证据来源**（哪条日志/哪个查询结果）

## 十、自动化误报治理与质量保障

### 10.1 误报来源分析
| 来源 | 典型原因 | 治理手段 |
|------|---------|---------|
| 扫描器规则过宽 | 正则/模板命中正常功能 | 规则瘦身、降级 severity |
| 检测规则阈值不当 | 阈值过低触发风暴 | 基线化调参 |
| 环境上下文缺失 | 测试环境/灰度流量被当攻击 | 资产标记+流量标签 |
| 静态规则无法推理 | 规则看不到业务上下文 | 引入 LLM 富化判定 |
| 重复扫描 | 相同漏洞多轮上报 | 指纹去重+区间合并 |

### 10.2 验证机制（Exploit-Validation）
- **自动化验证**：nuclei -verify / 自定义 PoC 复现，验证通过的才升级为"真实漏洞"
- **人工抽验**：AI/自动化关闭的告警按比例抽检（如 5%），维护召回率
- **双人复核**：高危自动处置动作执行后强制二次审计

### 10.3 质量指标与回归测试
```bash
# 指标
精确率(Precision)=真阳性/(真阳性+假阳性)    目标 >80%
召回率(Recall)=真阳性/(真阳性+假阴性)       目标 >90%（宁可误报不漏报的类别）
F1 = 2*P*R/(P+R)
误报率、升级率、MTTR、告警周转率
```
- **检测回归测试**：维护"已知攻击样本集"（Atomic Red Team/历史真实攻击），任何规则/模板/Agent 变更后自动回测，防止"修了误报丢了检测"
- **告警质量看板**：按检测源展示精确率/误报率/升级率，驱动针对性调优

### 10.4 规则/模板生命周期
```
起草 → 离线回放(历史数据) → 灰度(仅告警) → 强制 → 定期复盘(误报率/召回率) → 退役
```

## 十一、合规自动化与报告生成（证据收集/报告）

### 11.1 证据收集自动化
```bash
# 自动化证据包：扫描结果+配置快照+修复验证
# 1) 扫描结果（前文 DefectDojo 导入即可留存）
# 2) 配置基线快照
checkov -d . -o json > iac-baseline.json
# 3) 镜像签名与 SBOM 归档（审计可追溯）
cosign verify $IMAGE ... ; syft $IMAGE -o spdx-json > artifact.sbom
# 4) 合规状态导出（CIS/等保/NIST 控制项映射）
prowler -M csv -o prowler-report/ --checks cis
```
**证据链三要素**：时间戳（不可篡改）、来源（哪个工具/哪个版本）、原始数据（原始输出存档，报告仅引用）。

### 11.2 自动化报告生成
- **模板化报告**：Markdown/HTML/PDF 模板 + 数据填充（漏洞趋势、修复率、SLA 达标率、误报率、检测覆盖率）
- **LLM 报告撰写**：LLM 基于结构化数据生成"执行摘要"与"管理层解读"，人工复核后发布
- **定期自动推送**：周报/月报定时生成并推送到 IM/邮件

### 11.3 合规框架映射
| 框架 | 自动化支撑 |
|------|-----------|
| CIS Controls / CIS Benchmark | 扫描器 + 策略引擎（kube-bench/docker-bench/prowler） |
| NIST CSF / 800-53 | 控制项 → 证据 → 状态自动化映射 |
| ISO 27001 / SOC 2 | 证据收集 + 持续监控报告 |
| PCI DSS | 扫描报告 + 渗透测试证据 + 变更审计链 |
| 等保 2.0 | 自查项自动化核对 + 测评证据导出 |

### 11.4 审计链与留痕
- 所有自动化动作（谁/何时/调用了什么/结果）写入不可篡改审计日志
- 报告与证据按合规期限归档（通常 ≥1 年）
- AI 参与的证据：标注"AI 生成/辅助"，附推理与置信度，满足可解释性要求

## 十二、与 Eino 技能系统的集成

### 12.1 Eino 技能系统概述
本工作区采用 Eino（Agent Skills 兼容）技能包规范：**`SKILL.md` 为清单+主说明**，同目录可挂 `scripts/`、`references/`、`assets/` 子目录；由 Eino 的 `ListPackageFiles` / `resource_path` 与多代理内 ADK **`skill`** 工具按包加载，`FilesystemSkillsRetriever` 支持包摘要与 `##` 分块检索；平台同时提供 HTTP `GET /api/skills/...`、`section=`、`resource_path=` 访问机制。

### 12.2 将本技能封装/调用为 Eino skill
- 本文件即 `security-automation` 技能包主文档：多代理会话内用 **`skill`** 工具加载本包，即可获得 CI/CD 管道、扫描编排、SOAR、Agentic 自动化的可执行命令与模板
- 建议配套目录结构：
  - `scripts/`：管道扫描脚本（如 5.3 归一化脚本）、门禁检查脚本
  - `references/`：SBOM/CIS/合规证据收集清单、剧本模板
  - `assets/`：报告模板、规则示例
- 按需加载 `section=扫描工具链` 等分块，节省 token；需要脚本原文用 `resource_path=scripts/xxx.py`

### 12.3 多代理协作场景（Eino + 本技能）
```
协调代理(任务拆解/上下文传递)
 ├─ 扫描代理     → 加载 security-automation: nuclei/SAST/SCA 命令
 ├─ 利用代理     → 加载 fastjson-exploitation / log4shell 等利用技能（授权内）
 ├─ 响应代理     → 加载 incident-response: 处置动作/证据留痕
 └─ 报告代理     → 加载本技能第十一章: 证据收集/报告生成
```
技能间的上下文衔接：扫描代理输出（资产/漏洞清单 JSON）作为下游代理的输入，统一 schema 便于多代理传递。

### 12.4 与 AI 安全自动化结合
- Eino 技能包可作为 Agentic 安全自动化的**工具库**：LLM Agent 通过 `skill` 工具加载本技能后，即可调用其中被封装的扫描/门禁/报告命令，实现"Agent 用技能干活"
- 技能包版本化（frontmatter `version`）支持 Agent 选择稳定版本，避免行为漂移

## 十三、工具链

```bash
# CI/CD 集成
GitLab CI / GitHub Actions / Jenkins  # CI平台
Tekton / Argo CD                      # K8s原生CI/CD
Buildkite / CircleCI                  # 云原生CI

# 扫描编排
DefectDojo        # 开源漏洞管理平台
ThreadFix         # 漏洞聚合与修复管理
Faraday           # 渗透测试管理
ArcherySec / VulnIQ # 漏洞管理替代

# 策略引擎
OPA/Gatekeeper    # K8s策略
Kyverno           # K8s原生策略
Conftest          # 通用策略测试
Hashicorp Sentinel # Terraform Enterprise

# 供应链与容器
Syft / CycloneDX   # SBOM生成
cosign / Sigstore  # 镜像签名与验证
Trivy / Grype      # 容器与依赖扫描
SLSA / in-toto     # 供应链完整性

# 安全监控
Falco             # K8s运行时安全
Wazuh             # 主机安全/开源SIEM
Elastic Security  # SIEM/XDR
Microsoft Sentinel # 云原生SIEM/SOAR

# SOAR
Splunk SOAR / Palo Alto XSOAR(→Cortex AgentiX) / Microsoft Sentinel SOAR
Shuffle / Tines  # 轻量开源/低代码SOAR
TheHive / DFIR-IRIS # 开源案件管理

# 红队自动化
Subfinder/httpx/nuclei # 打点三件套
Metasploit / Cobalt Strike / Sliver # 利用与C2
BloodHound / PlumHound # AD域分析
CALDERA / Atomic Red Team # 攻击模拟
Nuclei / Xray / Yakit # 漏洞扫描与验证

# AI安全运营
LangChain / CrewAI / AutoGen  # Agent编排框架
Cisco Foundation-sec / 安全微调模型 # 安全LLM
Microsoft Security Copilot / CrowdStrike Charlotte AI # 商业化副驾/Agent
Dropzone AI / Radiant Security # AI分析师
MISP / OpenCTI # 威胁情报(RAG知识源)
```

## 十四、测试检查清单

### 14.1 DevSecOps 管道
- [ ] CI/CD 管道集成 SAST/DAST/SCA 扫描（含制品产物收集）
- [ ] 质量门禁：CRITICAL/HIGH 阻断，MEDIUM/LOW 风险登记
- [ ] Pre-commit Hook（密钥/敏感信息）
- [ ] 容器镜像自动扫描（Trivy/Grype）+ 镜像签名
- [ ] IaC 安全策略（Checkov/OPA/Kyverno）
- [ ] 依赖漏洞自动更新（Dependabot/Renovate）
- [ ] 密钥泄露防护（Git 全历史 + CI 日志）
- [ ] 供应链安全（SBOM 生成/签名验证/来源审计）

### 14.2 漏洞管理与联动
- [ ] 扫描结果自动录入漏洞管理平台（DefectDojo 等）
- [ ] 多扫描器结果归一化/去重/合并
- [ ] 修复验证自动复扫，闭环关闭
- [ ] SLA 跟踪与超时升级告警
- [ ] nuclei/SAST/DAST 与漏洞平台全链路联动

### 14.3 攻防自动化
- [ ] 红队打点自动化：资产收集→存活→指纹→nuclei→验证
- [ ] 蓝队检测响应：告警聚合→富化→Triage→分级响应
- [ ] 攻击模拟（Atomic Red Team/CALDERA）与检测覆盖率评估
- [ ] ATT&CK 映射与覆盖热力图
- [ ] 红蓝联动闭环（红队 TTP → 蓝队检测规则 → 复测）

### 14.4 SOAR 与案件管理
- [ ] 剧本覆盖高频场景（暴力破解/钓鱼/异常登录/Web攻击）
- [ ] 半自动剧本包含 HITL 审批节点
- [ ] 案件自动关联与误报关闭原因分类
- [ ] 全动作审计留痕，可回放

### 14.5 AI/Agentic 安全运营
- [ ] 三层管道：规则过滤→LLM Triage→分级响应
- [ ] 告警富化（资产/用户/IP信誉/关联事件）
- [ ] LLM 结构化输出与置信度阈值
- [ ] 误报率/召回率看板与检测回归测试
- [ ] AI 辅助剧本生成经人工评审+历史回放
- [ ] Agent 最小权限、动作白名单、HITL 红线
- [ ] Agent 推理与动作全量审计日志

### 14.6 合规与报告
- [ ] CIS/等保/NIST 控制项自动化核对
- [ ] 证据收集（时间戳/来源/原始数据）合规归档
- [ ] 自动化报告生成与定期推送
- [ ] AI 生成内容标注与可解释性

## 十五、修复建议

### 15.1 扫描工具链
- 保持扫描器与漏洞库**持续更新**（CVE/NVD/模板库每日同步），扫描器版本固定+定期升级
- 规则集按团队/项目细分，避免一刀切导致误报淹没
- SAST/DAST/SCA/IAST **组合使用**，单一扫描器覆盖率有限

### 15.2 流程与门禁
- 门禁分级（硬/软），先在小范围试点再全量；门禁参数集中管理
- 漏洞全生命周期闭环：发现→归一→评估→指派→修复→复验→SLA，缺一环即断链
- 建立"预期行为"白名单（安全扫描器自身流量、CI 账号、计划任务），显著降低误报

### 15.3 SOAR/Agentic 落地
- 从**确定性 SOAR 剧本**起步（高价值高频场景），再逐步引入 LLM 富化与 Agentic 决策
- Agentic 自动化坚持：最小权限、动作白名单、HITL 红线、可逆动作优先、全量审计
- LLM Triage 采用**源特定 Agent**，规则先行过滤，富化先行，置信度阈值化

### 15.4 质量保障
- 维护"已知攻击样本集"做检测回归测试，任何规则/模板/Agent 变更必须回测
- 误报率/召回率/升级率看板化，数据驱动调优
- 关键发现坚持 exploit-validated（PoC 验证），拒绝"纸面漏洞"

### 15.5 合规与数据
- 证据自动收集+不可篡改审计链，满足 ISO27001/PCI-DSS/等保等审计要求
- AI 处理数据注意合规边界（数据不出域/脱敏），大模型优先本地化部署
- 定期演练与复盘，用攻击模拟验证自动化体系有效性

## 十六、注意事项

- **仅限授权测试/合规声明**：本技能涉及的一切扫描、攻击模拟、自动化处置动作，**必须取得目标系统所有者的书面授权**，并严格限定在约定范围与时间窗口内执行。未授权使用任何工具或技术均属违法行为，后果自负。本技能仅用于授权的红队演练、蓝队防护、DevSecOps 建设与安全教学。
- **范围确认**：测试前明确域名/IP、接口列表、禁止动作（DoS、数据拖库、破坏性操作），高风险操作前二次确认授权边界
- **最小影响原则**：优先无危害探测（DNSLog/低并发扫描），确认后可利用性后再谨慎验证；自动化扫描注意控制并发，避免对目标造成可用性影响
- **数据保护**：不读取/修改/外传敏感业务数据；测试数据与真实数据隔离，证据脱敏
- **凭据与权限**：自动化体系使用独立的最小权限服务账号/API Key，绝不复用管理员凭据；密钥妥善保管（Vault 等）
- **可逆性与回滚**：处置动作优先可逆（撤销 Token>禁用>删除）；所有自动化变更可回滚
- **清理痕迹**：测试完成后删除写入的文件、WebShell、临时账号、测试数据，恢复配置基线
- **环境隔离**：破坏性测试仅在隔离靶场/测试环境进行，生产环境只做只读与低风险验证
- **AI 使用边界**：LLM/Agent 输出必须人工复核关键动作；幻觉与提示注入是真实风险，严格执行第八章护栏；AI 生成的剧本/规则需评审与回测后上线
- **版本情报更新**：安全自动化技术（Agentic SOC、SOAR 能力、安全模型）演进迅速，定期跟踪厂商公告与行业实践（Gartner Hype Cycle、MITRE 更新等），及时更新本技能
- **漏洞报告**：测试发现的问题及时向甲方提交完整报告（复现步骤/影响/修复建议），不公开未授权披露

## DECISION TREE

```
自动化目标？
├── 建流水线 → 第一章 DevSecOps 阶段定位（SAST/DAST/SCA/IaC 卡点选择）
├── 扫描能力落地 → 第二章工具链按资产类型路由（源码/镜像/API/Infrastructure）
├── 策略与合规 → 第三章 OPA 策略即代码
├── 漏洞全生命周期 → 第四章（发现→去重→派单→复测→指标）
├── 告警编排与响应 → 第七章 SOAR 剧本
├── Agentic 编排 → 第八章 LLM Agent 驱动扫描/响应 → 第十二章与 Eino skill 系统联动
├── 误报率高 → 第十章误报治理门槛 → 对齐 pentest-verification
└── 报告生成 → 第十一章证据自动收集 → 格式对齐 pentest-output-standards
```

## TARGET TOOL ADAPTATION

Use visible `execute-python-script` for 脚本化扫描编排与结果聚合、`nuclei` 仅以相关性模板运行。不假设 SOAR/SIEM/漏洞管理平台 API 可达；编排产出的每条结论保留原始证据引用。

## RELATED ROUTING

- [pentest-verification](../pentest-verification/SKILL.md) — 自动化产出的证据质量与可复现门槛
- [capability-primitive-search](../capability-primitive-search/SKILL.md) — 工具能力原语检索与编排
