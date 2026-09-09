---
name: incident-response
description: 安全事件响应深度专业技能（v3.0高级版）：NIST 800-61r3六阶段响应框架、攻防视角入侵链还原与MITRE ATT&CK映射、Volatility 3/KAPE内存与主机取证深度、无文件攻击追查、云与容器(K8s)事件响应专项、勒索软件专项响应流程、假设驱动威胁猎捕、AI辅助应急响应(LLM日志分析/事件聚合/响应决策/报告生成)、大模型安全事件(提示注入/LLM滥用)响应、红蓝对抗与检测规避识别、日志多源关联与溯源追踪、处置修复加固与复盘报告
metadata:
  version: 3.0.0
---

# 安全事件响应深度技能

> **AI LOAD INSTRUCTION**: 应急响应与取证专家方法论（NIST 800-61r3）。蓝队视角：事件定级→取证采集顺序→内存/日志/样本分析→ATT&CK 还原→云容器与大模型事件专项→复盘报告。取证只读优先。

## 概述

安全事件响应(Incident Response, IR)是安全运营的核心能力，本质是**在攻击者尚未达成最终目标之前，发现、遏制、根除并恢复**。本技能 v3.0 站在资深攻防专家视角，在保留 v2.0 全部核心内容（应急响应流程、现场取证、日志分析、处置、报告）基础上，新增并深化七大高级维度：**攻防视角入侵链还原、内存/主机取证深度、云与容器事件响应、勒索软件专项响应、假设驱动威胁猎捕、AI 辅助应急响应、大模型安全事件响应**，并引入红蓝对抗视角贯穿全流程。

本技能系统化覆盖 **告警分析→事件确认→现场取证→攻击链重建→溯源追踪→遏制清除→修复加固→复盘报告** 完整响应链，涵盖 APT 对抗、内存取证、恶意样本分析、无文件攻击追查、云原生取证、勒索软件实战等高级技术。

### 核心概念
- **事件(Incident) vs 告警(Alert)**：告警是信号，事件是经过确认的、实际发生或正在发生的安全破坏。先验证再升级
- **检测(Detection)/响应(Response)/恢复(Recovery)**：三者闭环，检测只是起点
- **关键指标**：MTTD(检测时间)、MTTR(响应时间)、MTTC(遏制时间)、Dwell Time(驻留时间，攻击者进入系统到被发现的天数)
- **NIST SP 800-61r3 六阶段**：准备→检测与分析→遏制→根除→恢复→事后活动（本技能采用的主流框架）
- **PICERL 模型**：准备/识别/遏制/根除/恢复/经验教训
- **情报驱动响应**：以威胁情报(IOC/TTP/攻击者画像)指导响应决策，而非被动防御
- **假设驱动猎捕**：以"攻击者可能做了什么"为假设主动搜寻证据，而非等告警
- **Dwell Time 定律**：2025-2026 数据显示，有成熟 IR 计划+演习的组织驻留时间可压至 24 小时内，无计划者平均 200+ 天——**先于攻击做足准备**是响应能力的分水岭
- **AI 双刃剑**：LLM 既加速防御侧分析，也催生 AI 辅助攻击；响应团队必须同时具备"用 AI 分析"与"应对 AI 攻击"两种能力

## 一、事件分级与优先级

### 1.1 事件分级矩阵

| 级别 | 场景 | 响应时效 | 典型示例 |
|------|------|---------|---------|
| P0-紧急 | 域控被控/核心数据泄露/勒索加密进行中/容器逃逸 | 15分钟内响应 | 勒索软件、AD 全域沦陷、核心数据库外传 |
| P1-严重 | Webshell/权限提升/横向移动/云 AK 泄露 | 1小时内响应 | 单主机入侵、凭据窃取、可疑横向移动 |
| P2-高 | 单主机入侵/凭据泄露/钓鱼成功 | 4小时内响应 | 弱口令、异常登录、邮件投递恶意附件 |
| P3-中 | 弱口令/异常登录/可疑流量/配置错误 | 24小时内响应 | 端口扫描、异常 DNS 查询、错误配置 |
| P4-低 | 信息泄露/配置缺陷/资产暴露 | 72小时内响应 | 敏感信息泄露、补丁缺失、暴露面过大 |

### 1.2 初步研判五问
```
1. 告警来源：WAF/IDS/HIDS/SIEM/EDR/蜜罐/用户报告/云审计日志
2. 影响范围：单主机/子网/全域/数据/云账号/容器集群
3. 攻击阶段：侦察/利用/安装/C2/目标达成（判断攻击者是否仍活跃）
4. 是否活跃：攻击者是否仍在系统中（决定遏制优先级）
5. 业务影响：业务中断风险/数据泄露规模/合规上报义务
```

### 1.3 优先级评分模型（进阶）
```
优先级分 = 资产价值权重(0.3) + 攻击阶段权重(0.3) + 影响面权重(0.2) + 威胁活跃度(0.2)
- 资产价值：核心数据库=5，域控=5，办公PC=2，测试机=1
- 攻击阶段：已达目标=5，C2阶段=4，安装后门=3，利用=2，扫描=1
- 威胁活跃度：EDR 实时拦截=5，告警滞后>24h=3，已清理=1
评分>4 即按 P0/P1 响应，先评估再扑火，避免"所有告警都是紧急"
```

## 二、事件响应全流程框架

### 2.1 NIST SP 800-61r3 六阶段
```
1. 准备(Preparation)：预案/演练/工具就绪/日志留存的长期投入（决定响应上限）
2. 检测与分析(Detection & Analysis)：告警确认→数据收集→分析定级→范围界定
3. 遏制(Containment)：短期(断网/隔离)与长期(重建/封堵)遏制，防扩散
4. 根除(Eradication)：清除恶意件/移除持久化/删除攻击路径
5. 恢复(Recovery)：备份恢复/业务上线/验证加固
6. 事后活动(Post-Incident)：复盘/报告/指标/改进项落地
```

### 2.2 作战时间线（黄金1小时）
```
0-15分钟：告警确认、初步研判、启动分级、通知响应负责人（IR Commander）
15-60分钟：遏制决策（隔离主机/撤销凭据/阻断C2）、启动取证（易失性数据）
1-4小时：范围界定、时间线初建、攻击入口确认、持续监控攻击者动向
4-24小时：深入取证（内存/磁盘）、恶意样本分析、数据影响面评估
24-72小时：根除与恢复、加固、向管理层/监管第一次正式汇报
3-7天：复盘报告、指标统计、检测规则与流程改进落地
```

### 2.3 指挥协调与 RACI
```
IR Commander(总指挥)：全局决策，唯一有权宣布"遏制完成"
技术调查组：取证、分析、样本分析
业务/运维组：隔离执行、业务恢复评估
法务/合规组：上报义务、取证合规、对外沟通把关
公关/沟通组：对外声明、内部通知（禁止未经法务审查对外发声）
每步操作必须留痕（时间/操作人/对象/结果），保证可审计
```

### 2.4 沟通与合规上报
- **数据泄露类事件**：多数司法辖区（如 GDPR 72 小时、中国数据安全法/网安法、等保2.0）对上报时限有硬性要求，**从"怀疑"而非"确认"起算倒计时**
- 涉及 PII/PCI/PHI 时第一时间通知法务
- 联系执法/监管机构（公安网安、CERT、CISA 等），其可能掌握特定变种解密工具与情报
- 对外口径统一：由法务+公关审核，禁止技术团队私自回复媒体或攻击者

## 三、攻防视角：入侵链还原与 MITRE ATT&CK 映射

### 3.1 攻击者视角还原入侵链
站在攻击者角度自问："如果我是攻击者，我会怎么进来？"以此指导证据收集方向：
```
1. 初始入口：哪条路径进来的？（钓鱼/0day/弱口令/供应链/云凭据/暴露服务）
2. 工具选择：用了什么？（Cobalt Strike/Metasploit/自定义Loader/LOLBins）
3. 权限目标：先提权到谁？AD 管理员/云高权限角色？
4. 持久化：如何保证下次还能进来？（计划任务/服务/启动项/注册表/AD后门）
5. 横向路径：如何在内网移动？（PTH/WMI/WinRM/RDP/云AssumeRole）
6. 目标与出口：最终要什么？数据从哪里、以什么方式出去？
每个环节都要问：证据在哪？日志源是哪个？查询语句是什么？
```

### 3.2 MITRE ATT&CK 战术映射表
| 战术 | 技术示例 | 关键证据源 |
|------|---------|-----------|
| 初始访问(TA0001) | 钓鱼、漏洞利用、暴力破解、供应链、云凭据泄露 | 邮件网关、WAF、登录日志、云审计 |
| 执行(TA0002) | PowerShell/CMD/WMI/计划任务/LOLBins | 4688进程创建、Sysmon EID 1/11 |
| 持久化(TA0003) | 注册表Run、计划任务、服务、WMI事件、AD证书 | 4698/7045、Sysmon EID 12/13/14 |
| 权限提升(TA0004) | 令牌操纵、CVE利用、Sudo滥用、云角色切换 | 4672、4688、云审计 |
| 防御规避(TA0005) | 进程注入、日志清除、AMSI绕过、Timestomping、直接系统调用 | 1102、Sysmon EID 10/25、EDR |
| 凭据访问(TA0006) | LSASS转储、Kerberoast、密码喷洒、云AK窃取 | 4663/4689、Sysmon EID 10、CloudTrail |
| 发现(TA0007) | 网络扫描、域枚举、用户枚举、云资源枚举 | DNS查询、SharpHound(见下)、云审计 |
| 横向移动(TA0008) | PTH/PTT、WMI/WinRM/RDP、SSH、云跨账号 | 4624 Type3/10、4776、RDP日志 |
| 收集(TA0009) | 文件收集、剪贴板、浏览器数据、数据库导出 | Sysmon EID 11、文件访问审计 |
| 数据外传(TA0010) | DNS/HTTP/ICMP隧道、云存储、邮件外发 | 流量分析、DNS日志、出口流量 |
| 影响(TA0040) | 数据加密、删除、篡改、DDoS | EDR行为检测、canary文件告警 |

### 3.3 攻击链时间线重建方法
```
1. 锚点法：先找"必须存在"的证据锚点（首次恶意文件创建、首个异常登录、首次C2回连）
2. 双向扩展：从锚点向前追初始访问，向后追横向移动与数据外传
3. 多源对齐：Windows日志、DNS日志、防火墙/NGFW日志、EDR、云审计逐层比对时间戳
4. 时间线工具：Plaso/log2timeline、Timesketch、ELK时间线视图
5. 输出物：带证据引用的攻击链图（每个节点标注：时间/主机/用户/日志源/ATT&CK ID）
```

### 3.4 常见入侵链模板（直接套用）
```
勒索软件链：外部暴露RDP/钓鱼→凭据窃取→横向移动→域控→备份删除→全网加密+数据外传
APT数据窃取链：钓鱼(带宏文档)→宏执行→Cobalt Strike→提权→域控→GPO下发→数据汇集→外传
挖矿链：公网漏洞(Redis/Log4j/Docker API)→反弹shell→下载挖矿程序→SSH密钥后门→批量蔓延
云入侵链：泄露AK→枚举S3/ECS→创建新用户→横向到其他账号→数据打包外传→计费炸弹
```

## 四、现场取证与易失性数据采集

### 4.1 取证优先级原则（易失性递减）
```
内存 > 网络连接 > 进程 > 磁盘 > 日志
先采"关机会丢"的数据；顺序错了证据就没了
取证前禁止：重启、杀毒扫描、删除文件、关闭服务（除非是遏制必须）
```

### 4.2 Windows取证
```bash
# 1. 内存dump（最先）
winpmem.exe --load driver --output RAMDump.raw
DumpIt.exe / DumpIt_x64.exe
Magnet RAM Capture（GUI）

# 2. 网络连接
netstat -ano > netstat.txt
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Export-Csv connections.csv

# 3. 进程信息
tasklist /svc /v > processes.txt
wmic process get ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId > wmic_process.txt
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | Format-List

# 4. 网络连接+进程关联
netstat -anob > net_process.txt

# 5. 服务与计划任务
sc query type= service state= all > services.txt
schtasks /query /fo LIST /v > scheduled_tasks.txt
wmic startup get Caption,Command,Location > startup.txt

# 6. 注册表（持久化）
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

# 7. 用户与登录
net user > users.txt
net localgroup administrators > admins.txt
wevtutil qe Security /q:"*[System[EventID=4624]]" /c:200 /f:text > logins.txt
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:200 /f:text > failed_logins.txt

# 8. 最近修改的文件（时间线）
forfiles /P C:\ /S /D +2026-06-27 /C "cmd /c echo @path @fdate @ftime" > recent_files.txt

# 9. 浏览器与远程桌面痕迹（作为补充）
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s > rdp_servers.txt
```

### 4.3 Linux取证
```bash
# 1. 内存
cat /proc/meminfo
# LiME：insmod lime-$(uname -r).ko "path=memdump.mem format=raw"

# 2. 网络连接
ss -antup > connections.txt
netstat -antup > netstat.txt

# 3. 进程
ps auxef > processes.txt
ls -la /proc/*/exe 2>/dev/null > proc_exe.txt
for p in /proc/[0-9]*; do echo "== $p =="; cat $p/cmdline 2>/dev/null | tr '\0' ' '; echo; done > proc_cmdline.txt

# 4. 用户与登录
last -20 > last_login.txt
lastb -20 > failed_login.txt
cat /etc/passwd > passwd.txt
cat /etc/shadow > shadow.txt
who > who.txt
ls -la /home/*/.ssh/ > ssh_keys.txt
cat /root/.bash_history > root_history.txt

# 5. 计划任务
crontab -l > crontab.txt
cat /etc/crontab >> crontab.txt
ls -la /etc/cron.* >> crontab.txt

# 6. 启动项
systemctl list-unit-files --type=service > services.txt
cat /etc/systemd/system/*.service > systemd_services.txt
cat /etc/init.d/* > init_scripts.txt
cat /etc/rc.local 2>/dev/null

# 7. 日志
cp /var/log/auth.log ./ 2>/dev/null
cp /var/log/secure ./ 2>/dev/null
cp /var/log/syslog ./ 2>/dev/null
cp /var/log/nginx/access.log ./ 2>/dev/null
cp /var/log/apache2/access.log ./ 2>/dev/null
journalctl --since "2026-06-27" > journal.txt 2>/dev/null

# 8. 文件系统时间线
find / -mtime -2 -type f -ls > recent_files.txt 2>/dev/null
find /tmp /var/tmp /dev/shm /var/www -type f -ls > suspicious_dirs.txt 2>/dev/null

# 9. SUID/Capabilities
find / -perm -4000 -type f -ls > suid.txt 2>/dev/null
getcap -r / > capabilities.txt 2>/dev/null

# 10. Rootkit检测
rkhunter --check --skip-keypress
chkrootkit

# 11. 内核模块与隐藏进程
lsmod > kernel_modules.txt
cat /proc/modules >> kernel_modules.txt
```
**所有采集文件完成后立即计算 SHA-256 并记录到证据清单（见4.4）**

### 4.4 证据保全与证据链
```
1. 每份采集文件：记录采集时间/主机/采集人/工具/命令
2. 全部计算 SHA-256：Get-FileHash file -Algorithm SHA256
3. 证据介质：只读挂载或写保护（Windows写保护块/ Linux mount -o ro）
4. 时间统一：以协调世界时(UTC)记录，避免时区歧义
5. 采集过程对系统的最小改动也要记录（本身也是"污染证据"）
6. 如涉司法取证：使用 EnCase/FTK 做镜像与校验，建立完整 Chain of Custody
```

### 4.5 远程取证（规模化）
```
KAPE（Kroll Artifact Parser & Extractor）：Windows 自动化取证，Targets批量提取工件
  kape.exe --tsource C:\ --tdest D:\output --target !SANS_Triage --tlog
UAC（Linux Artifact Collector）：Linux 自动化采集
Velociraptor：大规模远程取证与狩猎（DFIR/IR 一体化）
  velociraptor --config client.config.yaml artifacts collect Windows.Sys.Processes
GRR Rapid Response：Google 开源远程取证平台
F-Response/EnCase Enterprise：远程镜像
原则：能自动化就不手工，能并行就不串行，先采集再分析
```

## 五、内存取证与主机取证深度

### 5.1 内存采集工具
```
Windows：winpmem、DumpIt、Magnet RAM Capture、FTK Imager(内存)
Linux：LiME（内核模块）、avml（Linux内存采集，速度快）
macOS：osxpmem
云端VM：部分云厂商提供内存快照能力；无法直接采集时依赖进程/日志替代
K8s容器内进程：在宿主机上 avml --pid <容器内进程在宿主机的PID>（容器PID在宿主机可见）
```

### 5.2 Volatility 3 深度分析
```bash
# 系统信息与内核基址
vol -f memdump.raw windows.info

# 进程分析（核心三连）
vol -f memdump.raw windows.pslist      # 常规进程列表（对比EDR确认基线）
vol -f memdump.raw windows.pstree      # 父子进程树（发现可疑派生关系）
vol -f memdump.raw windows.psscan      # 扫描隐藏/已退出进程（反取证对抗）
vol -f memdump.raw windows.pstree --pid <PID>   # 单进程族谱

# 网络连接（内存中的socket）
vol -f memdump.raw windows.netscan     # 包括已断开但仍在内存中的连接
vol -f memdump.raw windows.netstat

# 注入与隐蔽代码（无文件攻击核心证据）
vol -f memdump.raw windows.dlllist     # 进程加载的DLL（异常路径/未签名）
vol -f memdump.raw windows.malfind     # 可疑可执行内存段（经典注入检测）
vol -f memdump.raw windows.ldrmodules  # 检查DLL是否从内存中被隐藏（反射注入）
vol -f memdump.raw windows.svcscan     # 服务（隐藏服务检测）

# 凭据与hash
vol -f memdump.raw windows.hashdump    # 本地账户hash
vol -f memdump.raw windows.lsadump     # LSA secrets（含服务账号明文）

# 命令与文件
vol -f memdump.raw windows.cmdline     # 进程命令行（LOLBins滥用证据）
vol -f memdump.raw windows.filescan    # 扫描内存中文件对象
vol -f memdump.raw windows.dumpfiles --pid PID   # 从内存提取文件
vol -f memdump.raw windows.memmap --pid PID > pid_map.txt  # 内存段映射

# Linux 对应插件
vol -f linuxmem.raw linux.pslist linux.bash linux.environ linux.malfind linux.dump_map
```

### 5.3 KAPE 自动化取证
```
KAPE = 集合器(kcollect)+处理器(kpsparse)，分钟级完成 Windows 关键工件采集
常用 Targets：
  !SANS_Triage        # SANS 三线采集（核心推荐）
  !EZ_Triage          # Eric Zimmerman 全家桶格式
  $MFT / Prefetch / ShimCache / AmCache / RecentDocs
  SRUM（应用资源使用，定位执行时间）
  EventLogs / Sysmon
KAPE 输出自动生成时间线，配合 EZ 工具（Timeline Explorer/EvtxECmd/Everything）
```

### 5.4 无文件攻击追查（Fileless 专项）
无文件攻击不落地二进制，或仅存在于内存/注册表/系统组件中，**传统杀软可能零检测**：
```
追查路径：
1. 内存证据：Volatility malfind/ldrmodules 找注入；提取内存样本做YARA匹配
2. 注册表负载：RunKeys/服务ImagePath指向powershell脚本、WMI EventSubscription持久化
   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WMI" /s
   Get-WmiObject -Namespace root\subscription -Class __EventConsumer  # 查看WMI消费器
3. 计划任务内嵌脚本：schtasks /query /fo LIST /v | findstr /i "powershell"
4. LOLBins 滥用：powershell.exe -enc、mshta、regsvr32、rundll32 启动链
   （对 4688/Sysmon EID1 做命令行规则检测是关键防线）
5. .NET CLR 劫持：AppDomainManager 注入（内存中托管代码）
6. 无文件勒索：直接在内存中加密或仅用系统工具（如部分 BlackCat/Medusa 变种行为）
判活确认后：内存样本+YARA规则留档，禁止直接杀掉重启（证据丢失）
```

### 5.5 反取证检测
```
Timestomping（篡改时间戳）：对比 MFT/PreFetch/日志时间，使用 MFTECmd 检查
日志清除：1102(安全日志清空)/104(系统日志清空)本身就是告警信号
ADS（NTFS 备用数据流）：dir /r 检测，可疑文件藏于隐藏流
卷影副本删除：vssadmin list shadows 对比记录
进程名欺骗/伪装：镜像路径与签名校验（sigcheck -a）
禁用安全工具：EDR/AV被停用的服务状态变化日志（7045/7036）
```

## 六、日志分析与多源关联

### 6.1 Windows日志关键EventID
| EventID | 事件 | 分析重点 |
|---------|------|---------|
| 4624 | 成功登录 | Logon Type 3(网络)/10(远程交互)；异地IP+工作时间外=重点 |
| 4625 | 失败登录 | 高频暴力破解（>10次/分钟）|
| 4672 | 特殊权限分配 | SeDebugPrivilege(提权/LSASS访问前置) |
| 4688 | 进程创建 | 可疑命令行（编码PowerShell/下载执行）|
| 4698 | 计划任务创建 | 持久化 |
| 4697/7045 | 服务安装 | 后门服务（对镜像路径做签名校验）|
| 1102 | 安全日志清除 | 反取证（发现即高价值告警）|
| 4776 | NTLM认证 | Pass The Hash 检测（工作站试图以域管认证）|
| 4768/4769 | Kerberos票据 | Golden/Silver Ticket、Kerberoast |
| 4720/4728/4732 | 用户/组创建与加组 | 新增管理员、域管组变更 |
| 4648 | 显式凭据登录 | 攻击者使用窃取凭据横向移动（配合4688）|
| 4104/4103 | PowerShell模块/脚本块日志 | 编码命令还原（PowerShell攻击核心证据）|
| 8004/8006 | PowerShell应用日志 | WMI Persistence |
| 1001/1002 | Sysmon 进程创建/进程变更 | 需部署Sysmon（推荐配置为高日志量）|

### 6.2 Linux日志分析
```bash
# 异常登录检测（高频源IP）
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# 成功登录后源IP
grep "Accepted" /var/log/auth.log | awk '{print $(NF-3), $9}' | sort | uniq -c | sort -rn

# 权限提升
grep "sudo:" /var/log/auth.log
grep "su:" /var/log/auth.log

# 命令历史（重点：下载、wget/curl、ssh隧道、反弹shell）
cat ~/.bash_history | grep -E "wget|curl|nc |bash -i|python.*socket"

# Web日志分析
awk '$9 >= 400' access.log | head -100                      # 4xx/5xx
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn | head  # UA画像
grep -E "eval|base64|cmd=|/proc/self|\.jsp|\.php\?" access.log | head -100  # 注入特征
grep -E "passwd|shadow|\.ssh|\.git|\.env|config\.php|wp-config" access.log  # 敏感文件探测

# DNS隧道/异常DNS
# 用 tcpdump 抓DNS：tcpdump -i eth0 -nn port 53 -w dns.pcap
# 关注：超长子域名、TXT记录频繁查询（dnscat2/iodine特征）

# 反连检测（防火墙/网关侧更可靠）
# ss -antup | grep ESTAB；关注 4444/8080/53/443 等非常规反连端口
```

### 6.3 多源日志关联（时间线法+图关联法）
```
1. 时间线法：将 Windows 日志、Linux 日志、防火墙、DNS、EDR、云审计拉平到统一时间轴
   工具：Timesketch（推荐）、ELK、Splunk timeline
2. 图关联法：以"账号→主机→IP→文件"为节点画关系图（BloodHound 反向用法）
   例：域管账号在3:47登录了DB服务器，DB服务器同刻访问了外网IP X
3. 入口寻找法：先找最早的异常事件（首次恶意登录/首次C2回连），再向前找初始访问
4. 交叉验证原则：单一日志结论不成立，至少两个独立源印证（如4688+网络流）
```

### 6.4 SIEM 查询速查
```
Splunk（SPL）：
  index=windows EventCode=4624 Logon_Type=10 | stats count by src_ip, user | sort -count
  index=windows EventCode=4688 | where match(CommandLine,"(?i)(-enc|bypass|IEX|DownloadString)")
KQL（Sentinel/Defender）：
  SecurityEvent | where EventID==4688 | where CommandLine contains "powershell"
  IdentityLogonEvents | where LogonType=="RemoteInteractive"
Sigma（跨平台规则）：sigma convert -t splunk -p 通用规则（社区共享检测规则）
```

## 七、恶意样本分析

### 7.1 静态分析
```bash
# 基础信息
file sample
strings -a -n 6 sample | head -100
sha256sum sample
ssdeep sample                      # 模糊Hash（变种聚类）

# PE分析
python -m pefile sample.exe        # 导入表/资源/节区（不常见的节名如.upx=加壳）
sigcheck -a sample.exe             # 签名/版本信息（VS)
# 加壳检测：DIE(Detect It Easy)、UPX、检查导入表密度

# 恶意文档
python -m oletools.olevba sample.doc        # 宏代码提取
python -m oletools.oleid sample.doc         # OLE结构风险标识
# 恶意PDF：pdfid、peepdf

# YARA规则匹配
yara -r rules/ sample               # 使用 MalwareBazaar/YARA-Forge 社区规则集
# 在线：VirusTotal、Hybrid Analysis（上传前确认样本无敏感信息）

# 配置提取（勒索/远控家族）
# 使用公开解密工具：如 DragonBuster 等勒索解密工具、通用C2配置提取器
```

### 7.2 动态分析
```
沙箱环境（必隔离）：
- Any.Run（在线交互式，可看进程树+网络）
- Joe Sandbox（在线深度报告）
- Cuckoo/CAPE Sandbox（本地自动化）
- 本地VM（禁用共享/快照回滚/仅主机网络+NAT代理）

监控项（对照记录）：
- 进程创建/注入（进程树形态）
- 文件操作（创建/修改/删除，重点自启动路径）
- 注册表操作（RunKeys/服务/WMI）
- 网络通信（DNS/HTTP/TCP，抓包分析C2协议）
- 互斥量/管道（去重与家族识别）
- 持久化机制（重启后是否存活）

行为结论输出：文件hash、C2域名/IP、家族归属、持久化点、窃取数据清单
```

### 7.3 快速判定流程（10分钟出结论）
```
1. VT/沙箱多引擎：命中数>10 → 高度恶意（先看家庭/行为标签）
2. 签名+加壳：未签名+加壳+高熵 → 可疑（提取静态配置）
3. 网络行为：主动外连非常规端口/域名 → 恶意概率大增
4. 持久化行为：写入自启动 → 确认恶意
5. 输出：该样本是"已知家族变种"还是"新型"，决定后续溯源与规则发布
```

### 7.4 逆向分析基础
```
Ghidra（免费）/ IDA Pro：静态反编译定位关键逻辑
x64dbg / WinDbg：动态调试（需在隔离环境）
分析重点：C2字符串、解密密钥、加密算法（勒索）、外传目标
进阶：脱壳（unpack）、混淆还原、行为指纹提取（用于YARA）
```

## 八、溯源追踪与威胁情报

### 8.1 IOC提取与共享
```
IOC类型：
- Hash（MD5/SHA256/SSDeep/TLSH）
- IP/Domain/URL/注册域名（whois/证书指纹JA3/JA3S）
- 文件名/路径/互斥量名称
- 注册表键值/计划任务名
- C2协议特征（User-Agent、Beacon间隔、公钥）
- YARA规则/Sigma规则

共享格式：STIX 2.1 / TAXII 2、OpenIOC、MISP 事件
共享渠道：MISP、企业威胁情报平台、行业CERT、国家CERT
```

### 8.2 攻击者画像
```
分析维度：
- 攻击时间规律（工作时区推断：UTC+8/UTC+3/UTC-5）
- 使用语言（代码注释/文件名/字符串：中文/俄语/英语/阿拉伯语）
- 工具特征（C2框架：Cobalt Strike/Metasploit/Sliver/自定义）
- TTPs映射（MITRE ATT&CK 分组匹配：APT28/Lazarus/BlackCat等）
- 目标选择（行业/地域偏好、社会工程话术）
- 基础设施（历史域名注册模式、托管商偏好、基础设施复用）
```

### 8.3 溯源反查方法
```
1. C2基础设施：域名whois反查注册人邮箱（注意隐私保护）、历史解析记录（Passive DNS）
2. 证书指纹：JA3/JA3S 匹配公开威胁情报库（如 ja3er）
3. 基础设施共享：IP段/ASN 聚类、域名关联图
4. 样本聚类：SSDeep 相似度、代码同源性（复用样本比较）
5. 攻击归因注意事项：归因需高置信度，避免误报；公开报告由专业团队（Mandiant/奇安信等）主导
```

## 九、勒索软件专项响应

### 9.1 2025-2026 威胁演变（响应思路必须同步更新）
```
1. 加密不再是主手段：纯数据窃取（不加密只偷）+ 双重勒索成为主流——"谈判位置"比"恢复"更重要
2. 身份失陷主导：攻击者通过凭据/云身份进入，而非漏洞——响应要围绕身份而非病毒
3. 攻击周期加快：从初始访问到引爆可能仅数天；凌晨/节假日/周末发起是常见"武器化时间"
4. RaaS 化：勒索即服务降低门槛，攻击者多样（技术小组+运营小组分工）
5. AI 辅助：AI 生成的钓鱼、自动化扫描、动态命令生成提升攻击效率
6. 响应含义：第一动作可能是"取证界定被窃走了什么+法律评估+准备谈判立场"，而非只隔离恢复
```

### 9.2 黄金时间响应流程
```
第0阶段-检测(加密前是最佳窗口)：canary文件/EDR行为/异常批量加密API调用/卷影删除
第1阶段-隔离(30分钟内)：拔网线或断网卡（虚拟机快照/云主机先拍快照再隔离）
   禁用被攻陷账号、轮换密码、阻断出口C2（防火墙/云安全组）
第2阶段-取证：保留加密样本/勒索信/内存/日志；禁止重启与尝试解密（可能二次损坏）
第3阶段-评估：界定泄露数据范围、加密范围、恢复可行性（含解密工具查询 no-more-ransom）
第4阶段-决策：是否谈判（见9.4）、是否联系执法
第5阶段-恢复：验证备份→逐业务恢复→加固
第6阶段-复盘：泄露面全量评估（数据窃取是永久性损失，必须对外披露评估）
```

### 9.3 响应命令速查
```bash
# 检测变种线索（勒索信/文件扩展名/加密特征）
find / -name "*.locky" -o -name "*.wannacry" 2>/dev/null   # 按已知扩展名
find / -name "*.txt" -newer /etc/hostname -exec grep -l "bitcoin" {} \; 2>/dev/null

# 识别加密进程与卷影删除
ps auxef | grep -iE "vssadmin|wmic|gpupdate"
ls -la /var/log/syslog | grep -i "vss" 2>/dev/null

# 隔离命令（Windows：禁用网络适配器）
Disable-NetAdapter -Name "以太网" -Confirm:$false
# Linux：ifdown eth0 或 iptables -P INPUT DROP; iptables -P OUTPUT DROP

# 判定是否在mimikatz转储（LSASS访问）
wevtutil qe Security /q:"*[System[EventID=4689]]" /f:text | findstr /i "lsass"

# 查询解密工具（免费官方渠道）
# https://www.nomoreransom.org/ 提供官方免费解密工具检索
```

### 9.4 是否支付赎金决策框架
```
1. 法律先行：攻击者可能位于制裁名单（如美国OFAC），支付可能违法——法务必须介入
2. 技术评估：备份可用性、解密器可用性、数据是否已外泄（支付无法消除泄露）
3. 支付≠保证：约1/4受害者支付后未获解密；二次勒索比例高
4. 谈判：若决定谈，由专业谈判团队执行，不直接暴露决策权限
5. 不因恐慌决策：公司政策预先明确"是否允许支付"，避免临时决定
```

### 9.5 恢复与加固
```
备份策略 3-2-1-1：3份副本、2种介质、1份离线（air-gap）、1份异地
身份恢复计划：域管/高权限账号轮换、云AK轮换、IAM策略核查（2026攻击多经身份路径）
离线备份验证：定期在隔离环境测试恢复（备份也会被加密/删除，2026年勒索攻击先打备份）
加固重点：RDP暴露最小化+多因素认证、补丁管理、EDR全量部署、出口流量监控
```

### 9.6 勒索软件应急演练
```
演练场景（2026推荐）：
- 场景A：凌晨收到勒索信，数据已被外传（重点练"泄露面评估+法律+谈判准备"）
- 场景B：加密进行中，备份可能已被删（练隔离+恢复决策）
- 场景C：跨职能桌面推演（安全+法务+公关+高管同一时钟，暴露沟通断层）
跨职能演练是关键：只练技术团队会让真正的断层（法务时限/公关口径）漏网
```

## 十、云与容器事件响应专项

### 10.1 云日志源映射（必须双平面采集）
| 组件 | AWS | Azure | GCP |
|------|-----|-------|-----|
| 云API调用 | CloudTrail | Activity Logs | Cloud Audit Logs |
| 托管K8s控制面 | EKS控制面日志 | AKS诊断日志 | GKE审计日志 |
| 网络流 | VPC Flow Logs | NSG Flow Logs | VPC Flow Logs |
| 身份/IAM | CloudTrail IAM事件 | Entra ID(Azure AD)日志 | Cloud IAM审计 |
| 负载均衡 | ALB/NLB访问日志 | Application Gateway | Cloud Load Balancing |
| DNS | Route 53查询日志 | Azure DNS分析 | Cloud DNS日志 |

**两平面原则**：平面1=VM内证据（SSH采集/磁盘快照）；平面2=云审计追踪（API调用/IAM变更/安全组修改）。
攻击者在云侧的活动（如修改安全组、创建新用户）从 VM 内部永远看不到——**两平面都要采**。

### 10.2 云取证与响应
```bash
# 云磁盘快照（VM证据，先于登录VM操作——快照不产生VM内污染）
# AWS EBS
aws ec2 create-snapshot --volume-id vol-xxxx --description "IR-$(date)"
# Azure 磁盘
az snapshot create -g rg -n snap1 --source disk1
# GCP
gcloud compute disks snapshot disk-1 --zone=us-central1-a

# 云审计日志采集
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=admin --start-time 2026-06-27
az monitor activity-log list --start-time 2026-06-27
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="admin@corp.com"' --limit=1000

# 响应动作
# 轮换泄露的AK/SK（立即生效，勿只禁用IAM用户）
aws iam create-access-key --user-name compromised-user   # 先建新key再删旧key
# 撤销角色AssumeRole链、删除异常安全组规则
# 云主机先打快照再隔离（云上"拔网线"=安全组deny-all或停止实例）
```

### 10.3 容器取证（易逝性最高，采集优先级第一）
```
容器是易失的：pod重建/镜像回收会秒杀证据——先采集再调查
采集顺序：
1. kubectl logs <pod> --previous        # 崩溃前日志（攻击导致重启时是关键）
2. kubectl describe pod <pod>           # 事件与配置
3. kubectl get pod <pod> -o yaml        # 保存Pod规格
4. 容器文件系统diff：docker diff <container> 或 overlay层差异
5. 容器内进程与网络：kubectl exec 或 宿主机 nsenter（优先用静态编译工具）
6. 镜像保全：docker save <image> -o image.tar 或 skopeo copy
7. 容器内存：宿主机上 avml --pid <容器内进程PID>（在宿主机PID空间可见）
8. 卷快照：CSI快照（EBS snapshot / gcloud compute disks snapshot）
9. 运行时取证：crictl logs / crictl inspect（containerd运行时）
10. 网络：宿主机 tcpdump -i any 过滤 pod IP；Cilium 下 hubble observe
```

### 10.4 Kubernetes 事件响应（前60分钟清单）
```
0-15分钟：
  kubectl cordon <node>                          # 封锁受影响节点
  kubectl label ns <ns> network-policy=deny       # 或直接下发deny-all NetworkPolicy
  采集：kubectl logs --previous、node卷快照、容器内存、网络连接
15-30分钟：
  导出审计日志（RequestResponse级才能看到exec内容）
  复制容器可写层、保全Pod规格
30-45分钟遏制：
  轮换被攻陷ServiceAccount令牌、撤销可疑RBAC绑定
  kubectl drain <node>（证据采集完成后）
  云防火墙封禁恶意IP
45-60分钟：
  通知指挥与利益相关方、更新事件工单、界定爆炸半径

检测工具：Falco/Tetragon（运行时syscall检测）、tracee-ebpf、Sysdig Inspect
审计日志：kube-apiserver audit policy 配置 RequestResponse 级别记录 exec/attach/portforward
  配置开启前无法回溯——把"审计策略配置"当作IR计划的一部分
安全上下文基线：容器以非root运行、seccomp/AppArmor、只读rootfs、限制特权容器
常见事件类型：容器逃逸、暴露API Server、ServiceAccount滥用、恶意镜像（供应链）
```

### 10.5 云身份与凭据事件
```
2026 云入侵主流路径：泄露AK/SK、OAuth应用滥用、云服务账号横向
响应重点：
1. 立即轮换（先建新再删旧，避免业务中断）
2. 审计 IAM 变更历史（谁在何时加了什么权限）
3. 检查：存储桶策略是否被改（公开读写）、函数/容器是否被注入后门
4. 计费异常（挖矿/资源消耗爆炸）也是重要信号
5. 云凭据扫描：GitHub/公开仓库泄露检测（trufflehog）
```

## 十一、威胁猎捕方法论（假设驱动）

### 11.1 猎捕 vs 响应
```
响应：事件已发生，被动处置，以"遏制止损"为目标
猎捕：主动在"没有告警"时搜索异常，以"发现未知威胁"为目标
猎捕输出：新增检测规则、IOC、环境基线修正、减少驻留时间
```

### 11.2 假设驱动猎捕流程（PTFH 模型）
```
1. 提出假设（Hypothesis）：基于威胁情报/最新攻击手法/近期事件
   例："攻击者可能通过RDP弱口令进入并在周末横向移动"
2. 确定数据源（Data Source）：假设落地到哪些日志/端点
   例：4624 Type10 + 4625 + 4688 + 防火墙日志
3. 选择技术（Technique）：查询/行为基线/机器学习异常检测
4. 验证假设（Validation）：命中→调查；未命中→记录为已排除
5. 产出（Output）：检测规则(Sigma/YARA)、IOC、故事时间线
每轮猎捕建议 2-4 小时，聚焦一个假设，避免"撒网式"低效搜索
```

### 11.3 六大高频猎捕假设模板
```
假设1-横向移动：同一账号从多台主机登录 / 新主机出现已知内网账号
假设2-持久化：近期新增的计划任务/服务/启动项（对比基线）
假设3-C2通信：低频长连接、非常规端口、DNS长域名、JA3指纹异常
假设4-凭据窃取：LSASS进程访问(4688+Sysmon EID10)、SAM/hashdump行为
假设5-数据外传：大流量突发、压缩包外传、非工作时间上传
假设6-0day信号：边缘设备(LVPN/VPN/网关)异常登录、内存注入但无已知签名
```

### 11.4 狩猎查询示例
```bash
# 假设：PowerShell 编码执行（近期钓鱼热点）
# Windows事件4688/Sysmon EID1
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
  Where-Object {$_.Message -match "-enc|encodedcommand|IEX|DownloadString"} |
  Select-Object -First 50 TimeCreated, Message | Format-List

# Linux：最近24h新增的计划任务
find /etc/cron* /var/spool/cron -type f -mtime -1 -ls 2>/dev/null

# 网络：非常规端口外连（假设C2）
# 在出口防火墙/NDR上查询：目标端口 not in (443,80,53,123) 且持续连接>5分钟
```

### 11.5 猎捕成熟度与工具
```
成熟度0：基于告警（IOC驱动，被动）
成熟度1：基于IOC+日志查询（半主动）
成熟度2：基于假设+TTP（主动，本方法论的日常形态）
成熟度3：基于行为基线+ML异常（数据驱动）
工具：Velociraptor、Elastic/OSQuery、Sigma、YARA、BloodHound（反向防御）、EDR狩猎API
```

## 十二、红蓝对抗视角

### 12.1 常见检测规避技术识别（蓝队视角"他们怎么躲我们"）
```
AMSI绕过：内存补丁/反射加载（Sysmon EID 16 可捕获部分）
进程注入：CreateRemoteThread/APC注入（Sysmon EID 8/10）
直接系统调用（Syscall）：绕过用户态钩子（EDR需内核检测）
Timestomping：篡改文件时间（MFT对比）
日志清除：EventLog服务停止/清空（1102/104告警）
白利用（LOLBins）：mshta/regsvr32/rundll32/msiexec 执行脚本（4688规则检测）
NTFS ADS隐藏：dir /r、Get-Item -Stream *
睡眠/压缩：恶意载荷在内存中压缩，周期性解压执行（Volatility malfind仍可见shellcode特征）
云侧规避：日志禁用、区域切换、用同一云厂商基础架构（检测难）
```

### 12.2 如何让规避无效（检测工程对策）
```
1. 内核级遥测：EDR开启内核传感器（对抗直接系统调用）
2. 冗余检测：多层检测交叉（EDR + 网络 + DNS + 云审计），单层被绕过仍有其它层
3. 日志先行：Sysmon高配置 + 日志集中 + 90天留存（攻击者清本地日志无法清SIEM）
4. 行为基线：正常基线越清晰，异常越显眼（猎捕前提）
5. 蜜罐/蜜标：蜜标文件/蜜号触发即告警（勒索与数据窃取类攻击高价值）
```

### 12.3 对抗取证（攻击者反取证 vs 取证对抗）
```
攻击者手段：内存篡改、磁盘覆写（wipe）、日志清空、时间戳、反虚拟机沙箱检测
取证对抗：
1. 内存优先采集+异地保存（攻击者无法清理已复制的镜像）
2. 日志异地（SIEM/集中日志服务器）——攻击者能删本机但删不掉远端
3. 取证时间线（MFT/PreFetch/ShimCache）即使篡改也能交叉验证
4. 沙箱识别绕过：样本在沙箱不发作，需人工动态分析+对抗样本手法
5. 伪装工具：取证工具本身可能被针对（如杀软对内存镜像触发），隔离环境分析
```

### 12.4 像攻击者一样思考（红队思维贯穿响应）
```
每个响应阶段自问：
- 入口：如果我是攻击者，我会用什么方式进入？这个入口有没有被排查过？
- 隐蔽：我可能在哪里藏身？（WMI/计划任务/内存/合法工具）
- 转移：我会在发现之后往哪跑？（关闭通道前先预估其横向路径，先取证后封堵）
- 出口：数据会从哪条路出去？（先盯住出口再清理入口）
把"红队假设清单"纳入调查模板，防止只见已发现路径、漏掉平行路径
```

## 十三、AI 辅助应急响应

### 13.1 LLM 在 IR 中的成熟应用场景
```
已产品化（高信任，可直接用）：
- 告警/日志摘要：把海量原始日志压缩成事件摘要
- 查询生成：自然语言 → KQL/SPL/SQL/YARA/Sigma 查询语句
- 脚本解释：解释 PowerShell/宏代码/混淆脚本（逆向辅助）
- 报告撰写：把调查结果改写成管理层/合规口径

有限自治（需人工复核，2025-2026已进入生产）：
- 告警分诊与事件调查：LLM 自主收集上下文、关联多源信号、给出结论（Tier-2 智能体）
- 威胁狩猎：根据假设自动生成并执行查询
- 响应决策建议：给出处置步骤（高影响动作需策略引擎/人工批准）

原则：模型决定推理上限，工具链+上下文+验证闭环决定实际效果；
高影响处置（隔离/禁号/改防火墙）必须人工或策略引擎批准
```

### 13.2 AI 辅助日志分析实战（Prompt 模板）
```
场景A-告警分诊：
"你是资深SOC分析师。以下是SIEM告警与关联日志，请：
1. 判断真阳性/误报并给出置信度
2. 还原攻击阶段（对应MITRE ATT&CK ID）
3. 给出下一步需要查询的3个日志源与查询语句
4. 输出格式：结论/证据链/建议动作
【日志数据】..."

场景B-时间线重建：
"以下是从多个日志源提取的事件（含时间戳/主机/用户/动作）。请：
1. 重建完整攻击时间线（按时间排序）
2. 标出事件间的因果/调用关系
3. 指出缺失的证据链（需要补充采集的日志）
4. 用表格输出【时间|主机|用户|动作|来源日志|ATT&CK ID】"

场景C-查询生成：
"请为以下检测目标生成 Splunk(或KQL/Sigma) 查询：
检测目标：内网主机向非常规端口发起长连接（疑似C2）
约束：查询在 windows 索引上运行，字段名见 schema: ..."
```
**注意**：日志脱敏后再喂LLM（避免敏感数据进入模型上下文）；结论必须人工验证。

### 13.3 LLM 生成响应决策与报告
```
响应决策辅助：
- 输入：事件类型+影响面+可行动作清单+约束条件
- 输出：决策建议表（动作/风险/收益/是否需批准）、SOP引用、沟通话术草稿
- 案例：勒索事件中"是否隔离X主机"——LLM汇总业务依赖关系给出
  建议表：隔离(风险=业务中断/收益=防扩散/需业务负责人批准) / 仅断网(折中) / 监控观察
- 事件聚合：把分散告警（EDR/SIEM/云审计/邮件网关）按同一攻击链聚合为单一事件编号

报告生成模板：
- 管理层报告：1页内，影响/进展/所需决策/对外口径
- 监管报告：泄露类型/数量/时间线/已采取措施/联系人（合规校验后发出）
- 技术复盘报告：攻击链/根因/证据索引/修复项（见十六章模板）
```

### 13.4 AI 驱动威胁猎捕（Agentic 实战）
```
形态：猎捕智能体 = LLM(推理) + 工具(MCP：SIEM/EDR/抓包/沙箱) + 上下文(资产/规则/历史)
流程示例（2026 真实案例：Cisco Agentic SOC 猎捕 SharpHound 侦察）：
1. 人工/自动提出假设："内网是否存在AD侦察(SharpHound)迹象"
2. 智能体读取XDR事件上下文 → 调抓包系统检索 LDAP/389 会话
3. 解码流量、关联 Zeek 日志与资产信息 → 输出结构化评估
4. 结论：良性近失事件（误报）——人工复核后关闭，节省数小时
适用场景：告警分诊、侦察/横向移动假设猎捕、C2判定、钓鱼研判
部署要点：规则引擎先做粗筛、LLM做精判；输出必须带证据引用；异常行为回退人工
```

### 13.5 AI 辅助的局限与幻觉治理
```
局限：LLM可能编造不存在的日志/证据（幻觉）、时间线错乱、对特定环境盲区
治理措施：
1. 强制证据引用：LLM输出必须附日志源与行号，人工抽查核验
2. 数据脱敏：PII/凭据/密钥不进模型上下文（日志脱敏或本地化部署）
3. 权限最小化：LLM工具调用只读优先；隔离/删除等高影响动作锁人工
4. 人在环上(HITL)：结论供参考，判活/定级/对外汇报由分析师负责
5. 提示注入防线：喂给LLM的外部内容（网页/邮件/文档）可能含恶意指令——
   与分析系统隔离，LLM只读处理后端数据，不直接消费未信任外部内容
6. 审计追踪：所有AI生成内容标记"AI辅助"，保留原始输入输出便于回溯
```

## 十四、大模型安全事件响应

### 14.1 LLM 攻击面与事件类型（OWASP LLM Top10 2025）
| ID | 风险 | 事件示例 | 响应要点 |
|----|------|---------|---------|
| LLM01 | 提示注入（直接/间接） | 邮件摘要助手被间接注入执行退款工具；M365 Copilot 命令注入 | 阻断工具调用、审计交互日志 |
| LLM02 | 敏感信息泄露 | 模型输出泄露训练数据/系统提示/API密钥 | 输出过滤、密钥轮换 |
| LLM03 | 供应链 | 恶意模型文件(pickle)、vLLM引擎漏洞、MCP服务器投毒 | SBOM、依赖审计 |
| LLM04 | 数据与模型投毒 | RAG知识库/训练数据被污染 | 向量库取证、数据源隔离 |
| LLM05 | 不当输出处理 | 模型生成代码/SQL/HTML直接执行 | 输出零信任校验 |
| LLM06 | 过度代理 | 插件权限过大执行删除/转账/发信 | 权限收口、操作审计 |
| LLM07 | 系统提示泄露 | 诱导模型吐露系统提示词/规则 | 提示词隔离 |
| LLM08 | 向量与嵌入弱点 | RAG向量库注入/跨租户泄露 | 向量库取证 |
| LLM09 | 错误信息 | 高置信度幻觉导致错误决策/传播 | 人机复核 |
| LLM10 | 无界消耗 | Token滥用、推理资源耗尽(DoS钱包) | 速率限制、配额 |

### 14.2 提示注入事件响应流程（重点场景）
```
1. 检测信号：异常工具调用(与用户意图不符)、异常输出内容、权限外操作
2. 立即处置：禁用受影响Agent/工具权限、回滚违规操作、阻断外连
3. 取证：保存输入/输出/工具调用链/上下文窗口（日志留存是核心证据）
   审计维度：谁/何时/哪个会话/哪个工具/做了什么
4. 分类定级：直接注入 vs 间接注入（间接=内容携带恶意指令，用户可能无辜）
   间接注入重点排查：检索来源文档/网页/邮件是否被投毒
5. 根因：模型权限过大？未隔离外部内容？工具描述被污染(工具投毒)？
6. 加固：工具最小权限、输出过滤、敏感操作人工审批、外部内容沙箱隔离
7. 案例参考：M365 Copilot 命令注入(2025)、GPT-4.1 工具投毒(2025)
```

### 14.3 大模型事件取证要点
```
- 推理日志：输入/输出/中间思考/工具调用参数（开启全量审计）
- 向量库：被检索文档快照（检查RAG数据源污染）
- 模型资产：微调权重/适配器(LoRA)哈希留档（对比是否被投毒）
- 工具/插件：MCP工具描述与权限配置快照（工具投毒取证）
- 训练/数据管道：数据版本、溯源记录（数据投毒取证——日志看不见，靠上游溯源）
- 对齐 MITRE ATLAS（针对AI的ATT&CK）：AML.T0051(直接/间接提示注入)、AML.T0010(提示泄露)等
```

### 14.4 大模型事件处置与恢复
```
处置：暂停受影响服务/Agent、吊销被滥用凭据、隔离被污染数据源
恢复：模型回滚到已知安全版本、重建向量库索引、权限重审计
监控加固：异常调用率基线、敏感输出检测、工具调用审批流
责任界定：区分"模型本身缺陷"与"应用层配置缺陷"（多数事件属后者）
```

## 十五、处置、修复与恢复

### 15.1 遏制（Containment）
```
短期遏制（止损优先）：
- 断网/隔离主机：拔网线、禁用网卡、防火墙阻断（云上：安全组deny-all）
- 禁用被攻陷账号、强制改密、吊销会话令牌
- 阻断C2出口：防火墙/代理/DNS sinkhole
- 注意：先取证后断网（网络连接是易失证据），除P0紧急情况
长期遏制（防复发）：
- 隔离网段、防火墙策略收敛、暴露面收敛(RDP/SSH最小化)
- 关键系统重新部署而非修补（重装系统+加固比清理更可靠）
```

### 15.2 根除（Eradication）
```
1. 移除恶意文件/进程/服务/计划任务/注册表项/WMI事件
2. 清理持久化：全量核查RunKeys/服务/计划任务/启动项/AD GPO后门
3. 轮换所有受影响凭据：用户密码、服务账号、云AK、证书
4. 高危主机建议重建：镜像重装+最新补丁+安全基线，避免隐藏后门残留
5. 全网检测：对同类主机批量扫描（EDR查杀+狩猎规则）
6. 清除后验证：确认无回连、无新增持久化（观察期24-72h）
```

### 15.3 恢复（Recovery）
```
1. 备份验证：从离线/异地备份测试恢复（勿直接信任备份可用性）
2. 恢复顺序：核心业务优先，按影响面逐批上线（先只读验证再开放写）
3. 恢复后持续监控：EDR/SIEM高警戒观察窗口（攻击者可能留下备用通道）
4. 与业务/法务确认后再对外宣布"已恢复"
```

### 15.4 加固（基于根因）
```
- 根因修复：漏洞补丁/配置修复/0day缓解措施
- 密码与身份：MFA强制（RDP/VPN/云控制台）、弱口令清理、特权账号管理(PAM)
- 检测增强：新增检测规则(本次攻击手法)、Sysmon全量部署、日志留存90天
- 架构加固：网络分段、最小权限(RBAC/IAM)、EDR覆盖率100%
- 应急能力：更新预案、补充工具、开展针对性演练
- 加固验证：复测(红队重测/自动化扫描)确认修复生效
```

## 十六、复盘报告与持续改进

### 16.1 复盘报告结构（技术版）
```
1. 事件摘要：时间/影响/级别/状态
2. 时间线：完整攻击链（含证据引用：日志源+条目）
3. 根因分析：初始访问路径、根本原因（漏洞/配置/流程）
4. 影响评估：受影响资产/数据/业务/合规
5. 响应过程回顾：做得好的/不足的（按阶段：检测/遏制/根除/恢复）
6. 证据索引：采集物清单+存放位置+校验值
7. 改进项清单（带责任人与期限）：
   - 检测缺口：新增规则（Sigma/YARA）
   - 流程缺口：预案修订、上报链路
   - 技术缺口：补丁/配置/架构
8. 附录：IOC清单、检测规则、与攻击者相关的公开情报
```

### 16.2 关键指标统计
```
MTTD（检测时间）：从攻击发生到检测发现
MTTA（告警确认时间）：从告警到人工确认
MTTR（响应时间）：从确认到遏制/恢复
MTTC（遏制时间）：从确认到控制住扩散
Dwell Time（驻留时间）：攻击者潜伏天数（趋势对比）
恢复耗时、泄露数据量、受影响主机数、成本估算
指标用于对比改进：每次事件后环比，验证IR能力是否在提升
```

### 16.3 复盘会议（Retrospective）
```
- 时间：事件结束后3-5天内（避免在事件高潮期开）
- 成员：技术调查组+业务+法务+必要时高管
- 原则：对事不对人，聚焦"流程与检测"缺口而非追责
- 产出：改进项(带Owner与Deadline)、下季度演练计划
- 验收：下次事件/演练中验证改进项是否生效
```

## 十七、工具链

### 17.1 主机取证与采集
```bash
# Windows
KAPE                   # 自动化工件采集与解析
Velociraptor           # 大规模远程取证/狩猎
winpmem / DumpIt / Magnet RAM Capture   # 内存采集
MFTECmd / EvtxECmd / Timeline Explorer  # EZ 工具家族
Sysinternals Suite     # sigcheck/process explorer/strings等
LogParser / EvtxECmd   # Windows日志解析

# Linux
LiME                   # 内存采集内核模块
avml                   # 快速内存采集
UAC                    # Linux自动化三线采集
Autopsy/Sleuth Kit     # 磁盘取证
```

### 17.2 内存与恶意样本
```bash
Volatility 3           # 内存分析（windows.*/linux.*插件）
Ghidra / IDA / x64dbg  # 逆向与调试
YARA                  # 规则匹配
CyberChef             # 编解码/混淆还原
Any.Run / Joe Sandbox / CAPE   # 动态沙箱
oletools              # 恶意文档分析
DIE / pefile          # 加壳与PE分析
```

### 17.3 日志与SIEM
```bash
ELK Stack / Splunk / Sentinel / XSIAM   # 日志聚合与SIEM
Timesketch            # 取证时间线
Sigma CLI             # 检测规则转换(sigma convert -t splunk)
Osquery / Elastic Defend   # 主机遥测
```

### 17.4 云与容器
```bash
aws cli / az cli / gcloud      # 云审计与快照
Falco / Tetragon / tracee-ebpf # 运行时检测
Sysdig Inspect / dive / trivy  # 容器镜像与运行时取证
kubectl / crictl / docker      # K8s取证基础命令
hubble (Cilium)                # 服务网格流量
```

### 17.5 响应编排与情报
```bash
TheHive / Cortex      # 事件管理与分析编排
MISP                  # 威胁情报共享（STIX/TAXII）
BloodHound            # AD攻击路径（反向防御用法）
Velociraptor          # 狩猎与远程采集
Dradis / XMind        # 调查记录与思维导图
AI助手(LLM/SOAR)      # 告警分诊与报告生成（见十三章）
```

## 十八、实战检查清单

### 18.1 事件确认与分级
- [ ] 告警确认（真阳性/误报），记录来源与原始告警
- [ ] 按分级矩阵定级（P0-P4），通知对应响应层级
- [ ] 建立事件编号与作战群（指挥/技术/业务/法务/公关）
- [ ] 判断攻击者是否仍活跃（决定遏制紧迫度）

### 18.2 取证采集（易失性顺序）
- [ ] 内存dump（Windows/Linux/容器）
- [ ] 网络连接（netstat/ss + 防火墙/NDR流量）
- [ ] 进程列表（含命令行与父进程）
- [ ] 服务/计划任务/启动项/注册表持久化点
- [ ] 用户与登录日志（4624/4625/4776/4768/4769）
- [ ] 最近修改文件与时间线
- [ ] 云：磁盘快照+云审计日志（双平面）
- [ ] 容器：kubectl logs --previous / 镜像save / 卷快照
- [ ] 证据Hash校验与证据链记录

### 18.3 攻击链重建与溯源
- [ ] MITRE ATT&CK 战术映射（初始访问→影响）
- [ ] 时间线重建（锚点法+多源对齐）
- [ ] 恶意样本分析（静态+动态，判家族）
- [ ] IOC提取（hash/IP/域名/YARA/Sigma）
- [ ] 攻击者画像与归因（时区/语言/工具/TTP）
- [ ] 情报共享（MISP/CERT）

### 18.4 处置与恢复
- [ ] 遏制（断网/禁号/轮换凭据/阻断C2）
- [ ] 根除（清持久化+重建高危及主机+全网排查）
- [ ] 恢复（备份验证→逐业务上线→观察期监控）
- [ ] 加固（补丁/配置/MFA/检测规则/日志留存）

### 18.5 大模型/云/勒索专项
- [ ] 勒索：加密样本+勒索信保全、解密器查询、谈判决策走法务
- [ ] 云：AK立即轮换、IAM变更审计、存储桶策略核查
- [ ] K8s：cordon节点、NetworkPolicy、审计日志导出、SA令牌轮换
- [ ] LLM事件：交互日志留存、工具权限禁用、向量库/模型资产取证

### 18.6 复盘与报告
- [ ] 技术复盘报告（时间线/根因/影响/证据索引）
- [ ] 管理层报告与对外声明（法务审核）
- [ ] 指标统计（MTTD/MTTR/MTTC/Dwell Time）
- [ ] 改进项落地（Owner+Deadline）与演练计划

## 修复建议

- **检测层**：部署EDR(含内核遥测)+Sysmon高日志配置+集中日志留存≥90天；上线针对性Sigma/YARA规则；部署canary/蜜标
- **身份层**：全员MFA（RDP/VPN/云控制台强制）；特权账号PAM；定期Kerberoast/弱口令自查；云AK最小权限+短时凭据
- **攻击面层**：RDP/SSH暴露最小化；边缘设备(VPN/LVPN/网关)优先补丁；供应链/镜像SBOM管理；镜像签名与漏洞扫描
- **数据层**：敏感数据分类分级与访问审计；数据外传监控（出口流量/DLP）；3-2-1-1离线备份
- **响应能力层**：维护并演练IR预案（跨职能桌面推演）；准备IR工具箱(离线取证工具+采集脚本)；明确法务/监管上报时限；预置谈判政策
- **AI应用层**：LLM工具最小权限+输出过滤+人工审批；外部内容沙箱隔离；AI交互全量审计日志
- **云原生层**：云审计日志(CloudTrail/Data Access审计)预先开启——事后无法回溯；K8s审计策略RequestResponse级；Falco/Tetragon运行时检测
- **补丁管理**：建立漏洞响应SLA（尤其0day与外网资产）；高危漏洞48小时内缓解
- **事件驱动改进**：每次事件后闭环改进项，下季度演练验证有效性

## 注意事项

- **仅限授权测试**：本技能所有技术仅适用于获得明确书面授权的安全事件响应、应急演练、红队测试与合规审计场景；未经授权对任何系统实施响应、取证或"模拟攻击"操作均属违法行为，后果自负
- **取证合规**：涉及司法取证（隐私数据/公司机密/跨域数据）时，取证过程须符合当地法律与公司合规要求，必要时由法务全程介入
- **证据保全**：先保全后处置；遏制动作可能破坏证据（如断网前未采集网络连接），除紧急止损外遵循取证顺序
- **数据保护**：采集样本与日志可能含敏感信息，传输存储须加密，分析完毕按规定留存或销毁；上传样本到第三方沙箱前脱敏确认
- **环境隔离**：恶意样本分析必须在隔离环境进行；严禁在生产环境直接执行可疑样本
- **AI 使用边界**：LLM 输出必须人工复核，高影响处置需审批；日志脱敏后入模型，防止敏感数据泄露与提示注入
- **不要传播IOC误报**：归因与情报共享须高置信度，避免错误IOC污染行业情报
- **合规声明**：本技能内容仅用于合法的安全防护、应急响应与授权测试目的。用户须自行确保所有操作符合所在司法辖区的法律法规及所在组织的授权与合规政策。因滥用本技能产生的任何后果由使用者自行承担
- **版本情报更新**：应急响应技术演进迅速（2026年勒索"数据窃取优先"、AI攻击/防御双线并进、云原生响应常态化），建议结合最新威胁情报持续更新本技能

## DECISION TREE

```
事件接入 → 按第一章矩阵定级
├── 勒索特征（加密信封/勒索信）→ 第九章专项：隔离 → 样本取证 → 解密可行性（ID Ransomware/_no_more_ransom）
├── 主机失陷 → 易失性顺序采集（内存→网络连接→进程→磁盘）→ Volatility3 内存分析（第五章）
├── 有日志面 → 第六章多源关联 → ATT&CK 映射还原入侵链（第三章）
├── 云/容器事件 → 第十章专项（控制面审计日志/事件历史/取证快照）
├── 涉及 LLM 应用 → 第十四章大模型安全事件专项（提示注入链/数据外带面）
├── 需要主动猎捕 → 第十一章假设驱动方法论
└── 处置完成 → 第十五章恢复 → 第十六章复盘报告 → 产出对齐 pentest-output-standards
```

## TARGET TOOL ADAPTATION

Use visible `read_file`/`glob`/`grep` for 日志与代码取证、`execute-python-script` for 日志解析/时间线聚合与内存镜像结构化分析。不假设 SIEM/EDR 控制台/沙箱平台可达；取证操作只读优先，采集前记录基线。

## RELATED ROUTING

- [pentest-output-standards](../pentest-output-standards/SKILL.md) — 事件结论与报告产出遵循统一分级与格式门槛
