---
name: capability-primitive-search
description: >-
  能力原语+状态空间搜索:read/write/exec/ssrf等原语凑RCE等式A-F,低危映射,正反向搜索,跨域兑现。Use when no single RCE, chaining low-severity vulns, or deriving novel attack chains.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 能力原语 + 状态空间搜索

```
心法: RCE不是一个"漏洞",是一组"能力"凑齐后的涌现。没单点大洞时,几个info级/低危照样拼出代码执行。
  固有思维(要打破): "扫不到RCE/反序列化/上传→这站打不动了"。你的活不是"找RCE漏洞",是"凑齐执行所需的原语"。
  把每个Fact抽象成能力原语(不记"发现X漏洞",记"现在拥有什么能力+限制"):
    read(path) write(path) exec(cmd) ssrf(url) sqli redirect(url) eval_expr idor(id) cred(svc,priv) coerce_auth write_acl

RCE只需满足任意一条等式,拆成可获取的原语去凑:
  A. 能写文件 + 文件被当代码执行                = RCE
  B. 能控配置/env + 配置指向你的代码            = RCE
  C. 能进管理面 + 面板自带执行功能              = RCE(不是漏洞,是功能!)
  D. 有凭据 + 服务有合法执行入口                = RCE(滥用合法功能)
  E. 能任意读 + 读到凭据 + 凭据可登录执行点      = RCE
  F. 能控数据 + 数据流入危险sink(eval/模板/SQL) = RCE

低危→原语映射(把"鸡肋漏洞"翻译成拼图碎片):
  info泄露(.git/备份/堆栈)→源码/路径/密钥→喂B/E/F | LFI/任意读→读配置密钥→E,或日志投毒→A
  SSRF(哪怕只GET)→打内网Redis/Consul/K8s/云元数据→C; 云元数据拿临时凭据→D
  弱/默认/复用凭据→进带任务/插件/webhook/CI功能的后台→C | CORS/CSRF/XSS→借管理员浏览器调执行类功能→C
  可控上传(哪怕限扩展名)→配路径穿越/解析差异/.htaccess→A | 配置写入→改模板/日志/连接串→B
  SQLi(哪怕只读)→读hash/密钥→E,或OUTFILE→A | 模板可控→SSTI→F | 原型污染→污染下游属性→F

状态空间搜索(无现成链时自己搜): 状态=当前能力集, 动作=用能力解锁新能力, 目标=Goal。
  正向: 对每个能力问"能解锁什么?"; 对每对能力问"组合出什么?"
    (read+write=改配置; ssrf+内网redis=RCE; sqli+FILE=webshell; coerce_auth+relay=域SYSTEM; idor+massassign=改他人admin)
  反向(卡住时主用): 锁定Goal=执行命令→选最接近现状的等式当模板→缺哪个原语设为子目标→
    手上哪个低危/功能/info泄露能凑出它?→凑不出递归拆/换等式 → 正反向在中间相遇=完整链浮现 → 逐段验证

突破口(看到别走开):
  ·"功能即原语": 后台的任务计划/插件/模板编辑/SQL控制台/文件管理器/导入导出/webhook —— 合法功能但登进去就是现成执行/读写原语。渗透者眼里没"功能/漏洞"之分,只有"能力"。
  ·跨协议跳跃: SSRF的gopher/dict/file把"只能发HTTP"变成"打Redis/发SMTP/读文件"。
  ·凭据复用是万能胶: 任意一处拿到的密码/key默认全网复用全部喷一遍。横向常比纵向快。
  ·解析差异: 上传校验/路由/反代三方理解不一致→缝隙里有绕过(双扩展名/编码/Host混淆)。
  ·时间维度: TOCTOU/token可预测/缓存投毒,把"偶尔"变"稳定",把不可利用变可利用。
  ·跨域兑现: 每拿一个能力问"它在别的域值多少钱"——能力是通用货币。Web SSRF→进云元数据接管账户; APK硬编码→直连内部API绕前端鉴权; 供应链→拿CI密钥进生产。
  ·创造模式(已知组合用尽时): 重审能力边界(只能读/var/log? /proc/self/environ呢) | 找等价RCE的sink(写crontab/.bashrc/CI配置/LD_PRELOAD/authorized_keys/systemd unit都=RCE) | 信息(报错/时序/响应长度)当侧信道 | 假设取反:列"我以为不可能"逐条问"凭什么不可能"
> 推导出的链是假设(可 tentative 记 note/chain),实际执行+证据后才写 confirmed Fact / record_vulnerability。整条链每步都验证过才成立。
```

