---
name: redteam-opsec
description: >-
  OPSEC隐蔽作战纪律:IP黑名单绕过,速率时序,流量混淆,最小足迹,反取证,渐进暴露。Use when maintaining stealth, bypassing IP bans, or planning covert red-team ops.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## OPSEC / 隐蔽作战纪律（免杀 / 稳定 / 隐蔽）

```
核心: 打得进 ≠ 打得稳。被发现即行动归零。每个动作执行前先问"这步在防守方眼里长什么样"。
🚨IP黑名单绕过(被ban后第一时间试): X-Forwarded-For: 随机IP (CDN信任此头时直接绕过应用层黑名单,返回code:10010/黑名单时逐个试XFF/X-Real-IP/CF-Connecting-IP/True-Client-IP)
  验证: 正常请求返回"黑名单"+你的IP → 加XFF头后返回正常200 → 后续所有请求都带XFF
  进阶: 每N个请求换一个XFF值(避免新IP也被ban) | 有些CDN只信任第一个XFF值,有些信最后一个
速率与时序: 扫描限速(nuclei -rl / nmap -T2 --max-rate / ffuf -p延迟)避开WAF封禁+IDS阈值告警 | 高危动作低频+随机jitter | 避业务高峰也避深夜(贴合目标作息最不显眼)
流量混淆: 贴正常业务(常见UA/Referer/合法路径) | 重武器前先探防御(进程列表/已知EDR/SIEM agent特征) → 有则静默手法优先,无监控才上自动化批量
最小足迹: 内存执行优先不落盘(DDexec/memfd/反射加载) | webshell强口令+非常见路径+功能伪装 | 隧道走443/DNS贴常见出站 | 工具用完即删(/dev/shm内存盘,不留残骸)
反取证: 命令历史 unset HISTFILE / set +o history | 日志选择性删自己条目(truncate全清反而触发告警) | 时间戳 touch -r参照邻近文件保persist mtime | 别动监控/审计服务(停了就是告警)
渐进暴露: 被动侦察(证书透明/被动DNS/搜索引擎/资产引擎)→确认无强监控→才主动扫描→最后才上利用落地。能公开情报拿到的绝不主动碰目标。每升一级问"值不值得暴露"。
> 隐蔽不是洁癖,是红队的生存能力。一次莽撞的全端口全速扫描就可能让整个行动归零。
```

