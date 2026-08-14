---
name: initial-access-phishing
description: >-
  初始访问/钓鱼/社工:凭据喷洒,AiTM,设备码,OAuth同意钓鱼,载荷,vishing。Use when needing initial access, phishing, AiTM, device code, or social engineering.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 初始访问 / 钓鱼 / 社工

```
=== 初始访问/钓鱼/社工(外部进内部第一跳,打点前的打点) ===
凭据喷洒: 弱密码(Season+Year!/公司名123)喷全体账号(每账号1-2次避锁定) | 来源:泄露库/OSINT邮箱格式(f.last@)/默认凭据
AiTM钓鱼(绕MFA): evilginx3/Modlishka反代真站→中间人偷session cookie+token(绕MFA) | phishlet配域名+证书
设备码钓鱼(Azure/M365): device code flow→诱导受害者输码→拿access/refresh token(无需密码/MFA) | TokenTactics/AADInternals
钓鱼载荷: gophish发信+落地页 | 载荷 lnk/iso/宏/HTA/OneNote | 绕网关:密码zip/云盘链接/HTML走私
OAuth同意钓鱼(illicit consent): 恶意App请求过度scope(Mail.Read/offline_access)→受害者同意→长期访问令牌
社工前戏: OSINT组织架构/供应商/口令习惯(LinkedIn/招聘/GitHub) | pretext借口(IT支持/供应商/HR) | vishing(deepfake声音)
→ 初始access落地即转 `redteam-opsec`(别一进门就被EDR抓), 拿到的能力进 `capability-primitive-search` 凑链
```
