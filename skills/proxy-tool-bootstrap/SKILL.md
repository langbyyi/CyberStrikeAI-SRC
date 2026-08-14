---
name: proxy-tool-bootstrap
description: >-
  自找代理+工具自举:SOCKS5/HTTP/Tor换路序列,工具Python自举,字典自生成,OOB基础设施。Use when blocked by 403/429/WAF/timeout, missing tools, or needing OOB confirmation.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 自找代理 + 工具自举（被拦换路，没工具自己写）

```
🔴代理(收到拒绝/限流/超时 → 第一反应不是重试,是换路。不换路=放弃=违反黑板触发器2（见 `pentest-blackboard`）):
  执行序列(按顺序,前一步失败才下一步):
  ①探目标地区: terminal: curl -s "http://ip-api.com/json/{目标IP}" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['country'],d['countryCode'])"
  ②获取该地区SOCKS5代理: terminal: curl -s "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country={countryCode}&timeout=5000" | head -20
  ③验证代理可达目标: terminal: curl --socks5 {PROXY_IP:PORT} --connect-timeout 8 -s -o /dev/null -w "%{http_code}" {目标URL}
  ④200=可用,立即用此代理重新执行被拦请求; 非200=换下一个代理重复③
  ⑤全部SOCKS5失败→获取HTTP代理: terminal: curl -s "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country={countryCode}&timeout=5000" | head -20
  ⑥HTTP代理验证: terminal: curl --proxy http://{PROXY_IP:PORT} --connect-timeout 8 -s -o /dev/null -w "%{http_code}" {目标URL}
  ⑦全代理失败→Tor: terminal: curl --socks5 127.0.0.1:9050 --connect-timeout 15 {目标URL}
  工具统一加代理参数: curl --socks5 / sqlmap --proxy=socks5://{P} / nmap --proxies socks5://{P} / nuclei -proxy socks5://{P} / ffuf -x socks5://{P}
  轮换策略: 429/403→立即换下一个代理,每20请求主动换(避免新IP也被ban) | Cloudflare→代理池+请求间隔2-5s随机
  🚨HTTP代理vs SOCKS5: HTTP代理会插入自己的错误页(502/无法显示此页)导致无法区分目标实际响应→需探测时必须用SOCKS5(--socks5)
    ProxyScrape SOCKS5: https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=CN,JP&timeout=5000
    验证SOCKS5: curl --socks5 IP:PORT --connect-timeout 5 目标 | HTTP代理只适合已确认可达的目标做匿名/轮换
工具自举(which X || 用Python实现):
  无nmap→socket扫端口 | 无ffuf→requests爆目录 | 无sqlmap→手工payload检测 | 无hydra→requests爆破 | 无nuclei→requests打已知payload
  复杂工具用Python模拟:爬虫requests+bs4 / 编码base64/hex / 哈希hashlib / 加密pycryptodome / 嗅探scapy
字典自生成: 基于目标域名/公司名造变体 | 从网页提关键词 | 用户名+年份+特殊字符组合 | 服务默认凭据
OOB基础设施(盲漏洞都靠它): interactsh-client拿oast.fun域名 | 或VPS python3 -m http.server/nc看回连 | ngrok/cloudflared隧道
  → 看到OOB回连(DNS查询/HTTP请求)才算确认 → 写Fact
```

