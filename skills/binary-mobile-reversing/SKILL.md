---
name: binary-mobile-reversing
description: >-
  APK/EXE/二进制:UniApp/DCloud/Flutter逆向,证书固定绕过,导出组件,内存破坏exploit链,IoT固件。Use when reversing APK/EXE, UniApp/Flutter, native .so, or memory-corruption exploits.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## APK / EXE / 二进制逆向

按任务渐进加载详细参考，避免一次灌入全部移动安全知识：

- Android 组件、存储、网络、WebView、逆向与动态分析：`references/android.md`
- iOS Keychain、ATS、URL Scheme、IPC、越狱检测与动态分析：`references/ios.md`
- 工具/命令快速选择与验证清单：`references/quick-reference.md`

```
=== APK/EXE/二进制 ===
APK: apktool d / jadx | Manifest看exported组件/deeplink/debuggable | rg硬编码密钥+API地址 | .so strings/Ghidra | frida/objection动态
🚨UniApp/DCloud APK逆向(H5混合应用,业务全在JS不在DEX):
  识别: __UNI__XXXXXXX + assets/apps/ + uni-jsframework.js (NOT Flutter,无libapp.so) | manifest.json含"uni-app"字段
  核心文件: assets/apps/__UNI__XXX/www/app-service.js (800KB+混淆JS=全部业务逻辑) | jadx只能看壳(native插件注册),真逻辑在JS
  JS解混淆(RC4+字符串数组旋转): 提取a0G()大数组(10000+元素)+a0m(idx,key)解码函数(base64→RC4)+rotation IIFE→拼可执行JS→node批量解码→JSON字典(offset→明文)
    🔴陷阱: rotation IIFE可能以逗号结尾(不是分号!属于更大表达式)→node报"Unexpected token"→按实际结束符提取
  加密配置zlsioh.dat/dcloud3.dat: header(96B偏移表:off40=block1解压/44=压缩/60=block2偏移/64=block2大小/80=block3偏移)+block1(zlib→DEX)+block2(加密,含API域名列表←关键,需.so解密)+block3(zlib→AndroidX类映射)
    zlib魔数78DA=未加密直接解压 | 无魔数=加密块(密钥在.so .rodata/汇编立即数)
  .so字符串解混淆: 偶数位字符提取→反转(e.g."mAojcl.dubdFiHaebP.nwywfwb"→"www.baidu.com") | strings -n8 lib*.so找含点号长串
  ⚠️陷阱: .so中x分隔IP串(如"x111.230.69.120x118.126.105.164")=DCloud HTTPDNS节点(非API后端!140.205.11.x=阿里云DNS,111.230/118.126/106.52/42.193=腾讯云) | resources.arsc报错是故意反编译保护(不影响jadx) | assets伪PNG(1-8px)=完整性校验非数据 | fcapp.run仅APK下载代理
  关键API变量: $apiHost/$opHost(运行时动态设置,不硬编码)/urlList/checkAvailableDomainList(HEAD domain/favicon.ico测连通,200-399=可用)
  高价值端点: /app_init /user/gustRegister(游客无验证注册) /user/getOssSts(OSS临时凭据!) /uploadFile2
  配置: manifest.json(appId/版本/nativePlugins→wrs-httpserver=内嵌HTTP服务!) | supplierconfig.json(vivo/xiaomi/huawei/oppo appid) | dcloud_uniplugins.json(插件清单)
  ChengZi SDK(橙子建站): init3接口返回XOR单字节(key=0x96,见chengzi_decrypt.py)加密JSON→解密得APK真实下载链接(fu字段)+渠道码
  域名兜底: 静态拿不到$apiHost时→Android模拟器(Waydroid/AVD)+tcpdump/mitmproxy抓运行时DNS
  参见: references/uniapp-apk-reverse-engineering.md, references/uniapp-apk-reversing.md, scripts/js_rc4_deobfuscate.js, scripts/chengzi_decrypt.py
🚨Flutter APK快速逆向(无需脱壳): 加固(MogoSec/梆梆/360)保护DEX层,但Flutter的lib/arm64-v8a/libapp.so(Dart AOT)通常不加密
  strings -n8 libapp.so|grep 'https\?://' → 全部硬编码URL/API域名/S3地址/CDN
  strings -n8 libapp.so|grep -E '^/' → API路径矩阵(/Member/Login, /Web/VideoList, /BBS/GetSTSToken等)
  strings -n8 libapp.so|grep -iE 'key|secret|token|aws|bucket' → 凭据/密钥泄露
  assets/config_*.xml + assets/data_*.dat → 加密配置(可能含域名/API地址) | .DS_Store → macOS开发者信息泄露 | assets/xinstall* → 渠道追踪SDK
🚨Native .so字符串反混淆(通用模式): 混淆字符串在.rodata段
  常见模式: 偶数位字符提取+反转(如"mAojcl.dubdFiHaebP..."→取偶数位→反转=明文域名) | XOR常量 | RC4+base64
  识别: strings -n8 lib*.so找16字节等长串(AES密钥/IV)/含点号串(域名)/x分隔IP串(HTTPDNS) | nm --dynamic找混淆导出符号(16字符随机大小写)
  验证: 已知字符串("classes.dex"/"io.dcloud.application")对照混淆版→逆推算法→批量解码
🚨移动通用(非UniApp/Flutter的常规APP):
  证书固定绕过(抓HTTPS): objection android sslpinning disable | frida universal-unpinning | 改smali删pinning重打包
  导出组件越权: Manifest exported=true的Activity/Service/Provider/Receiver → drozer/adb am start跨应用调 | ContentProvider SQLi/路径穿越
  深链接(deeplink)劫持: scheme://未校验→WebView加载任意URL(XSS/文件读) | 参数进intent→组件劫持
  不安全存储: /data/data/pkg/(shared_prefs明文token/db未加密/logcat泄露) | sdcard世界可读
  WebView: addJavascriptInterface(<4.2 RCE)/file://读本地/setAllowFileAccess | 静态:MobSF一把梭 | iOS:砸壳(frida-ios-dump)+Ghidra看Mach-O+objection动态
EXE/PE: file/strings | Ghidra/IDA反编译找硬编码/加密/网络逻辑 | x64dbg动调 | 漏洞:溢出/格式化串/UAF/DLL劫持
🚨内存破坏exploit链(崩溃→RCE): checksec看防护 → 确定原语(栈溢出/UAF/格式化串=任意读写)
  → 信息泄露绕ASLR → ROP链(ROPgadget/pwntools ret2libc) → 堆利用(tcache poison/__free_hook劫持)
  → 任意写改GOT/hook/vtable/exit_funcs → 控制流劫持 | 固件IoT:binwalk -Me提取+qemu-user调试(防护弱常直接栈溢出)
```
