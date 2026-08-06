# WebShell 管理

WebShell 管理用于保存授权目标的 WebShell 连接，并通过 Web 页面或 Agent 工具执行命令、文件操作和上下文分析。

## 基本流程

1. 在 WebShell 页面新增连接。
2. 填写名称、URL、密码或请求参数。
3. 测试连接。
4. 执行命令或文件操作。
5. 在对话中选择 WebShell 连接，让 AI 基于该连接辅助排查。

连接数据保存在 SQLite 中。

## 接口

主要 API：

- `GET /api/webshell/connections`
- `POST /api/webshell/connections`
- `PUT /api/webshell/connections/:id`
- `DELETE /api/webshell/connections/:id`
- `GET /api/webshell/connections/:id/state`
- `PUT /api/webshell/connections/:id/state`
- `POST /api/webshell/exec`
- `POST /api/webshell/file`
- `GET /api/webshell/connections/:id/ai-history`
- `GET /api/webshell/connections/:id/ai-conversations`

## MCP 工具

系统会注册 WebShell MCP 工具，例如：

- `webshell_exec`：在连接上执行命令。
- `webshell_file_list`：列目录。
- `webshell_file_read`：读取文件。
- `webshell_file_write`：写文件。
- WebShell 连接管理工具。

Agent 使用这些工具时需要 `connection_id`。前端通常会把当前选中的连接注入上下文。

## 命令执行

执行命令前确认：

- 当前连接属于授权目标。
- 命令不会破坏业务。
- 输出中可能包含敏感信息。
- 长命令和交互式命令不适合 WebShell 通道。

建议先执行只读命令确认环境：

```bash
whoami
pwd
uname -a
id
```

Windows 目标可用：

```cmd
whoami
cd
ver
ipconfig
```

## 文件操作

文件操作包括列目录、读取、写入。建议：

- 写入前先备份原文件。
- 不在生产目标写入未经确认的脚本或二进制。
- 大文件优先通过专用下载/上传通道处理。
- 注意目标编码和换行符。

## AI 辅助

AI 可以帮助：

- 识别操作系统和当前权限。
- 规划只读枚举步骤。
- 分析命令输出。
- 汇总风险和修复建议。

不建议让 AI 自动执行：

- 删除文件。
- 修改业务配置。
- 持久化。
- 凭证抓取。
- 大范围扫描内网。

这些操作应由人工确认，并配合 HITL。

## 安全建议

- 仅保存授权目标连接。
- 给连接命名时包含项目、环境、目标。
- 演练结束后删除连接。
- 不把 WebShell 写入工具加入全局免审批白名单。
- 重要输出及时纳入项目事实或报告，随后清理敏感原始数据。

## 排错

连接失败：

- URL 不可达。
- 参数名或密码错误。
- 目标 WAF 拦截。
- 代理或 TLS 配置异常。

命令乱码：

- 检查目标系统编码。
- 尝试切换命令输出编码或使用 base64 包装。

AI 找不到连接：

- 确认前端已选中 WebShell 连接。
- 确认连接未被删除。
- 检查 `connection_id` 是否正确。

## 操作分层

WebShell 操作建议分成四层，不同层级使用不同审批策略：

| 层级 | 操作 | 风险 | 建议 |
| --- | --- | --- | --- |
| 识别 | `whoami`、`pwd`、系统版本 | 低 | 可自动 |
| 枚举 | 目录、进程、环境变量 | 中 | 限定路径和命令 |
| 读取 | 配置、日志、源码 | 中高 | 人工确认敏感性 |
| 写入/执行 | 写文件、运行脚本、删除 | 高 | 人工审批，说明回滚 |

不要把“WebShell 已经拿到了”理解成“后续操作都低风险”。WebShell 通常位于业务系统内部，误操作成本很高。

## 连接命名规范

建议命名：

```text
<项目>-<环境>-<目标>-<权限>-<日期>
```

示例：

```text
acme-staging-web01-www-20260707
```

糟糕命名：

```text
test
shell1
客户机器
```

AI 和人类审批都依赖上下文，连接名称含糊会直接放大误操作概率。

## AI 使用约束模板

给 WebShell 相关角色加一段约束：

```text
使用 WebShell 前先确认 connection_id、目标名称、当前目录和权限。默认只执行只读命令。任何写入、删除、上传、权限修改、持久化、凭证读取、内网探测都必须先给出目的、影响和回滚方式，并等待审批。
```

## 源码锚点

- Handler：`internal/handler/webshell.go`
- 连接上下文：`internal/handler/webshell_context.go`
- 探测逻辑：`internal/handler/webshell_probe.go`
- OS/编码处理测试：`internal/handler/webshell_os_test.go`、`internal/handler/webshell_encoding_test.go`
- MCP 工具注册：`internal/app/app.go` 中 `registerWebshellTools`
