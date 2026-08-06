# 运维 Runbooks

[English](../en-US/runbooks.md)

Runbook 是“遇到一个真实任务时照着做”的步骤清单。本文覆盖 CyberStrikeAI 最常见的运维和安全测试操作。

## Runbook 1：生产实例从 0 到可用

适用：内网团队或生产红队平台首次部署。

如果只是本地或临时验证，优先用仓库自带脚本启动：

```bash
chmod +x run.sh && ./run.sh
```

确认可用后，再决定是否升级为 systemd + 反向代理的长期部署。

### 前置确认

- 运行主机已纳入资产管理。
- 访问路径确定：内网、VPN、堡垒机或反向代理。
- 有模型 API Key 和允许使用的模型。
- 已决定是否启用 C2、WebShell、外部 MCP。

### 步骤

1. 准备目录：

```bash
mkdir -p /opt/CyberStrikeAI
```

2. 放置二进制和资源目录：

```text
cyberstrike-ai
web/
tools/
roles/
skills/
agents/
docs/
config.yaml
```

3. 修改关键配置：

```yaml
auth:
  session_duration_hours: 12
server:
  host: 127.0.0.1
  port: 8080
  tls_enabled: false
audit:
  enabled: true
c2:
  enabled: false
```

4. 配置反向代理 HTTPS，并限制来源 IP。
5. 使用 systemd 托管进程。
6. 登录 Web，测试模型。
7. 检查工具列表和审计日志。
8. 建立备份策略。

### 验收

- `/api/auth/validate` 登录后返回成功。
- 模型测试成功。
- `tools/` 能正常加载。
- 审计页面能看到登录事件。
- C2 在不需要时访问返回禁用状态。

### 回滚

恢复：

- 上一版二进制。
- 上一版 `config.yaml`。
- 升级前 `data/`。

## Runbook 2：接入外部 MCP

适用：接入本地工具服务、Burp 辅助服务、资产查询服务等。

### 前置确认

- MCP 服务可信。
- 明确它是否能读文件、写文件、执行命令或访问第三方网络。
- 确定接入方式：stdio、HTTP、SSE。

### 步骤

1. 在外部 MCP 页面新增服务。
2. 如果是 stdio，填写命令、参数、工作目录和环境变量。
3. 如果是 HTTP/SSE，填写 URL 和认证信息。
4. 启动服务。
5. 查看 `/api/external-mcp/stats`。
6. 检查工具列表是否出现。
7. 用低风险参数执行一次工具。
8. 把高风险工具排除在全局免审批白名单之外。

### 验收

- MCP 状态为 running。
- 工具 schema 可见。
- Agent 能通过 `tool_search` 找到工具。
- 工具执行记录出现在监控页。
- 配置变更出现在审计页。

### 回滚

- 停止 MCP。
- 删除外部 MCP 配置。
- 从角色/白名单中移除相关工具。
- 检查 Agent 当前任务是否仍持有旧上下文。

## Runbook 3：启用知识库并调优召回

适用：把内部安全知识、漏洞手册或测试方法接入 Agent。

### 步骤

1. 修改配置：

```yaml
knowledge:
  enabled: true
  base_path: knowledge_base
  embedding:
    model: text-embedding-v4
  retrieval:
    top_k: 5
    similarity_threshold: 0.4
```

2. 把 Markdown 放入 `knowledge_base/`。
3. 在 Web 知识库页面执行扫描。
4. 重建索引。
5. 准备 5 到 10 个固定测试问题。
6. 搜索并记录命中情况。
7. 根据结果调 `threshold`、`top_k`、chunk 参数和文档标题。

### 验收

- `index-status` 显示索引完成。
- 常见问题能命中正确文档。
- Agent 在不确定时会先查知识库。
- 检索日志能显示查询和命中文档。

### 常见回滚

- 关闭 `knowledge.enabled`。
- 恢复旧的 `data/knowledge.db`。
- 降低 `batch_size` 后重新索引。

## Runbook 4：一次授权 Web 测试标准流程

适用：对授权目标做 Web 安全测试。

### 步骤

1. 创建项目，记录授权范围。
2. 新建对话，绑定项目。
3. 选择最小角色，例如“信息收集”或“Web 应用扫描”。
4. 明确目标、时间窗口、禁止动作。
5. 先执行只读信息收集。
6. 发现线索后写入项目事实。
7. 对高风险验证请求使用 HITL。
8. 确认漏洞后写入漏洞管理。
9. 生成攻击链或报告材料。
10. 清理上传文件、临时 workspace 和无用执行记录。

### 验收

- 每个漏洞都有证据、影响、复现和修复建议。
- 高风险操作有 HITL 记录。
- 项目事实能复现测试路径。
- 报告不包含无关敏感数据。

## Runbook 5：C2 演练结束清理

适用：授权演练中启用了 C2。

### 步骤

1. 停止所有 listener。
2. 列出 sessions，确认没有仍在线的授权会话。
3. 导出必要 task 结果。
4. 删除 payload 或移动到受控归档。
5. 删除无用 task、event、file。
6. 审计 C2 操作记录。
7. 将关键结果写入项目事实或报告。
8. 将 `c2.enabled` 改回 false，除非平台持续需要。

### 验收

- 无运行中 listener。
- 无待处理 task。
- payload 不再公开可下载。
- 审计与报告能解释整个生命周期。

## Runbook 6：Agent 不调用工具

排查顺序：

1. 当前角色是否绑定了该工具。
2. 工具是否在 `/api/config/tools` 中出现。
3. `tool_search` 是否隐藏了该工具。
4. 工具描述是否过短或命名不清。
5. HITL 是否挂起。
6. Agent 是否处于总结/结束阶段。
7. 多代理子 Agent 是否有自己的工具限制。

修复方式：

- 把工具加入角色。
- 优化 `short_description`。
- 加入 `tool_search_always_visible_tools`。
- 在提示词中明确什么时候使用。
- 检查过程详情和监控记录。
