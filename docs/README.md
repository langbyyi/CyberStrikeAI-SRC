# CyberStrikeAI 文档

文档按使用路径组织。建议从部署开始，再按任务进入对应主题。

### 按目标开始

- **本分支特性**：[SRC 二开特性](SRC二开.md)
- **快速体验**：[部署指南](zh-CN/deployment.md) → [配置参考](zh-CN/configuration.md) → [排错指南](zh-CN/troubleshooting.md)
- **生产部署**：[配置画像](zh-CN/configuration-profiles.md) → [安全加固](zh-CN/security-hardening.md) → [运维 Runbooks](zh-CN/runbooks.md) → [审计与监控](zh-CN/audit-and-monitoring.md)
- **接入与自动化**：[API 参考](zh-CN/api-reference.md) → [API Recipes](zh-CN/api-recipes.md) → [MCP 联邦](zh-CN/mcp-federation.md)
- **参与开发**：[开发者指南](zh-CN/developer-guide.md) → [测试指南](zh-CN/testing.md) → [贡献规范](zh-CN/contributing-guide.md)

### 核心概念与编排

- [架构说明](zh-CN/architecture.md)
- [安全模型](zh-CN/security-model.md)
- [Agent 与角色](zh-CN/agent-and-role-guide.md)
- [Skills 指南](zh-CN/skills-guide.md)
- [Eino 多代理](zh-CN/MULTI_AGENT_EINO.md)
- [工作流](zh-CN/workflow-graph.md)
- [工具执行治理](zh-CN/tool-execution-governance.md)
- [人机协同最佳实践](zh-CN/hitl-best-practices.md)

### 功能指南

- [知识库](zh-CN/knowledge-base.md)
- [RBAC 权限管理](zh-CN/rbac.md)
- [机器人接入](zh-CN/robot.md)
- [视觉分析](zh-CN/VISION.md)
- [WebShell 管理](zh-CN/webshell.md)
- [C2 使用说明](zh-CN/c2.md)

### 开发与发布

- [开发者指南](zh-CN/developer-guide.md)
- [插件开发](zh-CN/plugin-development.md)
- [前端国际化](zh-CN/frontend-i18n.md)
- [测试指南](zh-CN/testing.md)
- [贡献规范](zh-CN/contributing-guide.md)
- [发布流程](zh-CN/release-process.md)

## 文档约定

- 命令默认在仓库根目录执行，另有说明除外。
- 示例使用占位符；禁止提交真实凭据或未授权目标系统。
- 运行行为和配置默认值以 `config.example.yaml` 和源码为准。文档与代码不一致时，按文档漂移处理并修正。
