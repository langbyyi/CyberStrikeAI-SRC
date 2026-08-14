# Skills 目录（Agent Skills / Eino）

- 每个技能为**子目录**，根上必须有 **`SKILL.md`**（YAML front matter：`name`、`description` + Markdown 正文），见 [agentskills.io](https://agentskills.io/specification.md)。
- **目录名须与 `name` 一致**。
- **运行时加载**：Eino `single` / `deep` / `plan_execute` / `supervisor` 共用 ADK **`skill` 中间件**渐进披露（系统提示列出 name/description，模型再调用 **`skill`** 拉取正文）。可选开启 **`multi_agent.eino_skills.filesystem_tools`** 访问包内 references/scripts/assets。
- **Web 管理**：HTTP `/api/skills/*` 仍用于列表、编辑、上传包内文件（实现为 `internal/skillpackage`，非 MCP）。

## 权威层级

- `web-attack-methods`、`attack-surface-recon` 等宽 Skill 负责总览、分流和跨类型攻击链。
- SQLi、SSRF、IDOR、业务逻辑等细分 Skill 是对应漏洞类型的方法、差分、证据和停止条件的权威来源；自动 Skill Router 优先加载细分包。
- `pentest-verification` 负责证据质量，`pentest-output-standards` 负责弱信号(`upsert_project_fact`)/正式漏洞(`record_vulnerability`)分级、去重 update 与用户可见报告格式；其他 Skill 不维护另一套报告门槛。
- `authorized-attack-scope` 负责行为基调：授权资产与 SRC 收录范围内技法不设限、被拦换路；范围外（未授权内网、社工、破坏性手段）只记录为 Fact 留待授权扩展，不主动攻击。
- `browser-assisted-hunting` 负责浏览器交互式验证打法（双会话越权、DOM XSS 渲染取证、验证码登录、前端隐藏功能）；依赖外部 MCP（如 Playwright）时遵循下方降级原则，证据仍走可复现门。
- Skill 只提供方法，工具是否可见以及能否执行仍由角色白名单、RBAC/HITL 和运行时 vulnerability policy 决定。

## 外部工具降级

Burp、Collaborator 或其他外部 MCP 只在当前会话确实可见时使用。不可用时保留单变量差分、基线对照和最小证据方法，改用当前角色已加载的 HTTP/浏览器工具，不自动安装、不绕过权限。
