# 角色配置文件说明

本目录包含所有角色配置文件，每个角色定义了AI的行为模式与可用工具。

## 创建新角色

创建新角色时，请在 `roles/` 目录下创建 YAML 文件，格式如下：

**方式1：显式指定工具列表（推荐）**
```yaml
name: 角色名称
description: 角色描述
user_prompt: 用户提示词（追加到用户消息前，用于引导AI行为）
icon: "图标（可选）"
tools:
    # 添加你需要的工具...
    # ⚠️ 重要：建议包含以下核心内置 MCP 工具（漏洞与知识库）
    - record_vulnerability
    - list_knowledge_risk_types
    - search_knowledge_base
enabled: true
```

**方式2：不设置tools字段（仅默认角色使用）**
```yaml
name: 角色名称
description: 角色描述
user_prompt: 用户提示词（追加到用户消息前，用于引导AI行为）
icon: "图标（可选）"
# 不设置tools字段，将默认使用所有MCP管理中已开启的工具；专业角色禁止这样配置
enabled: true
```

## ⚠️ 重要提醒：核心内置 MCP 工具

漏洞挖掘角色应包含完整证据生命周期工具：

1. **`skill`** - 按需加载方法与报告规范
2. **`record_vulnerability`** - 保存满足证据门槛的正式漏洞
4. **`list/get/update_vulnerability`** - 查重、读取与补证升级
5. **`list_knowledge_risk_types` / `search_knowledge_base`** - 按需使用知识库

按需还可加入 WebShell、批量任务等其它内置或外部工具（以 MCP 管理中已启用的为准）。

**Skills（技能包）**：在 Eino 的 single/deep/plan_execute/supervisor 模式中由内置 **`skill`** 工具按需加载 `skills_dir` 下的包。专业角色需在 `tools` 中显式加入 `skill`，否则角色白名单会隐藏它。

**注意**：如果不设置 `tools` 字段，系统会默认使用所有 MCP 管理中已开启的工具。项目只对 `默认` 角色保留该语义；所有专业角色必须显式设置白名单。

## 角色配置字段说明

- **name**: 角色名称（必填）
- **description**: 角色描述（必填）
- **user_prompt**: 用户提示词，会追加到用户消息前，用于引导AI采用特定的测试方法和关注点（可选）
- **icon**: 角色图标，支持Unicode emoji（可选）
- **tools**: 工具列表，指定该角色可用的工具（可选）
  - **如果不设置 `tools` 字段**：默认会选中**全部MCP管理中已开启的工具**，仅允许默认角色采用
  - **如果设置了 `tools` 字段**：只使用列表中指定的工具（建议至少包含上述核心内置工具）
- **enabled**: 是否启用该角色（必填，true/false）

## 示例

参考本目录下的其他角色文件，如 `渗透测试.yaml`、`Web应用扫描.yaml` 等。
