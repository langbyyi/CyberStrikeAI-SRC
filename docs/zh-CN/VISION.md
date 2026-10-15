# 图片输入与视觉分析

图片进入模型有三条路径，**能读图的主模型一律原生直发**；纯文本主模型走旁路识图兜底。
开关只有一个：AI 通道的 `supports_vision`（系统设置 → 基本设置 → AI 通道 → 「主模型支持图片输入（多模态）」）。

## 一、原生直发（`supports_vision: true`，推荐）

| 来源 | 行为 |
|---|---|
| 对话中上传的图片 | 各通道主模型按上限裁剪（长边 ≤1568px、质量 88、单图 ≤4MB、单轮 ≤10 张且总量 ≤12MB）后，以**图片内容块**随本轮消息直发主模型 |
| `read_file` 读取磁盘图片 | 框架的多模态 `read_file` 直接把图片作为**工具结果图片块**返回给模型（截图、下载的验证码、报告配图都走这条） |
| 外部 MCP 工具返回的图片 | 先落盘（`tmp/mcp-images/`，保留 7 天），工具结果里给路径；模型按需 `read_file` 该路径即得到图片 |

要点：

- **不需要 analyze_image**：能读图的模型直接看图，比"先转文字再推理"信息无损。这也是 Codex / Claude Code / Cline 的做法。
- **图片不写进对话历史**：图片字节只存在于被上传/读取的那一轮请求；后续轮次若要再参考，重新 `read_file` 同一路径即可（路径已在历史消息里）。因此不会每轮重发 base64。
- **不落库、不进事件流**：图片不写入数据库、SSE 与摘要，工具结果在文本通道里只留一行占位（避免 base64 污染监控与压缩链路）。
- 系统提示自动注入 `## 图片输入` 段：明确"用户上传的图片已在上下文中"、"磁盘图片用 read_file"、"子代理看不到父对话的图片，需在委派描述里写路径"。

## 二、旁路识图（主模型为纯文本模型时的兜底）

- **工具名**：`analyze_image`（MCP 内置，`vision.enabled` 且 `vision.model` 非空时注册）
- **行为**：读取磁盘图片 → `imaging` 缩放/JPEG 压缩 → 调用独立 **Vision** 模型 → 返回**纯文本**给 Agent
- **适用**：`deepseek-chat` 等纯文本主模型——此时这是唯一可行的看图方式
- **提示词**：仅在 `supports_vision` 未开启时注入 `## 图片分析` 段（引导传路径给 `analyze_image`）
- **注意**：`analyze_image` 走的是 `vision` 段的独立模型配置，与主通道无关；主模型支持图片输入时不需要它

> `supports_vision` 与 `vision.enabled` 相互独立：可只开前者（原生读图、零旁路成本），也可以都开（原生为主，工具留给纯文本通道或专用场景）。

## 配置（`config.yaml`）

```yaml
ai:
  channels:
    qwen-vl:
      base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
      api_key: sk-xxx
      model: qwen-vl-max
      supports_vision: true   # 只要这一行即可获得原生读图能力

vision:                     # 可选：纯文本主模型的旁路兜底
  enabled: false
  model: qwen-vl-max   # enabled 时必填
  api_key:             # 留空 → 默认 AI 通道 api_key
  base_url:            # 留空 → 默认 AI 通道 base_url
  provider:            # 留空 → 默认 AI 通道 provider
  max_image_bytes: 5242880
  max_dimension: 2048
  jpeg_quality: 82
  max_payload_bytes: 524288
  skip_preprocess_below_bytes: 2097152  # 低于 2MB 且长边<=max_dimension 时原图直传；0=始终 JPEG 压缩
  detail: low          # low | high | auto
  timeout_seconds: 60
```

## Web 设置

- **系统设置 → 基本设置 → AI 通道**：勾选「主模型支持图片输入（多模态）」，随通道保存。
- **系统设置 → 基本设置 → 视觉分析（analyze_image）**：仅纯文本主模型需要；配置启用开关、视觉模型、API Key/Base URL、预处理参数。
- 两处都需要**保存并应用**才生效（应用会重建 MCP 工具注册与文件系统中间件）。
- 对话里已发送的图片会显示缩略图，点击放大（只做展示，与模型读图无关）。

## 持久化边界（图片不会污染存储与预算）

| 位置 | 图片处理 |
|---|---|
| 数据库消息 / `conversations.last_react_input`（模型视角轨迹） | **剥离为文本占位**（`[图片已作为图片输入提供给模型: image/png ~120KB]`）。轨迹会落库并在续跑时回灌，携带 base64 会撑大数据库与每轮请求体 |
| SSE / 监控落库 / 摘要 | 同样只留占位；摘要与文本通道永远看不到 base64 |
| 上下文预算与 token 估算 | 每张图片按 `vision.NativeImageTokenEstimate`（保守 1600 token）计入，否则软预算对图片不可见 |
| HITL 暂停的 checkpoint（`workflow_checkpoints`） | **会**包含当轮图片（框架的 gob 状态快照），上限受单轮图片预算约束（≤12MB 原始字节 ≈ 16MB base64）；随对话删除或按存储策略保留期清理 |
| `tmp/mcp-images/` | 外部 MCP 图片的派生缓存，写入时尽力清理 7 天前的文件 |

续跑/后续轮次若还需看图：路径已写在消息正文里，模型重新 `read_file` 即可（图片不在历史里重复发送，也不会重复计费）。

## 路径与安全

- `read_file` / `analyze_image` 受会话工作目录（`workspace_root_dir`）与本仓库的 RBAC/审批链路约束，和文本文件一致。
- 图片不写入数据库、不进 SSE、不进摘要；`tmp/mcp-images/` 只是派生缓存，7 天后自动清理。
- 外部 MCP 图片落盘目录可被 Agent `read_file`，属于本机文件访问：与其它文件读取走同一套审批与监控。

## 如何真实验证（读图答题，不只看接口 200）

仓库内置一条 env 门控的真实链路测试，图形与颜色每轮随机生成——只有真正看到图才能答对：

```bash
CSAI_LIVE_CLAUDE_BASE_URL=https://api.example.com/anthropic CSAI_LIVE_CLAUDE_API_KEY=sk-xxx CSAI_LIVE_CLAUDE_MODEL=some-vl-model go test ./internal/vision/ -run TestLive -v -timeout 10m
```

它同时覆盖两条真实链路：`llm.NewClaudeAgenticModel` + 图片块（原生直发）与 `vision.Client.Analyze`（旁路识图）。
不设环境变量时自动跳过，因此可安全放在 CI。

无凭据时也可用离线测试确认协议与接线：`go test ./internal/llm/ -run WireShape -v`（断言 `/v1/messages` 路径、
`x-api-key`/`anthropic-version` 头、`source.type=base64` 图片块与 payload 完整）、
`go test ./internal/multiagent/ -run 'SingleAgentSendsImagesOnly|Multimodal' -v`（断言只有声明多模态的通道才带图，
以及 read_file 读图返回图片块、轨迹与预算不含 base64）。

## 常见问题

- **「测试连接」通过 ≠ 支持图片**：该探针是纯文本 chat 请求，纯文本模型也会通过；是否可读图取决于 `supports_vision` 与模型真实能力。
- **打开 `supports_vision` 但模型不支持图片**：上游会返回图片相关的 400/422。请按模型能力填写。
- **角色工具白名单**：「默认」角色不声明 `tools`，自动使用全部工具；自定义角色若显式声明 `tools`，需要把 `analyze_image` 加进去（仅纯文本通道用得着）。`read_file` 属文件系统工具，由 `multi_agent.eino_skills.filesystem_tools` 控制。
- **合规**：原生路径会把图片直接发往该通道上游；旁路路径发往 `vision` 段配置的上游。敏感环境请使用可信网关或保持关闭。
