---
name: browser-assisted-hunting
description: >-
  浏览器交互式挖洞:登录态操作、双账号越权对比、SPA渲染取证、DOM XSS确认、验证码登录、前端隐藏功能绕过。
  Use when CLI/HTTP evidence is insufficient and the target needs real browser interaction to confirm.
metadata:
  tags: [SRC, 漏洞挖掘, 浏览器测试]
---

## 定位

命令行与 HTTP 工具拿不到**渲染后状态与交互反馈**。当目标的漏洞需要真浏览器操作才能确认时用本 skill（依赖外部 MCP，如 Playwright）。它只补验证手段，不降低任何证据门槛；授权边界遵循 `authorized-attack-scope`。

## 何时必须上浏览器

| 场景 | 命令行为什么不行 | 浏览器怎么做 |
|---|---|---|
| SPA 动态渲染 | 源码无数据，接口运行时才生成 | `browser_snapshot` 读无障碍树，定位真实接口与元素 |
| 登录态多步交互 | 登录流有 JS 挑战/跳转/加密 | 表单填写走完登录，再操作目标功能 |
| 越权对比 | 需两个独立会话 Cookie 环境 | 双浏览器 context 隔离登录，互相重放 |
| DOM XSS | 源码含 sink ≠ 执行 | 渲染后读 DOM/console + 截图执行效果 |
| CSRF 实操 | 需浏览器真实携带 Cookie 跨站提交 | 构造表单自动提交，观察副作用 |
| 前端隐藏功能 | hidden/disabled 元素命令行看不见 | snapshot 找到元素，绕过前端限制打后端 |

## 标准打法

### 1. 双账号越权对比（最常用）

1. 开两个浏览器 context（Cookie 隔离），分别登录测试账号 A、B。
2. A 中定位目标功能：订单/个人资料/文件下载/消息等，记下请求 URL 与参数。
3. B 中重放：改 ID 参数直接导航或重新发起，读取渲染结果。
4. B 能看到非 B 的数据即越权成立。证据：B 侧截图 + 快照关键节点 + 命中的 URL/参数。

### 2. DOM XSS 确认

1. 注入点提交 payload 后等渲染完成。
2. `browser_snapshot` 或执行 JS 读取 sink 处的实际值，确认 payload 进入且被解析执行。
3. 截图执行效果（弹窗/样式变化/外带请求）。「源码里看得到 payload」不算证据，**渲染后执行效果**才算。

### 3. 登录流与验证码

1. `browser_type` 填表单提交；遇验证码先截图。
2. 截图传给 `ddddocr` 工具识别（`ocr` 文字码 / `detect` 点选坐标 / `slide` 滑块缺口），结果回填。
3. 登录态建立后继续目标操作；登录成功本身可作为「auth_required」字段的实测依据。

### 4. 前端逻辑绕过

1. snapshot 找 disabled/hidden 的按钮、被前端拦截的接口。
2. 前端限制不代表后端校验：直接调用后端接口或修改元素状态后提交。
3. 后端未校验即成立；证据取请求/响应差分，浏览器只是发现手段。

## 证据衔接（不可降级）

- 浏览器工具调用记录即真实探测证据，`record_vulnerability` 可复现门认可。
- 截图是给人看的补充，**必须**配结构化证据：请求 URL/参数 + 渲染后快照的关键内容。
- 负结果也落 Fact：「浏览器实测 XX 无渲染执行 / 无越权」，防止重复验证。

## 降级

`tool_search` 查不到 browser_* 工具（未挂浏览器 MCP）时：退回 HTTP 工具 + 手动 Cookie 头模拟登录态；在 Fact 中标注「缺渲染态证据」，不虚构浏览器结果。
