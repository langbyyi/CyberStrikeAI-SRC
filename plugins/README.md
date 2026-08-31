## 插件

连接 CyberStrikeAI 与其他工具的可选集成。

### Burp Suite

- **路径**：`plugins/burp-suite/cyberstrikeai-burp-extension/`
- **构建**：`bash build-mvn.sh` → `dist/cyberstrikeai-burp-extension.jar`
- **文档**：`README.md`

### 浏览器扩展（Chrome / Edge）

- **路径**：`plugins/browser-extension/cyberstrikeai-browser-extension/`
- **安装**：`chrome://extensions/` → 加载已解压的扩展程序 → F12 → **CyberStrikeAI** 标签页
- **打包**：`bash package.sh` → `dist/cyberstrikeai-browser-extension.zip`
- **文档**：`README.md`

#### 亮点（v0.3.x）

| 功能 | 说明 |
|------|------|
| Token 过期检测 | 剩余时间显示 + 30s 校验探测；识别服务重启/不可达 |
| 抓包暂停 | **● Capturing** / **○ Paused** — 不关闭 DevTools 即可停止记录 |
| HTTP/1.1 显示 | 原始 HAR 存内存；UI 与 AI prompt 已归一化（去除 `:method` 伪头） |
| 连接栏折叠 | Host/Port/Validate 校验成功后可折叠 |
| Popup | 只读展示接口地址与连接状态 |
| 性能 | 仅 XHR 过滤、静态资源不读 body、rAF 节流的流式 UI |
| 数据上限 | 200 条抓包/标签页、50 次测试、512KB 进度 — 全部存内存 |
