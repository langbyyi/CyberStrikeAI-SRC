# 执行流程稳健性优化实施计划

> 对应设计：`docs/superpowers/specs/2026-07-24-execution-flow-hardening-design.md`

## 任务 1：统一执行超时

涉及文件：

- 新增 `internal/handler/execution_lifecycle.go`
- 新增 `internal/handler/execution_lifecycle_test.go`
- 修改 `internal/handler/eino_single_agent.go`
- 修改 `internal/handler/multi_agent.go`

步骤：

1. 先写测试，覆盖单代理显式配置、单代理默认值、多代理兼容值。
2. 实现唯一的 timeout 选择函数。
3. 替换四个入口和多代理恢复分支中的硬编码 deadline。

## 任务 2：修复 SSE 断连状态竞态

涉及文件：

- `internal/handler/execution_lifecycle.go`
- `internal/handler/execution_lifecycle_test.go`
- `internal/handler/eino_single_agent.go`
- `internal/handler/multi_agent.go`

步骤：

1. 为并发安全的连接状态补测试。
2. 使用 `atomic.Bool` 封装读写。
3. 两个流式 handler 共用该状态类型，响应写锁保持不变。

## 任务 3：收紧瞬时错误重试

涉及文件：

- 新增 `internal/multiagent/eino_transient_retry_test.go`
- 修改 `internal/multiagent/eino_transient_retry.go`
- 修改 `internal/config/config.go`
- 修改 `config.yaml.example`

步骤：

1. 先写误判与正确分类测试。
2. 将 HTTP 状态识别限定为明确状态码格式，删除宽泛数字和永久错误标记。
3. 将默认重试调整为 3 次、默认最大退避调整为 10 秒。
4. 验证显式配置仍覆盖默认值。

## 任务 4：清理会话执行状态

涉及文件：

- 修改 `internal/handler/conversation.go`
- 修改 `internal/app/app.go`
- 扩展 `internal/multiagent` 状态测试

步骤：

1. 给会话 handler 增加可注入的执行状态清理函数。
2. 仅在数据库删除成功后调用清理函数。
3. 在应用装配处注入 `multiagent.DeleteConversationExecutionState`。

## 任务 5：终态持久化失败可见

涉及文件：

- `internal/handler/execution_lifecycle.go`
- `internal/handler/execution_lifecycle_test.go`
- `internal/handler/eino_single_agent.go`
- `internal/handler/multi_agent.go`

步骤：

1. 为最终消息更新函数的错误传播补测试。
2. 四条成功路径在发送成功响应前检查落库结果。
3. 流式路径发送 `error + done`；非流式路径返回 500。

## 任务 6：验证

按顺序执行：

1. `go test ./internal/handler ./internal/multiagent -count=1`
2. `go test ./... -count=1`
3. `go vet ./...`
4. `go build ./cmd/server`
5. `git diff --check`

若构建产生根目录二进制，只删除本次构建生成且已确认路径的文件。

## 任务 7：执行状态 checkpoint

涉及文件：

- 新增 `internal/multiagent/execution_state_checkpoint.go`
- 新增 `internal/multiagent/execution_state_checkpoint_test.go`
- 修改 `internal/multiagent/eino_checkpoint.go`
- 修改 `internal/multiagent/eino_adk_run_loop.go`

步骤：

1. 先写 round-trip 测试，覆盖覆盖率、近期证据、死亡工具、会话意图和执行控制器。
2. 补版本、会话 ID、编排模式和损坏 JSON 拒绝测试。
3. 扩展文件 checkpoint store，使 ADK checkpoint 和状态 sidecar 成对保存、恢复、删除。
4. 运行循环只在 sidecar 校验并恢复成功后调用 `Runner.Resume`；否则清理并全新执行。
5. 正常完成时统一删除两类 checkpoint 文件。

## 任务 8：第二期验证

按顺序执行：

1. `go test ./internal/multiagent -run 'TestExecutionStateCheckpoint|TestFileCheckPointStore' -count=1`
2. `go test ./... -count=1`
3. `go vet ./...`
4. `go build ./cmd/server`
5. `git diff --check`

## 任务 9：run-loop 内终止策略

涉及文件：

- 新增 `internal/multiagent/finalize_continuation.go`
- 新增 `internal/multiagent/finalize_continuation_test.go`
- 修改 `internal/multiagent/eino_adk_run_loop.go`

步骤：

1. 把 coverage、surface-record 和 depth-force 合并为纯续跑决策。
2. 正常 run 完成后先评估决策；被拦截时追加内部 user continuation 并启动下一 Runner 段。
3. 每次请求最多自动续跑两段；仍未闭环时附加用户可读的范围限制说明。
4. partial/error 路径不再改写为带内部 marker 的最终文本。
5. panic recover 返回明确错误。

## 任务 10：非流式任务生命周期

涉及文件：

- `internal/handler/execution_lifecycle.go`
- `internal/handler/execution_lifecycle_test.go`
- `internal/handler/eino_single_agent.go`
- `internal/handler/multi_agent.go`

步骤：

1. 非流式单代理和多代理执行前注册会话任务，重复执行返回 409。
2. 将任务 cancel 绑定到请求执行 context。
3. 统一 completed/failed/cancelled/timeout 终态并确保 defer 清理。
4. 持久化失败标记任务失败，不返回成功。

## 任务 11：流式生命周期收敛

涉及文件：

- `internal/handler/execution_lifecycle.go`
- `internal/handler/execution_lifecycle_test.go`
- `internal/handler/eino_single_agent.go`
- `internal/handler/multi_agent.go`

步骤：

1. 抽取单/多代理共用的 SSE 编码、TaskEventBus 镜像、串行写入、flush、断连和取消错误抑制。
2. 抽取四入口共用的 managed task 所有权，只有成功注册的请求可以完成并移除任务。
3. 统一终态更新，重复 Finish 保持幂等。
4. 增加真实 ADK Runner 测试代理，验证 finalize 自动续跑、续跑上限和 panic 错误传播。
