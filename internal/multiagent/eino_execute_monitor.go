package multiagent

import (
	"fmt"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/einomcp"
)

// newEinoExecuteMonitorCallback 在 Eino filesystem execute 结束时写入 MCP 监控库并 recorder(executionId)，
// 与 CallTool 路径一致，供助手消息展示「渗透测试详情」芯片。
func newEinoExecuteMonitorCallback(ag *agent.Agent, recorder einomcp.ExecutionRecorder) func(command, stdout string, success bool, invokeErr error) {
	return func(command, stdout string, success bool, invokeErr error) {
		if ag == nil || recorder == nil {
			return
		}
		var err error
		if !success {
			if invokeErr != nil {
				err = invokeErr
			} else {
				err = fmt.Errorf("execute failed")
			}
		}
		args := map[string]interface{}{"command": command}
		id := ag.RecordLocalToolExecution("execute", args, stdout, err)
		if id != "" {
			recorder(id)
		}
	}
}
