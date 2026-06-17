package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/storage"

	"go.uber.org/zap"
)

// setupTestAgent 创建测试用的Agent
func setupTestAgent(t *testing.T) (*Agent, *storage.FileResultStorage) {
	logger := zap.NewNop()
	mcpServer := mcp.NewServer(logger)

	openAICfg := &config.OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: "https://api.test.com/v1",
		Model:   "test-model",
	}

	agentCfg := &config.AgentConfig{
		MaxIterations:        10,
		LargeResultThreshold: 100, // 设置较小的阈值便于测试
		ResultStorageDir:     "",
	}

	agent := NewAgent(openAICfg, agentCfg, mcpServer, nil, logger, 10)

	// 创建测试存储
	tmpDir := filepath.Join(os.TempDir(), "test_agent_storage_"+time.Now().Format("20060102_150405"))
	testStorage, err := storage.NewFileResultStorage(tmpDir, logger)
	if err != nil {
		t.Fatalf("创建测试存储失败: %v", err)
	}

	agent.SetResultStorage(testStorage)

	return agent, testStorage
}

func TestAgent_FormatMinimalNotification(t *testing.T) {
	agent, testStorage := setupTestAgent(t)
	_ = testStorage // 避免未使用变量警告

	executionID := "test_exec_001"
	toolName := "nmap_scan"
	size := 50000
	lineCount := 1000
	filePath := "tmp/test_exec_001.txt"

	notification := agent.formatMinimalNotification(executionID, toolName, size, lineCount, filePath)

	// 验证通知包含必要信息
	if !strings.Contains(notification, executionID) {
		t.Errorf("通知中应该包含执行ID: %s", executionID)
	}

	if !strings.Contains(notification, toolName) {
		t.Errorf("通知中应该包含工具名称: %s", toolName)
	}

	if !strings.Contains(notification, "50000") {
		t.Errorf("通知中应该包含大小信息")
	}

	if !strings.Contains(notification, "1000") {
		t.Errorf("通知中应该包含行数信息")
	}

	if !strings.Contains(notification, "query_execution_result") {
		t.Errorf("通知中应该包含查询工具的使用说明")
	}
}

func TestAgent_ExecuteToolViaMCP_LargeResult(t *testing.T) {
	agent, _ := setupTestAgent(t)

	// 创建模拟的MCP工具结果（大结果）
	largeResult := &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: strings.Repeat("This is a test line with some content.\n", 1000), // 约50KB
			},
		},
		IsError: false,
	}

	// 模拟MCP服务器返回大结果
	// 由于我们需要模拟CallTool的行为，这里需要创建一个mock或者使用实际的MCP服务器
	// 为了简化测试，我们直接测试结果处理逻辑

	// 设置阈值
	agent.mu.Lock()
	agent.largeResultThreshold = 1000 // 设置较小的阈值
	agent.mu.Unlock()

	// 创建执行ID
	executionID := "test_exec_large_001"
	toolName := "test_tool"

	// 格式化结果
	var resultText strings.Builder
	for _, content := range largeResult.Content {
		resultText.WriteString(content.Text)
		resultText.WriteString("\n")
	}

	resultStr := resultText.String()
	resultSize := len(resultStr)

	// 检测大结果并保存
	agent.mu.RLock()
	threshold := agent.largeResultThreshold
	storage := agent.resultStorage
	agent.mu.RUnlock()

	if resultSize > threshold && storage != nil {
		// 保存大结果
		err := storage.SaveResult(executionID, toolName, resultStr)
		if err != nil {
			t.Fatalf("保存大结果失败: %v", err)
		}

		// 生成通知
		lines := strings.Split(resultStr, "\n")
		filePath := storage.GetResultPath(executionID)
		notification := agent.formatMinimalNotification(executionID, toolName, resultSize, len(lines), filePath)

		// 验证通知格式
		if !strings.Contains(notification, executionID) {
			t.Errorf("通知中应该包含执行ID")
		}

		// 验证结果已保存
		savedResult, err := storage.GetResult(executionID)
		if err != nil {
			t.Fatalf("获取保存的结果失败: %v", err)
		}

		if savedResult != resultStr {
			t.Errorf("保存的结果与原始结果不匹配")
		}
	} else {
		t.Fatal("大结果应该被检测到并保存")
	}
}

func TestAgent_ExecuteToolViaMCP_SmallResult(t *testing.T) {
	agent, _ := setupTestAgent(t)

	// 创建小结果
	smallResult := &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: "Small result content",
			},
		},
		IsError: false,
	}

	// 设置较大的阈值
	agent.mu.Lock()
	agent.largeResultThreshold = 100000 // 100KB
	agent.mu.Unlock()

	// 格式化结果
	var resultText strings.Builder
	for _, content := range smallResult.Content {
		resultText.WriteString(content.Text)
		resultText.WriteString("\n")
	}

	resultStr := resultText.String()
	resultSize := len(resultStr)

	// 检测大结果
	agent.mu.RLock()
	threshold := agent.largeResultThreshold
	storage := agent.resultStorage
	agent.mu.RUnlock()

	if resultSize > threshold && storage != nil {
		t.Fatal("小结果不应该被保存")
	}

	// 小结果应该直接返回
	if resultSize <= threshold {
		// 这是预期的行为
		if resultStr == "" {
			t.Fatal("小结果应该直接返回，不应该为空")
		}
	}
}

func TestAgent_SetResultStorage(t *testing.T) {
	agent, _ := setupTestAgent(t)

	// 创建新的存储
	tmpDir := filepath.Join(os.TempDir(), "test_new_storage_"+time.Now().Format("20060102_150405"))
	newStorage, err := storage.NewFileResultStorage(tmpDir, zap.NewNop())
	if err != nil {
		t.Fatalf("创建新存储失败: %v", err)
	}

	// 设置新存储
	agent.SetResultStorage(newStorage)

	// 验证存储已更新
	agent.mu.RLock()
	currentStorage := agent.resultStorage
	agent.mu.RUnlock()

	if currentStorage != newStorage {
		t.Fatal("存储未正确更新")
	}

	// 清理
	os.RemoveAll(tmpDir)
}

func TestAgent_NewAgent_DefaultValues(t *testing.T) {
	logger := zap.NewNop()
	mcpServer := mcp.NewServer(logger)

	openAICfg := &config.OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: "https://api.test.com/v1",
		Model:   "test-model",
	}

	// 测试默认配置
	agent := NewAgent(openAICfg, nil, mcpServer, nil, logger, 0)

	if agent.maxIterations != 30 {
		t.Errorf("默认迭代次数不匹配。期望: 30, 实际: %d", agent.maxIterations)
	}

	agent.mu.RLock()
	threshold := agent.largeResultThreshold
	agent.mu.RUnlock()

	if threshold != 50*1024 {
		t.Errorf("默认阈值不匹配。期望: %d, 实际: %d", 50*1024, threshold)
	}
}

func TestAgent_NewAgent_CustomConfig(t *testing.T) {
	logger := zap.NewNop()
	mcpServer := mcp.NewServer(logger)

	openAICfg := &config.OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: "https://api.test.com/v1",
		Model:   "test-model",
	}

	agentCfg := &config.AgentConfig{
		MaxIterations:        20,
		LargeResultThreshold: 100 * 1024, // 100KB
		ResultStorageDir:     "custom_tmp",
	}

	agent := NewAgent(openAICfg, agentCfg, mcpServer, nil, logger, 15)

	if agent.maxIterations != 15 {
		t.Errorf("迭代次数不匹配。期望: 15, 实际: %d", agent.maxIterations)
	}

	agent.mu.RLock()
	threshold := agent.largeResultThreshold
	agent.mu.RUnlock()

	if threshold != 100*1024 {
		t.Errorf("阈值不匹配。期望: %d, 实际: %d", 100*1024, threshold)
	}
}
