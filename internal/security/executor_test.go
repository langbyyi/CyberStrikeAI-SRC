package security

import (
	"context"
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

// setupTestExecutor 创建测试用的执行器
func setupTestExecutor(t *testing.T) (*Executor, *mcp.Server) {
	logger := zap.NewNop()
	mcpServer := mcp.NewServer(logger)

	cfg := &config.SecurityConfig{
		Tools: []config.ToolConfig{},
	}

	executor := NewExecutor(cfg, mcpServer, logger)
	return executor, mcpServer
}

// setupTestStorage 创建测试用的存储
func setupTestStorage(t *testing.T) *storage.FileResultStorage {
	tmpDir := filepath.Join(os.TempDir(), "test_executor_storage_"+time.Now().Format("20060102_150405"))
	logger := zap.NewNop()

	storage, err := storage.NewFileResultStorage(tmpDir, logger)
	if err != nil {
		t.Fatalf("创建测试存储失败: %v", err)
	}

	return storage
}

func TestExecutor_ExecuteInternalTool_QueryExecutionResult(t *testing.T) {
	executor, _ := setupTestExecutor(t)
	testStorage := setupTestStorage(t)
	executor.SetResultStorage(testStorage)

	// 准备测试数据
	executionID := "test_exec_001"
	toolName := "nmap_scan"
	result := "Line 1: Port 22 open\nLine 2: Port 80 open\nLine 3: Port 443 open\nLine 4: error occurred"

	// 保存测试结果
	err := testStorage.SaveResult(executionID, toolName, result)
	if err != nil {
		t.Fatalf("保存测试结果失败: %v", err)
	}

	ctx := context.Background()

	// 测试1: 基本查询（第一页）
	args := map[string]interface{}{
		"execution_id": executionID,
		"page":         float64(1),
		"limit":        float64(2),
	}

	toolResult, err := executor.executeQueryExecutionResult(ctx, args)
	if err != nil {
		t.Fatalf("执行查询失败: %v", err)
	}

	if toolResult.IsError {
		t.Fatalf("查询应该成功，但返回了错误: %s", toolResult.Content[0].Text)
	}

	// 验证结果包含预期内容
	resultText := toolResult.Content[0].Text
	if !strings.Contains(resultText, executionID) {
		t.Errorf("结果中应该包含执行ID: %s", executionID)
	}

	if !strings.Contains(resultText, "第 1/") {
		t.Errorf("结果中应该包含分页信息")
	}

	// 测试2: 搜索功能
	args2 := map[string]interface{}{
		"execution_id": executionID,
		"search":       "error",
		"page":         float64(1),
		"limit":        float64(10),
	}

	toolResult2, err := executor.executeQueryExecutionResult(ctx, args2)
	if err != nil {
		t.Fatalf("执行搜索失败: %v", err)
	}

	if toolResult2.IsError {
		t.Fatalf("搜索应该成功，但返回了错误: %s", toolResult2.Content[0].Text)
	}

	resultText2 := toolResult2.Content[0].Text
	if !strings.Contains(resultText2, "error") {
		t.Errorf("搜索结果中应该包含关键词: error")
	}

	// 测试3: 过滤功能
	args3 := map[string]interface{}{
		"execution_id": executionID,
		"filter":       "Port",
		"page":         float64(1),
		"limit":        float64(10),
	}

	toolResult3, err := executor.executeQueryExecutionResult(ctx, args3)
	if err != nil {
		t.Fatalf("执行过滤失败: %v", err)
	}

	if toolResult3.IsError {
		t.Fatalf("过滤应该成功，但返回了错误: %s", toolResult3.Content[0].Text)
	}

	resultText3 := toolResult3.Content[0].Text
	if !strings.Contains(resultText3, "Port") {
		t.Errorf("过滤结果中应该包含关键词: Port")
	}

	// 测试4: 缺少必需参数
	args4 := map[string]interface{}{
		"page": float64(1),
	}

	toolResult4, err := executor.executeQueryExecutionResult(ctx, args4)
	if err != nil {
		t.Fatalf("执行查询失败: %v", err)
	}

	if !toolResult4.IsError {
		t.Fatal("缺少execution_id应该返回错误")
	}

	// 测试5: 不存在的执行ID
	args5 := map[string]interface{}{
		"execution_id": "nonexistent_id",
		"page":         float64(1),
	}

	toolResult5, err := executor.executeQueryExecutionResult(ctx, args5)
	if err != nil {
		t.Fatalf("执行查询失败: %v", err)
	}

	if !toolResult5.IsError {
		t.Fatal("不存在的执行ID应该返回错误")
	}
}

func TestExecutor_ExecuteInternalTool_UnknownTool(t *testing.T) {
	executor, _ := setupTestExecutor(t)

	ctx := context.Background()
	args := map[string]interface{}{
		"test": "value",
	}

	// 测试未知的内部工具类型
	toolResult, err := executor.executeInternalTool(ctx, "unknown_tool", "internal:unknown_tool", args)
	if err != nil {
		t.Fatalf("执行内部工具失败: %v", err)
	}

	if !toolResult.IsError {
		t.Fatal("未知的工具类型应该返回错误")
	}

	if !strings.Contains(toolResult.Content[0].Text, "未知的内部工具类型") {
		t.Errorf("错误消息应该包含'未知的内部工具类型'")
	}
}

func TestExecutor_ExecuteInternalTool_NoStorage(t *testing.T) {
	executor, _ := setupTestExecutor(t)
	// 不设置存储，测试未初始化的情况

	ctx := context.Background()
	args := map[string]interface{}{
		"execution_id": "test_id",
	}

	toolResult, err := executor.executeQueryExecutionResult(ctx, args)
	if err != nil {
		t.Fatalf("执行查询失败: %v", err)
	}

	if !toolResult.IsError {
		t.Fatal("未初始化的存储应该返回错误")
	}

	if !strings.Contains(toolResult.Content[0].Text, "结果存储未初始化") {
		t.Errorf("错误消息应该包含'结果存储未初始化'")
	}
}

func TestExecuteSystemCommand_BackgroundDoesNotBlockOnChildStdout(t *testing.T) {
	executor, _ := setupTestExecutor(t)
	// 子进程先向 stdout 写无换行字符再长时间 sleep；若与 echo $pid 共享管道且未重定向子进程 stdout，
	// ReadString('\n') 会阻塞到子进程退出。后台包装须将子进程标准流与 PID 行分离。
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	args := map[string]interface{}{
		"command": `(sh -c 'printf x; sleep 120') &`,
		"shell":   "sh",
	}
	res, err := executor.executeSystemCommand(ctx, args)
	if err != nil {
		t.Fatalf("executeSystemCommand: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("expected success, got %+v", res)
	}
	txt := res.Content[0].Text
	if !strings.Contains(txt, "后台命令已启动") {
		t.Fatalf("unexpected body: %q", txt)
	}
}

func TestPaginateLines(t *testing.T) {
	lines := []string{"Line 1", "Line 2", "Line 3", "Line 4", "Line 5"}

	// 测试第一页
	page := paginateLines(lines, 1, 2)
	if page.Page != 1 {
		t.Errorf("页码不匹配。期望: 1, 实际: %d", page.Page)
	}
	if page.Limit != 2 {
		t.Errorf("每页行数不匹配。期望: 2, 实际: %d", page.Limit)
	}
	if page.TotalLines != 5 {
		t.Errorf("总行数不匹配。期望: 5, 实际: %d", page.TotalLines)
	}
	if page.TotalPages != 3 {
		t.Errorf("总页数不匹配。期望: 3, 实际: %d", page.TotalPages)
	}
	if len(page.Lines) != 2 {
		t.Errorf("第一页行数不匹配。期望: 2, 实际: %d", len(page.Lines))
	}

	// 测试第二页
	page2 := paginateLines(lines, 2, 2)
	if len(page2.Lines) != 2 {
		t.Errorf("第二页行数不匹配。期望: 2, 实际: %d", len(page2.Lines))
	}
	if page2.Lines[0] != "Line 3" {
		t.Errorf("第二页第一行不匹配。期望: Line 3, 实际: %s", page2.Lines[0])
	}

	// 测试最后一页
	page3 := paginateLines(lines, 3, 2)
	if len(page3.Lines) != 1 {
		t.Errorf("第三页行数不匹配。期望: 1, 实际: %d", len(page3.Lines))
	}

	// 测试超出范围的页码（应该返回最后一页）
	page4 := paginateLines(lines, 4, 2)
	if page4.Page != 3 {
		t.Errorf("超出范围的页码应该被修正为最后一页。期望: 3, 实际: %d", page4.Page)
	}
	if len(page4.Lines) != 1 {
		t.Errorf("最后一页应该只有1行。实际: %d行", len(page4.Lines))
	}

	// 测试无效页码（小于1）
	page0 := paginateLines(lines, 0, 2)
	if page0.Page != 1 {
		t.Errorf("无效页码应该被修正为1。实际: %d", page0.Page)
	}

	// 测试空列表
	emptyPage := paginateLines([]string{}, 1, 10)
	if emptyPage.TotalLines != 0 {
		t.Errorf("空列表的总行数应该为0。实际: %d", emptyPage.TotalLines)
	}
	if len(emptyPage.Lines) != 0 {
		t.Errorf("空列表应该返回空结果。实际: %d行", len(emptyPage.Lines))
	}
}
