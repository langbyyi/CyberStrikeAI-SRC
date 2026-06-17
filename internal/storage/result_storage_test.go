package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// setupTestStorage 创建测试用的存储实例
func setupTestStorage(t *testing.T) (*FileResultStorage, string) {
	tmpDir := filepath.Join(os.TempDir(), "test_result_storage_"+time.Now().Format("20060102_150405"))
	logger := zap.NewNop()

	storage, err := NewFileResultStorage(tmpDir, logger)
	if err != nil {
		t.Fatalf("创建测试存储失败: %v", err)
	}

	return storage, tmpDir
}

// cleanupTestStorage 清理测试数据
func cleanupTestStorage(t *testing.T, tmpDir string) {
	if err := os.RemoveAll(tmpDir); err != nil {
		t.Logf("清理测试目录失败: %v", err)
	}
}

func TestNewFileResultStorage(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "test_new_storage_"+time.Now().Format("20060102_150405"))
	defer cleanupTestStorage(t, tmpDir)

	logger := zap.NewNop()
	storage, err := NewFileResultStorage(tmpDir, logger)
	if err != nil {
		t.Fatalf("创建存储失败: %v", err)
	}

	if storage == nil {
		t.Fatal("存储实例为nil")
	}

	// 验证目录已创建
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Fatal("存储目录未创建")
	}
}

func TestFileResultStorage_SaveResult(t *testing.T) {
	storage, tmpDir := setupTestStorage(t)
	defer cleanupTestStorage(t, tmpDir)

	executionID := "test_exec_001"
	toolName := "nmap_scan"
	result := "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"

	err := storage.SaveResult(executionID, toolName, result)
	if err != nil {
		t.Fatalf("保存结果失败: %v", err)
	}

	// 验证结果文件存在
	resultPath := filepath.Join(tmpDir, executionID+".txt")
	if _, err := os.Stat(resultPath); os.IsNotExist(err) {
		t.Fatal("结果文件未创建")
	}

	// 验证元数据文件存在
	metadataPath := filepath.Join(tmpDir, executionID+".meta.json")
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		t.Fatal("元数据文件未创建")
	}
}

func TestFileResultStorage_GetResult(t *testing.T) {
	storage, tmpDir := setupTestStorage(t)
	defer cleanupTestStorage(t, tmpDir)

	executionID := "test_exec_002"
	toolName := "test_tool"
	expectedResult := "Test result content\nLine 2\nLine 3"

	// 先保存结果
	err := storage.SaveResult(executionID, toolName, expectedResult)
	if err != nil {
		t.Fatalf("保存结果失败: %v", err)
	}

	// 获取结果
	result, err := storage.GetResult(executionID)
	if err != nil {
		t.Fatalf("获取结果失败: %v", err)
	}

	if result != expectedResult {
		t.Errorf("结果不匹配。期望: %q, 实际: %q", expectedResult, result)
	}

	// 测试不存在的执行ID
	_, err = storage.GetResult("nonexistent_id")
	if err == nil {
		t.Fatal("应该返回错误")
	}
}

func TestFileResultStorage_GetResultMetadata(t *testing.T) {
	storage, tmpDir := setupTestStorage(t)
	defer cleanupTestStorage(t, tmpDir)

	executionID := "test_exec_003"
	toolName := "test_tool"
	result := "Line 1\nLine 2\nLine 3"

	// 保存结果
	err := storage.SaveResult(executionID, toolName, result)
	if err != nil {
		t.Fatalf("保存结果失败: %v", err)
	}

	// 获取元数据
	metadata, err := storage.GetResultMetadata(executionID)
	if err != nil {
		t.Fatalf("获取元数据失败: %v", err)
	}

	if metadata.ExecutionID != executionID {
		t.Errorf("执行ID不匹配。期望: %s, 实际: %s", executionID, metadata.ExecutionID)
	}

	if metadata.ToolName != toolName {
		t.Errorf("工具名称不匹配。期望: %s, 实际: %s", toolName, metadata.ToolName)
	}

	if metadata.TotalSize != len(result) {
		t.Errorf("总大小不匹配。期望: %d, 实际: %d", len(result), metadata.TotalSize)
	}

	expectedLines := len(strings.Split(result, "\n"))
	if metadata.TotalLines != expectedLines {
		t.Errorf("总行数不匹配。期望: %d, 实际: %d", expectedLines, metadata.TotalLines)
	}

	// 验证创建时间在合理范围内
	now := time.Now()
	if metadata.CreatedAt.After(now) || metadata.CreatedAt.Before(now.Add(-time.Second)) {
		t.Errorf("创建时间不在合理范围内: %v", metadata.CreatedAt)
	}
}

func TestFileResultStorage_GetResultPage(t *testing.T) {
	storage, tmpDir := setupTestStorage(t)
	defer cleanupTestStorage(t, tmpDir)

	executionID := "test_exec_004"
	toolName := "test_tool"
	// 创建包含10行的结果
	lines := make([]string, 10)
	for i := 0; i < 10; i++ {
		lines[i] = fmt.Sprintf("Line %d", i+1)
	}
	result := strings.Join(lines, "\n")

	// 保存结果
	err := storage.SaveResult(executionID, toolName, result)
	if err != nil {
		t.Fatalf("保存结果失败: %v", err)
	}

	// 测试第一页（每页3行）
	page, err := storage.GetResultPage(executionID, 1, 3)
	if err != nil {
		t.Fatalf("获取第一页失败: %v", err)
	}

	if page.Page != 1 {
		t.Errorf("页码不匹配。期望: 1, 实际: %d", page.Page)
	}

	if page.Limit != 3 {
		t.Errorf("每页行数不匹配。期望: 3, 实际: %d", page.Limit)
	}

	if page.TotalLines != 10 {
		t.Errorf("总行数不匹配。期望: 10, 实际: %d", page.TotalLines)
	}

	if page.TotalPages != 4 {
		t.Errorf("总页数不匹配。期望: 4, 实际: %d", page.TotalPages)
	}

	if len(page.Lines) != 3 {
		t.Errorf("第一页行数不匹配。期望: 3, 实际: %d", len(page.Lines))
	}

	if page.Lines[0] != "Line 1" {
		t.Errorf("第一行内容不匹配。期望: Line 1, 实际: %s", page.Lines[0])
	}

	// 测试第二页
	page2, err := storage.GetResultPage(executionID, 2, 3)
	if err != nil {
		t.Fatalf("获取第二页失败: %v", err)
	}

	if len(page2.Lines) != 3 {
		t.Errorf("第二页行数不匹配。期望: 3, 实际: %d", len(page2.Lines))
	}

	if page2.Lines[0] != "Line 4" {
		t.Errorf("第二页第一行内容不匹配。期望: Line 4, 实际: %s", page2.Lines[0])
	}

	// 测试最后一页（可能不满一页）
	page4, err := storage.GetResultPage(executionID, 4, 3)
	if err != nil {
		t.Fatalf("获取第四页失败: %v", err)
	}

	if len(page4.Lines) != 1 {
		t.Errorf("第四页行数不匹配。期望: 1, 实际: %d", len(page4.Lines))
	}

	// 测试超出范围的页码（应该返回最后一页）
	page5, err := storage.GetResultPage(executionID, 5, 3)
	if err != nil {
		t.Fatalf("获取第五页失败: %v", err)
	}

	// 超出范围的页码会被修正为最后一页，所以应该返回最后一页的内容
	if page5.Page != 4 {
		t.Errorf("超出范围的页码应该被修正为最后一页。期望: 4, 实际: %d", page5.Page)
	}

	// 最后一页应该只有1行
	if len(page5.Lines) != 1 {
		t.Errorf("最后一页应该只有1行。实际: %d行", len(page5.Lines))
	}
}

func TestFileResultStorage_SearchResult(t *testing.T) {
	storage, tmpDir := setupTestStorage(t)
	defer cleanupTestStorage(t, tmpDir)

	executionID := "test_exec_005"
	toolName := "test_tool"
	result := "Line 1: error occurred\nLine 2: success\nLine 3: error again\nLine 4: ok"

	// 保存结果
	err := storage.SaveResult(executionID, toolName, result)
	if err != nil {
		t.Fatalf("保存结果失败: %v", err)
	}

	// 搜索包含"error"的行（简单字符串匹配）
	matchedLines, err := storage.SearchResult(executionID, "error", false)
	if err != nil {
		t.Fatalf("搜索失败: %v", err)
	}

	if len(matchedLines) != 2 {
		t.Errorf("搜索结果数量不匹配。期望: 2, 实际: %d", len(matchedLines))
	}

	// 验证搜索结果内容
	for i, line := range matchedLines {
		if !strings.Contains(line, "error") {
			t.Errorf("搜索结果第%d行不包含关键词: %s", i+1, line)
		}
	}

	// 测试搜索不存在的关键词
	noMatch, err := storage.SearchResult(executionID, "nonexistent", false)
	if err != nil {
		t.Fatalf("搜索失败: %v", err)
	}

	if len(noMatch) != 0 {
		t.Errorf("搜索不存在的关键词应该返回空结果。实际: %d行", len(noMatch))
	}

	// 测试正则表达式搜索
	regexMatched, err := storage.SearchResult(executionID, "error.*again", true)
	if err != nil {
		t.Fatalf("正则搜索失败: %v", err)
	}

	if len(regexMatched) != 1 {
		t.Errorf("正则搜索结果数量不匹配。期望: 1, 实际: %d", len(regexMatched))
	}
}

func TestFileResultStorage_FilterResult(t *testing.T) {
	storage, tmpDir := setupTestStorage(t)
	defer cleanupTestStorage(t, tmpDir)

	executionID := "test_exec_006"
	toolName := "test_tool"
	result := "Line 1: warning message\nLine 2: info message\nLine 3: warning again\nLine 4: debug message"

	// 保存结果
	err := storage.SaveResult(executionID, toolName, result)
	if err != nil {
		t.Fatalf("保存结果失败: %v", err)
	}

	// 过滤包含"warning"的行（简单字符串匹配）
	filteredLines, err := storage.FilterResult(executionID, "warning", false)
	if err != nil {
		t.Fatalf("过滤失败: %v", err)
	}

	if len(filteredLines) != 2 {
		t.Errorf("过滤结果数量不匹配。期望: 2, 实际: %d", len(filteredLines))
	}

	// 验证过滤结果内容
	for i, line := range filteredLines {
		if !strings.Contains(line, "warning") {
			t.Errorf("过滤结果第%d行不包含关键词: %s", i+1, line)
		}
	}
}

func TestFileResultStorage_DeleteResult(t *testing.T) {
	storage, tmpDir := setupTestStorage(t)
	defer cleanupTestStorage(t, tmpDir)

	executionID := "test_exec_007"
	toolName := "test_tool"
	result := "Test result"

	// 保存结果
	err := storage.SaveResult(executionID, toolName, result)
	if err != nil {
		t.Fatalf("保存结果失败: %v", err)
	}

	// 验证文件存在
	resultPath := filepath.Join(tmpDir, executionID+".txt")
	metadataPath := filepath.Join(tmpDir, executionID+".meta.json")

	if _, err := os.Stat(resultPath); os.IsNotExist(err) {
		t.Fatal("结果文件不存在")
	}

	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		t.Fatal("元数据文件不存在")
	}

	// 删除结果
	err = storage.DeleteResult(executionID)
	if err != nil {
		t.Fatalf("删除结果失败: %v", err)
	}

	// 验证文件已删除
	if _, err := os.Stat(resultPath); !os.IsNotExist(err) {
		t.Fatal("结果文件未被删除")
	}

	if _, err := os.Stat(metadataPath); !os.IsNotExist(err) {
		t.Fatal("元数据文件未被删除")
	}

	// 测试删除不存在的执行ID（应该不报错）
	err = storage.DeleteResult("nonexistent_id")
	if err != nil {
		t.Errorf("删除不存在的执行ID不应该报错: %v", err)
	}
}

func TestFileResultStorage_ConcurrentAccess(t *testing.T) {
	storage, tmpDir := setupTestStorage(t)
	defer cleanupTestStorage(t, tmpDir)

	// 并发保存多个结果
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			executionID := fmt.Sprintf("test_exec_%d", id)
			toolName := "test_tool"
			result := fmt.Sprintf("Result %d\nLine 2\nLine 3", id)

			err := storage.SaveResult(executionID, toolName, result)
			if err != nil {
				t.Errorf("并发保存失败 (ID: %s): %v", executionID, err)
			}

			// 并发读取
			_, err = storage.GetResult(executionID)
			if err != nil {
				t.Errorf("并发读取失败 (ID: %s): %v", executionID, err)
			}

			done <- true
		}(i)
	}

	// 等待所有goroutine完成
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestFileResultStorage_LargeResult(t *testing.T) {
	storage, tmpDir := setupTestStorage(t)
	defer cleanupTestStorage(t, tmpDir)

	executionID := "test_exec_large"
	toolName := "test_tool"

	// 创建大结果（1000行）
	lines := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		lines[i] = fmt.Sprintf("Line %d: This is a test line with some content", i+1)
	}
	result := strings.Join(lines, "\n")

	// 保存大结果
	err := storage.SaveResult(executionID, toolName, result)
	if err != nil {
		t.Fatalf("保存大结果失败: %v", err)
	}

	// 验证元数据
	metadata, err := storage.GetResultMetadata(executionID)
	if err != nil {
		t.Fatalf("获取元数据失败: %v", err)
	}

	if metadata.TotalLines != 1000 {
		t.Errorf("总行数不匹配。期望: 1000, 实际: %d", metadata.TotalLines)
	}

	// 测试分页查询大结果
	page, err := storage.GetResultPage(executionID, 1, 100)
	if err != nil {
		t.Fatalf("获取第一页失败: %v", err)
	}

	if page.TotalPages != 10 {
		t.Errorf("总页数不匹配。期望: 10, 实际: %d", page.TotalPages)
	}

	if len(page.Lines) != 100 {
		t.Errorf("第一页行数不匹配。期望: 100, 实际: %d", len(page.Lines))
	}
}
