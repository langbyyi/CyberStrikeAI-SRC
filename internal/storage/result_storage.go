package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ResultStorage 结果存储接口
type ResultStorage interface {
	// SaveResult 保存工具执行结果
	SaveResult(executionID string, toolName string, result string) error

	// GetResult 获取完整结果
	GetResult(executionID string) (string, error)

	// GetResultPage 分页获取结果
	GetResultPage(executionID string, page int, limit int) (*ResultPage, error)

	// SearchResult 搜索结果
	// useRegex: 如果为 true，将 keyword 作为正则表达式使用；如果为 false，使用简单的字符串包含匹配
	SearchResult(executionID string, keyword string, useRegex bool) ([]string, error)

	// FilterResult 过滤结果
	// useRegex: 如果为 true，将 filter 作为正则表达式使用；如果为 false，使用简单的字符串包含匹配
	FilterResult(executionID string, filter string, useRegex bool) ([]string, error)

	// GetResultMetadata 获取结果元信息
	GetResultMetadata(executionID string) (*ResultMetadata, error)

	// GetResultPath 获取结果文件路径
	GetResultPath(executionID string) string

	// DeleteResult 删除结果
	DeleteResult(executionID string) error
}

// ResultPage 分页结果
type ResultPage struct {
	Lines      []string `json:"lines"`
	Page       int      `json:"page"`
	Limit      int      `json:"limit"`
	TotalLines int      `json:"total_lines"`
	TotalPages int      `json:"total_pages"`
}

// ResultMetadata 结果元信息
type ResultMetadata struct {
	ExecutionID string    `json:"execution_id"`
	ToolName    string    `json:"tool_name"`
	TotalSize   int       `json:"total_size"`
	TotalLines  int       `json:"total_lines"`
	CreatedAt   time.Time `json:"created_at"`
}

// FileResultStorage 基于文件的结果存储实现
type FileResultStorage struct {
	baseDir string
	logger  *zap.Logger
	mu      sync.RWMutex
}

// NewFileResultStorage 创建新的文件结果存储
func NewFileResultStorage(baseDir string, logger *zap.Logger) (*FileResultStorage, error) {
	// 确保目录存在
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("创建存储目录失败: %w", err)
	}

	return &FileResultStorage{
		baseDir: baseDir,
		logger:  logger,
	}, nil
}

// getResultPath 获取结果文件路径
func (s *FileResultStorage) getResultPath(executionID string) string {
	return filepath.Join(s.baseDir, executionID+".txt")
}

// getMetadataPath 获取元数据文件路径
func (s *FileResultStorage) getMetadataPath(executionID string) string {
	return filepath.Join(s.baseDir, executionID+".meta.json")
}

// SaveResult 保存工具执行结果
func (s *FileResultStorage) SaveResult(executionID string, toolName string, result string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 保存结果文件
	resultPath := s.getResultPath(executionID)
	if err := os.WriteFile(resultPath, []byte(result), 0644); err != nil {
		return fmt.Errorf("保存结果文件失败: %w", err)
	}

	// 计算统计信息
	lines := strings.Split(result, "\n")
	metadata := &ResultMetadata{
		ExecutionID: executionID,
		ToolName:    toolName,
		TotalSize:   len(result),
		TotalLines:  len(lines),
		CreatedAt:   time.Now(),
	}

	// 保存元数据
	metadataPath := s.getMetadataPath(executionID)
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("序列化元数据失败: %w", err)
	}

	if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
		return fmt.Errorf("保存元数据文件失败: %w", err)
	}

	s.logger.Info("保存工具执行结果",
		zap.String("executionID", executionID),
		zap.String("toolName", toolName),
		zap.Int("size", len(result)),
		zap.Int("lines", len(lines)),
	)

	return nil
}

// GetResult 获取完整结果
func (s *FileResultStorage) GetResult(executionID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resultPath := s.getResultPath(executionID)
	data, err := os.ReadFile(resultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("结果不存在: %s", executionID)
		}
		return "", fmt.Errorf("读取结果文件失败: %w", err)
	}

	return string(data), nil
}

// GetResultMetadata 获取结果元信息
func (s *FileResultStorage) GetResultMetadata(executionID string) (*ResultMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metadataPath := s.getMetadataPath(executionID)
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("结果不存在: %s", executionID)
		}
		return nil, fmt.Errorf("读取元数据文件失败: %w", err)
	}

	var metadata ResultMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("解析元数据失败: %w", err)
	}

	return &metadata, nil
}

// GetResultPage 分页获取结果
func (s *FileResultStorage) GetResultPage(executionID string, page int, limit int) (*ResultPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 获取完整结果
	result, err := s.GetResult(executionID)
	if err != nil {
		return nil, err
	}

	// 分割为行
	lines := strings.Split(result, "\n")
	totalLines := len(lines)

	// 计算分页
	totalPages := (totalLines + limit - 1) / limit
	if page < 1 {
		page = 1
	}
	if page > totalPages && totalPages > 0 {
		page = totalPages
	}

	// 计算起始和结束索引
	start := (page - 1) * limit
	end := start + limit
	if end > totalLines {
		end = totalLines
	}

	// 提取指定页的行
	var pageLines []string
	if start < totalLines {
		pageLines = lines[start:end]
	} else {
		pageLines = []string{}
	}

	return &ResultPage{
		Lines:      pageLines,
		Page:       page,
		Limit:      limit,
		TotalLines: totalLines,
		TotalPages: totalPages,
	}, nil
}

// SearchResult 搜索结果
func (s *FileResultStorage) SearchResult(executionID string, keyword string, useRegex bool) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 获取完整结果
	result, err := s.GetResult(executionID)
	if err != nil {
		return nil, err
	}

	// 如果使用正则表达式，先编译正则
	var regex *regexp.Regexp
	if useRegex {
		compiledRegex, err := regexp.Compile(keyword)
		if err != nil {
			return nil, fmt.Errorf("无效的正则表达式: %w", err)
		}
		regex = compiledRegex
	}

	// 分割为行并搜索
	lines := strings.Split(result, "\n")
	var matchedLines []string

	for _, line := range lines {
		var matched bool
		if useRegex {
			matched = regex.MatchString(line)
		} else {
			matched = strings.Contains(line, keyword)
		}

		if matched {
			matchedLines = append(matchedLines, line)
		}
	}

	return matchedLines, nil
}

// FilterResult 过滤结果
func (s *FileResultStorage) FilterResult(executionID string, filter string, useRegex bool) ([]string, error) {
	// 过滤和搜索逻辑相同，都是查找包含关键词的行
	return s.SearchResult(executionID, filter, useRegex)
}

// GetResultPath 获取结果文件路径
func (s *FileResultStorage) GetResultPath(executionID string) string {
	return s.getResultPath(executionID)
}

// DeleteResult 删除结果
func (s *FileResultStorage) DeleteResult(executionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	resultPath := s.getResultPath(executionID)
	metadataPath := s.getMetadataPath(executionID)

	// 删除结果文件
	if err := os.Remove(resultPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除结果文件失败: %w", err)
	}

	// 删除元数据文件
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除元数据文件失败: %w", err)
	}

	s.logger.Info("删除工具执行结果",
		zap.String("executionID", executionID),
	)

	return nil
}
