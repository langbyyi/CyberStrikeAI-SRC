package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// MonitorHandler 监控处理器
type MonitorHandler struct {
	mcpServer      *mcp.Server
	externalMCPMgr *mcp.ExternalMCPManager
	executor       *security.Executor
	db             *database.DB
	logger         *zap.Logger
	audit          *audit.Service
}

// SetAudit wires platform audit logging.
func (h *MonitorHandler) SetAudit(s *audit.Service) {
	h.audit = s
}

// NewMonitorHandler 创建新的监控处理器
func NewMonitorHandler(mcpServer *mcp.Server, executor *security.Executor, db *database.DB, logger *zap.Logger) *MonitorHandler {
	return &MonitorHandler{
		mcpServer:      mcpServer,
		externalMCPMgr: nil, // 将在创建后设置
		executor:       executor,
		db:             db,
		logger:         logger,
	}
}

// SetExternalMCPManager 设置外部MCP管理器
func (h *MonitorHandler) SetExternalMCPManager(mgr *mcp.ExternalMCPManager) {
	h.externalMCPMgr = mgr
}

// MonitorResponse 监控响应
type MonitorResponse struct {
	Executions []*mcp.ToolExecution      `json:"executions"`
	Stats      map[string]*mcp.ToolStats `json:"stats"`
	Timestamp  time.Time                 `json:"timestamp"`
	Total      int                       `json:"total,omitempty"`
	Page       int                       `json:"page,omitempty"`
	PageSize   int                       `json:"page_size,omitempty"`
	TotalPages int                       `json:"total_pages,omitempty"`
}

// Monitor 获取监控信息
func (h *MonitorHandler) Monitor(c *gin.Context) {
	// 解析分页参数
	page := 1
	pageSize := 20
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	// 解析状态筛选参数
	status := c.Query("status")
	// 解析工具筛选参数（兼容 mcp__tool 与内部 mcp::tool）
	toolName := normalizeToolNameFilter(c.Query("tool"))

	executions, total := h.loadExecutionsWithPagination(page, pageSize, status, toolName)
	stats := h.loadStats()

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	c.JSON(http.StatusOK, MonitorResponse{
		Executions: executions,
		Stats:      stats,
		Timestamp:  time.Now(),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

func (h *MonitorHandler) loadExecutions() []*mcp.ToolExecution {
	executions, _ := h.loadExecutionsWithPagination(1, 1000, "", "")
	return executions
}

func (h *MonitorHandler) loadExecutionsWithPagination(page, pageSize int, status, toolName string) ([]*mcp.ToolExecution, int) {
	if h.db == nil {
		allExecutions := h.mcpServer.GetAllExecutions()
		// 如果指定了状态筛选或工具筛选，先进行筛选
		if status != "" || toolName != "" {
			filtered := make([]*mcp.ToolExecution, 0)
			for _, exec := range allExecutions {
				matchStatus := status == "" || exec.Status == status
				// 支持部分匹配（模糊搜索）
				matchTool := toolNameFilterMatches(exec.ToolName, toolName)
				if matchStatus && matchTool {
					filtered = append(filtered, exec)
				}
			}
			allExecutions = filtered
		}
		total := len(allExecutions)
		offset := (page - 1) * pageSize
		end := offset + pageSize
		if end > total {
			end = total
		}
		if offset >= total {
			return []*mcp.ToolExecution{}, total
		}
		return allExecutions[offset:end], total
	}

	offset := (page - 1) * pageSize
	executions, err := h.db.LoadToolExecutionsWithPagination(offset, pageSize, status, toolName)
	if err != nil {
		h.logger.Warn("从数据库加载执行记录失败，回退到内存数据", zap.Error(err))
		allExecutions := h.mcpServer.GetAllExecutions()
		// 如果指定了状态筛选或工具筛选，先进行筛选
		if status != "" || toolName != "" {
			filtered := make([]*mcp.ToolExecution, 0)
			for _, exec := range allExecutions {
				matchStatus := status == "" || exec.Status == status
				// 支持部分匹配（模糊搜索）
				matchTool := toolNameFilterMatches(exec.ToolName, toolName)
				if matchStatus && matchTool {
					filtered = append(filtered, exec)
				}
			}
			allExecutions = filtered
		}
		total := len(allExecutions)
		offset := (page - 1) * pageSize
		end := offset + pageSize
		if end > total {
			end = total
		}
		if offset >= total {
			return []*mcp.ToolExecution{}, total
		}
		return allExecutions[offset:end], total
	}

	// 获取总数（考虑状态筛选和工具筛选）
	total, err := h.db.CountToolExecutions(status, toolName)
	if err != nil {
		h.logger.Warn("获取执行记录总数失败", zap.Error(err))
		// 回退：使用已加载的记录数估算
		total = offset + len(executions)
		if len(executions) == pageSize {
			total = offset + len(executions) + 1
		}
	}

	return executions, total
}

func (h *MonitorHandler) loadStats() map[string]*mcp.ToolStats {
	// 合并内部MCP服务器和外部MCP管理器的统计信息
	stats := make(map[string]*mcp.ToolStats)

	// 加载内部MCP服务器的统计信息
	if h.db == nil {
		internalStats := h.mcpServer.GetStats()
		for k, v := range internalStats {
			stats[k] = v
		}
	} else {
		dbStats, err := h.db.LoadToolStats()
		if err != nil {
			h.logger.Warn("从数据库加载统计信息失败，回退到内存数据", zap.Error(err))
			internalStats := h.mcpServer.GetStats()
			for k, v := range internalStats {
				stats[k] = v
			}
		} else {
			for k, v := range dbStats {
				stats[k] = v
			}
		}
	}

	// 合并外部MCP管理器的统计信息
	if h.externalMCPMgr != nil {
		externalStats := h.externalMCPMgr.GetToolStats()
		for k, v := range externalStats {
			// 如果已存在，合并统计信息
			if existing, exists := stats[k]; exists {
				existing.TotalCalls += v.TotalCalls
				existing.SuccessCalls += v.SuccessCalls
				existing.FailedCalls += v.FailedCalls
				// 使用最新的调用时间
				if v.LastCallTime != nil && (existing.LastCallTime == nil || v.LastCallTime.After(*existing.LastCallTime)) {
					existing.LastCallTime = v.LastCallTime
				}
			} else {
				stats[k] = v
			}
		}
	}

	return stats
}

// GetExecution 获取特定执行记录
func (h *MonitorHandler) GetExecution(c *gin.Context) {
	id := c.Param("id")

	// 先从内部MCP服务器查找
	exec, exists := h.mcpServer.GetExecution(id)
	if exists {
		c.JSON(http.StatusOK, exec)
		return
	}

	// 如果找不到，尝试从外部MCP管理器查找
	if h.externalMCPMgr != nil {
		exec, exists = h.externalMCPMgr.GetExecution(id)
		if exists {
			c.JSON(http.StatusOK, exec)
			return
		}
	}

	// 如果都找不到，尝试从数据库查找（如果使用数据库存储）
	if h.db != nil {
		exec, err := h.db.GetToolExecution(id)
		if err == nil && exec != nil {
			c.JSON(http.StatusOK, exec)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "执行记录未找到"})
}

// CancelExecution 手动取消进行中的 MCP 工具调用（仅取消该次 tools/call 的上下文，不停止整条 Agent / 迭代任务）
// 请求体可选 JSON：{ "note": "用户说明" }，将与工具已返回输出合并交给模型（含「用户终止说明」标题块，与命令行原文区分）。
func (h *MonitorHandler) CancelExecution(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "执行记录ID不能为空"})
		return
	}
	note := ""
	dec := json.NewDecoder(c.Request.Body)
	var body struct {
		Note string `json:"note"`
	}
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体须为 JSON，例如 {\"note\":\"说明\"}，可为空对象"})
		return
	}
	note = strings.TrimSpace(body.Note)
	if h.mcpServer.CancelToolExecutionWithNote(id, note) {
		h.logger.Info("已请求取消 MCP 工具执行", zap.String("executionId", id), zap.String("source", "internal"), zap.Bool("hasNote", note != ""))
		c.JSON(http.StatusOK, gin.H{"message": "已发送终止信号", "executionId": id})
		return
	}
	if h.externalMCPMgr != nil && h.externalMCPMgr.CancelToolExecutionWithNote(id, note) {
		h.logger.Info("已请求取消 MCP 工具执行", zap.String("executionId", id), zap.String("source", "external"), zap.Bool("hasNote", note != ""))
		c.JSON(http.StatusOK, gin.H{"message": "已发送终止信号", "executionId": id})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "未找到进行中的工具执行，或该任务已结束"})
}

// BatchGetToolNames 批量获取工具执行的工具名称（消除前端 N+1 请求）
func (h *MonitorHandler) BatchGetToolNames(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := make(map[string]string, len(req.IDs))
	for _, id := range req.IDs {
		// 先从内部MCP服务器查找
		if exec, exists := h.mcpServer.GetExecution(id); exists {
			result[id] = exec.ToolName
			continue
		}
		// 再从外部MCP管理器查找
		if h.externalMCPMgr != nil {
			if exec, exists := h.externalMCPMgr.GetExecution(id); exists {
				result[id] = exec.ToolName
				continue
			}
		}
		// 最后从数据库查找
		if h.db != nil {
			if exec, err := h.db.GetToolExecution(id); err == nil && exec != nil {
				result[id] = exec.ToolName
			}
		}
	}

	c.JSON(http.StatusOK, result)
}

// GetStats 获取统计信息
func (h *MonitorHandler) GetStats(c *gin.Context) {
	stats := h.loadStats()
	c.JSON(http.StatusOK, stats)
}

// CallsTimelinePoint 调用趋势数据点
type CallsTimelinePoint struct {
	T      time.Time `json:"t"`
	Total  int       `json:"total"`
	Failed int       `json:"failed"`
}

// CallsTimelineSummary 调用趋势汇总
type CallsTimelineSummary struct {
	TotalCalls int `json:"totalCalls"`
	Peak       int `json:"peak"`
}

// CallsTimelineResponse 调用趋势响应
type CallsTimelineResponse struct {
	Range   string               `json:"range"`
	Points  []CallsTimelinePoint `json:"points"`
	Summary CallsTimelineSummary `json:"summary"`
}

type callsTimelineConfig struct {
	rangeKey     string
	duration     time.Duration
	bucketSize   time.Duration
	dailyBuckets bool
}

func parseCallsTimelineRange(raw string) (callsTimelineConfig, bool) {
	switch strings.TrimSpace(raw) {
	case "24h":
		return callsTimelineConfig{rangeKey: "24h", duration: 24 * time.Hour, bucketSize: time.Hour, dailyBuckets: false}, true
	case "30d":
		return callsTimelineConfig{rangeKey: "30d", duration: 30 * 24 * time.Hour, bucketSize: 24 * time.Hour, dailyBuckets: true}, true
	default:
		return callsTimelineConfig{rangeKey: "7d", duration: 7 * 24 * time.Hour, bucketSize: time.Hour, dailyBuckets: false}, true
	}
}

func truncateToBucket(t time.Time, bucketSize time.Duration, dailyBuckets bool) time.Time {
	if dailyBuckets {
		y, m, d := t.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
	}
	return t.Truncate(bucketSize)
}

func buildCallsTimelinePoints(cfg callsTimelineConfig, buckets map[time.Time]struct{ total, failed int }) []CallsTimelinePoint {
	now := time.Now()
	start := truncateToBucket(now.Add(-cfg.duration), cfg.bucketSize, cfg.dailyBuckets)
	end := truncateToBucket(now, cfg.bucketSize, cfg.dailyBuckets)

	points := make([]CallsTimelinePoint, 0)
	for current := start; !current.After(end); current = current.Add(cfg.bucketSize) {
		val := buckets[current]
		points = append(points, CallsTimelinePoint{
			T:      current,
			Total:  val.total,
			Failed: val.failed,
		})
	}
	return points
}

func (h *MonitorHandler) loadCallsTimeline(cfg callsTimelineConfig) []CallsTimelinePoint {
	since := time.Now().Add(-cfg.duration)
	bucketMap := make(map[time.Time]struct{ total, failed int })

	if h.db != nil {
		dbBuckets, err := h.db.LoadCallsTimeline(since, cfg.dailyBuckets)
		if err != nil {
			h.logger.Warn("从数据库加载调用趋势失败，回退到内存数据", zap.Error(err))
		} else {
			for _, b := range dbBuckets {
				key := truncateToBucket(b.BucketTime, cfg.bucketSize, cfg.dailyBuckets)
				entry := bucketMap[key]
				entry.total += b.Total
				entry.failed += b.Failed
				bucketMap[key] = entry
			}
			return buildCallsTimelinePoints(cfg, bucketMap)
		}
	}

	for _, exec := range h.mcpServer.GetAllExecutions() {
		if exec == nil || exec.StartTime.Before(since) {
			continue
		}
		key := truncateToBucket(exec.StartTime, cfg.bucketSize, cfg.dailyBuckets)
		entry := bucketMap[key]
		entry.total++
		if exec.Status == "failed" || exec.Status == "cancelled" {
			entry.failed++
		}
		bucketMap[key] = entry
	}
	return buildCallsTimelinePoints(cfg, bucketMap)
}

// GetCallsTimeline 获取 MCP 工具调用趋势
func (h *MonitorHandler) GetCallsTimeline(c *gin.Context) {
	cfg, _ := parseCallsTimelineRange(c.Query("range"))
	points := h.loadCallsTimeline(cfg)

	summary := CallsTimelineSummary{}
	for _, p := range points {
		summary.TotalCalls += p.Total
		if p.Total > summary.Peak {
			summary.Peak = p.Total
		}
	}

	c.JSON(http.StatusOK, CallsTimelineResponse{
		Range:   cfg.rangeKey,
		Points:  points,
		Summary: summary,
	})
}

// DeleteExecution 删除执行记录
func (h *MonitorHandler) DeleteExecution(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "执行记录ID不能为空"})
		return
	}

	// 如果使用数据库，先获取执行记录信息，然后删除并更新统计
	if h.db != nil {
		// 先获取执行记录信息（用于更新统计）
		exec, err := h.db.GetToolExecution(id)
		if err != nil {
			// 如果找不到记录，可能已经被删除，直接返回成功
			h.logger.Warn("执行记录不存在，可能已被删除", zap.String("executionId", id), zap.Error(err))
			c.JSON(http.StatusOK, gin.H{"message": "执行记录不存在或已被删除"})
			return
		}

		// 删除执行记录
		err = h.db.DeleteToolExecution(id)
		if err != nil {
			h.logger.Error("删除执行记录失败", zap.Error(err), zap.String("executionId", id))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "删除执行记录失败: " + err.Error()})
			return
		}

		// 更新统计信息（减少相应的计数）
		totalCalls := 1
		successCalls := 0
		failedCalls := 0
		if exec.Status == "failed" || exec.Status == "cancelled" {
			failedCalls = 1
		} else if exec.Status == "completed" {
			successCalls = 1
		}

		if exec.ToolName != "" {
			if err := h.db.DecreaseToolStats(exec.ToolName, totalCalls, successCalls, failedCalls); err != nil {
				h.logger.Warn("更新统计信息失败", zap.Error(err), zap.String("toolName", exec.ToolName))
				// 不返回错误，因为记录已经删除成功
			}
		}

		h.logger.Info("执行记录已从数据库删除", zap.String("executionId", id), zap.String("toolName", exec.ToolName))
		if h.audit != nil {
			h.audit.RecordOK(c, "tool", "execution_delete", "删除工具执行记录", "tool_execution", id, map[string]interface{}{
				"tool_name": exec.ToolName,
			})
		}
		c.JSON(http.StatusOK, gin.H{"message": "执行记录已删除"})
		return
	}

	// 如果不使用数据库，尝试从内存中删除（内部MCP服务器）
	// 注意：内存中的记录可能已经被清理，所以这里只记录日志
	h.logger.Info("尝试删除内存中的执行记录", zap.String("executionId", id))
	c.JSON(http.StatusOK, gin.H{"message": "执行记录已删除（如果存在）"})
}

// DeleteExecutions 批量删除执行记录
func (h *MonitorHandler) DeleteExecutions(c *gin.Context) {
	var request struct {
		IDs []string `json:"ids"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数无效: " + err.Error()})
		return
	}

	if len(request.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "执行记录ID列表不能为空"})
		return
	}

	// 如果使用数据库，先获取执行记录信息，然后删除并更新统计
	if h.db != nil {
		// 先获取执行记录信息（用于更新统计）
		executions, err := h.db.GetToolExecutionsByIds(request.IDs)
		if err != nil {
			h.logger.Error("获取执行记录失败", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "获取执行记录失败: " + err.Error()})
			return
		}

		// 按工具名称分组统计需要减少的数量
		toolStats := make(map[string]struct {
			totalCalls   int
			successCalls int
			failedCalls  int
		})

		for _, exec := range executions {
			if exec.ToolName == "" {
				continue
			}

			stats := toolStats[exec.ToolName]
			stats.totalCalls++
			if exec.Status == "failed" || exec.Status == "cancelled" {
				stats.failedCalls++
			} else if exec.Status == "completed" {
				stats.successCalls++
			}
			toolStats[exec.ToolName] = stats
		}

		// 批量删除执行记录
		err = h.db.DeleteToolExecutions(request.IDs)
		if err != nil {
			h.logger.Error("批量删除执行记录失败", zap.Error(err), zap.Int("count", len(request.IDs)))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "批量删除执行记录失败: " + err.Error()})
			return
		}

		// 更新统计信息（减少相应的计数）
		for toolName, stats := range toolStats {
			if err := h.db.DecreaseToolStats(toolName, stats.totalCalls, stats.successCalls, stats.failedCalls); err != nil {
				h.logger.Warn("更新统计信息失败", zap.Error(err), zap.String("toolName", toolName))
				// 不返回错误，因为记录已经删除成功
			}
		}

		h.logger.Info("批量删除执行记录成功", zap.Int("count", len(request.IDs)))
		if h.audit != nil {
			h.audit.RecordOK(c, "tool", "execution_delete_batch", "批量删除工具执行记录", "tool_execution", "", map[string]interface{}{
				"count": len(request.IDs),
			})
		}
		c.JSON(http.StatusOK, gin.H{"message": "成功删除执行记录", "deleted": len(executions)})
		return
	}

	// 如果不使用数据库，尝试从内存中删除（内部MCP服务器）
	// 注意：内存中的记录可能已经被清理，所以这里只记录日志
	h.logger.Info("尝试批量删除内存中的执行记录", zap.Int("count", len(request.IDs)))
	c.JSON(http.StatusOK, gin.H{"message": "执行记录已删除（如果存在）"})
}

// normalizeToolNameFilter 将模型侧 mcp__tool 转为内部存储用的 mcp::tool。
func normalizeToolNameFilter(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}
	if strings.Contains(name, "::") {
		return name
	}
	if idx := strings.Index(name, "__"); idx > 0 {
		return name[:idx] + "::" + name[idx+2:]
	}
	return name
}

func toolNameFilterMatches(storedName, filter string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	storedLower := strings.ToLower(storedName)
	filterLower := strings.ToLower(filter)
	if strings.Contains(storedLower, filterLower) {
		return true
	}
	normFilter := strings.ToLower(normalizeToolNameFilter(filter))
	if normFilter != filterLower && strings.Contains(storedLower, normFilter) {
		return true
	}
	return strings.Contains(strings.ReplaceAll(storedLower, "::", "__"), filterLower)
}
