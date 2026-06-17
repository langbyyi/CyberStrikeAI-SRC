package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/c2"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/openai"
	"cyberstrike-ai/internal/storage"

	"go.uber.org/zap"
)

// Agent AI代理
type Agent struct {
	openAIClient          *openai.Client
	config                *config.OpenAIConfig
	agentConfig           *config.AgentConfig
	mcpServer             *mcp.Server
	externalMCPMgr        *mcp.ExternalMCPManager // 外部MCP管理器
	logger                *zap.Logger
	maxIterations         int
	resultStorage         ResultStorage     // 结果存储
	largeResultThreshold  int               // 大结果阈值（字节）
	mu                    sync.RWMutex      // 添加互斥锁以支持并发更新
	toolNameMapping       map[string]string // 工具名称映射：OpenAI格式 -> 原始格式（用于外部MCP工具）
	currentConversationID string            // 当前对话ID（用于自动传递给工具）
	promptBaseDir         string            // 解析 system_prompt_path 时相对路径的基准目录（通常为 config.yaml 所在目录）
	toolDescriptionMode   string            // 工具描述模式: "short" | "full"，默认 short
}

// ResultStorage 结果存储接口（直接使用 storage 包的类型）
type ResultStorage interface {
	SaveResult(executionID string, toolName string, result string) error
	GetResult(executionID string) (string, error)
	GetResultPage(executionID string, page int, limit int) (*storage.ResultPage, error)
	SearchResult(executionID string, keyword string, useRegex bool) ([]string, error)
	FilterResult(executionID string, filter string, useRegex bool) ([]string, error)
	GetResultMetadata(executionID string) (*storage.ResultMetadata, error)
	GetResultPath(executionID string) string
	DeleteResult(executionID string) error
}

type agentConversationIDKey struct{}

func withAgentConversationID(ctx context.Context, id string) context.Context {
	id = strings.TrimSpace(id)
	if id == "" || ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, agentConversationIDKey{}, id)
}

func agentConversationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(agentConversationIDKey{}).(string)
	return v
}

// ConversationIDFromContext 返回当前 Agent 请求上下文中注入的对话 ID（如 C2 MCP 入队与人机协同门控使用）。
func ConversationIDFromContext(ctx context.Context) string {
	return agentConversationIDFromContext(ctx)
}

// NewAgent 创建新的Agent
func NewAgent(cfg *config.OpenAIConfig, agentCfg *config.AgentConfig, mcpServer *mcp.Server, externalMCPMgr *mcp.ExternalMCPManager, logger *zap.Logger, maxIterations int) *Agent {
	// 如果 maxIterations 为 0 或负数，使用默认值 30
	if maxIterations <= 0 {
		maxIterations = 30
	}

	// 设置大结果阈值，默认50KB
	largeResultThreshold := 50 * 1024
	if agentCfg != nil && agentCfg.LargeResultThreshold > 0 {
		largeResultThreshold = agentCfg.LargeResultThreshold
	}

	// 设置结果存储目录，默认tmp
	resultStorageDir := "tmp"
	if agentCfg != nil && agentCfg.ResultStorageDir != "" {
		resultStorageDir = agentCfg.ResultStorageDir
	}

	// 初始化结果存储
	var resultStorage ResultStorage
	if resultStorageDir != "" {
		// 导入storage包（避免循环依赖，使用接口）
		// 这里需要在实际使用时初始化
		// 暂时设为nil，在需要时初始化
	}

	// 配置HTTP Transport，优化连接管理和超时设置
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   300 * time.Second,
			KeepAlive: 300 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Minute, // 响应头超时：增加到15分钟，应对大响应
		DisableKeepAlives:     false,            // 启用连接复用
	}

	// 增加超时时间到30分钟，以支持长时间运行的AI推理
	// 特别是当使用流式响应或处理复杂任务时
	httpClient := &http.Client{
		Timeout:   30 * time.Minute, // 从5分钟增加到30分钟
		Transport: transport,
	}
	llmClient := openai.NewClient(cfg, httpClient, logger)

	return &Agent{
		openAIClient:         llmClient,
		config:               cfg,
		agentConfig:          agentCfg,
		mcpServer:            mcpServer,
		externalMCPMgr:       externalMCPMgr,
		logger:               logger,
		maxIterations:        maxIterations,
		resultStorage:        resultStorage,
		largeResultThreshold: largeResultThreshold,
		toolNameMapping:      make(map[string]string), // 初始化工具名称映射
		toolDescriptionMode:  "short",
	}
}

// SetResultStorage 设置结果存储（用于避免循环依赖）
func (a *Agent) SetResultStorage(storage ResultStorage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resultStorage = storage
}

// SetPromptBaseDir 设置单代理 system_prompt_path 相对路径的基准目录（一般为 config.yaml 所在目录）。
func (a *Agent) SetPromptBaseDir(dir string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.promptBaseDir = strings.TrimSpace(dir)
}

// ChatMessage 聊天消息
type ChatMessage struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	// ToolName 仅 tool 角色：从 Eino/轨迹 JSON 的 name 或 tool_name 恢复，供续跑构造 ToolMessage。
	ToolName string `json:"tool_name,omitempty"`
	// ReasoningContent 对应 OpenAI/DeepSeek 的 reasoning_content；思考模式 + 工具调用后续跑须回传（见 DeepSeek 文档）。
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

// MarshalJSON 自定义JSON序列化，将tool_calls中的arguments转换为JSON字符串
func (cm ChatMessage) MarshalJSON() ([]byte, error) {
	// 构建序列化结构
	aux := map[string]interface{}{
		"role": cm.Role,
	}

	// 添加content（如果存在）
	if cm.Content != "" {
		aux["content"] = cm.Content
	}
	if cm.ReasoningContent != "" {
		aux["reasoning_content"] = cm.ReasoningContent
	}

	// 添加tool_call_id（如果存在）
	if cm.ToolCallID != "" {
		aux["tool_call_id"] = cm.ToolCallID
	}
	if cm.ToolName != "" {
		aux["tool_name"] = cm.ToolName
	}

	// 转换tool_calls，将arguments转换为JSON字符串
	if len(cm.ToolCalls) > 0 {
		toolCallsJSON := make([]map[string]interface{}, len(cm.ToolCalls))
		for i, tc := range cm.ToolCalls {
			// 将arguments转换为JSON字符串
			argsJSON := ""
			if tc.Function.Arguments != nil {
				argsBytes, err := json.Marshal(tc.Function.Arguments)
				if err != nil {
					return nil, err
				}
				argsJSON = string(argsBytes)
			}

			toolCallsJSON[i] = map[string]interface{}{
				"id":   tc.ID,
				"type": tc.Type,
				"function": map[string]interface{}{
					"name":      tc.Function.Name,
					"arguments": argsJSON,
				},
			}
		}
		aux["tool_calls"] = toolCallsJSON
	}

	return json.Marshal(aux)
}

// OpenAIRequest OpenAI API请求
type OpenAIRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Tools    []Tool        `json:"tools,omitempty"`
	Stream   bool          `json:"stream,omitempty"`
}

// OpenAIResponse OpenAI API响应
type OpenAIResponse struct {
	ID      string   `json:"id"`
	Choices []Choice `json:"choices"`
	Error   *Error   `json:"error,omitempty"`
}

// Choice 选择
type Choice struct {
	Message      MessageWithTools `json:"message"`
	FinishReason string           `json:"finish_reason"`
}

// MessageWithTools 带工具调用的消息
type MessageWithTools struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// Tool OpenAI工具定义
type Tool struct {
	Type     string             `json:"type"`
	Function FunctionDefinition `json:"function"`
}

// FunctionDefinition 函数定义
type FunctionDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// Error OpenAI错误
type Error struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// ToolCall 工具调用
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall 函数调用
type FunctionCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// UnmarshalJSON 自定义JSON解析，处理arguments可能是字符串或对象的情况
func (fc *FunctionCall) UnmarshalJSON(data []byte) error {
	type Alias FunctionCall
	aux := &struct {
		Name      string      `json:"name"`
		Arguments interface{} `json:"arguments"`
		*Alias
	}{
		Alias: (*Alias)(fc),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	fc.Name = aux.Name

	// 处理arguments可能是字符串或对象的情况
	switch v := aux.Arguments.(type) {
	case map[string]interface{}:
		fc.Arguments = v
	case string:
		// 如果是字符串，尝试解析为JSON
		if err := json.Unmarshal([]byte(v), &fc.Arguments); err != nil {
			// 如果解析失败，创建一个包含原始字符串的map
			fc.Arguments = map[string]interface{}{
				"raw": v,
			}
		}
	case nil:
		fc.Arguments = make(map[string]interface{})
	default:
		// 其他类型，尝试转换为map
		fc.Arguments = map[string]interface{}{
			"value": v,
		}
	}

	return nil
}

// ProgressCallback 进度回调函数类型
type ProgressCallback func(eventType, message string, data interface{})

// EinoSingleAgentSystemInstruction 供 Eino adk.ChatModelAgent.Instruction 使用（含 system_prompt_path）。
func (a *Agent) EinoSingleAgentSystemInstruction() string {
	systemPrompt := DefaultSingleAgentSystemPrompt()
	if a.agentConfig != nil {
		if p := strings.TrimSpace(a.agentConfig.SystemPromptPath); p != "" {
			path := p
			a.mu.RLock()
			base := a.promptBaseDir
			a.mu.RUnlock()
			if !filepath.IsAbs(path) && base != "" {
				path = filepath.Join(base, path)
			}
			if b, err := os.ReadFile(path); err != nil {
				a.logger.Warn("读取单代理 system_prompt_path 失败，使用内置提示", zap.String("path", path), zap.Error(err))
			} else if s := strings.TrimSpace(string(b)); s != "" {
				systemPrompt = s
			}
		}
	}
	return systemPrompt
}

// getAvailableTools 获取可用工具
// 从MCP服务器动态获取工具列表，描述模式由 tool_description_mode 控制
// roleTools: 角色配置的工具列表（toolKey格式），如果为空或nil，则使用所有工具（默认角色）
func (a *Agent) getAvailableTools(roleTools []string) []Tool {
	// 构建角色工具集合（用于快速查找）
	roleToolSet := make(map[string]bool)
	if len(roleTools) > 0 {
		for _, toolKey := range roleTools {
			roleToolSet[toolKey] = true
		}
	}

	// 从MCP服务器获取所有已注册的内部工具
	mcpTools := a.mcpServer.GetAllTools()

	// 转换为OpenAI格式的工具定义
	tools := make([]Tool, 0, len(mcpTools))
	for _, mcpTool := range mcpTools {
		// 如果指定了角色工具列表，只添加在列表中的工具
		if len(roleToolSet) > 0 {
			toolKey := mcpTool.Name // 内置工具使用工具名称作为key
			if !roleToolSet[toolKey] {
				continue // 不在角色工具列表中，跳过
			}
		}
		description := a.pickToolDescription(mcpTool.ShortDescription, mcpTool.Description)

		// 转换schema中的类型为OpenAI标准类型
		convertedSchema := a.convertSchemaTypes(mcpTool.InputSchema)

		tools = append(tools, Tool{
			Type: "function",
			Function: FunctionDefinition{
				Name:        mcpTool.Name,
				Description: description, // 使用简短描述减少token消耗
				Parameters:  convertedSchema,
			},
		})
	}

	// 获取外部MCP工具
	if a.externalMCPMgr != nil {
		// 增加超时时间到30秒，因为通过代理连接远程服务器可能需要更长时间
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		externalTools, err := a.externalMCPMgr.GetAllTools(ctx)
		extMap := make(map[string]string)
		if err != nil {
			a.logger.Warn("获取外部MCP工具失败", zap.Error(err))
		} else {
			// 获取外部MCP配置，用于检查工具启用状态
			externalMCPConfigs := a.externalMCPMgr.GetConfigs()

			// 将外部MCP工具添加到工具列表（只添加启用的工具）
			for _, externalTool := range externalTools {
				// 外部工具使用 "mcpName::toolName" 作为toolKey
				externalToolKey := externalTool.Name

				// 如果指定了角色工具列表，只添加在列表中的工具
				if len(roleToolSet) > 0 {
					if !roleToolSet[externalToolKey] {
						continue // 不在角色工具列表中，跳过
					}
				}

				// 解析工具名称：mcpName::toolName
				var mcpName, actualToolName string
				if idx := strings.Index(externalTool.Name, "::"); idx > 0 {
					mcpName = externalTool.Name[:idx]
					actualToolName = externalTool.Name[idx+2:]
				} else {
					continue // 跳过格式不正确的工具
				}

				// 检查工具是否启用
				enabled := false
				if cfg, exists := externalMCPConfigs[mcpName]; exists {
					// 首先检查外部MCP是否启用
					if !cfg.ExternalMCPEnable {
						enabled = false // MCP未启用，所有工具都禁用
					} else {
						// MCP已启用，检查单个工具的启用状态
						// 如果ToolEnabled为空或未设置该工具，默认为启用（向后兼容）
						if cfg.ToolEnabled == nil {
							enabled = true // 未设置工具状态，默认为启用
						} else if toolEnabled, exists := cfg.ToolEnabled[actualToolName]; exists {
							enabled = toolEnabled // 使用配置的工具状态
						} else {
							enabled = true // 工具未在配置中，默认为启用
						}
					}
				}

				// 只添加启用的工具
				if !enabled {
					continue
				}

				description := a.pickToolDescription(externalTool.ShortDescription, externalTool.Description)

				// 转换schema中的类型为OpenAI标准类型
				convertedSchema := a.convertSchemaTypes(externalTool.InputSchema)

				// 将工具名称中的 "::" 替换为 "__" 以符合OpenAI命名规范
				// OpenAI要求工具名称只能包含 [a-zA-Z0-9_-]
				openAIName := strings.ReplaceAll(externalTool.Name, "::", "__")

				// 保存名称映射关系（OpenAI格式 -> 原始格式）
				extMap[openAIName] = externalTool.Name

				tools = append(tools, Tool{
					Type: "function",
					Function: FunctionDefinition{
						Name:        openAIName, // 使用符合OpenAI规范的名称
						Description: description,
						Parameters:  convertedSchema,
					},
				})
			}
		}
		a.mu.Lock()
		a.toolNameMapping = extMap
		a.mu.Unlock()
	}

	a.logger.Debug("获取可用工具列表",
		zap.Int("internalTools", len(mcpTools)),
		zap.Int("totalTools", len(tools)),
	)

	return tools
}

func (a *Agent) pickToolDescription(shortDesc, fullDesc string) string {
	a.mu.RLock()
	mode := strings.TrimSpace(strings.ToLower(a.toolDescriptionMode))
	a.mu.RUnlock()
	if mode == "full" {
		return fullDesc
	}
	if shortDesc != "" {
		return shortDesc
	}
	return fullDesc
}

// convertSchemaTypes 递归转换schema中的类型为OpenAI标准类型
func (a *Agent) convertSchemaTypes(schema map[string]interface{}) map[string]interface{} {
	if schema == nil {
		return schema
	}

	// 创建新的schema副本
	converted := make(map[string]interface{})
	for k, v := range schema {
		converted[k] = v
	}

	// 转换properties中的类型
	if properties, ok := converted["properties"].(map[string]interface{}); ok {
		convertedProperties := make(map[string]interface{})
		for propName, propValue := range properties {
			if prop, ok := propValue.(map[string]interface{}); ok {
				convertedProp := make(map[string]interface{})
				for pk, pv := range prop {
					if pk == "type" {
						// 转换类型
						if typeStr, ok := pv.(string); ok {
							convertedProp[pk] = a.convertToOpenAIType(typeStr)
						} else {
							convertedProp[pk] = pv
						}
					} else {
						convertedProp[pk] = pv
					}
				}
				convertedProperties[propName] = convertedProp
			} else {
				convertedProperties[propName] = propValue
			}
		}
		converted["properties"] = convertedProperties
	}

	return converted
}

// convertToOpenAIType 将配置中的类型转换为OpenAI/JSON Schema标准类型
func (a *Agent) convertToOpenAIType(configType string) string {
	switch configType {
	case "bool":
		return "boolean"
	case "int", "integer":
		return "number"
	case "float", "double":
		return "number"
	case "string", "array", "object":
		return configType
	default:
		// 默认返回原类型
		return configType
	}
}

// ToolExecutionResult MCP 工具执行结果（供 Eino 桥与监控落库使用）。
type ToolExecutionResult struct {
	Result      string
	ExecutionID string
	IsError     bool
}

// executeToolViaMCP 通过MCP执行工具
// 即使工具执行失败，也返回结果而不是错误，让AI能够处理错误情况
func (a *Agent) executeToolViaMCP(ctx context.Context, toolName string, args map[string]interface{}) (*ToolExecutionResult, error) {
	a.logger.Info("通过MCP执行工具",
		zap.String("tool", toolName),
		zap.Any("args", args),
	)

	// 如果是record_vulnerability工具，自动添加conversation_id
	if toolName == builtin.ToolRecordVulnerability {
		conversationID := agentConversationIDFromContext(ctx)
		if conversationID == "" {
			a.mu.RLock()
			conversationID = a.currentConversationID
			a.mu.RUnlock()
		}

		if conversationID != "" {
			args["conversation_id"] = conversationID
			a.logger.Debug("自动添加conversation_id到record_vulnerability工具",
				zap.String("conversation_id", conversationID),
			)
		} else {
			a.logger.Warn("record_vulnerability工具调用时conversation_id为空")
		}
	}

	var result *mcp.ToolResult
	var executionID string
	var err error

	// 单次工具执行超时：防止单个工具长时间挂起（如 30 分钟仍显示执行中）
	toolCtx := ctx
	var toolCancel context.CancelFunc
	if a.agentConfig != nil && a.agentConfig.ToolTimeoutMinutes > 0 {
		toolCtx, toolCancel = context.WithTimeout(ctx, time.Duration(a.agentConfig.ToolTimeoutMinutes)*time.Minute)
		defer func() {
			if toolCancel != nil {
				toolCancel()
			}
		}()
	}
	// C2 危险任务 HITL 异步等待：须绑定整条 Agent 运行期 ctx，而非单次工具子 ctx（return 时会被 cancel）
	toolCtx = c2.WithHITLRunContext(toolCtx, ctx)

	// 检查是否是外部MCP工具（通过工具名称映射）
	a.mu.RLock()
	originalToolName, isExternalTool := a.toolNameMapping[toolName]
	a.mu.RUnlock()

	if isExternalTool && a.externalMCPMgr != nil {
		// 使用原始工具名称调用外部MCP工具
		a.logger.Debug("调用外部MCP工具",
			zap.String("openAIName", toolName),
			zap.String("originalName", originalToolName),
		)
		result, executionID, err = a.externalMCPMgr.CallTool(toolCtx, originalToolName, args)
	} else {
		// 调用内部MCP工具
		result, executionID, err = a.mcpServer.CallTool(toolCtx, toolName, args)
	}

	// 如果调用失败（如工具不存在、超时），返回友好的错误信息而不是抛出异常
	if err != nil {
		detail := err.Error()
		if errors.Is(err, context.Canceled) {
			detail = "工具调用已被手动终止（MCP 监控页）。智能体将携带此结果继续后续步骤，整条任务不会因此被停止。"
		} else if errors.Is(err, context.DeadlineExceeded) {
			min := 10
			if a.agentConfig != nil && a.agentConfig.ToolTimeoutMinutes > 0 {
				min = a.agentConfig.ToolTimeoutMinutes
			}
			detail = fmt.Sprintf("工具执行超过 %d 分钟被自动终止（可在 config.yaml 的 agent.tool_timeout_minutes 中调整）", min)
		}
		errorMsg := fmt.Sprintf(`工具调用失败

工具名称: %s
错误类型: 系统错误
错误详情: %s

可能的原因：
- 工具 "%s" 不存在或未启用
- 单次执行超时（agent.tool_timeout_minutes）
- 系统配置问题
- 网络或权限问题

建议：
- 检查工具名称是否正确
- 若需更长执行时间，可适当增大 agent.tool_timeout_minutes
- 尝试使用其他替代工具
- 如果这是必需的工具，请向用户说明情况`, toolName, detail, toolName)

		return &ToolExecutionResult{
			Result:      errorMsg,
			ExecutionID: executionID,
			IsError:     true,
		}, nil // 返回 nil 错误，让调用者处理结果
	}

	// 格式化结果
	var resultText strings.Builder
	for _, content := range result.Content {
		resultText.WriteString(content.Text)
		resultText.WriteString("\n")
	}

	resultStr := resultText.String()
	resultSize := len(resultStr)

	// 检测大结果并保存
	a.mu.RLock()
	threshold := a.largeResultThreshold
	storage := a.resultStorage
	a.mu.RUnlock()

	if resultSize > threshold && storage != nil {
		// 异步保存大结果
		go func() {
			if err := storage.SaveResult(executionID, toolName, resultStr); err != nil {
				a.logger.Warn("保存大结果失败",
					zap.String("executionID", executionID),
					zap.String("toolName", toolName),
					zap.Error(err),
				)
			} else {
				a.logger.Info("大结果已保存",
					zap.String("executionID", executionID),
					zap.String("toolName", toolName),
					zap.Int("size", resultSize),
				)
			}
		}()

		// 返回最小化通知
		lines := strings.Split(resultStr, "\n")
		filePath := ""
		if storage != nil {
			filePath = storage.GetResultPath(executionID)
		}
		notification := a.formatMinimalNotification(executionID, toolName, resultSize, len(lines), filePath)

		return &ToolExecutionResult{
			Result:      notification,
			ExecutionID: executionID,
			IsError:     result != nil && result.IsError,
		}, nil
	}

	return &ToolExecutionResult{
		Result:      resultStr,
		ExecutionID: executionID,
		IsError:     result != nil && result.IsError,
	}, nil
}

// formatMinimalNotification 格式化最小化通知
func (a *Agent) formatMinimalNotification(executionID string, toolName string, size int, lineCount int, filePath string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("工具执行完成。结果已保存（ID: %s）。\n\n", executionID))
	sb.WriteString("结果信息：\n")
	sb.WriteString(fmt.Sprintf("  - 工具: %s\n", toolName))
	sb.WriteString(fmt.Sprintf("  - 大小: %d 字节 (%.2f KB)\n", size, float64(size)/1024))
	sb.WriteString(fmt.Sprintf("  - 行数: %d 行\n", lineCount))
	if filePath != "" {
		sb.WriteString(fmt.Sprintf("  - 文件路径: %s\n", filePath))
	}
	sb.WriteString("\n")
	sb.WriteString("推荐使用 query_execution_result 工具查询完整结果：\n")
	sb.WriteString(fmt.Sprintf("  - 查询第一页: query_execution_result(execution_id=\"%s\", page=1, limit=100)\n", executionID))
	sb.WriteString(fmt.Sprintf("  - 搜索关键词: query_execution_result(execution_id=\"%s\", search=\"关键词\")\n", executionID))
	sb.WriteString(fmt.Sprintf("  - 过滤条件: query_execution_result(execution_id=\"%s\", filter=\"error\")\n", executionID))
	sb.WriteString(fmt.Sprintf("  - 正则匹配: query_execution_result(execution_id=\"%s\", search=\"\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+\", use_regex=true)\n", executionID))
	sb.WriteString("\n")
	if filePath != "" {
		sb.WriteString("如果 query_execution_result 工具不满足需求，也可以使用其他工具处理文件：\n")
		sb.WriteString("\n")
		sb.WriteString("**分段读取示例：**\n")
		sb.WriteString(fmt.Sprintf("  - 查看前100行: exec(command=\"head\", args=[\"-n\", \"100\", \"%s\"])\n", filePath))
		sb.WriteString(fmt.Sprintf("  - 查看后100行: exec(command=\"tail\", args=[\"-n\", \"100\", \"%s\"])\n", filePath))
		sb.WriteString(fmt.Sprintf("  - 查看第50-150行: exec(command=\"sed\", args=[\"-n\", \"50,150p\", \"%s\"])\n", filePath))
		sb.WriteString("\n")
		sb.WriteString("**搜索和正则匹配示例：**\n")
		sb.WriteString(fmt.Sprintf("  - 搜索关键词: exec(command=\"grep\", args=[\"关键词\", \"%s\"])\n", filePath))
		sb.WriteString(fmt.Sprintf("  - 正则匹配IP地址: exec(command=\"grep\", args=[\"-E\", \"\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+\", \"%s\"])\n", filePath))
		sb.WriteString(fmt.Sprintf("  - 不区分大小写搜索: exec(command=\"grep\", args=[\"-i\", \"关键词\", \"%s\"])\n", filePath))
		sb.WriteString(fmt.Sprintf("  - 显示匹配行号: exec(command=\"grep\", args=[\"-n\", \"关键词\", \"%s\"])\n", filePath))
		sb.WriteString("\n")
		sb.WriteString("**过滤和统计示例：**\n")
		sb.WriteString(fmt.Sprintf("  - 统计总行数: exec(command=\"wc\", args=[\"-l\", \"%s\"])\n", filePath))
		sb.WriteString(fmt.Sprintf("  - 过滤包含error的行: exec(command=\"grep\", args=[\"error\", \"%s\"])\n", filePath))
		sb.WriteString(fmt.Sprintf("  - 排除空行: exec(command=\"grep\", args=[\"-v\", \"^$\", \"%s\"])\n", filePath))
		sb.WriteString("\n")
		sb.WriteString("**完整读取（不推荐大文件）：**\n")
		sb.WriteString(fmt.Sprintf("  - 使用 cat 工具: cat(file=\"%s\")\n", filePath))
		sb.WriteString(fmt.Sprintf("  - 使用 exec 工具: exec(command=\"cat\", args=[\"%s\"])\n", filePath))
		sb.WriteString("\n")
		sb.WriteString("**注意：**\n")
		sb.WriteString("  - 直接读取大文件可能会再次触发大结果保存机制\n")
		sb.WriteString("  - 建议优先使用分段读取和搜索功能，避免一次性加载整个文件\n")
		sb.WriteString("  - 正则表达式语法遵循标准 POSIX 正则表达式规范\n")
	}

	return sb.String()
}

// UpdateConfig 更新OpenAI配置
func (a *Agent) UpdateConfig(cfg *config.OpenAIConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = cfg

	a.logger.Info("Agent配置已更新",
		zap.String("base_url", cfg.BaseURL),
		zap.String("model", cfg.Model),
	)
}

// UpdateMaxIterations 更新最大迭代次数
func (a *Agent) UpdateMaxIterations(maxIterations int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if maxIterations > 0 {
		a.maxIterations = maxIterations
		a.logger.Info("Agent最大迭代次数已更新", zap.Int("max_iterations", maxIterations))
	}
}

// UpdateToolDescriptionMode 更新工具描述模式（short/full）
func (a *Agent) UpdateToolDescriptionMode(mode string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode != "full" {
		mode = "short"
	}
	a.toolDescriptionMode = mode
	a.logger.Info("Agent工具描述模式已更新", zap.String("tool_description_mode", mode))
}

// RepairOrphanToolMessages 清理失去配对的tool消息和未完成的tool_calls，避免OpenAI报错
// 同时确保历史消息中的tool_calls只作为上下文记忆，不会触发重新执行
// 这是一个公开方法，可以在恢复历史消息时调用
func (a *Agent) RepairOrphanToolMessages(messages *[]ChatMessage) bool {
	return a.repairOrphanToolMessages(messages)
}

// repairOrphanToolMessages 清理失去配对的tool消息和未完成的tool_calls，避免OpenAI报错
// 同时确保历史消息中的tool_calls只作为上下文记忆，不会触发重新执行
func (a *Agent) repairOrphanToolMessages(messages *[]ChatMessage) bool {
	if messages == nil {
		return false
	}

	msgs := *messages
	if len(msgs) == 0 {
		return false
	}

	pending := make(map[string]int)
	cleaned := make([]ChatMessage, 0, len(msgs))
	removed := false

	for _, msg := range msgs {
		switch strings.ToLower(msg.Role) {
		case "assistant":
			if len(msg.ToolCalls) > 0 {
				// 记录所有tool_call IDs
				for _, tc := range msg.ToolCalls {
					if tc.ID != "" {
						pending[tc.ID]++
					}
				}
			}
			cleaned = append(cleaned, msg)
		case "tool":
			callID := msg.ToolCallID
			if callID == "" {
				removed = true
				continue
			}
			if count, exists := pending[callID]; exists && count > 0 {
				if count == 1 {
					delete(pending, callID)
				} else {
					pending[callID] = count - 1
				}
				cleaned = append(cleaned, msg)
			} else {
				removed = true
				continue
			}
		default:
			cleaned = append(cleaned, msg)
		}
	}

	// 如果还有未匹配的tool_calls（即assistant消息有tool_calls但没有对应的tool响应）
	// 需要从最后的assistant消息中移除这些tool_calls，避免AI重新执行它们
	if len(pending) > 0 {
		// 从后往前查找最后一个assistant消息
		for i := len(cleaned) - 1; i >= 0; i-- {
			if strings.ToLower(cleaned[i].Role) == "assistant" && len(cleaned[i].ToolCalls) > 0 {
				// 移除未匹配的tool_calls
				originalCount := len(cleaned[i].ToolCalls)
				validToolCalls := make([]ToolCall, 0)
				for _, tc := range cleaned[i].ToolCalls {
					if tc.ID != "" && pending[tc.ID] > 0 {
						// 这个tool_call没有对应的tool响应，移除它
						removed = true
						delete(pending, tc.ID)
					} else {
						validToolCalls = append(validToolCalls, tc)
					}
				}
				// 更新消息的ToolCalls
				if len(validToolCalls) != originalCount {
					cleaned[i].ToolCalls = validToolCalls
					a.logger.Info("移除了未完成的tool_calls，避免重新执行",
						zap.Int("removed_count", originalCount-len(validToolCalls)),
					)
				}
				break
			}
		}
	}

	if removed {
		a.logger.Warn("修复了对话历史中的tool消息和tool_calls",
			zap.Int("original_messages", len(msgs)),
			zap.Int("cleaned_messages", len(cleaned)),
		)
		*messages = cleaned
	}

	return removed
}

// ToolsForRole 返回与单 Agent 循环一致的工具定义（OpenAI function 格式），供 Eino DeepAgent 等编排层绑定 MCP 工具。
func (a *Agent) ToolsForRole(roleTools []string) []Tool {
	return a.getAvailableTools(roleTools)
}

// ExecuteMCPToolForConversation 在指定会话上下文中执行 MCP 工具（行为与主 Agent 循环中的工具调用一致，如自动注入 conversation_id）。
func (a *Agent) ExecuteMCPToolForConversation(ctx context.Context, conversationID, toolName string, args map[string]interface{}) (*ToolExecutionResult, error) {
	a.mu.Lock()
	prev := a.currentConversationID
	a.currentConversationID = conversationID
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.currentConversationID = prev
		a.mu.Unlock()
	}()
	ctx = withAgentConversationID(ctx, conversationID)
	return a.executeToolViaMCP(ctx, toolName, args)
}

// RecordLocalToolExecution 将非 CallTool 路径完成的工具调用写入 MCP 监控库（与 CallTool 落库一致），返回 executionId。
// 用于 Eino filesystem execute 等场景，使助手气泡「渗透测试详情」与常规 MCP 一致可点进监控。
func (a *Agent) RecordLocalToolExecution(toolName string, args map[string]interface{}, resultText string, invokeErr error) string {
	if a == nil || a.mcpServer == nil {
		return ""
	}
	return a.mcpServer.RecordCompletedToolInvocation(toolName, args, resultText, invokeErr)
}

// CancelMCPToolExecutionWithNote 取消一次进行中的 MCP 工具（先内部后外部），与监控页「终止工具」一致；note 非空时合并进返回给模型的文本。
func (a *Agent) CancelMCPToolExecutionWithNote(executionID, note string) bool {
	executionID = strings.TrimSpace(executionID)
	note = strings.TrimSpace(note)
	if executionID == "" {
		return false
	}
	if a.mcpServer != nil && a.mcpServer.CancelToolExecutionWithNote(executionID, note) {
		return true
	}
	if a.externalMCPMgr != nil && a.externalMCPMgr.CancelToolExecutionWithNote(executionID, note) {
		return true
	}
	return false
}

// extractQuotedToolName 尝试从错误信息中提取被引用的工具名称
func extractQuotedToolName(errMsg string) string {
	start := strings.Index(errMsg, "\"")
	if start == -1 {
		return ""
	}
	rest := errMsg[start+1:]
	end := strings.Index(rest, "\"")
	if end == -1 {
		return ""
	}
	return rest[:end]
}
