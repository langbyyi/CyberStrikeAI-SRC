package handler

import (
	"context"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/multiagent"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/vision"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// multiAgentPrepared 多代理请求在调用 Eino 前的会话与消息准备结果。
type multiAgentPrepared struct {
	ConversationID     string
	CreatedNew         bool
	History            []agent.ChatMessage
	FinalMessage       string
	RoleTools          []string
	AssistantMessageID string
	UserMessageID      string
	// TurnImages 本轮随附的图片（仅当所走 AI 通道声明 supports_vision 时非空）。
	// 图片字节只随本轮消息直发主模型，不写入历史；历史里只有附件路径。
	TurnImages []multiagent.TurnImage
}

// withTurnImages 把本轮图片挂到 ctx 交给 runner；通道未声明多模态或本轮无图时原样返回。
func (h *AgentHandler) withTurnImages(ctx context.Context, runCfg *config.Config, prep *multiAgentPrepared) context.Context {
	if ctx == nil || runCfg == nil || prep == nil || len(prep.TurnImages) == 0 {
		return ctx
	}
	if !runCfg.OpenAI.SupportsVision {
		return ctx
	}
	return multiagent.WithTurnImages(ctx, prep.TurnImages)
}

// aiChannelSupportsVision 该请求所走 AI 通道的主模型是否声明可直接接收图片。
func (h *AgentHandler) aiChannelSupportsVision(channelID string) bool {
	if h == nil || h.config == nil {
		return false
	}
	oa, _, _ := h.config.ResolveAIChannel(channelID)
	return oa.SupportsVision
}

// buildTurnImages 把附件里的图片编码为主模型可原生消费的图片输入。
// 逐张失败只降级该张（其余走路径 + analyze_image），总量超预算即停止追加。
func buildTurnImages(paths []string, logger *zap.Logger) []multiagent.TurnImage {
	filtered := vision.FilterImagePaths(paths, vision.NativeMaxImages)
	out := make([]multiagent.TurnImage, 0, len(filtered))
	var total int
	for _, p := range filtered {
		img, err := vision.PrepareNativeImage(p)
		if err != nil {
			if logger != nil {
				logger.Warn("附件图片编码失败，退回流路径", zap.String("path", p), zap.Error(err))
			}
			continue
		}
		if total+img.Bytes > vision.NativeMaxTotalBytes {
			if logger != nil {
				logger.Info("附件图片总量超出本轮预算，后续图片退回流路径",
					zap.Int("included", len(out)), zap.Int("budget_bytes", vision.NativeMaxTotalBytes))
			}
			break
		}
		total += img.Bytes
		out = append(out, multiagent.TurnImage{
			Path:     img.Path,
			Base64:   img.Base64,
			MIMEType: img.MIMEType,
			Detail:   img.Detail,
		})
	}
	return out
}

func chatRequestAgentMode(req *ChatRequest, source string) string {
	if strings.HasPrefix(strings.TrimSpace(source), "multi_agent") {
		return config.NormalizeMultiAgentOrchestration(req.Orchestration)
	}
	return "eino_single"
}

func (h *AgentHandler) prepareMultiAgentSession(req *ChatRequest, c *gin.Context, source string) (*multiAgentPrepared, error) {
	if _, err := database.NormalizeTestingSpecification(req.TestingSpecification); err != nil {
		return nil, err
	}
	if len(req.Attachments) > maxAttachments {
		return nil, fmt.Errorf("附件最多 %d 个", maxAttachments)
	}

	conversationID := strings.TrimSpace(req.ConversationID)
	projectID := strings.TrimSpace(effectiveProjectID(h.config, req.ProjectID))
	webshellID := strings.TrimSpace(req.WebShellConnectionID)
	session, hasSession := security.CurrentSession(c)
	if !hasSession || !session.Permissions["chat:write"] {
		return nil, fmt.Errorf("无权写入对话")
	}
	canAccess := func(resourceType, resourceID string) bool {
		if !hasSession || h.db == nil || strings.TrimSpace(resourceID) == "" {
			return false
		}
		return h.db.UserCanAccessResource(session.UserID, session.Scope, resourceType, resourceID)
	}
	if projectID != "" && (!session.Permissions["project:read"] || h.db == nil || !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("project:read"), "project", projectID)) {
		return nil, fmt.Errorf("无权访问目标项目")
	}
	if webshellID != "" && (!session.Permissions["webshell:write"] || !canAccess("webshell", webshellID)) {
		return nil, fmt.Errorf("无权访问该 WebShell 连接")
	}
	createdNew := false
	if conversationID == "" {
		title := safeTruncateString(req.Message, 50)
		var conv *database.Conversation
		var err error
		meta := audit.ConversationCreateMetaFromGin(c, source)
		meta.ProjectID = projectID
		meta.TestingSpecification = req.TestingSpecification
		meta.RoleName = req.Role
		meta.AgentMode = chatRequestAgentMode(req, source)
		if webshellID != "" {
			meta.Source = source + "_webshell"
			meta.WebShellConnectionID = webshellID
			conv, err = h.db.CreateConversationWithWebshell(meta.WebShellConnectionID, title, meta)
		} else {
			conv, err = h.db.CreateConversation(title, meta)
		}
		if err != nil {
			return nil, fmt.Errorf("创建对话失败: %w", err)
		}
		conversationID = conv.ID
		createdNew = true
		if hasSession {
			_ = h.db.SetResourceOwner("conversation", conversationID, session.UserID)
			_ = h.db.AssignResourceToUser(session.UserID, "conversation", conversationID)
		}
	} else {
		if _, err := h.db.GetConversation(conversationID); err != nil {
			return nil, fmt.Errorf("对话不存在")
		}
		if !canAccess("conversation", conversationID) {
			return nil, fmt.Errorf("无权访问该对话")
		}
		if req.TestingSpecification != nil {
			if err := h.db.SetConversationTestingSpecification(conversationID, req.TestingSpecification); err != nil {
				return nil, err
			}
		}
	}
	if _, err := h.db.ConversationTestingSpecificationBlock(conversationID); err != nil {
		return nil, fmt.Errorf("读取任务规范失败: %w", err)
	}
	if err := h.db.SetConversationRoleName(conversationID, req.Role); err != nil {
		h.logger.Warn("更新对话角色失败", zap.String("conversationId", conversationID), zap.String("role", req.Role), zap.Error(err))
	}
	if err := h.db.SetConversationAgentMode(conversationID, chatRequestAgentMode(req, source)); err != nil {
		h.logger.Warn("更新对话模式失败", zap.String("conversationId", conversationID), zap.String("source", source), zap.String("orchestration", req.Orchestration), zap.Error(err))
	}

	agentHistoryMessages, err := h.loadHistoryFromAgentTrace(conversationID)
	if err != nil {
		historyMessages, getErr := h.db.GetMessages(conversationID)
		if getErr != nil {
			agentHistoryMessages = []agent.ChatMessage{}
		} else {
			agentHistoryMessages = dbMessagesToAgentChatMessages(historyMessages)
		}
	}

	resolvedMessage, resolveErr := h.db.ResolveConversationPlaceholders(conversationID, req.Message)
	if resolveErr != nil {
		return nil, fmt.Errorf("解析对话占位符失败: %w", resolveErr)
	}
	req.Message = resolvedMessage
	finalMessage := req.Message
	var roleTools []string
	if webshellID != "" {
		conn, errConn := h.db.GetWebshellConnection(webshellID)
		if errConn != nil || conn == nil {
			h.logger.Warn("WebShell AI 助手：未找到连接", zap.String("id", req.WebShellConnectionID), zap.Error(errConn))
			return nil, fmt.Errorf("未找到该 WebShell 连接")
		}
		webshellContext := BuildWebshellAssistantContext(conn, WebshellSkillHintMultiAgent, req.Message)
		// WebShell 模式下如果同时指定了角色，追加角色 user_prompt（工具集仍仅限 webshell 专用工具）
		if req.Role != "" && req.Role != "默认" && h.config != nil && h.config.Roles != nil {
			if role, exists := h.config.Roles[req.Role]; exists && role.Enabled && role.UserPrompt != "" {
				finalMessage = role.UserPrompt + "\n\n" + webshellContext
				h.logger.Info("WebShell + 角色: 应用角色提示词（多代理）", zap.String("role", req.Role))
			} else {
				finalMessage = webshellContext
			}
		} else {
			finalMessage = webshellContext
		}
		roleTools = []string{
			builtin.ToolWebshellExec,
			builtin.ToolWebshellFileList,
			builtin.ToolWebshellFileRead,
			builtin.ToolWebshellFileWrite,
			builtin.ToolRecordVulnerability,
			builtin.ToolListVulnerabilities,
			builtin.ToolGetVulnerability,
			builtin.ToolUpdateVulnerabilityStatus,
			builtin.ToolUpsertProjectFact,
			builtin.ToolGetProjectFact,
			builtin.ToolListProjectFacts,
			builtin.ToolSearchProjectFacts,
			builtin.ToolDeprecateProjectFact,
			builtin.ToolRestoreProjectFact,
			builtin.ToolListKnowledgeRiskTypes,
			builtin.ToolSearchKnowledgeBase,
		}
	} else if req.Role != "" && req.Role != "默认" && h.config != nil && h.config.Roles != nil {
		if role, exists := h.config.Roles[req.Role]; exists && role.Enabled {
			if role.UserPrompt != "" {
				finalMessage = role.UserPrompt + "\n\n" + req.Message
			}
			roleTools = role.Tools
		}
	}

	retest, retestErr := h.db.GetVulnerabilityRetest(conversationID)
	if retestErr != nil {
		return nil, fmt.Errorf("读取复测上下文失败: %w", retestErr)
	}
	if retest != nil && len(roleTools) > 0 {
		// Retesting requires these tools even when the inherited role has an
		// older tool allowlist. MCP still enforces user and finding permissions.
		roleTools = append(append([]string(nil), roleTools...), builtin.ToolGetVulnerability, builtin.ToolUpdateVulnerabilityStatus)
	}

	finalMessage, resolveErr = h.db.ResolveConversationPlaceholders(conversationID, finalMessage)
	if resolveErr != nil {
		return nil, fmt.Errorf("解析提示词占位符失败: %w", resolveErr)
	}

	var savedPaths []string
	if len(req.Attachments) > 0 {
		var aerr error
		savedPaths, aerr = saveAttachmentsToDateAndConversationDir(req.Attachments, conversationID, h.logger)
		if aerr != nil {
			return nil, fmt.Errorf("保存上传文件失败: %w", aerr)
		}
	}
	finalMessage = appendAttachmentsToMessage(finalMessage, req.Attachments, savedPaths)

	// 主模型声明多模态时，把本轮附件中的图片编码为原生图片输入（直发主模型）；
	// 否则维持旧行为：只给路径，由 analyze_image 旁路 VL 模型识图。
	// WebShell 助手会话的工具集与上下文独立，不注入图片。
	var turnImages []multiagent.TurnImage
	if len(savedPaths) > 0 && webshellID == "" && h.aiChannelSupportsVision(req.AIChannelID) {
		turnImages = buildTurnImages(savedPaths, h.logger)
		if len(turnImages) > 0 && h.logger != nil {
			h.logger.Info("本轮附件图片将直发主模型（supports_vision）",
				zap.Int("images", len(turnImages)), zap.String("conversationId", conversationID))
		}
	}

	userContent := userMessageContentForStorage(req.Message, req.Attachments, savedPaths)
	userMsgRow, uerr := h.db.AddMessage(conversationID, "user", userContent, nil)
	if uerr != nil {
		h.logger.Error("保存用户消息失败", zap.Error(uerr))
		return nil, fmt.Errorf("保存用户消息失败: %w", uerr)
	}
	if retest != nil {
		if err := h.db.SetVulnerabilityRetestPrompt(conversationID, ""); err != nil {
			h.logger.Warn("清除已发送复测提示词失败", zap.Error(err))
		}
	}
	userMessageID := ""
	if userMsgRow != nil {
		userMessageID = userMsgRow.ID
	}

	assistantMsg, aerr := h.db.AddMessage(conversationID, "assistant", "处理中...", nil)
	var assistantMessageID string
	if aerr != nil {
		h.logger.Warn("创建助手消息占位失败", zap.Error(aerr))
	} else if assistantMsg != nil {
		assistantMessageID = assistantMsg.ID
	}

	return &multiAgentPrepared{
		ConversationID:     conversationID,
		CreatedNew:         createdNew,
		History:            agentHistoryMessages,
		FinalMessage:       finalMessage,
		RoleTools:          roleTools,
		AssistantMessageID: assistantMessageID,
		UserMessageID:      userMessageID,
		TurnImages:         turnImages,
	}, nil
}
