package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ApprovalHTTPStore interface {
	GetRequest(context.Context, string) (*approval.Request, error)
	List(context.Context, approval.ListFilter) ([]*approval.Request, error)
	Count(context.Context, approval.ListFilter) (int, error)
	RecordDecision(context.Context, approval.DecisionRecord, string, string, string) error
}

type approvalDecisionReader interface {
	ListDecisions(context.Context, string) ([]approval.DecisionRecord, error)
}

// approvalDecisionBatchReader 一次查询装配多个审批的决定历史。
type approvalDecisionBatchReader interface {
	ListDecisionsForApprovals(context.Context, []string) (map[string][]approval.DecisionRecord, error)
}

type ApprovalAdminStore interface {
	ListApprovalRules(context.Context) ([]approval.Rule, error)
	PublishApprovalRule(context.Context, approval.Rule) (approval.Rule, error)
	DeleteApprovalRule(context.Context, string) error
}

type approvalAuditSink interface {
	RecordOK(*gin.Context, string, string, string, string, string, map[string]interface{})
}

type GlobalApprovalConfigSaver interface {
	SaveGlobalApprovalConfig(approval.Config) error
}

type ApprovalHandler struct {
	store             ApprovalHTTPStore
	admin             ApprovalAdminStore
	broker            *approval.HumanReviewBroker
	globalRuntime     *approval.GlobalRuntime
	globalConfigSaver GlobalApprovalConfigSaver
	resourceAccess    func(userID, scope, resourceType, resourceID string) bool
	audit             approvalAuditSink
	logger            *zap.Logger
}

func (h *ApprovalHandler) SetGlobalRuntime(runtime *approval.GlobalRuntime, saver GlobalApprovalConfigSaver) {
	h.globalRuntime = runtime
	h.globalConfigSaver = saver
}

func (h *ApprovalHandler) refreshGlobalRules(ctx context.Context) error {
	if h.globalRuntime == nil || h.admin == nil {
		return nil
	}
	stored, err := h.admin.ListApprovalRules(ctx)
	if err != nil {
		return err
	}
	return h.globalRuntime.Update(h.globalRuntime.Config(), stored)
}

func NewApprovalHandler(store ApprovalHTTPStore, broker *approval.HumanReviewBroker, logger *zap.Logger) *ApprovalHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	handler := &ApprovalHandler{store: store, broker: broker, logger: logger}
	if admin, ok := store.(ApprovalAdminStore); ok {
		handler.admin = admin
	}
	return handler
}

func (h *ApprovalHandler) SetResourceAccessChecker(checker func(userID, scope, resourceType, resourceID string) bool) {
	h.resourceAccess = checker
}

func (h *ApprovalHandler) SetAudit(service *audit.Service) {
	h.audit = service
}

func registerApprovalRoutes(group *gin.RouterGroup, handler *ApprovalHandler) {
	group.GET("/approvals", handler.List)
	group.GET("/approvals/ledger", handler.ListLedger)
	group.GET("/approvals/:id", handler.Get)
	group.POST("/approvals/:id/decision", handler.Decide)
	group.GET("/approval-config", handler.GetGlobalConfig)
	group.PUT("/approval-config", handler.UpdateGlobalConfig)
	group.GET("/approval-rules", handler.ListRules)
	group.POST("/approval-rules", handler.PublishRule)
	group.DELETE("/approval-rules", handler.DeleteRule)
}

func (h *ApprovalHandler) GetGlobalConfig(c *gin.Context) {
	if !security.SessionHasPermission(c, "approval:read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval read permission is required", "permission": "approval:read"})
		return
	}
	if h == nil || h.globalRuntime == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "approval runtime is unavailable"})
		return
	}
	c.JSON(http.StatusOK, h.globalRuntime.Config())
}

func (h *ApprovalHandler) UpdateGlobalConfig(c *gin.Context) {
	if !security.SessionHasPermission(c, "approval:policy:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval policy mutation permission is required", "permission": "approval:policy:write"})
		return
	}
	if h == nil || h.globalRuntime == nil || h.globalConfigSaver == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "approval configuration is unavailable"})
		return
	}
	var input approval.Config
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy := approval.NormalizeConfig(input)
	if err := h.globalConfigSaver.SaveGlobalApprovalConfig(policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.globalRuntime.Update(policy, h.globalRuntime.Rules()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policy)
}

func (h *ApprovalHandler) ListRules(c *gin.Context) {
	if !security.SessionHasPermission(c, "approval:read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval read permission is required", "permission": "approval:read"})
		return
	}
	if h.admin == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "approval rule store is unavailable"})
		return
	}
	items, err := h.admin.ListApprovalRules(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if items == nil {
		items = make([]approval.Rule, 0)
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *ApprovalHandler) PublishRule(c *gin.Context) {
	if h.admin == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "approval rule store is unavailable"})
		return
	}
	if !security.SessionHasPermission(c, "approval:policy:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval policy mutation permission is required", "permission": "approval:policy:write"})
		return
	}
	var input approval.Rule
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := approval.ValidateRule(input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	published, err := h.admin.PublishApprovalRule(c.Request.Context(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.refreshGlobalRules(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "规则已保存但全局运行时刷新失败: " + err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "approval", "rule_publish", "发布危险操作规则", "approval_rule", published.ID, nil)
	}
	c.JSON(http.StatusCreated, published)
}

// DeleteRule 删除规则并记录墓碑，防止默认规则在重启时复活。
func (h *ApprovalHandler) DeleteRule(c *gin.Context) {
	if h.admin == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "approval rule store is unavailable"})
		return
	}
	if !security.SessionHasPermission(c, "approval:policy:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval policy mutation permission is required", "permission": "approval:policy:write"})
		return
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(input.ID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "approval rule id is required"})
		return
	}
	current, err := h.admin.ListApprovalRules(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	exists := false
	for _, rule := range current {
		if rule.ID == input.ID {
			exists = true
			break
		}
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval rule not found", "code": "rule_not_found"})
		return
	}
	if err := h.admin.DeleteApprovalRule(c.Request.Context(), input.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.refreshGlobalRules(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "规则已删除但全局运行时刷新失败: " + err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "approval", "rule_delete", "删除危险操作规则", "approval_rule", input.ID, nil)
	}
	c.JSON(http.StatusOK, gin.H{"deleted": input.ID})
}

// RegisterApprovalRoutes registers the unified approval endpoints on an authenticated route group.
func RegisterApprovalRoutes(group *gin.RouterGroup, handler *ApprovalHandler) {
	registerApprovalRoutes(group, handler)
}

func (h *ApprovalHandler) List(c *gin.Context) {
	if !security.SessionHasPermission(c, "approval:read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval read permission is required", "permission": "approval:read"})
		return
	}
	limit := 50
	if rawLimit, exists := c.GetQuery("limit"); exists {
		parsed, err := strconv.Atoi(strings.TrimSpace(rawLimit))
		if err != nil || parsed < 1 || parsed > 200 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be an integer between 1 and 200"})
			return
		}
		limit = parsed
	}
	offset := 0
	if rawOffset, exists := c.GetQuery("offset"); exists {
		parsed, err := strconv.Atoi(strings.TrimSpace(rawOffset))
		if err != nil || parsed < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "offset must be a non-negative integer"})
			return
		}
		offset = parsed
	}
	filter := approval.ListFilter{
		ConversationID:  strings.TrimSpace(c.Query("conversationId")),
		ProjectID:       strings.TrimSpace(c.Query("projectId")),
		RequesterUserID: strings.TrimSpace(c.Query("requesterUserId")),
		Status:          strings.TrimSpace(c.Query("status")),
		Query:           strings.TrimSpace(c.Query("q")),
		Decision:        strings.ToLower(strings.TrimSpace(c.Query("decision"))),
		ActorType:       strings.ToLower(strings.TrimSpace(c.Query("actorType"))),
		Limit:           limit,
		Offset:          offset,
	}
	if terminal, exists := c.GetQuery("terminal"); exists {
		switch strings.ToLower(strings.TrimSpace(terminal)) {
		case "true":
			filter.TerminalOnly = true
		case "false":
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "terminal must be true or false"})
			return
		}
	}
	if filter.Decision != "" && filter.Decision != approval.ReviewerApprove && filter.Decision != approval.ReviewerReject {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decision must be approve or reject"})
		return
	}
	if filter.ActorType != "" && filter.ActorType != "human" && filter.ActorType != "agent" && filter.ActorType != "system" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "actorType must be human, agent, or system"})
		return
	}
	if h.resourceAccess != nil && !h.sessionScopeSeesAll(c) {
		// 资源授权无法下推 SQL：分批取回全量后内存过滤，再切页，
		// 保证 total 是过滤后的总数且分页语义正确（而非当前页可见数）。
		// RBACScopeAll 会话对所有行可见，直接走下方 SQL 分页路径。
		const batch = 200
		visible := make([]*approval.Request, 0)
		batchFilter := filter
		for offset := 0; ; offset += batch {
			batchFilter.Limit = batch
			batchFilter.Offset = offset
			page, pageErr := h.store.List(c.Request.Context(), batchFilter)
			if pageErr != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": pageErr.Error()})
				return
			}
			for _, item := range page {
				if h.requestAllowed(c, item) {
					visible = append(visible, item)
				}
			}
			if len(page) < batch {
				break
			}
		}
		items := visible
		if filter.Offset < len(visible) {
			end := filter.Offset + filter.Limit
			if end > len(visible) {
				end = len(visible)
			}
			items = visible[filter.Offset:end]
		} else {
			items = nil
		}
		if !h.attachDecisions(c, items) {
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items, "total": len(visible), "limit": filter.Limit, "offset": filter.Offset})
		return
	}
	items, err := h.store.List(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	total, err := h.store.Count(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !h.attachDecisions(c, items) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "limit": limit, "offset": offset})
}

// attachDecisions 为列表项装配决定历史；返回 false 表示已写错误响应。
// 优先一次批量加载当页全部请求，避免逐行查询。
func (h *ApprovalHandler) attachDecisions(c *gin.Context, items []*approval.Request) bool {
	if len(items) == 0 {
		return true
	}
	if batch, ok := h.store.(approvalDecisionBatchReader); ok {
		ids := make([]string, 0, len(items))
		for _, item := range items {
			ids = append(ids, item.ID)
		}
		byApproval, err := batch.ListDecisionsForApprovals(c.Request.Context(), ids)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return false
		}
		for _, item := range items {
			item.Decisions = byApproval[item.ID]
		}
		return true
	}
	reader, ok := h.store.(approvalDecisionReader)
	if !ok {
		return true
	}
	for _, item := range items {
		decisions, decisionErr := reader.ListDecisions(c.Request.Context(), item.ID)
		if decisionErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": decisionErr.Error()})
			return false
		}
		item.Decisions = decisions
	}
	return true
}

func (h *ApprovalHandler) Get(c *gin.Context) {
	if !security.SessionHasPermission(c, "approval:read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval read permission is required", "permission": "approval:read"})
		return
	}
	request, err := h.store.GetRequest(c.Request.Context(), strings.TrimSpace(c.Param("id")))
	if errors.Is(err, approval.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !h.requestAllowed(c, request) {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval request is outside the authorized scope"})
		return
	}
	if reader, ok := h.store.(approvalDecisionReader); ok {
		request.Decisions, err = reader.ListDecisions(c.Request.Context(), request.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusOK, request)
}

func (h *ApprovalHandler) Decide(c *gin.Context) {
	if !security.SessionHasPermission(c, "approval:decide") {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval decision permission is required", "permission": "approval:decide"})
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	var input struct {
		Decision string `json:"decision" binding:"required"`
		Comment  string `json:"comment,omitempty"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Decision = strings.ToLower(strings.TrimSpace(input.Decision))
	if input.Decision != approval.ReviewerApprove && input.Decision != approval.ReviewerReject {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decision must be approve or reject"})
		return
	}
	request, err := h.store.GetRequest(c.Request.Context(), id)
	if errors.Is(err, approval.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !h.requestAllowed(c, request) {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval request is outside the authorized scope"})
		return
	}
	if request.Status != approval.StatusPendingHuman {
		c.JSON(http.StatusConflict, gin.H{"error": approval.ErrStateConflict.Error()})
		return
	}
	actorID := ""
	if principal, ok := authctx.PrincipalFromContext(c.Request.Context()); ok {
		actorID = principal.UserID
	}
	if actorID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "approval principal is required"})
		return
	}
	decision := approval.ReviewDecision{
		Decision: input.Decision, Comment: strings.TrimSpace(input.Comment),
		ActorType: "human", ActorID: actorID,
	}
	if h.broker != nil && h.broker.HasPending(id) {
		if err := h.broker.Decide(id, decision); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		h.recordDecisionAudit(c, id, input.Decision, input.Comment)
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	c.JSON(http.StatusConflict, gin.H{"error": "approval runtime is not available"})
}

func (h *ApprovalHandler) recordDecisionAudit(c *gin.Context, id, decision, comment string) {
	if h.audit == nil {
		return
	}
	h.audit.RecordOK(c, "approval", "decision", "统一审批决策", "approval_request", id, map[string]interface{}{
		"decision": decision, "comment": strings.TrimSpace(comment),
	})
}

func (h *ApprovalHandler) requestAllowed(c *gin.Context, request *approval.Request) bool {
	if h.resourceAccess == nil {
		return true
	}
	session, ok := security.CurrentSession(c)
	if !ok || request == nil {
		return false
	}
	if session.Scope == database.RBACScopeAll || request.RequesterUserID == session.UserID {
		return true
	}
	if request.ConversationID != "" && h.resourceAccess(session.UserID, session.Scope, "conversation", request.ConversationID) {
		return true
	}
	return request.ProjectID != "" && h.resourceAccess(session.UserID, session.Scope, "project", request.ProjectID)
}

// sessionScopeSeesAll 报告会话是否对所有审批行可见（管理员/审计员），
// 这类会话无需逐行授权过滤，可直接使用 SQL 分页。
func (h *ApprovalHandler) sessionScopeSeesAll(c *gin.Context) bool {
	session, ok := security.CurrentSession(c)
	return ok && session.Scope == database.RBACScopeAll
}
