package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
)

// 本文件承载统一审批台账查询；审批单核心 CRUD 见 approval.go。

func (h *ApprovalHandler) ledgerEventAllowed(c *gin.Context, event approval.LedgerEvent) bool {
	if h.resourceAccess == nil {
		return true
	}
	session, ok := security.CurrentSession(c)
	if !ok {
		return false
	}
	if session.Scope == database.RBACScopeAll || event.RequesterUserID == session.UserID {
		return true
	}
	if event.ConversationID != "" && h.resourceAccess(session.UserID, session.Scope, "conversation", event.ConversationID) {
		return true
	}
	return event.ProjectID != "" && h.resourceAccess(session.UserID, session.Scope, "project", event.ProjectID)
}

func (h *ApprovalHandler) ListLedger(c *gin.Context) {
	if !security.SessionHasPermission(c, "approval:read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "approval read permission is required", "permission": "approval:read"})
		return
	}
	ledger, ok := h.store.(approval.Ledger)
	if !ok {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "approval ledger store is unavailable"})
		return
	}
	limit := 100
	if rawLimit, exists := c.GetQuery("limit"); exists {
		parsed, err := strconv.Atoi(strings.TrimSpace(rawLimit))
		if err != nil || parsed < 1 || parsed > 500 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be an integer between 1 and 500"})
			return
		}
		limit = parsed
	}
	filter := approval.LedgerFilter{InvocationID: strings.TrimSpace(c.Query("invocationId")), Limit: limit}
	parseTime := func(raw, name string) (*time.Time, error) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil, nil
		}
		if unix, err := strconv.ParseInt(raw, 10, 64); err == nil {
			t := time.Unix(unix, 0).UTC()
			return &t, nil
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, fmt.Errorf("%s must be RFC3339 or unix seconds", name)
		}
		return &t, nil
	}
	var err error
	if filter.From, err = parseTime(c.Query("from"), "from"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if filter.To, err = parseTime(c.Query("to"), "to"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	events, err := ledger.ListFiltered(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if h.resourceAccess != nil && !h.sessionScopeSeesAll(c) {
		visible := make([]approval.LedgerEvent, 0, len(events))
		for _, event := range events {
			if h.ledgerEventAllowed(c, event) {
				visible = append(visible, event)
			}
		}
		events = visible
	}
	c.JSON(http.StatusOK, gin.H{"items": events, "total": len(events), "limit": limit})
}
