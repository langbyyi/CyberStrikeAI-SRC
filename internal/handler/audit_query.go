package handler

import (
	"strconv"
	"time"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
)

func auditFilterFromQuery(c *gin.Context) database.ListAuditLogsFilter {
	filter := database.ListAuditLogsFilter{
		Level:        c.Query("level"),
		Category:     c.Query("category"),
		Action:       c.Query("action"),
		Result:       c.Query("result"),
		Query:        c.Query("q"),
		ResourceType: c.Query("resource_type"),
		ResourceID:   c.Query("resource_id"),
	}
	if since := c.Query("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = &t
		}
	}
	if until := c.Query("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = &t
		}
	}
	return filter
}

func auditPaginationFromQuery(c *gin.Context) (page, pageSize int) {
	page = 1
	pageSize = 20
	if p, err := strconv.Atoi(c.DefaultQuery("page", "1")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(c.DefaultQuery("page_size", "20")); err == nil && ps > 0 {
		pageSize = ps
		if pageSize > 100 {
			pageSize = 100
		}
	}
	return page, pageSize
}
