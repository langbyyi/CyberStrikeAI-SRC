package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/multiagent"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type hitlRuntimeConfig struct {
	Enabled        bool
	Mode           string
	SensitiveTools map[string]struct{}
	Timeout        time.Duration
}

type hitlDecision struct {
	Decision        string
	Comment         string
	EditedArguments map[string]interface{}
}

type pendingInterrupt struct {
	ConversationID string
	InterruptID    string
	Mode           string
	ToolName       string
	ToolCallID     string
	decideCh       chan hitlDecision
}

type HITLManager struct {
	db     *database.DB
	logger *zap.Logger

	mu      sync.RWMutex
	runtime map[string]hitlRuntimeConfig
	pending map[string]*pendingInterrupt
}

func NewHITLManager(db *database.DB, logger *zap.Logger) *HITLManager {
	return &HITLManager{
		db:      db,
		logger:  logger,
		runtime: make(map[string]hitlRuntimeConfig),
		pending: make(map[string]*pendingInterrupt),
	}
}

func (m *HITLManager) EnsureSchema() error {
	if _, err := m.db.Exec(`
CREATE TABLE IF NOT EXISTS hitl_interrupts (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    message_id TEXT,
    mode TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_call_id TEXT,
    payload TEXT,
    status TEXT NOT NULL,
    decision TEXT,
    decision_comment TEXT,
    created_at DATETIME NOT NULL,
    decided_at DATETIME
);`); err != nil {
		return err
	}
	_, err := m.db.Exec(`
CREATE TABLE IF NOT EXISTS hitl_conversation_configs (
    conversation_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    mode TEXT NOT NULL DEFAULT 'off',
    sensitive_tools TEXT NOT NULL DEFAULT '[]',
    timeout_seconds INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL
);`)
	if err != nil {
		return err
	}

	// On startup, cancel all orphaned pending interrupts from previous process.
	// Their in-memory channels are gone, so they can never be resolved.
	res, err := m.db.Exec(`UPDATE hitl_interrupts SET status='cancelled', decision='reject',
		decision_comment='process restarted', decided_at=CURRENT_TIMESTAMP WHERE status='pending'`)
	if err != nil {
		m.logger.Warn("failed to cancel orphaned HITL interrupts", zap.Error(err))
	} else if n, _ := res.RowsAffected(); n > 0 {
		m.logger.Info("cancelled orphaned HITL interrupts from previous process", zap.Int64("count", n))
	}
	return nil
}

func normalizeHitlMode(mode string) string {
	v := strings.ToLower(strings.TrimSpace(mode))
	if v == "" {
		return "approval"
	}
	switch v {
	case "off":
		return "off"
	case "feedback", "followup":
		return "approval"
	case "approval", "review_edit":
		return v
	default:
		return "approval"
	}
}

func (m *HITLManager) ActivateConversation(conversationID string, req *HITLRequest) {
	if req == nil || !req.Enabled {
		m.DeactivateConversation(conversationID)
		return
	}
	tools := make(map[string]struct{})
	for _, t := range req.SensitiveTools {
		n := strings.ToLower(strings.TrimSpace(t))
		if n != "" {
			tools[n] = struct{}{}
		}
	}
	// timeout <= 0 means wait forever (no timeout).
	timeout := time.Duration(0)
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	m.mu.Lock()
	m.runtime[conversationID] = hitlRuntimeConfig{
		Enabled:        true,
		Mode:           normalizeHitlMode(req.Mode),
		SensitiveTools: tools,
		Timeout:        timeout,
	}
	m.mu.Unlock()
}

func (m *HITLManager) DeactivateConversation(conversationID string) {
	m.mu.Lock()
	delete(m.runtime, conversationID)
	m.mu.Unlock()
}

// hitlConfigGlobalToolWhitelist 来自 config.yaml hitl.tool_whitelist（去重、去空）。
func (h *AgentHandler) hitlConfigGlobalToolWhitelist() []string {
	if h == nil || h.config == nil {
		return nil
	}
	raw := h.config.Hitl.ToolWhitelist
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		n := strings.ToLower(strings.TrimSpace(t))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, strings.TrimSpace(t))
	}
	return out
}

// hitlRequestWithMergedConfigWhitelist 将会话/API 中的白名单与 config.yaml 全局白名单合并（并集），仅用于运行时 Activate；不写入数据库。
func (h *AgentHandler) hitlRequestWithMergedConfigWhitelist(req *HITLRequest) *HITLRequest {
	gw := h.hitlConfigGlobalToolWhitelist()
	if len(gw) == 0 {
		return req
	}
	if req == nil {
		return nil
	}
	seen := make(map[string]struct{})
	union := make([]string, 0, len(gw)+len(req.SensitiveTools))
	for _, t := range gw {
		n := strings.ToLower(strings.TrimSpace(t))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		union = append(union, strings.TrimSpace(t))
	}
	for _, t := range req.SensitiveTools {
		n := strings.ToLower(strings.TrimSpace(t))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		union = append(union, strings.TrimSpace(t))
	}
	out := *req
	out.SensitiveTools = union
	return &out
}

func (m *HITLManager) shouldInterrupt(conversationID, toolName string) (hitlRuntimeConfig, bool) {
	m.mu.RLock()
	cfg, ok := m.runtime[conversationID]
	m.mu.RUnlock()
	if !ok || !cfg.Enabled {
		return hitlRuntimeConfig{}, false
	}
	// 语义：SensitiveTools 现在作为“白名单（免审批工具）”
	// 空白名单 => 全部工具都需要审批
	if len(cfg.SensitiveTools) == 0 {
		return cfg, true
	}
	_, inWhitelist := cfg.SensitiveTools[strings.ToLower(strings.TrimSpace(toolName))]
	return cfg, !inWhitelist
}

// NeedsToolApproval 与 Agent 工具层 shouldInterrupt 语义一致：仅当该会话已开启人机协同且工具不在免审批白名单时为 true。
func (m *HITLManager) NeedsToolApproval(conversationID, toolName string) bool {
	if m == nil {
		return false
	}
	_, need := m.shouldInterrupt(conversationID, toolName)
	return need
}

func (m *HITLManager) CreatePendingInterrupt(conversationID, assistantMessageID, mode, toolName, toolCallID, payload string) (*pendingInterrupt, error) {
	now := time.Now()
	id := "hitl_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if _, err := m.db.Exec(`INSERT INTO hitl_interrupts
		(id, conversation_id, message_id, mode, tool_name, tool_call_id, payload, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
		id, conversationID, assistantMessageID, mode, toolName, toolCallID, payload, now); err != nil {
		return nil, err
	}
	// 刷新页面后侧栏依赖 DB 配置；若仅内存 Activate 未落库，会导致「有待审批却显示关闭」
	_ = m.ensureConversationHITLModePersisted(conversationID, mode)
	p := &pendingInterrupt{
		ConversationID: conversationID,
		InterruptID:    id,
		Mode:           normalizeHitlMode(mode),
		ToolName:       toolName,
		ToolCallID:     toolCallID,
		decideCh:       make(chan hitlDecision, 1),
	}
	m.mu.Lock()
	m.pending[id] = p
	m.mu.Unlock()
	return p, nil
}

// ensureConversationHITLModePersisted 在产生待审批时把 mode 写入 hitl_conversation_configs，避免刷新后 GET 配置仍为关闭。
func (m *HITLManager) ensureConversationHITLModePersisted(conversationID, interruptMode string) error {
	if strings.TrimSpace(conversationID) == "" {
		return nil
	}
	nm := normalizeHitlMode(interruptMode)
	if nm == "off" {
		return nil
	}
	cfg, err := m.LoadConversationConfig(conversationID)
	if err != nil {
		return err
	}
	if cfg.Enabled && normalizeHitlMode(cfg.Mode) == nm {
		return nil
	}
	cfg.Enabled = true
	cfg.Mode = nm
	if cfg.TimeoutSeconds < 0 {
		cfg.TimeoutSeconds = 0
	}
	return m.SaveConversationConfig(conversationID, cfg)
}

// PendingHITLInterruptMode 返回该会话最新一条 pending 中断的协同模式（用于 GET 配置时与库内「关闭」状态对齐）。
func (m *HITLManager) PendingHITLInterruptMode(conversationID string) (string, bool) {
	if strings.TrimSpace(conversationID) == "" {
		return "", false
	}
	var mode string
	err := m.db.QueryRow(`SELECT mode FROM hitl_interrupts WHERE conversation_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1`, conversationID).
		Scan(&mode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false
		}
		return "", false
	}
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return "", false
	}
	return mode, true
}

func hitlStoredConfigEffective(cfg *HITLRequest) bool {
	if cfg == nil {
		return false
	}
	if cfg.Enabled {
		return true
	}
	return normalizeHitlMode(cfg.Mode) != "off"
}

func (m *HITLManager) ResolveInterrupt(interruptID, decision, comment string, editedArguments map[string]interface{}) error {
	decision = strings.ToLower(strings.TrimSpace(decision))
	if decision != "approve" && decision != "reject" {
		return errors.New("decision must be approve/reject")
	}
	m.mu.RLock()
	p, ok := m.pending[interruptID]
	m.mu.RUnlock()
	if !ok {
		return errors.New("interrupt not found or already resolved")
	}
	d := hitlDecision{
		Decision:        decision,
		Comment:         strings.TrimSpace(comment),
		EditedArguments: editedArguments,
	}
	select {
	case p.decideCh <- d:
		return nil
	default:
		return errors.New("interrupt already resolved or decision channel busy")
	}
}

func (m *HITLManager) SaveConversationConfig(conversationID string, req *HITLRequest) error {
	if strings.TrimSpace(conversationID) == "" {
		return errors.New("conversationId is required")
	}
	if req == nil {
		req = &HITLRequest{Enabled: false, Mode: "off", TimeoutSeconds: 0}
	}
	mode := normalizeHitlMode(req.Mode)
	if !req.Enabled {
		mode = "off"
	}
	tools, _ := json.Marshal(req.SensitiveTools)
	timeout := req.TimeoutSeconds
	if timeout < 0 {
		timeout = 0
	}
	_, err := m.db.Exec(`INSERT INTO hitl_conversation_configs
		(conversation_id, enabled, mode, sensitive_tools, timeout_seconds, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(conversation_id) DO UPDATE SET
		enabled=excluded.enabled, mode=excluded.mode, sensitive_tools=excluded.sensitive_tools, timeout_seconds=excluded.timeout_seconds, updated_at=excluded.updated_at`,
		conversationID, boolToInt(req.Enabled), mode, string(tools), timeout, time.Now())
	return err
}

func (m *HITLManager) LoadConversationConfig(conversationID string) (*HITLRequest, error) {
	var enabledInt int
	var mode, toolsJSON string
	var timeout int
	err := m.db.QueryRow(`SELECT enabled, mode, sensitive_tools, timeout_seconds FROM hitl_conversation_configs WHERE conversation_id = ?`, conversationID).
		Scan(&enabledInt, &mode, &toolsJSON, &timeout)
	if errors.Is(err, sql.ErrNoRows) {
		return &HITLRequest{Enabled: false, Mode: "off", SensitiveTools: []string{}, TimeoutSeconds: 0}, nil
	}
	if err != nil {
		return nil, err
	}
	if timeout < 0 {
		timeout = 0
	}
	tools := make([]string, 0)
	_ = json.Unmarshal([]byte(toolsJSON), &tools)
	return &HITLRequest{
		Enabled:        enabledInt == 1,
		Mode:           mode,
		SensitiveTools: tools,
		TimeoutSeconds: timeout,
	}, nil
}

func (m *HITLManager) waitDecision(ctx context.Context, p *pendingInterrupt, timeout time.Duration) (hitlDecision, error) {
	defer func() {
		m.mu.Lock()
		delete(m.pending, p.InterruptID)
		m.mu.Unlock()
	}()
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		timeoutCh = timer.C
	}
	select {
	case d := <-p.decideCh:
		// 只有 review_edit 模式允许改参；其他模式一律忽略 edited arguments
		if p.Mode != "review_edit" && len(d.EditedArguments) > 0 {
			d.EditedArguments = nil
		}
		_, _ = m.db.Exec(`UPDATE hitl_interrupts SET status='decided', decision=?, decision_comment=?, decided_at=? WHERE id=?`,
			d.Decision, d.Comment, time.Now(), p.InterruptID)
		return d, nil
	case <-timeoutCh:
		_, _ = m.db.Exec(`UPDATE hitl_interrupts SET status='timeout', decision='approve', decision_comment='timeout auto approve', decided_at=? WHERE id=?`,
			time.Now(), p.InterruptID)
		return hitlDecision{Decision: "approve", Comment: "timeout auto approve"}, nil
	case <-ctx.Done():
		_, _ = m.db.Exec(`UPDATE hitl_interrupts SET status='cancelled', decision='reject', decision_comment='task cancelled', decided_at=? WHERE id=?`,
			time.Now(), p.InterruptID)
		return hitlDecision{Decision: "reject", Comment: "task cancelled"}, ctx.Err()
	}
}

func (h *AgentHandler) activateHITLForConversation(conversationID string, req *HITLRequest) {
	if h.hitlManager == nil {
		return
	}
	if req == nil {
		cfg, err := h.hitlManager.LoadConversationConfig(conversationID)
		if err == nil {
			req = cfg
		}
	}
	h.hitlManager.ActivateConversation(conversationID, h.hitlRequestWithMergedConfigWhitelist(req))
}

func (h *AgentHandler) waitHITLApproval(runCtx context.Context, cancelRun context.CancelCauseFunc, conversationID, assistantMessageID, toolName, toolCallID string, payload map[string]interface{}, sendEventFunc func(eventType, message string, data interface{})) (*hitlDecision, error) {
	cfg, need := h.hitlManager.shouldInterrupt(conversationID, toolName)
	if !need {
		return nil, nil
	}
	payloadRaw, _ := json.Marshal(payload)
	p, err := h.hitlManager.CreatePendingInterrupt(conversationID, assistantMessageID, cfg.Mode, toolName, toolCallID, string(payloadRaw))
	if err != nil {
		h.logger.Warn("创建 HITL 中断失败", zap.Error(err))
		return nil, err
	}
	if sendEventFunc != nil {
		sendEventFunc("hitl_interrupt", "命中人机协同审批", map[string]interface{}{
			"conversationId": conversationID,
			"interruptId":    p.InterruptID,
			"mode":           cfg.Mode,
			"toolName":       toolName,
			"toolCallId":     toolCallID,
			"payload":        payload,
		})
	}
	d, waitErr := h.hitlManager.waitDecision(runCtx, p, cfg.Timeout)
	if waitErr != nil {
		if cancelRun != nil && (errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded)) {
			cause := context.Cause(runCtx)
			switch {
			case errors.Is(cause, ErrTaskCancelled):
				cancelRun(ErrTaskCancelled)
			case cause != nil:
				cancelRun(cause)
			case errors.Is(waitErr, context.DeadlineExceeded):
				cancelRun(context.DeadlineExceeded)
			default:
				cancelRun(ErrTaskCancelled)
			}
		}
		return nil, waitErr
	}
	if d.Decision == "reject" {
		if sendEventFunc != nil {
			sendEventFunc("hitl_rejected", "人工拒绝本次工具调用，模型将基于反馈继续迭代", map[string]interface{}{
				"conversationId": conversationID,
				"interruptId":    p.InterruptID,
				"toolName":       toolName,
				"comment":        d.Comment,
			})
		}
		return &d, nil
	}
	if sendEventFunc != nil {
		sendEventFunc("hitl_resumed", "人工确认通过，继续执行", map[string]interface{}{
			"conversationId": conversationID,
			"interruptId":    p.InterruptID,
			"toolName":       toolName,
			"comment":        d.Comment,
			"editedArgs":     d.EditedArguments,
		})
	}
	return &d, nil
}

func (h *AgentHandler) handleHITLToolCall(runCtx context.Context, cancelRun context.CancelCauseFunc, conversationID, assistantMessageID string, data map[string]interface{}, sendEventFunc func(eventType, message string, data interface{})) {
	if h.hitlManager == nil {
		return
	}
	toolName, _ := data["toolName"].(string)
	toolCallID, _ := data["toolCallId"].(string)
	d, err := h.waitHITLApproval(runCtx, cancelRun, conversationID, assistantMessageID, toolName, toolCallID, data, sendEventFunc)
	if err != nil || d == nil {
		return
	}
	if len(d.EditedArguments) > 0 {
		if argsObj, ok := data["argumentsObj"].(map[string]interface{}); ok {
			for k := range argsObj {
				delete(argsObj, k)
			}
			for k, v := range d.EditedArguments {
				argsObj[k] = v
			}
			if b, mErr := json.Marshal(argsObj); mErr == nil {
				data["arguments"] = string(b)
			}
		}
	}
}

func (h *AgentHandler) ListHITLPending(c *gin.Context) {
	conversationID := strings.TrimSpace(c.Query("conversationId"))
	status := strings.TrimSpace(c.Query("status"))
	if status == "" {
		status = "pending"
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	pageSize = int(math.Max(1, math.Min(float64(pageSize), 200)))
	offset := (page - 1) * pageSize
	q := `SELECT id, conversation_id, message_id, mode, tool_name, tool_call_id, payload, status, decision, decision_comment, created_at, decided_at FROM hitl_interrupts WHERE 1=1`
	args := []interface{}{}
	if conversationID != "" {
		q += " AND conversation_id = ?"
		args = append(args, conversationID)
	}
	if status != "all" {
		q += " AND status = ?"
		args = append(args, status)
	}
	q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)
	rows, err := h.db.Query(q, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	items := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id, cid, mode, toolName, toolCallID, payload, rowStatus string
		var messageID sql.NullString
		var decision, comment sql.NullString
		var createdAt time.Time
		var decidedAt sql.NullTime
		if err := rows.Scan(&id, &cid, &messageID, &mode, &toolName, &toolCallID, &payload, &rowStatus, &decision, &comment, &createdAt, &decidedAt); err != nil {
			continue
		}
		msgID := ""
		if messageID.Valid {
			msgID = messageID.String
		}
		items = append(items, map[string]interface{}{
			"id":             id,
			"conversationId": cid,
			"messageId":      msgID,
			"mode":           mode,
			"toolName":       toolName,
			"toolCallId":     toolCallID,
			"payload":        payload,
			"status":         rowStatus,
			"decision":       decision.String,
			"comment":        comment.String,
			"createdAt":      createdAt,
			"decidedAt": func() interface{} {
				if decidedAt.Valid {
					return decidedAt.Time
				}
				return nil
			}(),
		})
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "page": page, "pageSize": pageSize})
}

type hitlDecisionReq struct {
	InterruptID     string                 `json:"interruptId" binding:"required"`
	Decision        string                 `json:"decision" binding:"required"`
	Comment         string                 `json:"comment,omitempty"`
	EditedArguments map[string]interface{} `json:"editedArguments,omitempty"`
}

func (h *AgentHandler) DecideHITLInterrupt(c *gin.Context) {
	var req hitlDecisionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if h.hitlManager == nil {
		c.JSON(500, gin.H{"error": "hitl manager unavailable"})
		return
	}
	if err := h.hitlManager.ResolveInterrupt(req.InterruptID, req.Decision, req.Comment, req.EditedArguments); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "hitl", "decision", "HITL 审批决策", "hitl_interrupt", req.InterruptID, map[string]interface{}{
			"decision": req.Decision,
		})
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AgentHandler) DismissHITLInterrupt(c *gin.Context) {
	var req struct {
		InterruptID string `json:"interruptId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if h.hitlManager == nil {
		c.JSON(500, gin.H{"error": "hitl manager unavailable"})
		return
	}
	res, err := h.db.Exec(`UPDATE hitl_interrupts SET status='cancelled', decision='reject',
		decision_comment='dismissed by user', decided_at=CURRENT_TIMESTAMP
		WHERE id=? AND status='pending'`, req.InterruptID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(404, gin.H{"error": "interrupt not found or already resolved"})
		return
	}
	// Also drain from in-memory map if present
	h.hitlManager.mu.Lock()
	if p, ok := h.hitlManager.pending[req.InterruptID]; ok {
		delete(h.hitlManager.pending, req.InterruptID)
		select {
		case p.decideCh <- hitlDecision{Decision: "reject", Comment: "dismissed by user"}:
		default:
		}
	}
	h.hitlManager.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AgentHandler) interceptHITLForEinoTool(runCtx context.Context, cancelRun context.CancelCauseFunc, conversationID, assistantMessageID string, sendEventFunc func(eventType, message string, data interface{}), toolName, arguments string) (string, error) {
	payload := map[string]interface{}{
		"toolName":   toolName,
		"arguments":  arguments,
		"source":     "eino_middleware",
		"toolCallId": "",
	}
	var argsObj map[string]interface{}
	if strings.TrimSpace(arguments) != "" {
		_ = json.Unmarshal([]byte(arguments), &argsObj)
		if argsObj != nil {
			payload["argumentsObj"] = argsObj
		}
	}
	d, err := h.waitHITLApproval(runCtx, cancelRun, conversationID, assistantMessageID, toolName, "", payload, sendEventFunc)
	if err != nil || d == nil {
		return arguments, err
	}
	if d.Decision == "reject" {
		return arguments, multiagent.NewHumanRejectError(d.Comment)
	}
	if len(d.EditedArguments) > 0 {
		edited, mErr := json.Marshal(d.EditedArguments)
		if mErr == nil {
			return string(edited), nil
		}
	}
	return arguments, nil
}


type hitlConfigReq struct {
	ConversationID string `json:"conversationId" binding:"required"`
	HITLRequest
}

func (h *AgentHandler) GetHITLConversationConfig(c *gin.Context) {
	conversationID := strings.TrimSpace(c.Param("conversationId"))
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "conversationId is required"})
		return
	}
	cfg, err := h.hitlManager.LoadConversationConfig(conversationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !hitlStoredConfigEffective(cfg) {
		if pendMode, ok := h.hitlManager.PendingHITLInterruptMode(conversationID); ok {
			cfg2 := *cfg
			cfg2.Enabled = true
			cfg2.Mode = normalizeHitlMode(pendMode)
			if cfg2.TimeoutSeconds < 0 {
				cfg2.TimeoutSeconds = 0
			}
			cfg = &cfg2
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"conversationId":          conversationID,
		"hitl":                    cfg,
		"hitlGlobalToolWhitelist": h.hitlConfigGlobalToolWhitelist(),
	})
}

func (h *AgentHandler) UpsertHITLConversationConfig(c *gin.Context) {
	var req hitlConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Mode = normalizeHitlMode(req.Mode)
	if err := h.hitlManager.SaveConversationConfig(req.ConversationID, &req.HITLRequest); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if h.hitlWhitelistSaver != nil && len(req.SensitiveTools) > 0 {
		if err := h.hitlWhitelistSaver.MergeHitlToolWhitelistIntoConfig(req.SensitiveTools); err != nil {
			h.logger.Warn("HITL 会话配置已保存，但合并工具白名单到 config.yaml 失败", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "会话配置已保存，但写入 config.yaml 失败: " + err.Error(),
			})
			return
		}
	}
	h.hitlManager.ActivateConversation(req.ConversationID, h.hitlRequestWithMergedConfigWhitelist(&req.HITLRequest))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type mergeHitlGlobalWhitelistReq struct {
	SensitiveTools []string `json:"sensitiveTools"`
}

// MergeHITLGlobalToolWhitelist 无会话 ID 时将侧栏提交的免审批工具合并进 config.yaml（与 PUT /hitl/config 中白名单落盘规则一致）。
func (h *AgentHandler) MergeHITLGlobalToolWhitelist(c *gin.Context) {
	if h.hitlWhitelistSaver == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "HITL 配置持久化不可用"})
		return
	}
	var req mergeHitlGlobalWhitelistReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.SensitiveTools) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"ok":                        true,
			"hitlGlobalToolWhitelist":   h.hitlConfigGlobalToolWhitelist(),
			"hitlGlobalWhitelistMerged": false,
		})
		return
	}
	if err := h.hitlWhitelistSaver.MergeHitlToolWhitelistIntoConfig(req.SensitiveTools); err != nil {
		h.logger.Warn("合并 HITL 工具白名单到 config.yaml 失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":                        true,
		"hitlGlobalToolWhitelist":   h.hitlConfigGlobalToolWhitelist(),
		"hitlGlobalWhitelistMerged": true,
	})
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
