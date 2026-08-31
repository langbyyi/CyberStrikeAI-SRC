package approval

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// SQLiteStore 同时实现 Store 与 Ledger：台账与审批单共用一套 schema 与
// 连接管理。Append 只插入；任何既有行都不被更新（append-only）。
func (s *SQLiteStore) Append(ctx context.Context, event LedgerEvent) error {
	if s == nil || s.execer == nil {
		return errors.New("approval ledger database is unavailable")
	}
	if strings.TrimSpace(event.ID) == "" || strings.TrimSpace(event.EventType) == "" ||
		strings.TrimSpace(event.InvocationID) == "" {
		return errors.New("ledger event requires id, event type and invocation id")
	}
	matchedRules := "[]"
	if len(event.MatchedRules) > 0 {
		if raw, err := json.Marshal(event.MatchedRules); err == nil {
			matchedRules = string(raw)
		}
	}
	var success any
	if event.Success != nil {
		if *event.Success {
			success = 1
		} else {
			success = 0
		}
	}
	createdAt := event.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := s.execer.ExecContext(ctx, `
INSERT INTO approval_ledger (
    id, event_type, invocation_id, approval_id, source, conversation_id, project_id,
    requester_user_id, tool_name, tool_call_id, action_class, assessment_decision,
    enforcement, review_strategy, risk_level, args_hash, edited, actor_type, actor_id,
    matched_rules, comment, success, summary, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.EventType, event.InvocationID, event.ApprovalID, event.Source,
		event.ConversationID, event.ProjectID, event.RequesterUserID, event.ToolName,
		event.ToolCallID, "", "", event.Enforcement,
		event.Reviewer, event.RiskLevel, event.ArgsHash, 0, event.ActorType,
		event.ActorID, matchedRules, event.Comment, success, event.Summary, createdAt)
	if err != nil {
		return err
	}
	return nil
}

const ledgerColumns = `
    id, event_type, invocation_id, approval_id, source, conversation_id, project_id,
    requester_user_id, tool_name, tool_call_id, action_class, assessment_decision,
    enforcement, review_strategy, risk_level, args_hash, edited, actor_type, actor_id,
    matched_rules, comment, success, summary, created_at`

func scanLedgerEvent(scan func(...any) error) (LedgerEvent, error) {
	var event LedgerEvent
	var matchedRules string
	var success any
	var ignoredLegacyClass, ignoredLegacyAssessment string
	var legacyEdited bool
	var createdAt time.Time
	if err := scan(&event.ID, &event.EventType, &event.InvocationID, &event.ApprovalID,
		&event.Source, &event.ConversationID, &event.ProjectID, &event.RequesterUserID,
		&event.ToolName, &event.ToolCallID, &ignoredLegacyClass, &ignoredLegacyAssessment,
		&event.Enforcement, &event.Reviewer, &event.RiskLevel, &event.ArgsHash,
		&legacyEdited, &event.ActorType, &event.ActorID, &matchedRules, &event.Comment,
		&success, &event.Summary, &createdAt); err != nil {
		return LedgerEvent{}, err
	}
	if matchedRules != "" && matchedRules != "[]" {
		_ = json.Unmarshal([]byte(matchedRules), &event.MatchedRules)
	}
	if success != nil {
		value := success.(int64) == 1
		event.Success = &value
	}
	event.CreatedAt = createdAt
	return event, nil
}

func (s *SQLiteStore) ListByInvocation(ctx context.Context, invocationID string) ([]LedgerEvent, error) {
	if s == nil || s.execer == nil {
		return nil, errors.New("approval ledger database is unavailable")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT`+ledgerColumns+` FROM approval_ledger WHERE invocation_id = ? ORDER BY created_at, id`, invocationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectLedgerEvents(rows)
}

func (s *SQLiteStore) ListRecent(ctx context.Context, limit int) ([]LedgerEvent, error) {
	if s == nil || s.execer == nil {
		return nil, errors.New("approval ledger database is unavailable")
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT`+ledgerColumns+` FROM approval_ledger ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events, err := collectLedgerEvents(rows)
	if err != nil {
		return nil, err
	}
	// ListRecent 语义为"最近 limit 条按时间正序"。
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events, nil
}

func (s *SQLiteStore) ListFiltered(ctx context.Context, filter LedgerFilter) ([]LedgerEvent, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("approval ledger database is unavailable")
	}
	conditions := []string{"1=1"}
	args := []any{}
	if filter.InvocationID != "" {
		conditions = append(conditions, "invocation_id = ?")
		args = append(args, filter.InvocationID)
	}
	if filter.From != nil {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, *filter.From)
	}
	if filter.To != nil {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, *filter.To)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT` + ledgerColumns + ` FROM approval_ledger WHERE ` +
		strings.Join(conditions, " AND ") + ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events, err := collectLedgerEvents(rows)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events, nil
}

func collectLedgerEvents(rows *sql.Rows) ([]LedgerEvent, error) {
	out := make([]LedgerEvent, 0)
	for rows.Next() {
		event, err := scanLedgerEvent(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}
