package approval

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"
)

type contextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type SQLiteStore struct {
	db     *database.DB
	execer contextExecer
}

func NewSQLiteStore(db *database.DB) *SQLiteStore {
	return &SQLiteStore{db: db, execer: db}
}

func (s *SQLiteStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.execer == nil {
		return errors.New("approval store database is unavailable")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS approval_requests (
    id TEXT PRIMARY KEY,
    invocation_id TEXT NOT NULL UNIQUE,
    invocation_hash TEXT NOT NULL,
    source TEXT NOT NULL,
    conversation_id TEXT,
    message_id TEXT,
    project_id TEXT,
    requester_user_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_call_id TEXT,
    arguments_json TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    trigger_sources_json TEXT NOT NULL,
    matched_rule_revisions_json TEXT NOT NULL,
    review_strategy TEXT NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at DATETIME,
    claimed_at DATETIME,
    execution_id TEXT,
    execution_summary TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
)`,
		`CREATE INDEX IF NOT EXISTS idx_approval_requests_status_created ON approval_requests(status, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_approval_requests_conversation_status ON approval_requests(conversation_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_approval_requests_project_status ON approval_requests(project_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_approval_requests_requester_status ON approval_requests(requester_user_id, status)`,
		`CREATE TABLE IF NOT EXISTS approval_decisions (
    id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    decision TEXT NOT NULL,
    comment TEXT,
    metadata_json TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (approval_id) REFERENCES approval_requests(id)
)`,
		`CREATE INDEX IF NOT EXISTS idx_approval_decisions_request_created ON approval_decisions(approval_id, created_at)`,
		`CREATE TABLE IF NOT EXISTS approval_rules (
    id TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    matcher_json TEXT NOT NULL,
    review_strategy TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id, scope_type, scope_id)
)`,
		// 删除墓碑：默认规则被管理员删除后，重启播种不再恢复同 ID 规则。
		`CREATE TABLE IF NOT EXISTS approval_rule_tombstones (
    id TEXT PRIMARY KEY,
    deleted_at DATETIME NOT NULL
)`,
		// 决策台账（append-only）：代码中无 UPDATE/DELETE 路径；
		// 保留期清理是唯一允许的删除来源。
		`CREATE TABLE IF NOT EXISTS approval_ledger (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    approval_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    conversation_id TEXT NOT NULL DEFAULT '',
    project_id TEXT NOT NULL DEFAULT '',
    requester_user_id TEXT NOT NULL DEFAULT '',
    tool_name TEXT NOT NULL DEFAULT '',
    tool_call_id TEXT NOT NULL DEFAULT '',
    action_class TEXT NOT NULL DEFAULT '',
    assessment_decision TEXT NOT NULL DEFAULT '',
    enforcement TEXT NOT NULL DEFAULT '',
    review_strategy TEXT NOT NULL DEFAULT '',
    risk_level TEXT NOT NULL DEFAULT '',
    args_hash TEXT NOT NULL DEFAULT '',
    edited INTEGER NOT NULL DEFAULT 0,
    actor_type TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL DEFAULT '',
    matched_rules TEXT NOT NULL DEFAULT '[]',
    comment TEXT NOT NULL DEFAULT '',
    success INTEGER,
    summary TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
)`,
		`CREATE INDEX IF NOT EXISTS idx_approval_ledger_invocation ON approval_ledger(invocation_id)`,
		`CREATE INDEX IF NOT EXISTS idx_approval_ledger_created ON approval_ledger(created_at)`,
	}
	for _, statement := range statements {
		if _, err := s.execer.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize approval schema: %w", err)
		}
	}
	return s.migrateRuleTableFromRevisioned(ctx)
}

// migrateRuleTableFromRevisioned 把旧版按修订（revision 主键）存储的规则表
// 重建为单行直更表，每个规则仅保留最新修订；新版表无 revision 列，直接跳过。
func (s *SQLiteStore) migrateRuleTableFromRevisioned(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(approval_rules)`)
	if err != nil {
		return fmt.Errorf("inspect approval rules table: %w", err)
	}
	hasRevision := false
	for rows.Next() {
		var cid, notNull, pk int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan approval rules columns: %w", err)
		}
		if name == "revision" {
			hasRevision = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list approval rules columns: %w", err)
	}
	rows.Close()
	if !hasRevision {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin approval rules migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	steps := []string{
		`CREATE TABLE approval_rules_migrated (
    id TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    matcher_json TEXT NOT NULL,
    review_strategy TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id, scope_type, scope_id)
)`,
		`INSERT INTO approval_rules_migrated
(id, scope_type, scope_id, enabled, priority, risk_level, matcher_json, review_strategy, created_at, updated_at)
SELECT id, scope_type, scope_id, enabled, priority, risk_level, matcher_json, review_strategy, created_at, updated_at
FROM approval_rules r WHERE NOT EXISTS (
    SELECT 1 FROM approval_rules newer
    WHERE newer.id = r.id AND newer.scope_type = r.scope_type AND newer.scope_id = r.scope_id
      AND newer.revision > r.revision
)`,
		`DROP TABLE approval_rules`,
		`ALTER TABLE approval_rules_migrated RENAME TO approval_rules`,
	}
	for _, step := range steps {
		if _, err := tx.ExecContext(ctx, step); err != nil {
			return fmt.Errorf("migrate approval rules table: %w", err)
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) CreateRequest(ctx context.Context, request *Request) error {
	if s == nil || s.execer == nil {
		return errors.New("approval store database is unavailable")
	}
	if err := validateRequest(request); err != nil {
		return err
	}
	arguments, err := json.Marshal(request.Arguments)
	if err != nil {
		return fmt.Errorf("marshal approval arguments: %w", err)
	}
	triggers, _ := json.Marshal(sortedUnique(request.TriggerSources))
	policies, _ := json.Marshal(sortedUnique(request.MatchedPolicies))
	now := time.Now().UTC()
	if request.CreatedAt.IsZero() {
		request.CreatedAt = now
	}
	if request.UpdatedAt.IsZero() {
		request.UpdatedAt = request.CreatedAt
	}
	_, err = s.execer.ExecContext(ctx, `INSERT INTO approval_requests (
id, invocation_id, invocation_hash, source, conversation_id, message_id, project_id,
requester_user_id, tool_name, tool_call_id, arguments_json, risk_level,
trigger_sources_json, matched_rule_revisions_json, review_strategy, stage, status,
expires_at, claimed_at, execution_id, execution_summary, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		request.ID, request.InvocationID, request.InvocationHash, request.Source,
		nullableString(request.ConversationID), nullableString(request.MessageID), nullableString(request.ProjectID),
		request.RequesterUserID, request.ToolName, nullableString(request.ToolCallID), string(arguments), request.RiskLevel,
		string(triggers), string(policies), request.Reviewer, request.Stage, request.Status,
		request.ExpiresAt, nil, nullableString(request.ExecutionID), nullableString(request.ExecutionSummary),
		request.CreatedAt, request.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create approval request: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetRequest(ctx context.Context, id string) (*Request, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("approval store database is unavailable")
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, invocation_id, invocation_hash, source,
conversation_id, message_id, project_id, requester_user_id, tool_name, tool_call_id,
arguments_json, risk_level, trigger_sources_json, matched_rule_revisions_json,
review_strategy, stage, status, expires_at, claimed_at, execution_id, execution_summary,
created_at, updated_at FROM approval_requests WHERE id = ?`, strings.TrimSpace(id))
	request, err := scanRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get approval request: %w", err)
	}
	return request, nil
}

func (s *SQLiteStore) AppendDecision(ctx context.Context, decision DecisionRecord) error {
	if s == nil || s.execer == nil {
		return errors.New("approval store database is unavailable")
	}
	if decision.ID == "" || decision.ApprovalID == "" || decision.ActorType == "" || decision.Decision == "" {
		return errors.New("approval decision is incomplete")
	}
	metadata, err := json.Marshal(decision.Metadata)
	if err != nil {
		return fmt.Errorf("marshal approval decision metadata: %w", err)
	}
	if decision.CreatedAt.IsZero() {
		decision.CreatedAt = time.Now().UTC()
	}
	_, err = s.execer.ExecContext(ctx, `INSERT INTO approval_decisions
(id, approval_id, stage, actor_type, actor_id, decision, comment, metadata_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, decision.ID, decision.ApprovalID, decision.Stage,
		decision.ActorType, nullableString(decision.ActorID), decision.Decision,
		nullableString(decision.Comment), string(metadata), decision.CreatedAt)
	if err != nil {
		return fmt.Errorf("append approval decision: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListDecisions(ctx context.Context, approvalID string) ([]DecisionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("approval store database is unavailable")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, approval_id, stage, actor_type,
COALESCE(actor_id,''), decision, COALESCE(comment,''), COALESCE(metadata_json,'{}'), created_at
FROM approval_decisions WHERE approval_id = ? ORDER BY created_at, id`, strings.TrimSpace(approvalID))
	if err != nil {
		return nil, fmt.Errorf("list approval decisions: %w", err)
	}
	defer rows.Close()
	items := make([]DecisionRecord, 0)
	for rows.Next() {
		var item DecisionRecord
		var metadataJSON string
		if err := rows.Scan(&item.ID, &item.ApprovalID, &item.Stage, &item.ActorType, &item.ActorID,
			&item.Decision, &item.Comment, &metadataJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan approval decision: %w", err)
		}
		if err := json.Unmarshal([]byte(metadataJSON), &item.Metadata); err != nil {
			return nil, fmt.Errorf("decode approval decision metadata: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListDecisionsForApprovals 一次查询装配多个审批的决定历史，供列表页
// 批量使用，替代逐审批查询。
func (s *SQLiteStore) ListDecisionsForApprovals(ctx context.Context, approvalIDs []string) (map[string][]DecisionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("approval store database is unavailable")
	}
	result := make(map[string][]DecisionRecord, len(approvalIDs))
	wanted := make(map[string]struct{}, len(approvalIDs))
	args := make([]any, 0, len(approvalIDs))
	for _, raw := range approvalIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, dup := wanted[id]; dup {
			continue
		}
		wanted[id] = struct{}{}
		args = append(args, id)
	}
	if len(args) == 0 {
		return result, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	rows, err := s.db.QueryContext(ctx, `SELECT id, approval_id, stage, actor_type,
COALESCE(actor_id,''), decision, COALESCE(comment,''), COALESCE(metadata_json,'{}'), created_at
FROM approval_decisions WHERE approval_id IN (`+placeholders+`) ORDER BY approval_id, created_at, id`, args...)
	if err != nil {
		return nil, fmt.Errorf("list approval decisions batch: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item DecisionRecord
		var metadataJSON string
		if err := rows.Scan(&item.ID, &item.ApprovalID, &item.Stage, &item.ActorType, &item.ActorID,
			&item.Decision, &item.Comment, &metadataJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan approval decision: %w", err)
		}
		if err := json.Unmarshal([]byte(metadataJSON), &item.Metadata); err != nil {
			return nil, fmt.Errorf("decode approval decision metadata: %w", err)
		}
		if _, wantedID := wanted[item.ApprovalID]; !wantedID {
			continue
		}
		result[item.ApprovalID] = append(result[item.ApprovalID], item)
	}
	return result, rows.Err()
}

// RecordDecision persists the decision and its state transition atomically so
// readers can never observe a final decision with a stale request state.
func (s *SQLiteStore) RecordDecision(ctx context.Context, decision DecisionRecord, from, to, stage string) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
	}
	if s == nil || s.db == nil {
		return errors.New("approval store database is unavailable")
	}
	if decision.ID == "" || decision.ApprovalID == "" || decision.ActorType == "" || decision.Decision == "" {
		return errors.New("approval decision is incomplete")
	}
	metadata, err := json.Marshal(decision.Metadata)
	if err != nil {
		return fmt.Errorf("marshal approval decision metadata: %w", err)
	}
	if decision.CreatedAt.IsZero() {
		decision.CreatedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin approval decision: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO approval_decisions
(id, approval_id, stage, actor_type, actor_id, decision, comment, metadata_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, decision.ID, decision.ApprovalID, decision.Stage,
		decision.ActorType, nullableString(decision.ActorID), decision.Decision,
		nullableString(decision.Comment), string(metadata), decision.CreatedAt)
	if err != nil {
		return fmt.Errorf("append approval decision: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE approval_requests
SET status = ?, stage = ?, updated_at = ? WHERE id = ? AND status = ?`,
		to, stage, decision.CreatedAt, decision.ApprovalID, from)
	if err := stateChangeResult(result, err); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit approval decision: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Claim(ctx context.Context, id, executionID string) error {
	if s == nil || s.execer == nil {
		return errors.New("approval store database is unavailable")
	}
	now := time.Now().UTC()
	result, err := s.execer.ExecContext(ctx, `UPDATE approval_requests
SET status = ?, stage = ?, claimed_at = ?, execution_id = ?, updated_at = ?
WHERE id = ? AND status = ?`, StatusExecuting, StageExecution, now,
		strings.TrimSpace(executionID), now, strings.TrimSpace(id), StatusApproved)
	return stateChangeResult(result, err)
}

func (s *SQLiteStore) Complete(ctx context.Context, id string, execution ExecutionResult) error {
	if s == nil || s.execer == nil {
		return errors.New("approval store database is unavailable")
	}
	status := StatusFailed
	if execution.Success {
		status = StatusSucceeded
	}
	completedAt := execution.CompletedAt
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}
	result, err := s.execer.ExecContext(ctx, `UPDATE approval_requests
SET status = ?, stage = ?, execution_id = CASE WHEN ? <> '' THEN ? ELSE execution_id END,
execution_summary = ?, updated_at = ? WHERE id = ? AND status = ?`,
		status, StageTerminal, execution.ExecutionID, execution.ExecutionID,
		execution.Summary, completedAt, strings.TrimSpace(id), StatusExecuting)
	return stateChangeResult(result, err)
}

func (s *SQLiteStore) PurgeTerminalBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("approval store database is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	terminalStatuses := []string{StatusSucceeded, StatusFailed, StatusRejected, StatusExpired, StatusCancelled}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(terminalStatuses)), ",")
	args := make([]any, 0, len(terminalStatuses)+1)
	for _, status := range terminalStatuses {
		args = append(args, status)
	}
	args = append(args, cutoff.UTC())
	where := "status IN (" + placeholders + ") AND datetime(updated_at) < datetime(?)"
	if _, err := tx.ExecContext(ctx, `DELETE FROM approval_decisions WHERE approval_id IN
(SELECT id FROM approval_requests WHERE `+where+`)`, args...); err != nil {
		return 0, fmt.Errorf("purge approval decisions: %w", err)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM approval_requests WHERE `+where, args...)
	if err != nil {
		return 0, fmt.Errorf("purge approval requests: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *SQLiteStore) List(ctx context.Context, filter ListFilter) ([]*Request, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("approval store database is unavailable")
	}
	query := `SELECT id, invocation_id, invocation_hash, source,
conversation_id, message_id, project_id, requester_user_id, tool_name, tool_call_id,
arguments_json, risk_level, trigger_sources_json, matched_rule_revisions_json,
review_strategy, stage, status, expires_at, claimed_at, execution_id, execution_summary,
created_at, updated_at FROM approval_requests WHERE `
	where, args := buildApprovalRequestWhere(filter)
	query += where
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	// id 作为 tie-breaker：同 created_at 的行跨页必须稳定不重不漏
	query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, filter.Offset)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list approval requests: %w", err)
	}
	defer rows.Close()
	requests := make([]*Request, 0)
	for rows.Next() {
		request, scanErr := scanRequest(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan approval request: %w", scanErr)
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (s *SQLiteStore) Count(ctx context.Context, filter ListFilter) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("approval store database is unavailable")
	}
	query := `SELECT COUNT(1) FROM approval_requests WHERE `
	where, args := buildApprovalRequestWhere(filter)
	query += where
	var total int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count approval requests: %w", err)
	}
	return total, nil
}

func buildApprovalRequestWhere(filter ListFilter) (string, []any) {
	clauses := []string{"1=1"}
	args := make([]any, 0, 16)
	if filter.ConversationID != "" {
		clauses = append(clauses, "conversation_id = ?")
		args = append(args, filter.ConversationID)
	}
	if filter.ProjectID != "" {
		clauses = append(clauses, "project_id = ?")
		args = append(args, filter.ProjectID)
	}
	if filter.RequesterUserID != "" {
		clauses = append(clauses, "requester_user_id = ?")
		args = append(args, filter.RequesterUserID)
	}
	if filter.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, filter.Status)
	}
	if filter.TerminalOnly {
		clauses = append(clauses, "status IN (?, ?, ?, ?, ?)")
		args = append(args, StatusSucceeded, StatusFailed, StatusRejected, StatusExpired, StatusCancelled)
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		pattern := "%" + escapeApprovalLike(query) + "%"
		clauses = append(clauses, `(id LIKE ? ESCAPE '\' OR tool_name LIKE ? ESCAPE '\' OR source LIKE ? ESCAPE '\' OR conversation_id LIKE ? ESCAPE '\' OR matched_rule_revisions_json LIKE ? ESCAPE '\')`)
		for range 5 {
			args = append(args, pattern)
		}
	}
	if filter.Decision != "" || filter.ActorType != "" {
		decisionClauses := []string{"approval_decisions.approval_id = approval_requests.id"}
		if filter.Decision != "" {
			decisionClauses = append(decisionClauses, "approval_decisions.decision = ?")
			args = append(args, filter.Decision)
		}
		if filter.ActorType != "" {
			decisionClauses = append(decisionClauses, "approval_decisions.actor_type = ?")
			args = append(args, filter.ActorType)
		}
		clauses = append(clauses, "EXISTS (SELECT 1 FROM approval_decisions WHERE "+strings.Join(decisionClauses, " AND ")+")")
	}
	return strings.Join(clauses, " AND "), args
}

func escapeApprovalLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

func (s *SQLiteStore) ListApprovalRules(ctx context.Context) ([]Rule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("approval store database is unavailable")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, r.enabled,
r.priority, r.risk_level, r.matcher_json
FROM approval_rules r
WHERE r.scope_type = 'global' AND r.scope_id = ''
ORDER BY r.scope_type, r.scope_id, r.id`)
	if err != nil {
		return nil, fmt.Errorf("list approval rules: %w", err)
	}
	defer rows.Close()
	rules := make([]Rule, 0)
	for rows.Next() {
		var rule Rule
		var matcherJSON string
		var enabled int
		if err := rows.Scan(&rule.ID, &enabled, &rule.Priority,
			&rule.RiskLevel, &matcherJSON); err != nil {
			return nil, fmt.Errorf("scan approval rule: %w", err)
		}
		rule.Enabled = enabled != 0
		if err := json.Unmarshal([]byte(matcherJSON), &rule.Matcher); err != nil {
			return nil, fmt.Errorf("decode approval rule matcher: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// SeedDefaultRules 把系统默认规则播种为普通数据库规则：只插入当前没有落行、
// 也未被删除（墓碑）的默认 ID；已存在的行（含管理员改动）一律不动。
// 因此默认规则之后与自定义规则完全同权：可编辑、可停用、可删除。
func (s *SQLiteStore) SeedDefaultRules(ctx context.Context, defaults []Rule) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("approval store database is unavailable")
	}
	seeded := 0
	for _, rule := range defaults {
		input := rule
		if err := validateRule(input); err != nil {
			return seeded, fmt.Errorf("default approval rule %s: %w", rule.ID, err)
		}
		matcherJSON, err := json.Marshal(input.Matcher)
		if err != nil {
			return seeded, fmt.Errorf("encode default approval rule matcher %s: %w", rule.ID, err)
		}
		var exists, tombstoned int
		if err := s.db.QueryRowContext(ctx, `SELECT
    (SELECT COUNT(1) FROM approval_rules WHERE id = ? AND scope_type = 'global' AND scope_id = ''),
    (SELECT COUNT(1) FROM approval_rule_tombstones WHERE id = ?)`, rule.ID, rule.ID).Scan(&exists, &tombstoned); err != nil {
			return seeded, fmt.Errorf("check default approval rule %s: %w", rule.ID, err)
		}
		if exists > 0 || tombstoned > 0 {
			continue
		}
		now := time.Now().UTC()
		if _, err := s.db.ExecContext(ctx, `INSERT INTO approval_rules
(id, scope_type, scope_id, enabled, priority, risk_level, matcher_json,
review_strategy, created_at, updated_at)
VALUES (?, 'global', '', ?, ?, ?, ?, '', ?, ?)`, input.ID,
			boolInt(input.Enabled), input.Priority, input.RiskLevel, string(matcherJSON), now, now); err != nil {
			return seeded, fmt.Errorf("seed default approval rule %s: %w", rule.ID, err)
		}
		seeded++
	}
	return seeded, nil
}

// PublishApprovalRule 以单行直更语义保存规则：同 ID 已存在则原地更新
// （保留 created_at），不存在则插入。规则无版本概念。
func (s *SQLiteStore) PublishApprovalRule(ctx context.Context, input Rule) (Rule, error) {
	if s == nil || s.db == nil {
		return Rule{}, errors.New("approval store database is unavailable")
	}
	if err := validateRule(input); err != nil {
		return Rule{}, err
	}
	matcherJSON, err := json.Marshal(input.Matcher)
	if err != nil {
		return Rule{}, fmt.Errorf("encode approval rule matcher: %w", err)
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO approval_rules
(id, scope_type, scope_id, enabled, priority, risk_level, matcher_json, review_strategy, created_at, updated_at)
VALUES (?, 'global', '', ?, ?, ?, ?, '', ?, ?)
ON CONFLICT(id, scope_type, scope_id) DO UPDATE SET
enabled = excluded.enabled, priority = excluded.priority, risk_level = excluded.risk_level,
matcher_json = excluded.matcher_json, updated_at = excluded.updated_at`, input.ID,
		boolInt(input.Enabled), input.Priority, input.RiskLevel, string(matcherJSON), now, now); err != nil {
		return Rule{}, fmt.Errorf("publish approval rule: %w", err)
	}
	return input, nil
}

// DeleteApprovalRule 删除某个全局规则的全部修订，并记录墓碑，
// 使重启时的默认规则播种不会复活被管理员显式删除的同 ID 规则。
func (s *SQLiteStore) DeleteApprovalRule(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("approval store database is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin approval rule delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM approval_rules WHERE id = ? AND scope_type = 'global' AND scope_id = ''`, id); err != nil {
		return fmt.Errorf("delete approval rule: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO approval_rule_tombstones (id, deleted_at) VALUES (?, ?)
ON CONFLICT(id) DO UPDATE SET deleted_at = excluded.deleted_at`, id, time.Now().UTC()); err != nil {
		return fmt.Errorf("record approval rule tombstone: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit approval rule delete: %w", err)
	}
	return nil
}

func (s *SQLiteStore) CancelUnrecoverable(ctx context.Context, now time.Time) (int64, error) {
	if s == nil || s.execer == nil {
		return 0, errors.New("approval store database is unavailable")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.execer.ExecContext(ctx, `UPDATE approval_requests
SET status = ?, stage = ?, execution_summary = ?, updated_at = ?
WHERE source <> 'workflow_node' AND status IN (?, ?, ?, ?)`,
		StatusCancelled, StageTerminal, "process restarted", now,
		StatusPendingAgent, StatusPendingHuman, StatusApproved, "claimed")
	if err != nil {
		return 0, fmt.Errorf("cancel unrecoverable approvals: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count cancelled approvals: %w", err)
	}
	return count, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanRequest(row rowScanner) (*Request, error) {
	request := &Request{}
	var conversationID, messageID, projectID, toolCallID sql.NullString
	var executionID, executionSummary sql.NullString
	var expiresAt, claimedAt sql.NullTime
	var argumentsJSON, triggersJSON, policiesJSON string
	err := row.Scan(&request.ID, &request.InvocationID, &request.InvocationHash, &request.Source,
		&conversationID, &messageID, &projectID, &request.RequesterUserID, &request.ToolName, &toolCallID,
		&argumentsJSON, &request.RiskLevel, &triggersJSON, &policiesJSON,
		&request.Reviewer, &request.Stage, &request.Status, &expiresAt, &claimedAt,
		&executionID, &executionSummary, &request.CreatedAt, &request.UpdatedAt)
	if err != nil {
		return nil, err
	}
	request.ConversationID = conversationID.String
	request.MessageID = messageID.String
	request.ProjectID = projectID.String
	request.ToolCallID = toolCallID.String
	request.ExecutionID = executionID.String
	request.ExecutionSummary = executionSummary.String
	if expiresAt.Valid {
		request.ExpiresAt = &expiresAt.Time
	}
	if err := json.Unmarshal([]byte(argumentsJSON), &request.Arguments); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(triggersJSON), &request.TriggerSources); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(policiesJSON), &request.MatchedPolicies); err != nil {
		return nil, err
	}
	return request, nil
}

func stateChangeResult(result sql.Result, err error) error {
	if err != nil {
		return fmt.Errorf("change approval state: %w", err)
	}
	if result == nil {
		return ErrStateConflict
	}
	changed, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return fmt.Errorf("read approval state change result: %w", rowsErr)
	}
	if changed != 1 {
		return ErrStateConflict
	}
	return nil
}

func validateRequest(request *Request) error {
	if request == nil {
		return errors.New("approval request is nil")
	}
	if request.ID == "" || request.InvocationID == "" || request.InvocationHash == "" ||
		request.Source == "" || request.RequesterUserID == "" || request.ToolName == "" ||
		request.Reviewer == "" || request.Stage == "" || request.Status == "" {
		return errors.New("approval request is incomplete")
	}
	if CanonicalArguments(request.Arguments) == "" {
		return errors.New("approval request arguments are not JSON-compatible")
	}
	return nil
}

func nullableString(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
