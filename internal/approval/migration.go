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

const legacyPolicyRevision = "legacy.hitl@1"

type MigrationResult struct {
	Requests int64
}

type legacyHITLRow struct {
	ID, ConversationID, MessageID, Mode, ToolName, ToolCallID string
	Payload, Status, Reviewer, Decision, Comment, DecidedBy   string
	CreatedAt                                                 time.Time
	DecidedAt                                                 *time.Time
}

// MigrateLegacyHITL copies legacy HITL history and conversation settings into
// the unified approval schema. Stable IDs and INSERT OR IGNORE make it safe to
// execute during every startup.
func MigrateLegacyHITL(ctx context.Context, db *database.DB) (MigrationResult, error) {
	if db == nil {
		return MigrationResult{}, errors.New("approval migration database is unavailable")
	}
	exists, err := sqliteTableExists(ctx, db, "hitl_interrupts")
	if err != nil || !exists {
		return MigrationResult{}, err
	}
	decidedByExpr := "''"
	if ok, columnErr := sqliteColumnExists(ctx, db, "hitl_interrupts", "decided_by"); columnErr != nil {
		return MigrationResult{}, columnErr
	} else if ok {
		decidedByExpr = "COALESCE(decided_by,'')"
	}
	reviewerExpr := "'human'"
	if ok, columnErr := sqliteColumnExists(ctx, db, "hitl_interrupts", "reviewer"); columnErr != nil {
		return MigrationResult{}, columnErr
	} else if ok {
		reviewerExpr = "COALESCE(reviewer,'human')"
	}
	query := `SELECT id, conversation_id, COALESCE(message_id,''), mode, tool_name,
COALESCE(tool_call_id,''), COALESCE(payload,'{}'), status, ` + reviewerExpr + `,
COALESCE(decision,''), COALESCE(decision_comment,''), ` + decidedByExpr + `,
created_at, decided_at FROM hitl_interrupts`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("read legacy HITL rows: %w", err)
	}
	legacyRows := make([]legacyHITLRow, 0)
	for rows.Next() {
		var row legacyHITLRow
		var decidedAt sql.NullTime
		if err := rows.Scan(&row.ID, &row.ConversationID, &row.MessageID, &row.Mode, &row.ToolName,
			&row.ToolCallID, &row.Payload, &row.Status, &row.Reviewer, &row.Decision, &row.Comment,
			&row.DecidedBy, &row.CreatedAt, &decidedAt); err != nil {
			_ = rows.Close()
			return MigrationResult{}, fmt.Errorf("scan legacy HITL row: %w", err)
		}
		if decidedAt.Valid {
			value := decidedAt.Time
			row.DecidedAt = &value
		}
		legacyRows = append(legacyRows, row)
	}
	if err := rows.Close(); err != nil {
		return MigrationResult{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return MigrationResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	result := MigrationResult{}
	for _, row := range legacyRows {
		request, decision, mapErr := mapLegacyHITLRow(row)
		if mapErr != nil {
			return MigrationResult{}, mapErr
		}
		arguments, _ := json.Marshal(request.Arguments)
		triggers, _ := json.Marshal(request.TriggerSources)
		policies, _ := json.Marshal(request.MatchedPolicies)
		inserted, execErr := tx.ExecContext(ctx, `INSERT OR IGNORE INTO approval_requests (
id, invocation_id, invocation_hash, source, conversation_id, message_id, project_id,
requester_user_id, tool_name, tool_call_id, arguments_json, risk_level,
trigger_sources_json, matched_rule_revisions_json, review_strategy, stage, status,
expires_at, claimed_at, execution_id, execution_summary, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?)`,
			request.ID, request.InvocationID, request.InvocationHash, request.Source,
			nullableString(request.ConversationID), nullableString(request.MessageID), request.RequesterUserID,
			request.ToolName, nullableString(request.ToolCallID), string(arguments), request.RiskLevel,
			string(triggers), string(policies), request.Reviewer, request.Stage, request.Status,
			request.ExecutionSummary, request.CreatedAt, request.UpdatedAt)
		if execErr != nil {
			return MigrationResult{}, fmt.Errorf("migrate legacy approval %s: %w", row.ID, execErr)
		}
		changed, _ := inserted.RowsAffected()
		result.Requests += changed
		metadata, _ := json.Marshal(decision.Metadata)
		if _, execErr = tx.ExecContext(ctx, `INSERT OR IGNORE INTO approval_decisions
(id, approval_id, stage, actor_type, actor_id, decision, comment, metadata_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, decision.ID, decision.ApprovalID, decision.Stage,
			decision.ActorType, decision.ActorID, decision.Decision, decision.Comment, string(metadata), decision.CreatedAt); execErr != nil {
			return MigrationResult{}, fmt.Errorf("migrate legacy decision %s: %w", row.ID, execErr)
		}
	}

	if err := tx.Commit(); err != nil {
		return MigrationResult{}, err
	}
	return result, nil
}

func mapLegacyHITLRow(row legacyHITLRow) (*Request, DecisionRecord, error) {
	if strings.TrimSpace(row.ID) == "" || row.CreatedAt.IsZero() {
		return nil, DecisionRecord{}, errors.New("legacy HITL row is incomplete")
	}
	arguments := make(map[string]any)
	if err := json.Unmarshal([]byte(row.Payload), &arguments); err != nil {
		arguments = map[string]any{"legacyPayload": row.Payload}
	}
	toolName := strings.TrimSpace(row.ToolName)
	if toolName == "" {
		toolName = "legacy_hitl"
	}
	reviewer := ReviewerHuman
	actorType := "human"
	actorID := strings.TrimSpace(row.DecidedBy)
	if strings.EqualFold(row.Reviewer, "audit_agent") || strings.EqualFold(actorID, "audit_agent") {
		reviewer, actorType = ReviewerAgent, "agent"
	} else if actorID == "system" || strings.EqualFold(row.Status, "pending") || strings.EqualFold(row.Status, "timeout") {
		actorType = "system"
	}
	if actorID == "" {
		actorID = actorType
	}
	status := StatusRejected
	decision := ReviewerReject
	switch strings.ToLower(strings.TrimSpace(row.Status)) {
	case "pending", "cancelled":
		status = StatusCancelled
		actorType, actorID = "system", "migration"
		if strings.TrimSpace(row.Comment) == "" {
			row.Comment = "legacy pending approval cannot be resumed"
		}
	case "timeout", "expired":
		status = StatusExpired
	case "decided":
		if strings.EqualFold(row.Decision, ReviewerApprove) {
			status, decision = StatusSucceeded, ReviewerApprove
		}
	}
	updatedAt := row.CreatedAt
	if row.DecidedAt != nil {
		updatedAt = *row.DecidedAt
	}
	invocation := Invocation{ID: "legacy:" + row.ID, Source: "legacy_hitl", ConversationID: row.ConversationID,
		AssistantMessageID: row.MessageID, RequesterUserID: "legacy", ToolName: toolName, ToolCallID: row.ToolCallID, Arguments: arguments}
	request := &Request{
		ID: "apr_legacy_" + row.ID, InvocationID: invocation.ID,
		InvocationHash: InvocationHash(invocation, []string{legacyPolicyRevision}), Source: invocation.Source,
		ConversationID: row.ConversationID, MessageID: row.MessageID, RequesterUserID: "legacy",
		ToolName: toolName, ToolCallID: row.ToolCallID, Arguments: arguments, RiskLevel: RiskMedium,
		TriggerSources: []string{"legacy_hitl"}, MatchedPolicies: []string{legacyPolicyRevision},
		Reviewer: reviewer, Stage: StageTerminal, Status: status,
		ExecutionSummary: "migrated legacy HITL history", CreatedAt: row.CreatedAt, UpdatedAt: updatedAt,
	}
	return request, DecisionRecord{
		ID: "apd_legacy_" + row.ID, ApprovalID: request.ID, Stage: StageTerminal,
		ActorType: actorType, ActorID: actorID, Decision: decision, Comment: row.Comment,
		Metadata: map[string]any{"legacyStatus": row.Status}, CreatedAt: updatedAt,
	}, nil
}

func sqliteTableExists(ctx context.Context, db *database.DB, table string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count)
	return count > 0, err
}

func sqliteColumnExists(ctx context.Context, db *database.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
