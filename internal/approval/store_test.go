package approval

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestApprovalStateMachineAcceptsOnlyDeclaredTransitions(t *testing.T) {
	allowed := [][2]string{
		{StatusPendingAgent, StatusApproved},
		{StatusPendingAgent, StatusRejected},
		{StatusPendingAgent, StatusPendingHuman},
		{StatusPendingHuman, StatusApproved},
		{StatusPendingHuman, StatusRejected},
		{StatusPendingHuman, StatusExpired},
		{StatusPendingHuman, StatusCancelled},
		{StatusApproved, StatusExecuting},
		{StatusExecuting, StatusSucceeded},
		{StatusExecuting, StatusFailed},
	}
	for _, transition := range allowed {
		if !CanTransition(transition[0], transition[1]) {
			t.Errorf("expected transition %s -> %s to be allowed", transition[0], transition[1])
		}
	}

	rejected := [][2]string{
		{StatusPendingHuman, StatusExecuting},
		{StatusApproved, StatusSucceeded},
		{StatusSucceeded, StatusExecuting},
		{StatusRejected, StatusApproved},
	}
	for _, transition := range rejected {
		if CanTransition(transition[0], transition[1]) {
			t.Errorf("expected transition %s -> %s to be rejected", transition[0], transition[1])
		}
	}
}

func TestSQLiteStoreClaimHasSingleWinner(t *testing.T) {
	execer := &claimExecer{status: StatusApproved}
	store := &SQLiteStore{execer: execer}

	var winners atomic.Int32
	var conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := store.Claim(context.Background(), "approval-1", "execution-1")
			switch {
			case err == nil:
				winners.Add(1)
			case errors.Is(err, ErrStateConflict):
				conflicts.Add(1)
			default:
				t.Errorf("unexpected Claim error: %v", err)
			}
		}()
	}
	wg.Wait()

	if winners.Load() != 1 {
		t.Fatalf("claim winners = %d, want 1", winners.Load())
	}
	if conflicts.Load() != 99 {
		t.Fatalf("claim conflicts = %d, want 99", conflicts.Load())
	}
	if execer.status != StatusExecuting {
		t.Fatalf("claim status = %s, want %s", execer.status, StatusExecuting)
	}
}

type claimExecer struct {
	mu     sync.Mutex
	status string
}

func (e *claimExecer) ExecContext(_ context.Context, _ string, args ...any) (sql.Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	expected := args[len(args)-1].(string)
	if e.status != expected {
		return fixedSQLResult(0), nil
	}
	e.status = args[0].(string)
	return fixedSQLResult(1), nil
}

type fixedSQLResult int64

func (r fixedSQLResult) LastInsertId() (int64, error) { return 0, nil }
func (r fixedSQLResult) RowsAffected() (int64, error) { return int64(r), nil }

func TestSeedDefaultRulesSeedsEditsAndTombstones(t *testing.T) {
	ctx := context.Background()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "approval-rules.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewSQLiteStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	defaults := []Rule{
		{ID: "default.one", Enabled: true, Priority: 100, RiskLevel: RiskHigh, Matcher: RuleMatcher{Tools: []string{"exec"}}},
		{ID: "default.two", Enabled: true, Priority: 100, RiskLevel: RiskMedium, Matcher: RuleMatcher{TextPatterns: []string{"(?i)rm -rf"}}},
	}
	seeded, err := store.SeedDefaultRules(ctx, defaults)
	if err != nil || seeded != 2 {
		t.Fatalf("first seed = %d, %v; want 2, nil", seeded, err)
	}

	// 管理员编辑 default.one（revision 递增），再播种不得覆盖改动。
	edited := defaults[0]
	edited.Enabled = false
	if _, err := store.PublishApprovalRule(ctx, edited); err != nil {
		t.Fatal(err)
	}
	if seeded, err = store.SeedDefaultRules(ctx, defaults); err != nil || seeded != 0 {
		t.Fatalf("second seed = %d, %v; want 0, nil", seeded, err)
	}
	rules, err := store.ListApprovalRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %+v, want 2 ordinary rules", rules)
	}
	for _, rule := range rules {
		if rule.ID == "default.one" && rule.Enabled {
			t.Fatalf("edited rule was overwritten by seed: %+v", rule)
		}
	}

	// 删除 default.two 记录墓碑：再次播种（重启）不得复活。
	if err := store.DeleteApprovalRule(ctx, "default.two"); err != nil {
		t.Fatal(err)
	}
	if seeded, err = store.SeedDefaultRules(ctx, defaults); err != nil || seeded != 0 {
		t.Fatalf("third seed = %d, %v; want 0, nil", seeded, err)
	}
	rules, err = store.ListApprovalRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != "default.one" {
		t.Fatalf("rules after delete+reseed = %+v; tombstoned default must not resurrect", rules)
	}
}

func TestDeleteApprovalRuleRollsBackWhenTombstoneCannotBeRecorded(t *testing.T) {
	ctx := context.Background()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "approval-rules.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewSQLiteStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	rule := Rule{ID: "custom.keep-on-failure", Enabled: true, Priority: 100, RiskLevel: RiskHigh, Matcher: RuleMatcher{Tools: []string{"exec"}}}
	if _, err := store.PublishApprovalRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER reject_approval_rule_tombstone
BEFORE INSERT ON approval_rule_tombstones
BEGIN SELECT RAISE(FAIL, 'tombstone unavailable'); END`); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteApprovalRule(ctx, rule.ID); err == nil {
		t.Fatal("expected tombstone write failure")
	}
	rules, err := store.ListApprovalRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != rule.ID {
		t.Fatalf("delete must roll back when tombstone fails, got %+v", rules)
	}
}

func TestEnsureSchemaMigratesRevisionedRuleTable(t *testing.T) {
	ctx := context.Background()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "approval-legacy.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// 造一个旧版按修订存储的规则表：default.one 有 v1/v2 两行，custom.v3 一行。
	legacy := []string{
		`CREATE TABLE approval_rules (
    id TEXT NOT NULL, scope_type TEXT NOT NULL, scope_id TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL, enabled INTEGER NOT NULL, priority INTEGER NOT NULL,
    risk_level TEXT NOT NULL, matcher_json TEXT NOT NULL, review_strategy TEXT NOT NULL,
    builtin INTEGER NOT NULL DEFAULT 0, locked INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL,
    PRIMARY KEY (id, scope_type, scope_id, revision)
)`,
		`INSERT INTO approval_rules VALUES ('default.one', 'global', '', 1, 1, 100, 'high', '{"tools":["old"]}', '', 1, 1, '2026-01-01', '2026-01-01')`,
		`INSERT INTO approval_rules VALUES ('default.one', 'global', '', 2, 0, 200, 'critical', '{"tools":["new"]}', '', 0, 0, '2026-01-02', '2026-01-02')`,
		`INSERT INTO approval_rules VALUES ('custom.rule', 'global', '', 3, 1, 50, 'medium', '{"tools":["exec"]}', '', 0, 0, '2026-01-03', '2026-01-03')`,
	}
	for _, stmt := range legacy {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	store := NewSQLiteStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	rules, err := store.ListApprovalRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules after migration = %+v, want latest row per rule", rules)
	}
	byID := map[string]Rule{}
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	got := byID["default.one"]
	if got.Enabled || got.Priority != 200 || got.RiskLevel != "critical" {
		t.Fatalf("default.one = %+v, want latest revision (v2) preserved", got)
	}
	// 迁移后的表支持单行直更。
	if _, err := store.PublishApprovalRule(ctx, Rule{ID: "custom.rule", Enabled: false, Priority: 60, RiskLevel: RiskMedium, Matcher: RuleMatcher{Tools: []string{"exec"}}}); err != nil {
		t.Fatal(err)
	}
	rules, _ = store.ListApprovalRules(ctx)
	if len(rules) != 2 {
		t.Fatalf("rules after upsert = %+v, want 2 (no version rows)", rules)
	}
	for _, rule := range rules {
		if rule.ID == "custom.rule" && rule.Enabled {
			t.Fatalf("custom.rule was not updated in place: %+v", rule)
		}
	}
}
