package approval

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

type recordingReviewer struct {
	calls  int
	result ReviewDecision
}

func (r *recordingReviewer) Review(_ context.Context, _ ReviewRequest) (ReviewDecision, error) {
	r.calls++
	return r.result, nil
}

func TestCoordinatorCreatesOneRequestForMergedTriggersAndOneShotGrant(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "approval.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewSQLiteStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	reviewer := &recordingReviewer{result: ReviewDecision{
		Decision: ReviewerApprove, ActorType: ReviewerAgent, ActorID: "reviewer-1",
	}}
	evaluator := NewEvaluator(
		fixedTrigger{name: PolicyTypeToolApproval, result: TriggerResult{Matched: true}},
		fixedTrigger{name: PolicyTypeDangerousAction, result: TriggerResult{Matched: true, RiskLevel: RiskHigh}},
	)
	coordinator := NewCoordinator(CoordinatorOptions{
		Evaluator: evaluator, Config: Config{Reviewer: ReviewerAgent}, Store: store, AgentReviewer: reviewer,
	})
	invocation := Invocation{
		ID: "inv-1", Source: "test", RequesterUserID: "user-1", ToolName: "exec",
		Arguments: map[string]any{"command": "id"},
	}
	grant, err := coordinator.Authorize(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if reviewer.calls != 1 || grant.IsEmpty() {
		t.Fatalf("review calls=%d grant=%+v", reviewer.calls, grant)
	}
	items, err := store.List(context.Background(), ListFilter{Limit: 10})
	if err != nil || len(items) != 1 || len(items[0].TriggerSources) != 2 {
		t.Fatalf("requests=%+v err=%v", items, err)
	}
	if !grant.AuthorizesToolCall("exec", map[string]any{"command": "id"}, coordinator.now()) ||
		grant.AuthorizesToolCall("exec", map[string]any{"command": "whoami"}, coordinator.now()) {
		t.Fatal("grant must authorize only the exact reviewed arguments")
	}
	if err := coordinator.Claim(context.Background(), grant, "exec-1"); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Claim(context.Background(), grant, "exec-2"); err == nil {
		t.Fatal("grant must not be claimable twice")
	}
}

func TestBundledDangerRulesCompileUnderGlobalRuleContract(t *testing.T) {
	rules, err := LoadBundledDangerRules()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuleLoader(rules); err != nil {
		t.Fatal(err)
	}
}

func TestGrantArgumentsCannotMutateAuthorizedCall(t *testing.T) {
	original := map[string]any{"command": "id"}
	grant := newGrant(GrantSpec{
		ApprovalID: "approval-1", InvocationID: "inv-1", InvocationHash: "hash-1",
		ToolName: "exec", Arguments: original,
	})
	original["command"] = "shutdown"
	returned := grant.Arguments()
	if returned["command"] != "id" {
		t.Fatalf("grant arguments changed through constructor input: %+v", returned)
	}
	returned["command"] = "rm -rf /"
	if !grant.AuthorizesToolCall("exec", map[string]any{"command": "id"}, time.Now()) {
		t.Fatal("mutating returned arguments changed the frozen approved arguments")
	}
	if grant.AuthorizesToolCall("exec", map[string]any{"command": "rm -rf /"}, time.Now()) {
		t.Fatal("grant authorized arguments introduced after approval")
	}
}

type switchingStore struct {
	Store
	afterCreate func()
}

func (s switchingStore) CreateRequest(ctx context.Context, request *Request) error {
	if err := s.Store.CreateRequest(ctx, request); err != nil {
		return err
	}
	s.afterCreate()
	return nil
}

func TestCoordinatorUsesReviewerFrozenOnRequest(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "reviewer.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewSQLiteStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewGlobalRuntime(Config{Reviewer: ReviewerAgent, ToolApproval: TriggerConfig{Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	agent := &recordingReviewer{result: ReviewDecision{Decision: ReviewerApprove, ActorType: "agent", ActorID: "agent-1"}}
	human := &recordingReviewer{result: ReviewDecision{Decision: ReviewerReject, ActorType: "human", ActorID: "human-1"}}
	coordinator := NewCoordinator(CoordinatorOptions{
		Evaluator: runtime,
		Store: switchingStore{Store: store, afterCreate: func() {
			if err := runtime.Update(Config{Reviewer: ReviewerHuman, ToolApproval: TriggerConfig{Enabled: true}}, nil); err != nil {
				t.Fatal(err)
			}
		}},
		AgentReviewer: agent, HumanReviewer: human,
	})
	_, err = coordinator.Authorize(context.Background(), Invocation{
		ID: "inv-switch", Source: "test", RequesterUserID: "user-1", ToolName: "exec", Arguments: map[string]any{"command": "id"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent.calls != 1 || human.calls != 0 {
		t.Fatalf("agent calls=%d human calls=%d; request reviewer was not frozen", agent.calls, human.calls)
	}
}
