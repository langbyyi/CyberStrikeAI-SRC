package multiagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutionStateCheckpointRoundTrip(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	const (
		conversationID = "conversation-a"
		orchestration  = "deep"
		checkPointID   = "runner-deep"
	)
	state := GetConversationExecutionState(conversationID)
	state.SetSessionIntent(SessionIntentPentest)
	state.SetPrimaryTarget("https://example.com/admin")
	state.MarkToolDead("missing-scanner", "not in PATH")
	state.MarkSurfaceSignalSeen()
	state.MarkVulnerabilityRecorded()
	state.MarkSuccessfulDualAuthProbe("https://example.com/orders/1")
	state.SetRoleTools([]string{"http_probe", "upsert_execution_coverage"})
	state.MarkSkillsInjected([]string{"sqli", "xss"})
	state.UpsertCoverage(CoverageItem{
		Path:     "auth.login",
		Status:   "in_progress",
		Priority: "P0",
		Note:     "candidate",
	})
	state.RecordTool(ToolEvidenceEntry{
		ToolName:   "http_probe",
		StatusHint: "success",
		Summary:    "login endpoint discovered",
	})
	state.CheckAndRecordFinalizeAttempt("finalize", true)
	state.Controller().RecordToolBatch(4, 1)
	state.Controller().ObserveSignals([]ExecutionSignal{{
		Class:      "auth_bypass",
		Target:     "https://example.com/login",
		Reportable: true,
		Confidence: "confirmed",
		Priority:   "P0",
		Summary:    "authentication bypass candidate",
	}}, []string{"auth.login"})

	store, err := newFileCheckPointStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.BindExecutionState(conversationID, orchestration)
	if err := store.Set(context.Background(), checkPointID, []byte("runner-checkpoint")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	ClearAllConversationExecutionStatesForTest()
	restored, err := store.RestoreExecutionState(context.Background(), checkPointID)
	if err != nil {
		t.Fatalf("RestoreExecutionState() error = %v", err)
	}
	if !restored {
		t.Fatal("RestoreExecutionState() restored = false, want true")
	}

	got := GetConversationExecutionState(conversationID)
	if got.SessionIntent() != SessionIntentPentest {
		t.Fatalf("session intent = %q, want %q", got.SessionIntent(), SessionIntentPentest)
	}
	if got.Controller().PrimaryTarget() != "example.com" {
		t.Fatalf("primary target = %q, want example.com", got.Controller().PrimaryTarget())
	}
	if dead, reason := got.IsToolDead("missing-scanner"); !dead || reason != "not in PATH" {
		t.Fatalf("dead tool = (%v, %q), want (true, %q)", dead, reason, "not in PATH")
	}
	if !got.SurfaceSignalSeen() || !got.VulnerabilityRecorded() || !got.HasDualAuthProbe() {
		t.Fatal("execution decision flags were not restored")
	}
	if !got.HasDualAuthProbeForTarget("https://example.com/orders/2") {
		t.Fatal("target-scoped dual-auth evidence was not restored")
	}
	if got.EvidenceCursor() == 0 {
		t.Fatal("evidence sequence cursor was not restored")
	}
	if got.CoverageCursor() == 0 {
		t.Fatal("coverage sequence cursor was not restored")
	}
	if got.FinalizeAttempts() != 1 {
		t.Fatalf("finalize attempts = %d, want 1", got.FinalizeAttempts())
	}
	if tools := got.RoleTools(); len(tools) != 2 || tools[0] != "http_probe" {
		t.Fatalf("role tools = %#v, want preserved tools", tools)
	}
	if skills := got.InjectedSkillsCopy(); len(skills) != 2 {
		t.Fatalf("injected skills = %#v, want 2 entries", skills)
	}
	if coverage := got.ListCoverage(); len(coverage) != 1 || coverage[0].Path != "auth.login" {
		t.Fatalf("coverage = %#v, want auth.login", coverage)
	}
	if evidence := got.LastK(1); len(evidence) != 1 || evidence[0].ToolName != "http_probe" {
		t.Fatalf("evidence = %#v, want http_probe", evidence)
	}
	summary := got.Controller().Summary()
	if summary.ToolCallsPlanned != 4 || summary.ToolCallsExecuted != 3 || summary.ToolCallsDropped != 1 {
		t.Fatalf("controller summary = %#v, want preserved counters", summary)
	}
	if obligation := got.Controller().PendingObligation(); obligation == nil || obligation.Kind != "record_finding" {
		t.Fatalf("pending obligation = %#v, want record_finding", obligation)
	}
}

func TestExecutionStateCheckpointRejectsMismatchedConversation(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	dir := t.TempDir()
	store, err := newFileCheckPointStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.BindExecutionState("conversation-a", "deep")
	GetConversationExecutionState("conversation-a").SetSessionIntent(SessionIntentPentest)
	if err := store.Set(context.Background(), "runner-deep", []byte("checkpoint")); err != nil {
		t.Fatal(err)
	}

	store.BindExecutionState("conversation-b", "deep")
	restored, err := store.RestoreExecutionState(context.Background(), "runner-deep")
	if err == nil || !strings.Contains(err.Error(), "conversation") {
		t.Fatalf("RestoreExecutionState() error = %v, want conversation mismatch", err)
	}
	if restored {
		t.Fatal("mismatched checkpoint must not be restored")
	}
}

func TestExecutionStateCheckpointRejectsMismatchedOrchestration(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	store, err := newFileCheckPointStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.BindExecutionState("conversation-a", "deep")
	if err := store.Set(context.Background(), "runner-deep", []byte("checkpoint")); err != nil {
		t.Fatal(err)
	}

	store.BindExecutionState("conversation-a", "supervisor")
	restored, err := store.RestoreExecutionState(context.Background(), "runner-deep")
	if err == nil || !strings.Contains(err.Error(), "orchestration") {
		t.Fatalf("RestoreExecutionState() error = %v, want orchestration mismatch", err)
	}
	if restored {
		t.Fatal("mismatched orchestration checkpoint must not be restored")
	}
}

func TestExecutionStateCheckpointRejectsUnsupportedVersion(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	dir := t.TempDir()
	store, err := newFileCheckPointStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.BindExecutionState("conversation-a", "deep")
	if err := store.Set(context.Background(), "runner-deep", []byte("checkpoint")); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(dir, "runner-deep.state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["version"] = float64(999)
	data, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	ClearAllConversationExecutionStatesForTest()
	restored, err := store.RestoreExecutionState(context.Background(), "runner-deep")
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("RestoreExecutionState() error = %v, want version error", err)
	}
	if restored || ConversationExecutionStateCount() != 0 {
		t.Fatal("unsupported checkpoint must not mutate execution state")
	}
}

func TestExecutionStateCheckpointRejectsCorruptJSON(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	dir := t.TempDir()
	store, err := newFileCheckPointStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.BindExecutionState("conversation-a", "deep")
	if err := store.Set(context.Background(), "runner-deep", []byte("checkpoint")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runner-deep.state.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}

	ClearAllConversationExecutionStatesForTest()
	restored, err := store.RestoreExecutionState(context.Background(), "runner-deep")
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("RestoreExecutionState() error = %v, want decode error", err)
	}
	if restored || ConversationExecutionStateCount() != 0 {
		t.Fatal("corrupt checkpoint must not mutate execution state")
	}
}

func TestFileCheckPointStoreDeleteRemovesRunnerAndExecutionState(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	dir := t.TempDir()
	store, err := newFileCheckPointStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.BindExecutionState("conversation-a", "deep")
	if err := store.Set(context.Background(), "runner-deep", []byte("checkpoint")); err != nil {
		t.Fatal(err)
	}

	if err := store.Delete(context.Background(), "runner-deep"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	for _, name := range []string{"runner-deep.ckpt", "runner-deep.state.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after Delete(), stat error = %v", name, err)
		}
	}
}

func TestFileCheckPointStoreSetReplacesExistingPair(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	store, err := newFileCheckPointStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.BindExecutionState("conversation-a", "deep")
	if err := store.Set(context.Background(), "runner-deep", []byte("first")); err != nil {
		t.Fatal(err)
	}
	GetConversationExecutionState("conversation-a").SetSessionIntent(SessionIntentPentest)
	if err := store.Set(context.Background(), "runner-deep", []byte("second")); err != nil {
		t.Fatalf("second Set() error = %v", err)
	}
	got, exists, err := store.Get(context.Background(), "runner-deep")
	if err != nil || !exists || string(got) != "second" {
		t.Fatalf("Get() = (%q, %v, %v), want second checkpoint", got, exists, err)
	}
}

func TestEinoCheckpointReadyForResumeRequiresExecutionState(t *testing.T) {
	dir := t.TempDir()
	store, err := newFileCheckPointStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(context.Background(), "runner-deep", []byte("legacy-checkpoint")); err != nil {
		t.Fatal(err)
	}
	store.BindExecutionState("conversation-a", "deep")

	ready, err := einoCheckpointReadyForResume(context.Background(), store, "runner-deep")
	if err == nil || !strings.Contains(err.Error(), "execution state") {
		t.Fatalf("einoCheckpointReadyForResume() error = %v, want missing execution state", err)
	}
	if ready {
		t.Fatal("legacy checkpoint without execution state must not be resumed")
	}
}
