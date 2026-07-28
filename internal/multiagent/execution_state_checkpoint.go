package multiagent

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const executionStateCheckpointVersion = 1

type executionStateCheckpointEnvelope struct {
	Version        int                    `json:"version"`
	ConversationID string                 `json:"conversation_id"`
	Orchestration  string                 `json:"orchestration"`
	SavedAt        time.Time              `json:"saved_at"`
	ExecutionState executionStateSnapshot `json:"execution_state"`
}

type executionStateSnapshot struct {
	RecentTools           []ToolEvidenceEntry         `json:"recent_tools,omitempty"`
	Coverage              map[string]CoverageItem     `json:"coverage,omitempty"`
	InjectedSkills        []string                    `json:"injected_skills,omitempty"`
	DualAuthProbe         bool                        `json:"dual_auth_probe,omitempty"`
	AuthASeen             bool                        `json:"auth_a_seen,omitempty"`
	AuthBSeen             bool                        `json:"auth_b_seen,omitempty"`
	RecentToolNames       []string                    `json:"recent_tool_names,omitempty"`
	RecentUpsertCount     int                         `json:"recent_upsert_count,omitempty"`
	FinalizeAttempts      int                         `json:"finalize_attempts,omitempty"`
	ToolDead              map[string]string           `json:"tool_dead,omitempty"`
	SurfaceSignalSeen     bool                        `json:"surface_signal_seen,omitempty"`
	VulnerabilityRecorded bool                        `json:"vulnerability_recorded,omitempty"`
	RoleTools             []string                    `json:"role_tools,omitempty"`
	SessionIntent         SessionIntent               `json:"session_intent,omitempty"`
	Controller            executionControllerSnapshot `json:"controller"`
}

type executionControllerSnapshot struct {
	Primary             string               `json:"primary,omitempty"`
	Obligations         []DecisionObligation `json:"obligations,omitempty"`
	Seen                []string             `json:"seen,omitempty"`
	Directives          []string             `json:"directives,omitempty"`
	SeenResults         []string             `json:"seen_results,omitempty"`
	SeenCalls           []string             `json:"seen_calls,omitempty"`
	CallAttempts        map[string]int       `json:"call_attempts,omitempty"`
	LastCallCode        map[string]string    `json:"last_call_code,omitempty"`
	ActiveProbeCalls    []string             `json:"active_probe_calls,omitempty"`
	ActiveBatchNovel    bool                 `json:"active_batch_novel,omitempty"`
	NoNovelBatches      int                  `json:"no_novel_batches,omitempty"`
	NoNovelProbeCalls   int                  `json:"no_novel_probe_calls,omitempty"`
	PivotRequired       bool                 `json:"pivot_required,omitempty"`
	PivotDirectiveShown bool                 `json:"pivot_directive_shown,omitempty"`
	Summary             ExecutionSummary     `json:"summary"`
}

func newExecutionStateCheckpointEnvelope(conversationID, orchestration string) executionStateCheckpointEnvelope {
	conversationID = normalizeExecutionCheckpointConversationID(conversationID)
	return executionStateCheckpointEnvelope{
		Version:        executionStateCheckpointVersion,
		ConversationID: conversationID,
		Orchestration:  normalizeExecutionCheckpointOrchestration(orchestration),
		SavedAt:        time.Now().UTC(),
		ExecutionState: snapshotConversationExecutionState(conversationID),
	}
}

func validateExecutionStateCheckpointEnvelope(envelope executionStateCheckpointEnvelope, conversationID, orchestration string) error {
	if envelope.Version != executionStateCheckpointVersion {
		return fmt.Errorf("unsupported execution state checkpoint version %d", envelope.Version)
	}
	wantConversationID := normalizeExecutionCheckpointConversationID(conversationID)
	if normalizeExecutionCheckpointConversationID(envelope.ConversationID) != wantConversationID {
		return fmt.Errorf("execution state checkpoint conversation mismatch: got %q want %q", envelope.ConversationID, wantConversationID)
	}
	wantOrchestration := normalizeExecutionCheckpointOrchestration(orchestration)
	if normalizeExecutionCheckpointOrchestration(envelope.Orchestration) != wantOrchestration {
		return fmt.Errorf("execution state checkpoint orchestration mismatch: got %q want %q", envelope.Orchestration, wantOrchestration)
	}
	if len(envelope.ExecutionState.RecentTools) > defaultMaxEvidence ||
		len(envelope.ExecutionState.Coverage) > defaultMaxCoverage {
		return fmt.Errorf("execution state checkpoint exceeds configured bounds")
	}
	return nil
}

func normalizeExecutionCheckpointConversationID(conversationID string) string {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return "default"
	}
	return conversationID
}

func normalizeExecutionCheckpointOrchestration(orchestration string) string {
	orchestration = strings.ToLower(strings.TrimSpace(orchestration))
	if orchestration == "" {
		return "default"
	}
	return orchestration
}

func snapshotConversationExecutionState(conversationID string) executionStateSnapshot {
	state := GetConversationExecutionState(conversationID)
	state.mu.Lock()
	snapshot := executionStateSnapshot{
		RecentTools:           append([]ToolEvidenceEntry(nil), state.RecentTools...),
		Coverage:              cloneCoverageMap(state.Coverage),
		InjectedSkills:        sortedStringSet(state.InjectedSkills),
		DualAuthProbe:         state.dualAuthProbe,
		AuthASeen:             state.authASeen,
		AuthBSeen:             state.authBSeen,
		RecentToolNames:       append([]string(nil), state.recentToolNames...),
		RecentUpsertCount:     state.recentUpsertCount,
		FinalizeAttempts:      state.finalizeAttempts,
		ToolDead:              cloneStringMap(state.toolDead),
		SurfaceSignalSeen:     state.surfaceSignalSeen,
		VulnerabilityRecorded: state.vulnerabilityRecorded,
		RoleTools:             append([]string(nil), state.roleTools...),
		SessionIntent:         state.sessionIntent,
	}
	controller := state.controller
	state.mu.Unlock()
	snapshot.Controller = snapshotExecutionController(controller)
	return snapshot
}

func restoreConversationExecutionState(conversationID string, snapshot executionStateSnapshot) {
	state := GetConversationExecutionState(conversationID)
	controller := restoreExecutionController(snapshot.Controller)

	state.mu.Lock()
	state.RecentTools = append([]ToolEvidenceEntry(nil), snapshot.RecentTools...)
	state.Coverage = cloneCoverageMap(snapshot.Coverage)
	state.InjectedSkills = stringSetFromSlice(snapshot.InjectedSkills)
	state.dualAuthProbe = snapshot.DualAuthProbe
	state.authASeen = snapshot.AuthASeen
	state.authBSeen = snapshot.AuthBSeen
	state.recentToolNames = append([]string(nil), snapshot.RecentToolNames...)
	state.recentUpsertCount = snapshot.RecentUpsertCount
	state.finalizeAttempts = snapshot.FinalizeAttempts
	state.toolDead = cloneStringMap(snapshot.ToolDead)
	state.surfaceSignalSeen = snapshot.SurfaceSignalSeen
	state.vulnerabilityRecorded = snapshot.VulnerabilityRecorded
	state.roleTools = append([]string(nil), snapshot.RoleTools...)
	state.sessionIntent = snapshot.SessionIntent
	state.maxEvidence = defaultMaxEvidence
	state.maxCoverage = defaultMaxCoverage
	state.lastAccess = time.Now()
	state.controller = controller
	state.mu.Unlock()
}

func snapshotExecutionController(controller *ExecutionController) executionControllerSnapshot {
	if controller == nil {
		controller = NewExecutionController("")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()

	obligations := make([]DecisionObligation, 0, len(controller.obligations))
	for _, obligation := range controller.obligations {
		if obligation != nil {
			obligations = append(obligations, *cloneObligation(obligation))
		}
	}
	return executionControllerSnapshot{
		Primary:             controller.primary,
		Obligations:         obligations,
		Seen:                sortedStringSet(controller.seen),
		Directives:          sortedStringSet(controller.directives),
		SeenResults:         sortedStringSet(controller.seenResults),
		SeenCalls:           sortedStringSet(controller.seenCalls),
		CallAttempts:        cloneIntMap(controller.callAttempts),
		LastCallCode:        cloneStringMap(controller.lastCallCode),
		ActiveProbeCalls:    sortedStringSet(controller.activeProbeCalls),
		ActiveBatchNovel:    controller.activeBatchNovel,
		NoNovelBatches:      controller.noNovelBatches,
		NoNovelProbeCalls:   controller.noNovelProbeCalls,
		PivotRequired:       controller.pivotRequired,
		PivotDirectiveShown: controller.pivotDirectiveShown,
		Summary:             controller.summary,
	}
}

func restoreExecutionController(snapshot executionControllerSnapshot) *ExecutionController {
	controller := NewExecutionController(snapshot.Primary)
	controller.obligations = make([]*DecisionObligation, 0, len(snapshot.Obligations))
	for i := range snapshot.Obligations {
		obligation := snapshot.Obligations[i]
		controller.obligations = append(controller.obligations, cloneObligation(&obligation))
	}
	controller.seen = stringSetFromSlice(snapshot.Seen)
	controller.directives = stringSetFromSlice(snapshot.Directives)
	controller.seenResults = stringSetFromSlice(snapshot.SeenResults)
	controller.seenCalls = stringSetFromSlice(snapshot.SeenCalls)
	controller.callAttempts = cloneIntMap(snapshot.CallAttempts)
	controller.lastCallCode = cloneStringMap(snapshot.LastCallCode)
	controller.activeProbeCalls = stringSetFromSlice(snapshot.ActiveProbeCalls)
	controller.activeBatchNovel = snapshot.ActiveBatchNovel
	controller.noNovelBatches = snapshot.NoNovelBatches
	controller.noNovelProbeCalls = snapshot.NoNovelProbeCalls
	controller.pivotRequired = snapshot.PivotRequired
	controller.pivotDirectiveShown = snapshot.PivotDirectiveShown
	controller.summary = snapshot.Summary
	return controller
}

func cloneCoverageMap(source map[string]CoverageItem) map[string]CoverageItem {
	out := make(map[string]CoverageItem, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func cloneStringMap(source map[string]string) map[string]string {
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func cloneIntMap(source map[string]int) map[string]int {
	out := make(map[string]int, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func sortedStringSet(source map[string]struct{}) []string {
	out := make([]string, 0, len(source))
	for value := range source {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stringSetFromSlice(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}
