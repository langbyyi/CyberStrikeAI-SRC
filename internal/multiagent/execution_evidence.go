package multiagent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/database"
)

// ToolEvidenceEntry is a compact structured summary of a tool call for task handoff.
type ToolEvidenceEntry struct {
	ToolName          string    `json:"tool_name"`
	StatusHint        string    `json:"status_hint,omitempty"`
	Length            int       `json:"length"`
	ErrorSig          string    `json:"error_sig,omitempty"`
	PayloadHint       string    `json:"payload_hint,omitempty"`
	InterestingParams string    `json:"interesting_params,omitempty"`
	Summary           string    `json:"summary"`
	At                time.Time `json:"at"`
	// SkipBreaker, when true, prevents this tool call from counting toward the
	// upsert circuit breaker. Used for terminal-status upserts (done/blocked)
	// which represent real closure, not management churn.
	SkipBreaker bool `json:"-"`
}

// CoverageItem tracks whether a hunting path was exercised / closed.
type CoverageItem struct {
	Path      string    `json:"path"`     // e.g. auth.login, sqli.param:id
	Status    string    `json:"status"`   // open | in_progress | done | blocked
	Priority  string    `json:"priority"` // P0 | P1 | P2
	Note      string    `json:"note,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ConversationExecutionState holds per-conversation evidence + coverage + skill dedupe.
// All methods are concurrency-safe (per-state mutex). Global map is also mutex-guarded.
type ConversationExecutionState struct {
	mu             sync.Mutex
	RecentTools    []ToolEvidenceEntry
	Coverage       map[string]CoverageItem
	InjectedSkills map[string]struct{}
	// Dual-auth probe tracking (Logic Track E): set when logic_probe_diff sees both auth_a and auth_b.
	dualAuthProbe bool
	authASeen     bool
	authBSeen     bool
	// Recent upsert tracking: sliding window of recent tool names and the count of
	// upsert_execution_coverage calls within that window. This prevents LLM from
	// bypassing the breaker by interleaving upserts with management tools.
	recentToolNames   []string
	recentUpsertCount int
	// finalizeAttempts tracks how many times should_continue_execution(intent=finalize)
	// returned true in a row. Reset when cont=false or intent != finalize.
	finalizeAttempts int
	maxEvidence      int
	maxCoverage      int
	lastAccess       time.Time

	// Iteration-1 decision flags (execution decision architecture).
	// toolDead: hard-failed tools (templates_missing / not in PATH) — do not re-call.
	toolDead map[string]string
	// surfaceSignalSeen: high-value attack surface detected this session (inventory/disclosure taxonomy).
	surfaceSignalSeen bool
	// vulnerabilityRecorded: L1 candidate or L2 formal record succeeded this session.
	vulnerabilityRecorded bool
	// roleTools: tools bound for this conversation (empty = unrestricted / default role).
	roleTools  []string
	controller *ExecutionController
	pending    *PendingLedger
	// evidenceRejections is keyed by evidence fingerprint, not category, so
	// changing vulnerability labels cannot bypass a prior policy rejection.
	evidenceRejections map[string]string
	// sessionIntent: chat | recon | pentest — gates record obligations (see session_intent.go).
	sessionIntent SessionIntent

	// pendingCloser clears ADK run-loop pending tool IDs (framework-dropped calls).
	// Separate mutex so emit path never deadlocks with s.mu.
	pendingCloserMu sync.Mutex
	pendingCloser   func(ids []string)
}

const (
	// defaultMaxEvidence caps RecentTools ring buffer.
	defaultMaxEvidence = 40
	// defaultMaxCoverage caps Coverage map size (evict oldest UpdatedAt when exceeded).
	defaultMaxCoverage = 200
	// defaultMaxConversations caps global session map (evict least-recently-accessed).
	defaultMaxConversations = 500
	// UpsertBreakerWindow is the number of recent tool calls inspected by the
	// upsert circuit breaker.
	UpsertBreakerWindow = 5
	// MaxRecentUpsertsBeforeWarn is the threshold of upsert calls within the
	// recent window that triggers the circuit breaker.
	MaxRecentUpsertsBeforeWarn = 3
)

var (
	execStateMu           sync.Mutex
	execStates            = map[string]*ConversationExecutionState{}
	maxConversationsLimit = defaultMaxConversations
)

// GetConversationExecutionState returns (creating if needed) session state.
func GetConversationExecutionState(conversationID string) *ConversationExecutionState {
	id := strings.TrimSpace(conversationID)
	if id == "" {
		id = "default"
	}
	execStateMu.Lock()
	defer execStateMu.Unlock()
	if s, ok := execStates[id]; ok {
		s.mu.Lock()
		s.lastAccess = time.Now()
		s.mu.Unlock()
		return s
	}
	s := &ConversationExecutionState{
		Coverage:           map[string]CoverageItem{},
		InjectedSkills:     map[string]struct{}{},
		toolDead:           map[string]string{},
		maxEvidence:        defaultMaxEvidence,
		maxCoverage:        defaultMaxCoverage,
		lastAccess:         time.Now(),
		controller:         NewExecutionController(""),
		pending:            NewPendingLedger(),
		evidenceRejections: map[string]string{},
	}
	execStates[id] = s
	evictOldestConversationsLocked()
	return s
}

// Controller returns the single-target execution controller for this conversation.
func (s *ConversationExecutionState) Controller() *ExecutionController {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controller == nil {
		s.controller = NewExecutionController("")
	}
	return s.controller
}

func (s *ConversationExecutionState) PendingLedger() *PendingLedger {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = NewPendingLedger()
	}
	return s.pending
}

func (s *ConversationExecutionState) ResetPendingLedger() *PendingLedger {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = NewPendingLedger()
	return s.pending
}

func (s *ConversationExecutionState) RememberEvidenceRejection(fingerprint, code string) {
	if s == nil || strings.TrimSpace(fingerprint) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.evidenceRejections == nil {
		s.evidenceRejections = make(map[string]string)
	}
	s.evidenceRejections[strings.TrimSpace(fingerprint)] = strings.TrimSpace(code)
}

func (s *ConversationExecutionState) EvidenceRejection(fingerprint string) (string, bool) {
	if s == nil || strings.TrimSpace(fingerprint) == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.evidenceRejections[strings.TrimSpace(fingerprint)]
	return code, ok
}

// SetPrimaryTarget fixes the first non-empty target for this conversation.
func (s *ConversationExecutionState) SetPrimaryTarget(target string) string {
	return s.Controller().SetPrimaryTarget(target)
}

// SetPendingToolCallCloser registers the active ADK run-loop pending map cleaner.
// Pass nil on run end. Middleware framework-drops call this so UI pending is not orphaned.
func (s *ConversationExecutionState) SetPendingToolCallCloser(fn func(ids []string)) {
	if s == nil {
		return
	}
	s.pendingCloserMu.Lock()
	s.pendingCloser = fn
	s.pendingCloserMu.Unlock()
}

// NotifyPendingToolCallsResolved removes tool call IDs from the active run-loop pending map.
func NotifyPendingToolCallsResolved(conversationID string, ids ...string) {
	cleaned := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			cleaned = append(cleaned, id)
		}
	}
	if len(cleaned) == 0 {
		return
	}
	id := strings.TrimSpace(conversationID)
	if id == "" {
		id = "default"
	}
	execStateMu.Lock()
	state := execStates[id]
	execStateMu.Unlock()
	if state == nil {
		return
	}
	ledger := state.PendingLedger()
	for _, callID := range cleaned {
		ledger.Resolve(callID)
	}
	state.pendingCloserMu.Lock()
	fn := state.pendingCloser
	state.pendingCloserMu.Unlock()
	if fn != nil {
		fn(cleaned)
	}
}

// ResetConversationExecutionStateForTest clears state (tests only).
func ResetConversationExecutionStateForTest(conversationID string) {
	execStateMu.Lock()
	defer execStateMu.Unlock()
	delete(execStates, strings.TrimSpace(conversationID))
}

// ClearAllConversationExecutionStatesForTest wipes the global map (tests only).
func ClearAllConversationExecutionStatesForTest() {
	execStateMu.Lock()
	defer execStateMu.Unlock()
	execStates = map[string]*ConversationExecutionState{}
}

// ConversationExecutionStateCount returns number of tracked sessions (tests / observability).
func ConversationExecutionStateCount() int {
	execStateMu.Lock()
	defer execStateMu.Unlock()
	return len(execStates)
}

// ConversationExecutionSummary snapshots an existing controller without creating state.
func ConversationExecutionSummary(conversationID string) (ExecutionSummary, bool) {
	id := strings.TrimSpace(conversationID)
	if id == "" {
		id = "default"
	}
	execStateMu.Lock()
	state, ok := execStates[id]
	execStateMu.Unlock()
	if !ok || state == nil {
		return ExecutionSummary{}, false
	}
	summary := state.Controller().Summary()
	meaningful := summary.ToolCallsPlanned != 0 || summary.ToolCallsExecuted != 0 || summary.ToolCallsDropped != 0 ||
		summary.Timeouts != 0 || summary.StagnationGates != 0 || summary.ObligationsCreated != 0 || summary.ObligationsPending != 0 ||
		!summary.LastNewEvidenceAt.IsZero()
	return summary, meaningful
}

// SetMaxConversationsForTest overrides global session cap (tests only; 0 restores default).
func SetMaxConversationsForTest(n int) {
	execStateMu.Lock()
	defer execStateMu.Unlock()
	if n <= 0 {
		maxConversationsLimit = defaultMaxConversations
	} else {
		maxConversationsLimit = n
	}
}

// evictOldestConversationsLocked trims global map to maxConversationsLimit (caller holds execStateMu).
func evictOldestConversationsLocked() {
	limit := maxConversationsLimit
	if limit <= 0 {
		limit = defaultMaxConversations
	}
	for len(execStates) > limit {
		var oldestID string
		var oldestAt time.Time
		first := true
		for id, s := range execStates {
			if s == nil {
				delete(execStates, id)
				continue
			}
			s.mu.Lock()
			at := s.lastAccess
			s.mu.Unlock()
			if first || at.Before(oldestAt) {
				first = false
				oldestAt = at
				oldestID = id
			}
		}
		if oldestID == "" {
			break
		}
		delete(execStates, oldestID)
	}
}

// DeleteConversationExecutionState removes session state (optional cleanup after run end).
func DeleteConversationExecutionState(conversationID string) {
	execStateMu.Lock()
	defer execStateMu.Unlock()
	delete(execStates, strings.TrimSpace(conversationID))
}

// MarkToolDead records a hard tool failure so the agent should not re-invoke it.
func (s *ConversationExecutionState) MarkToolDead(name, reason string) {
	if s == nil {
		return
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.toolDead == nil {
		s.toolDead = map[string]string{}
	}
	if strings.TrimSpace(reason) == "" {
		reason = "unavailable"
	}
	s.toolDead[name] = reason
}

// IsToolDead reports whether the tool was marked dead this session.
func (s *ConversationExecutionState) IsToolDead(name string) (bool, string) {
	if s == nil {
		return false, ""
	}
	name = strings.ToLower(strings.TrimSpace(name))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.toolDead == nil {
		return false, ""
	}
	r, ok := s.toolDead[name]
	return ok, r
}

// SessionIntent returns the stored conversation intent (empty if unset).
func (s *ConversationExecutionState) SessionIntent() SessionIntent {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionIntent
}

// SetSessionIntent stores chat | recon | pentest for obligation gating.
func (s *ConversationExecutionState) SetSessionIntent(intent SessionIntent) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionIntent = intent
}

// MarkSurfaceSignalSeen marks that a high-value attack surface was observed.
func (s *ConversationExecutionState) MarkSurfaceSignalSeen() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.surfaceSignalSeen = true
}

// SurfaceSignalSeen reports whether a high-value surface was observed.
func (s *ConversationExecutionState) SurfaceSignalSeen() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.surfaceSignalSeen
}

// MarkVulnerabilityRecorded marks successful L1 candidate or L2 formal record.
func (s *ConversationExecutionState) MarkVulnerabilityRecorded() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vulnerabilityRecorded = true
}

// VulnerabilityRecorded reports whether L1/L2 was written this session.
func (s *ConversationExecutionState) VulnerabilityRecorded() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vulnerabilityRecorded
}

// SurfaceNeedsRecord is true when a surface was seen but no L1/L2 was recorded yet.
func (s *ConversationExecutionState) SurfaceNeedsRecord() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.surfaceSignalSeen && !s.vulnerabilityRecorded
}

// SetRoleTools stores the role tool allowlist for this conversation (empty = unrestricted).
func (s *ConversationExecutionState) SetRoleTools(tools []string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(tools) == 0 {
		s.roleTools = nil
		return
	}
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	s.roleTools = out
}

// RoleTools returns a copy of the role tool allowlist (nil/empty = unrestricted).
func (s *ConversationExecutionState) RoleTools() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.roleTools) == 0 {
		return nil
	}
	out := make([]string, len(s.roleTools))
	copy(out, s.roleTools)
	return out
}

// Package-level helpers for conversation id convenience.

// MarkConversationSurfaceSignalSeen marks surface seen for conversationID.
func MarkConversationSurfaceSignalSeen(conversationID string) {
	GetConversationExecutionState(conversationID).MarkSurfaceSignalSeen()
}

// MarkConversationVulnerabilityRecorded marks L1/L2 written for conversationID.
func MarkConversationVulnerabilityRecorded(conversationID string) {
	GetConversationExecutionState(conversationID).MarkVulnerabilityRecorded()
}

// SetConversationRoleTools stores role tools for conversationID (session memory; optional diagnostics).
// Exec 扫描器纪律由提示词约束，不做 toolboundary 硬拦截。
func SetConversationRoleTools(conversationID string, tools []string) {
	GetConversationExecutionState(conversationID).SetRoleTools(tools)
}

func (s *ConversationExecutionState) RecordTool(entry ToolEvidenceEntry) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry.At.IsZero() {
		entry.At = time.Now()
	}
	s.RecentTools = append(s.RecentTools, entry)
	if s.maxEvidence <= 0 {
		s.maxEvidence = 40
	}
	if len(s.RecentTools) > s.maxEvidence {
		s.RecentTools = s.RecentTools[len(s.RecentTools)-s.maxEvidence:]
	}
	// Maintain sliding window of recent tool names and upsert count.
	s.recordRecentToolNameLocked(entry.ToolName, entry.SkipBreaker)
}

func (s *ConversationExecutionState) recordRecentToolNameLocked(toolName string, skipBreaker bool) {
	if s.recentToolNames == nil {
		s.recentToolNames = make([]string, 0, UpsertBreakerWindow)
	}
	if len(s.recentToolNames) >= UpsertBreakerWindow {
		if isUpsertCoverageTool(s.recentToolNames[0]) {
			s.recentUpsertCount--
		}
		s.recentToolNames = s.recentToolNames[1:]
	}
	s.recentToolNames = append(s.recentToolNames, toolName)
	if isUpsertCoverageTool(toolName) && !skipBreaker {
		s.recentUpsertCount++
	}
}

// MaxFinalizeAttemptsBeforeForceStop is the number of consecutive times
// should_continue_execution(intent=finalize) can return true before the
// system forces should_continue=false to prevent dead loops.
const MaxFinalizeAttemptsBeforeForceStop = 3

// RecentUpsertCount returns the number of upsert_execution_coverage calls in
// the recent sliding window (UpsertBreakerWindow).
func (s *ConversationExecutionState) RecentUpsertCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recentUpsertCount
}

// isUpsertCoverageTool reports whether toolName is upsert_execution_coverage.
func isUpsertCoverageTool(toolName string) bool {
	low := strings.ToLower(strings.TrimSpace(toolName))
	return low == "upsert_execution_coverage"
}

// CheckAndRecordFinalizeAttempt tracks consecutive finalize attempts.
// Returns (overriddenCont, attemptCount):
//   - If intent != "finalize" or cont=false: resets counter, returns (cont, 0)
//   - If intent="finalize" and cont=true: increments counter, returns (true, count)
//   - If count >= MaxFinalizeAttemptsBeforeForceStop: returns (false, count) — force stop
func (s *ConversationExecutionState) CheckAndRecordFinalizeAttempt(intent string, cont bool) (bool, int) {
	if s == nil {
		return cont, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if intent != "finalize" || !cont {
		s.finalizeAttempts = 0
		return cont, 0
	}
	s.finalizeAttempts++
	if s.finalizeAttempts >= MaxFinalizeAttemptsBeforeForceStop {
		return false, s.finalizeAttempts
	}
	return true, s.finalizeAttempts
}

// FinalizeAttempts returns the current finalize attempt count (tests only).
func (s *ConversationExecutionState) FinalizeAttempts() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finalizeAttempts
}

func (s *ConversationExecutionState) LastK(k int) []ToolEvidenceEntry {
	if s == nil || k <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.RecentTools) == 0 {
		return nil
	}
	if k >= len(s.RecentTools) {
		out := make([]ToolEvidenceEntry, len(s.RecentTools))
		copy(out, s.RecentTools)
		return out
	}
	out := make([]ToolEvidenceEntry, k)
	copy(out, s.RecentTools[len(s.RecentTools)-k:])
	return out
}

func (s *ConversationExecutionState) MarkSkillsInjected(skills []string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.InjectedSkills == nil {
		s.InjectedSkills = map[string]struct{}{}
	}
	for _, sk := range skills {
		sk = strings.TrimSpace(sk)
		if sk != "" {
			s.InjectedSkills[sk] = struct{}{}
		}
	}
}

func (s *ConversationExecutionState) InjectedSkillsCopy() map[string]struct{} {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]struct{}, len(s.InjectedSkills))
	for k := range s.InjectedSkills {
		out[k] = struct{}{}
	}
	return out
}

func (s *ConversationExecutionState) UpsertCoverage(item CoverageItem) {
	s.upsertCoverage(item, false)
}

// UpsertAutomaticCoverage preserves terminal coverage written by explicit decisions.
func (s *ConversationExecutionState) UpsertAutomaticCoverage(item CoverageItem) {
	s.upsertCoverage(item, true)
}

func (s *ConversationExecutionState) upsertCoverage(item CoverageItem, automatic bool) {
	if s == nil {
		return
	}
	path := strings.TrimSpace(item.Path)
	if path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Coverage == nil {
		s.Coverage = map[string]CoverageItem{}
	}
	item.Path = path
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = time.Now()
	}
	if item.Status == "" {
		item.Status = "open"
	}
	if item.Priority == "" {
		item.Priority = "P1"
	}
	// Normalize priority casing
	item.Priority = strings.ToUpper(strings.TrimSpace(item.Priority))
	item.Status = strings.ToLower(strings.TrimSpace(item.Status))
	if automatic {
		if existing, ok := s.Coverage[path]; ok {
			status := strings.ToLower(strings.TrimSpace(existing.Status))
			if status == "done" || status == "blocked" {
				return
			}
		}
	}
	s.Coverage[path] = item
	s.lastAccess = time.Now()
	if s.maxCoverage <= 0 {
		s.maxCoverage = defaultMaxCoverage
	}
	// Evict oldest (by UpdatedAt) when over cap — keeps map bounded under long sessions.
	for len(s.Coverage) > s.maxCoverage {
		var oldestPath string
		var oldestAt time.Time
		first := true
		for p, it := range s.Coverage {
			if first || it.UpdatedAt.Before(oldestAt) {
				first = false
				oldestAt = it.UpdatedAt
				oldestPath = p
			}
		}
		if oldestPath == "" {
			break
		}
		delete(s.Coverage, oldestPath)
	}
}

func (s *ConversationExecutionState) ListCoverage() []CoverageItem {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CoverageItem, 0, len(s.Coverage))
	for _, v := range s.Coverage {
		out = append(out, v)
	}
	return out
}

// ShouldContinue reports whether P0/P1 open paths remain.
// Logic-class open items (workflow_skip/param_tamper/… ) use the same P0/P1 rule as inject classes.
// tool.* paths (tool execution records like tool.list_vulnerabilities, tool.get_execution_coverage)
// are excluded — they are framework artifacts, not real vulnerability hunting paths.
func (s *ConversationExecutionState) ShouldContinue() (continueWork bool, reason string, open []CoverageItem) {
	items := s.ListCoverage()
	if len(items) == 0 {
		return true, "尚无 coverage 记录：探索期建议继续并 upsert_execution_coverage", nil
	}
	for _, it := range items {
		st := strings.ToLower(strings.TrimSpace(it.Status))
		pr := strings.ToUpper(strings.TrimSpace(it.Priority))
		path := strings.TrimSpace(it.Path)
		// Skip tool execution records — these are framework artifacts, not actionable paths.
		if strings.HasPrefix(strings.ToLower(path), "tool.") {
			continue
		}
		if (pr == "P0" || pr == "P1") && (st == "open" || st == "in_progress" || st == "") {
			open = append(open, it)
		}
	}
	if len(open) > 0 {
		return true, fmt.Sprintf("存在 %d 条 P0/P1 未闭环 coverage，禁止以「无洞/完成」收尾", len(open)), open
	}
	return false, "P0/P1 coverage 均已闭环（done/blocked），可进入 finalize", nil
}

// MarkAuthProbe records whether auth_a / auth_b were supplied (logic_probe_diff).
// Dual auth is true only when both have been seen (same or across calls).
func (s *ConversationExecutionState) MarkAuthProbe(authA, authB bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if authA {
		s.authASeen = true
	}
	if authB {
		s.authBSeen = true
	}
	if s.authASeen && s.authBSeen {
		s.dualAuthProbe = true
	}
}

// HasDualAuthProbe reports whether this session recorded both identities for horizontal tests.
func (s *ConversationExecutionState) HasDualAuthProbe() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dualAuthProbe
}

// SummarizeToolResult builds a compact evidence entry from raw tool I/O (pure-ish helper).
func SummarizeToolResult(toolName, arguments, output string) ToolEvidenceEntry {
	out := output
	if len(out) > 4000 {
		out = out[:4000]
	}
	entry := ToolEvidenceEntry{
		ToolName: strings.TrimSpace(toolName),
		Length:   len(output),
		At:       time.Now(),
	}
	low := strings.ToLower(output)
	switch {
	case strings.Contains(low, "error") || strings.Contains(low, "failed") || strings.Contains(low, "拒绝"):
		entry.StatusHint = "error_or_reject"
	case strings.Contains(low, "vulnerable") || strings.Contains(low, "injection") || strings.Contains(low, "poc"):
		entry.StatusHint = "interesting"
	default:
		entry.StatusHint = "ok"
	}
	// error signature: first error-like line
	for _, line := range strings.Split(output, "\n") {
		l := strings.TrimSpace(line)
		ll := strings.ToLower(l)
		if strings.Contains(ll, "error") || strings.Contains(ll, "exception") || strings.Contains(ll, "traceback") {
			entry.ErrorSig = truncateRunes(l, 160)
			break
		}
	}
	// payload / param hints from args JSON
	if strings.TrimSpace(arguments) != "" {
		var raw map[string]interface{}
		if json.Unmarshal([]byte(arguments), &raw) == nil {
			keys := make([]string, 0, 8)
			for k, v := range raw {
				ks := strings.ToLower(k)
				if strings.Contains(ks, "url") || strings.Contains(ks, "param") || strings.Contains(ks, "payload") ||
					strings.Contains(ks, "data") || strings.Contains(ks, "target") || strings.Contains(ks, "cmd") {
					keys = append(keys, fmt.Sprintf("%s=%v", k, truncateRunes(fmt.Sprint(v), 80)))
				}
			}
			if len(keys) > 0 {
				entry.InterestingParams = strings.Join(keys, "; ")
			}
			if p, ok := raw["payload"]; ok {
				entry.PayloadHint = truncateRunes(fmt.Sprint(p), 120)
			}
		}
	}
	// summary: first non-empty lines + length
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		lines = append(lines, l)
		if len(lines) >= 3 {
			break
		}
	}
	entry.Summary = truncateRunes(strings.Join(lines, " | "), 280)
	if entry.Summary == "" {
		entry.Summary = fmt.Sprintf("(empty output, len=%d)", entry.Length)
	}
	return entry
}

// FormatToolEvidenceBlock renders last-K entries for task description attachment.
func FormatToolEvidenceBlock(entries []ToolEvidenceEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n## 最近工具结构化摘要（框架附加，子代理必读）\n")
	for i, e := range entries {
		b.WriteString(fmt.Sprintf("%d. tool=%s status=%s len=%d", i+1, e.ToolName, e.StatusHint, e.Length))
		if e.ErrorSig != "" {
			b.WriteString(" error_sig=" + e.ErrorSig)
		}
		if e.InterestingParams != "" {
			b.WriteString(" params=" + e.InterestingParams)
		}
		if e.PayloadHint != "" {
			b.WriteString(" payload=" + e.PayloadHint)
		}
		b.WriteString("\n   " + e.Summary + "\n")
	}
	return b.String()
}

// ExtractTargetFromText finds a URL / host:port / bare domain from user text.
var (
	reURL      = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
	reHostPort = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b`)
	reDomain   = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
)

func ExtractTargetFromText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if m := reURL.FindString(s); m != "" {
		return strings.TrimRight(m, ".,;)]}>\"'")
	}
	if m := reHostPort.FindString(s); m != "" {
		return m
	}
	if m := reDomain.FindString(s); m != "" {
		// skip common false positives
		low := strings.ToLower(m)
		if strings.HasSuffix(low, ".md") || strings.HasSuffix(low, ".json") || strings.HasSuffix(low, ".yaml") {
			return ""
		}
		return m
	}
	return ""
}

// CorrectSubagentRouting adjusts subagent_type for verify/exploit keywords (code policy, not prompt).
func CorrectSubagentRouting(description, subagentType string) (corrected string, changed bool) {
	sub := strings.TrimSpace(subagentType)
	desc := strings.ToLower(description)
	verifyHints := []string{"verify", "exploit", "验证", "利用", "复现", "poc", "confirm vuln", "weaponize"}
	hit := false
	for _, h := range verifyHints {
		if strings.Contains(desc, h) {
			hit = true
			break
		}
	}
	if !hit {
		return sub, false
	}
	// Pure recon/intel agents are wrong for verify/exploit handoffs.
	bad := map[string]bool{
		"recon": true, "intel-collection": true, "attack-surface-enumeration": true,
		"engagement-planning": true, "reporting-remediation": true,
	}
	key := strings.ToLower(sub)
	if bad[key] || sub == "" {
		return "vulnerability-triage", true
	}
	return sub, false
}

// AutoCoveragePathFromTool suggests a coverage path key from tool name/output.
func AutoCoveragePathFromTool(toolName, output string) string {
	tn := strings.ToLower(strings.TrimSpace(toolName))
	if tn == "" {
		return ""
	}
	// strip mcp prefixes
	if idx := strings.LastIndex(tn, "__"); idx >= 0 {
		tn = tn[idx+2:]
	}
	if idx := strings.LastIndex(tn, "::"); idx >= 0 {
		tn = tn[idx+2:]
	}
	low := strings.ToLower(output)
	status := "in_progress"
	if strings.Contains(low, "vulnerable") || strings.Contains(low, "injection found") {
		status = "open" // signal open for deeper work
	}
	_ = status
	return "tool." + tn
}

// buildTaskFactBodies loads a short slice of project fact bodies for task handoff.
func buildTaskFactBodies(db *database.DB, projectID string, maxRunes int) string {
	if db == nil {
		return ""
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return ""
	}
	if maxRunes <= 0 {
		maxRunes = 4000
	}
	facts, err := db.ListProjectFacts(projectID, database.ProjectFactListFilter{}, 12, 0)
	if err != nil || len(facts) == 0 {
		return ""
	}
	var b strings.Builder
	used := 0
	for _, f := range facts {
		if f == nil {
			continue
		}
		body := strings.TrimSpace(f.Body)
		if body == "" {
			body = strings.TrimSpace(f.Summary)
		}
		if body == "" {
			continue
		}
		chunk := fmt.Sprintf("### %s\n%s\n", f.FactKey, truncateRunes(body, 800))
		cr := len([]rune(chunk))
		if used+cr > maxRunes {
			break
		}
		b.WriteString(chunk)
		used += cr
	}
	return strings.TrimSpace(b.String())
}
