package multiagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type executionToolCallIDContextKey struct{}

func WithExecutionToolCallID(ctx context.Context, callID string) context.Context {
	return context.WithValue(ctx, executionToolCallIDContextKey{}, strings.TrimSpace(callID))
}

func ExecutionToolCallIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(executionToolCallIDContextKey{}).(string)
	return strings.TrimSpace(value)
}

const (
	ObligationPending   = "pending"
	ObligationSatisfied = "satisfied"
	ObligationBlocked   = "blocked"
)

// ExecutionSignal is a scenario-neutral evidence signal consumed by the execution layer.
type ExecutionSignal struct {
	Class      string
	Target     string
	Resources  []string
	Reportable bool
	Confidence string
	Priority   string
	Summary    string
}

// DecisionObligation represents a mandatory state transition caused by confirmed evidence.
type DecisionObligation struct {
	ID              string
	Kind            string
	Target          string
	EvidenceHash    string
	EvidenceSummary string
	Priority        string
	RequiredTools   []string
	LinkedCoverage  []string
	BoundToolCallID string
	Status          string
	CreatedAt       time.Time
	ResolvedAt      time.Time
	Resolution      string
}

// ExecutionSummary is a compact snapshot suitable for task/process diagnostics.
type ExecutionSummary struct {
	ToolCallsPlanned   int       `json:"toolCallsPlanned"`
	ToolCallsExecuted  int       `json:"toolCallsExecuted"`
	ToolCallsDropped   int       `json:"toolCallsDropped"`
	Timeouts           int       `json:"timeouts"`
	StagnationGates    int       `json:"stagnationGates"`
	ObligationsCreated int       `json:"obligationsCreated"`
	ObligationsPending int       `json:"obligationsPending"`
	LastNewEvidenceAt  time.Time `json:"lastNewEvidenceAt,omitempty"`
}

// ExecutionController owns the single-target decision state for one Eino single run.
type ExecutionController struct {
	mu                  sync.Mutex
	primary             string
	obligations         []*DecisionObligation
	seen                map[string]struct{}
	directives          map[string]struct{}
	seenResults         map[string]struct{}
	seenCalls           map[string]struct{}
	callAttempts        map[string]int
	lastCallCode        map[string]string
	activeProbeCalls    map[string]struct{}
	activeBatchNovel    bool
	noNovelBatches      int
	noNovelProbeCalls   int
	pivotRequired       bool
	pivotDirectiveShown bool
	summary             ExecutionSummary
}

func NewExecutionController(primaryTarget string) *ExecutionController {
	return &ExecutionController{
		primary:      NormalizePrimaryTarget(primaryTarget),
		seen:         make(map[string]struct{}),
		directives:   make(map[string]struct{}),
		seenResults:  make(map[string]struct{}),
		seenCalls:    make(map[string]struct{}),
		callAttempts: make(map[string]int),
		lastCallCode: make(map[string]string),
	}
}

// NormalizePrimaryTarget keeps the delegated asset boundary (host[:port]) while
// coverage normalization continues to preserve individual paths.
func NormalizePrimaryTarget(target string) string {
	normalized := NormalizeCoverageTarget(target)
	if strings.HasPrefix(normalized, "/") {
		return normalized
	}
	if index := strings.Index(normalized, "/"); index >= 0 {
		return normalized[:index]
	}
	if index := strings.Index(normalized, "?"); index >= 0 {
		return normalized[:index]
	}
	return normalized
}

var resultVolatilePattern = regexp.MustCompile(`(?i)(?:\b\d{4}-\d{2}-\d{2}[t ][0-9:.+\-z]+\b|\b[0-9a-f]{8}-[0-9a-f-]{27,}\b)`)

// CallSignature identifies a semantic tool hypothesis while ignoring output-only fields.
func CallSignature(toolName, arguments string) string {
	var value interface{}
	if json.Unmarshal([]byte(strings.TrimSpace(arguments)), &value) != nil {
		value = strings.TrimSpace(arguments)
	} else {
		value = normalizeCallValue(value, "")
	}
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256([]byte(normalizedExecutionToolName(toolName) + "\x1f" + string(encoded)))
	return hex.EncodeToString(sum[:])
}

func normalizeCallValue(value interface{}, key string) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for childKey, child := range typed {
			low := strings.ToLower(strings.TrimSpace(childKey))
			switch low {
			case "output", "output_file", "outfile", "file", "timestamp", "tool_call_id", "call_id", "execution_id":
				continue
			}
			out[childKey] = normalizeCallValue(child, low)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i := range typed {
			out[i] = normalizeCallValue(typed[i], key)
		}
		return out
	case string:
		if key == "url" || key == "target" || key == "host" || key == "base_url" || key == "endpoint" || key == "uri" {
			return NormalizeCoverageTarget(typed)
		}
		return strings.TrimSpace(typed)
	default:
		return value
	}
}

// ResultFingerprint removes volatile timestamps/UUIDs before hashing a bounded result view.
func ResultFingerprint(toolName, result string) string {
	if normalizedExecutionToolName(toolName) == "http-framework-test" {
		status := BuildStructuredToolSummary(toolName, "", result).HTTPStatus
		switch status {
		case "404", "405", "410", "412":
			sum := sha256.Sum256([]byte(normalizedExecutionToolName(toolName) + "\x1fhttp:" + status))
			return hex.EncodeToString(sum[:])
		}
	}
	normalized := strings.ToLower(strings.TrimSpace(result))
	normalized = resultVolatilePattern.ReplaceAllString(normalized, "<volatile>")
	normalized = strings.Join(strings.Fields(normalized), " ")
	if len(normalized) > 8000 {
		normalized = normalized[:8000]
	}
	sum := sha256.Sum256([]byte(normalizedExecutionToolName(toolName) + "\x1f" + normalized))
	return hex.EncodeToString(sum[:])
}

func (c *ExecutionController) StartProbeBatch(callIDs []string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeProbeCalls = make(map[string]struct{}, len(callIDs))
	for _, id := range callIDs {
		if id = strings.TrimSpace(id); id != "" {
			c.activeProbeCalls[id] = struct{}{}
		}
	}
	c.activeBatchNovel = false
}

func (c *ExecutionController) RecordProbeResult(callID, signature, fingerprint, code string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	signature = strings.TrimSpace(signature)
	fingerprint = strings.TrimSpace(fingerprint)
	code = strings.ToLower(strings.TrimSpace(code))
	if signature != "" {
		c.seenCalls[signature] = struct{}{}
		c.callAttempts[signature]++
		c.lastCallCode[signature] = code
	}
	_, known := c.seenResults[fingerprint]
	novel := fingerprint != "" && !known
	if novel {
		c.seenResults[fingerprint] = struct{}{}
		c.activeBatchNovel = true
		c.noNovelProbeCalls = 0
		c.summary.LastNewEvidenceAt = time.Now()
	} else {
		c.noNovelProbeCalls++
	}
	return novel
}

func (c *ExecutionController) CompleteProbeBatch() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeProbeCalls == nil {
		return
	}
	if c.activeBatchNovel {
		c.noNovelBatches = 0
		c.pivotRequired = false
	} else {
		c.noNovelBatches++
		if c.noNovelBatches >= 3 || c.noNovelProbeCalls >= 12 {
			if !c.pivotRequired {
				c.summary.StagnationGates++
				c.pivotDirectiveShown = false
			}
			c.pivotRequired = true
		}
	}
	c.activeProbeCalls = nil
	c.activeBatchNovel = false
}

func (c *ExecutionController) PivotRequired() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pivotRequired
}

func (c *ExecutionController) CheckProbeCallAllowed(signature string) (bool, string) {
	if c == nil {
		return true, ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	signature = strings.TrimSpace(signature)
	code := c.lastCallCode[signature]
	attempts := c.callAttempts[signature]
	maxAttempts := retryMaxAttempts(code)
	if maxAttempts >= 0 && attempts >= maxAttempts {
		return false, "retry_exhausted"
	}
	if c.pivotRequired {
		return false, "stagnation_blocked"
	}
	return true, ""
}

func retryMaxAttempts(code string) int {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "timeout", "idle_timeout", "config_error", "templates_missing", "dependency_blocked", "stagnation_blocked", "unavailable":
		return 1
	case "target_unreachable", "connect", "http_429", "http_5xx", "external_transient":
		return 2
	case "":
		return -1
	default:
		return -1
	}
}

func (c *ExecutionController) PivotDirective() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.pivotRequired || c.pivotDirectiveShown {
		return ""
	}
	c.pivotDirectiveShown = true
	return fmt.Sprintf("[framework_next_action]\n当前探测连续无新证据，已停止继续扩展同类路径。请保留已有发现并完成记录、总结或结束执行；禁止继续扩大同类字典。")
}

func (c *ExecutionController) ConsumePendingDirective() *DecisionObligation {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ob := c.pendingLocked()
	if ob == nil {
		return nil
	}
	if _, ok := c.directives[ob.ID]; ok {
		return nil
	}
	c.directives[ob.ID] = struct{}{}
	return cloneObligation(ob)
}

func (c *ExecutionController) SetPrimaryTarget(target string) string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.primary == "" {
		c.primary = NormalizePrimaryTarget(target)
	}
	return c.primary
}

// ClearPrimaryTarget drops the session primary target (e.g. when intent falls back to chat).
func (c *ExecutionController) ClearPrimaryTarget() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.primary = ""
}

func (c *ExecutionController) PrimaryTarget() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.primary
}

func (c *ExecutionController) ObserveSignals(signals []ExecutionSignal, linkedCoverage []string) []DecisionObligation {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	created := make([]DecisionObligation, 0, len(signals))
	for _, signal := range signals {
		if !signal.Reportable || !strings.EqualFold(strings.TrimSpace(signal.Confidence), "confirmed") {
			continue
		}
		target := NormalizePrimaryTarget(signal.Target)
		if c.primary == "" {
			c.primary = target
		}
		if target == "" || c.primary == "" || !strings.EqualFold(target, c.primary) {
			continue
		}
		hash := executionEvidenceHash(target, signal)
		if _, ok := c.seen[hash]; ok {
			continue
		}
		c.seen[hash] = struct{}{}
		priority := strings.ToUpper(strings.TrimSpace(signal.Priority))
		if priority == "" {
			priority = "P1"
		}
		now := time.Now()
		ob := &DecisionObligation{
			ID:              "obl-" + hash[:16],
			Kind:            "record_finding",
			Target:          c.primary,
			EvidenceHash:    hash,
			EvidenceSummary: strings.TrimSpace(signal.Summary),
			Priority:        priority,
			RequiredTools:   []string{"record_vulnerability_candidate", "record_vulnerability", "update_vulnerability"},
			LinkedCoverage:  normalizedUniqueStrings(linkedCoverage),
			Status:          ObligationPending,
			CreatedAt:       now,
		}
		c.obligations = append(c.obligations, ob)
		c.summary.ObligationsCreated++
		c.summary.LastNewEvidenceAt = now
		created = append(created, *cloneObligation(ob))
	}
	return created
}

func (c *ExecutionController) PendingObligation() *DecisionObligation {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneObligation(c.pendingLocked())
}

func (c *ExecutionController) pendingLocked() *DecisionObligation {
	var best *DecisionObligation
	for _, ob := range c.obligations {
		if ob == nil || ob.Status != ObligationPending {
			continue
		}
		if best == nil || obligationPriority(ob.Priority) < obligationPriority(best.Priority) ||
			(ob.Priority == best.Priority && ob.CreatedAt.Before(best.CreatedAt)) {
			best = ob
		}
	}
	return best
}

func (c *ExecutionController) BindResolutionCall(obligationID, callID string) bool {
	if c == nil || strings.TrimSpace(callID) == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ob := range c.obligations {
		if ob != nil && ob.ID == obligationID && ob.Status == ObligationPending {
			ob.BoundToolCallID = strings.TrimSpace(callID)
			return true
		}
	}
	return false
}

func (c *ExecutionController) ResolveBoundObligation(callID, resolution string) *DecisionObligation {
	if c == nil || strings.TrimSpace(callID) == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ob := range c.obligations {
		if ob == nil || ob.Status != ObligationPending || ob.BoundToolCallID != strings.TrimSpace(callID) {
			continue
		}
		ob.Status = ObligationSatisfied
		ob.Resolution = strings.TrimSpace(resolution)
		ob.ResolvedAt = time.Now()
		return cloneObligation(ob)
	}
	return nil
}

// ClearPendingObligations marks all pending obligations satisfied (e.g. session switched to chat).
// Returns how many were cleared.
func (c *ExecutionController) ClearPendingObligations(resolution string) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	now := time.Now()
	res := strings.TrimSpace(resolution)
	if res == "" {
		res = "cleared"
	}
	for _, ob := range c.obligations {
		if ob == nil || ob.Status != ObligationPending {
			continue
		}
		ob.Status = ObligationSatisfied
		ob.Resolution = res
		ob.ResolvedAt = now
		n++
	}
	return n
}

// ResolveTopPendingObligation satisfies the highest-priority pending obligation without a bound call ID.
// Used by free update_vulnerability path (cross-session retest rewrite).
func (c *ExecutionController) ResolveTopPendingObligation(resolution string) *DecisionObligation {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ob := c.pendingLocked()
	if ob == nil {
		return nil
	}
	ob.Status = ObligationSatisfied
	ob.Resolution = strings.TrimSpace(resolution)
	ob.ResolvedAt = time.Now()
	return cloneObligation(ob)
}

func (c *ExecutionController) Summary() ExecutionSummary {
	if c == nil {
		return ExecutionSummary{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.summary
	for _, ob := range c.obligations {
		if ob != nil && ob.Status == ObligationPending {
			out.ObligationsPending++
		}
	}
	return out
}

func (c *ExecutionController) RecordToolBatch(planned, dropped int) {
	if c == nil {
		return
	}
	if planned < 0 {
		planned = 0
	}
	if dropped < 0 {
		dropped = 0
	}
	if dropped > planned {
		dropped = planned
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary.ToolCallsPlanned += planned
	c.summary.ToolCallsDropped += dropped
	// Calls surviving the model-state rewrite are considered scheduled for execution.
	c.summary.ToolCallsExecuted += planned - dropped
}

func (c *ExecutionController) RecordTimeout() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary.Timeouts++
}

func executionEvidenceHash(target string, signal ExecutionSignal) string {
	resources := normalizedUniqueStrings(signal.Resources)
	parts := []string{
		strings.ToLower(strings.TrimSpace(target)),
		strings.ToLower(strings.TrimSpace(signal.Class)),
		strings.Join(resources, "\x00"),
		strings.TrimSpace(signal.Summary),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func normalizedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

func cloneObligation(ob *DecisionObligation) *DecisionObligation {
	if ob == nil {
		return nil
	}
	out := *ob
	out.RequiredTools = append([]string(nil), ob.RequiredTools...)
	out.LinkedCoverage = append([]string(nil), ob.LinkedCoverage...)
	return &out
}

func obligationPriority(priority string) int {
	switch strings.ToUpper(strings.TrimSpace(priority)) {
	case "P0":
		return 0
	case "P1":
		return 1
	default:
		return 2
	}
}
