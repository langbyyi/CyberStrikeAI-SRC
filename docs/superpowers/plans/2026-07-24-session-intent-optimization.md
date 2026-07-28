# Session Intent Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make conversation intent classification fast, non-disruptive, and correctly separated from execution-state transitions.

**Architecture:** Consolidate deterministic classification into one internal result, preserve active execution state for task-context dialogue, and keep the LLM as a bounded ambiguity resolver. Retry only request-shape incompatibilities and keep transport diagnostics out of user-facing progress labels.

**Tech Stack:** Go, `net/http`, `httptest`, OpenAI-compatible Chat Completions, Anthropic bridge.

## Global Constraints

- Preserve existing public behavior for `chat`, `recon`, and `pentest`.
- Do not add dependencies or configuration.
- Keep user-provided uncommitted changes intact.
- Use test-first red-green cycles.

---

### Task 1: Separate task-context dialogue from task cancellation

**Files:**
- Modify: `internal/multiagent/session_intent.go`
- Test: `internal/multiagent/session_intent_test.go`

**Interfaces:**
- Consumes: previous `SessionIntent`, current user message, existing execution state.
- Produces: state transition that preserves an active task for continuation/status queries and clears it for explicit cancellation or unrelated new work.

- [ ] Add failing tests for active pentest + progress query, explicit stop, and unrelated new work.
- [ ] Run the tests and verify the state-preservation case fails.
- [ ] Add the minimum transition classification required for those cases.
- [ ] Run the focused tests and verify they pass.

### Task 2: Consolidate deterministic classification

**Files:**
- Modify: `internal/multiagent/session_intent.go`
- Test: `internal/multiagent/session_intent_test.go`

**Interfaces:**
- Consumes: user message and role hint.
- Produces: one internal rule decision containing intent and confidence.

- [ ] Add a failing consistency test covering explicit chat, recon, target-only, pentest, role-only, and ambiguous messages.
- [ ] Run the test and verify the duplicated interface cannot satisfy the expected result.
- [ ] Replace duplicated rule branches with one internal rule decision implementation.
- [ ] Run all multiagent tests.

### Task 3: Bound and classify LLM compatibility retries

**Files:**
- Modify: `internal/multiagent/session_intent.go`
- Test: `internal/multiagent/session_intent_test.go`

**Interfaces:**
- Consumes: OpenAI-compatible client and an ambiguous message.
- Produces: one normal request, at most one 400/422 compatibility retry, otherwise immediate rules fallback.

- [ ] Add HTTP tests that count requests for 400→success, 401, 403, 404, 429, and canceled context.
- [ ] Run the tests and verify the current four-attempt implementation fails.
- [ ] Implement two bounded payloads and status-aware retry selection.
- [ ] Remove response snippets from warning logs and normalize fallback source labels.
- [ ] Run focused HTTP tests and all multiagent tests.

### Task 4: Lock down Claude token-field compatibility

**Files:**
- Create: `internal/openai/claude_bridge_test.go`
- Verify: `internal/openai/claude_bridge.go`

**Interfaces:**
- Consumes: OpenAI request maps containing `max_tokens` or `max_completion_tokens`.
- Produces: Claude requests with the corresponding positive `MaxTokens`.

- [ ] Add table-driven tests for both token fields and default behavior.
- [ ] Run the tests and verify current conversion behavior.
- [ ] Adjust conversion only if a case fails.
- [ ] Run all OpenAI package tests.

### Task 5: Full verification

**Files:**
- Verify all modified files.

**Interfaces:**
- Consumes: completed implementation.
- Produces: evidence that formatting, tests, vetting, and diff hygiene pass.

- [ ] Run `gofmt` on modified Go files.
- [ ] Run `git diff --check`.
- [ ] Run `go test ./... -count=1`.
- [ ] Run `go vet ./...`.
- [ ] Confirm no executable `rules_llm_error`, `rules_parse_error`, or `rules_llm_empty` source labels remain.
