package multiagent

import "testing"

func TestPendingLedgerDropBeforeRegisterCreatesTombstone(t *testing.T) {
	ledger := NewPendingLedger()
	call := toolCallPendingInfo{ToolCallID: "call-1", ToolName: "http-framework-test"}

	if resolved := ledger.Drop(call); resolved {
		t.Fatal("dropping a not-yet-registered call must report no pending entry")
	}
	if registered := ledger.Register(call); registered {
		t.Fatal("a late register must not resurrect a dropped call")
	}
	if got := ledger.Count(); got != 0 {
		t.Fatalf("dropped call must not remain pending, count=%d", got)
	}
}

func TestPendingLedgerResolveIsIdempotent(t *testing.T) {
	ledger := NewPendingLedger()
	call := toolCallPendingInfo{ToolCallID: "call-1", ToolName: "execute"}
	if !ledger.Register(call) {
		t.Fatal("first register must succeed")
	}
	if !ledger.Resolve(call.ToolCallID) {
		t.Fatal("first resolve must close the pending call")
	}
	if ledger.Resolve(call.ToolCallID) {
		t.Fatal("second resolve must be a no-op")
	}
	if ledger.Register(call) {
		t.Fatal("late duplicate event must not reopen a resolved call")
	}
}

func TestPendingLedgerFlushOnlyReturnsRealPendingCalls(t *testing.T) {
	ledger := NewPendingLedger()
	dropped := toolCallPendingInfo{ToolCallID: "drop-1", ToolName: "http-framework-test"}
	pending := toolCallPendingInfo{ToolCallID: "pending-1", ToolName: "execute"}
	ledger.Drop(dropped)
	ledger.Register(dropped)
	ledger.Register(pending)

	flushed := ledger.Flush()
	if len(flushed) != 1 || flushed[0].ToolCallID != pending.ToolCallID {
		t.Fatalf("flush must exclude tombstoned calls, got %+v", flushed)
	}
	if ledger.Count() != 0 {
		t.Fatal("flush must empty pending entries")
	}
}

func TestNotifyPendingToolCallsResolvedPreventsLateRunnerRegister(t *testing.T) {
	const conversationID = "pending-drop-before-register"
	ResetConversationExecutionStateForTest(conversationID)
	t.Cleanup(func() { ResetConversationExecutionStateForTest(conversationID) })

	ledger := GetConversationExecutionState(conversationID).ResetPendingLedger()
	NotifyPendingToolCallsResolved(conversationID, "dropped-call")

	if ledger.Register(toolCallPendingInfo{ToolCallID: "dropped-call", ToolName: "http-framework-test"}) {
		t.Fatal("middleware drop notification must tombstone the call before the runner sees it")
	}
}

func TestPendingLedgerOwnsSnapshotAndAgentQueue(t *testing.T) {
	ledger := NewPendingLedger()
	first := toolCallPendingInfo{ToolCallID: "call-1", ToolName: "execute", EinoAgent: "agent-a"}
	second := toolCallPendingInfo{ToolCallID: "call-2", ToolName: "nmap", EinoAgent: "agent-a"}
	other := toolCallPendingInfo{ToolCallID: "call-3", ToolName: "http-framework-test", EinoAgent: "agent-b"}
	for _, call := range []toolCallPendingInfo{first, second, other} {
		if !ledger.Register(call) {
			t.Fatalf("register %s failed", call.ToolCallID)
		}
	}

	snapshot := ledger.Snapshot()
	if len(snapshot) != 3 {
		t.Fatalf("snapshot count=%d want 3", len(snapshot))
	}
	popped, ok := ledger.PopNext("agent-a")
	if !ok || popped.ToolCallID != first.ToolCallID {
		t.Fatalf("first agent queue item=%+v ok=%v", popped, ok)
	}
	if got := ledger.Count(); got != 2 {
		t.Fatalf("count after pop=%d want 2", got)
	}

	resolved := ledger.ResolveAgent("agent-a")
	if len(resolved) != 1 || resolved[0].ToolCallID != second.ToolCallID {
		t.Fatalf("remaining agent calls=%+v", resolved)
	}
	if snapshot = ledger.Snapshot(); len(snapshot) != 1 || snapshot[0].ToolCallID != other.ToolCallID {
		t.Fatalf("snapshot after agent resolve=%+v", snapshot)
	}
}

func TestPendingLedgerResolveBeforeRegisterNeverAppearsInSnapshot(t *testing.T) {
	ledger := NewPendingLedger()
	ledger.Resolve("late-call")
	if ledger.Register(toolCallPendingInfo{ToolCallID: "late-call", ToolName: "execute", EinoAgent: "agent-a"}) {
		t.Fatal("tombstoned call unexpectedly registered")
	}
	if snapshot := ledger.Snapshot(); len(snapshot) != 0 {
		t.Fatalf("late registration leaked into snapshot: %+v", snapshot)
	}
	if _, ok := ledger.PopNext("agent-a"); ok {
		t.Fatal("late registration leaked into agent queue")
	}
}
