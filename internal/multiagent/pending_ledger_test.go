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
