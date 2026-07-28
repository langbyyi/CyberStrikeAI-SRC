package multiagent

import "testing"

func TestDeleteConversationExecutionState(t *testing.T) {
	ClearAllConversationExecutionStatesForTest()
	t.Cleanup(ClearAllConversationExecutionStatesForTest)

	GetConversationExecutionState("conversation-to-delete")
	if got := ConversationExecutionStateCount(); got != 1 {
		t.Fatalf("state count before delete = %d, want 1", got)
	}

	DeleteConversationExecutionState("conversation-to-delete")

	if got := ConversationExecutionStateCount(); got != 0 {
		t.Fatalf("state count after delete = %d, want 0", got)
	}
}
