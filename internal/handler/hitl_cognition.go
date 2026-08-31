package handler

import "strings"

// hitlCognitionState only retains user-authored declarations that can establish
// approval scope. Assistant reasoning and plans are intentionally excluded.
type hitlCognitionState struct {
	UserMessages []string
}

func (m *AgentTaskManager) GetHitlUserMessages(conversationID string) []string {
	conversationID = strings.TrimSpace(conversationID)
	if m == nil || conversationID == "" {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := m.tasks[conversationID]
	if t == nil || t.hitlCognition == nil {
		return nil
	}
	return append([]string(nil), t.hitlCognition.UserMessages...)
}

// RecordHitlUserDeclaration records user-authored text that may establish an
// approval scope for the currently running task.
func (m *AgentTaskManager) RecordHitlUserDeclaration(conversationID, message string) {
	conversationID = strings.TrimSpace(conversationID)
	if m == nil || conversationID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tasks[conversationID]
	if t == nil {
		return
	}
	if t.hitlCognition == nil {
		t.hitlCognition = &hitlCognitionState{}
	}
	appendHitlUserMessage(t.hitlCognition, message)
}

func appendHitlUserMessage(state *hitlCognitionState, message string) {
	message = strings.TrimSpace(message)
	if state == nil || message == "" {
		return
	}
	if n := len(state.UserMessages); n > 0 && state.UserMessages[n-1] == message {
		return
	}
	state.UserMessages = append(state.UserMessages, message)
}
