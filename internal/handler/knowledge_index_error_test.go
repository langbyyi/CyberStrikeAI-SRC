package handler

import (
	"testing"
	"time"
)

func TestKnowledgeIndexFailureRemainsVisibleUntilCleared(t *testing.T) {
	occurred := time.Now().Add(-time.Hour)
	status := map[string]interface{}{}
	appendKnowledgeIndexError(status, "test-only embedding failure: 401 Unauthorized", occurred)
	if status["last_error"] == nil || status["last_error_time"] != occurred.Format(time.RFC3339) {
		t.Fatal("older failure disappeared")
	}
	cleared := map[string]interface{}{}
	appendKnowledgeIndexError(cleared, "", time.Time{})
	if _, ok := cleared["last_error"]; ok {
		t.Fatal("cleared failure remained")
	}
}
