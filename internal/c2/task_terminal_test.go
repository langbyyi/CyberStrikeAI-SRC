package c2

import (
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

func terminalTestManager(t *testing.T) (*Manager, *database.DB) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "terminal.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	if err := db.CreateC2Listener(&database.C2Listener{ID: "listener", Name: "test", Type: "websocket", BindHost: "127.0.0.1", BindPort: 12345, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertC2Session(&database.C2Session{ID: "session", ListenerID: "listener", ImplantUUID: "test-uuid", Status: "active", FirstSeenAt: now, LastCheckIn: now}); err != nil {
		t.Fatal(err)
	}
	return NewManager(db, zap.NewNop(), t.TempDir()), db
}

func TestLateC2ResultDoesNotOverwriteTerminalState(t *testing.T) {
	m, db := terminalTestManager(t)
	for _, status := range []string{"cancelled", "success", "failed"} {
		task := &database.C2Task{ID: "t_" + status, SessionID: "session", TaskType: "exec", Status: status, ResultText: "original", CreatedAt: time.Now()}
		if err := db.CreateC2Task(task); err != nil {
			t.Fatal(err)
		}
		if err := m.IngestTaskResult(TaskResultReport{TaskID: task.ID, Success: true, Output: "late"}); err != nil {
			t.Fatal(err)
		}
		saved, err := db.GetC2Task(task.ID)
		if err != nil || saved.Status != status || saved.ResultText != "original" {
			t.Fatalf("overwrote terminal task: %#v %v", saved, err)
		}
	}
}

func TestWebSocketOldConnectionCannotRetireReplacement(t *testing.T) {
	m, db := terminalTestManager(t)
	old := &wsConn{sessionID: "session"}
	current := &wsConn{sessionID: "session"}
	l := &WebSocketListener{manager: m, conns: map[string]*wsConn{"session": current}}
	l.detachConnection(old)
	session, err := db.GetC2Session("session")
	if err != nil || session.Status != "active" || l.conns["session"] != current {
		t.Fatalf("old connection retired replacement: %#v %v", session, err)
	}
	l.detachConnection(current)
	session, err = db.GetC2Session("session")
	if err != nil || session.Status != "dead" || len(l.conns) != 0 {
		t.Fatalf("current connection failed to retire: %#v %v", session, err)
	}
}
