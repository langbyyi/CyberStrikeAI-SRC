package c2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

func TestResultTransportOwnershipRejectsForeignTask(t *testing.T) {
	m, db := terminalTestManager(t)
	now := time.Now()
	if err := db.UpsertC2Session(&database.C2Session{ID: "other", ListenerID: "listener", ImplantUUID: "other-uuid", Status: "active", FirstSeenAt: now, LastCheckIn: now}); err != nil {
		t.Fatal(err)
	}
	task := &database.C2Task{ID: "t_owner", SessionID: "session", TaskType: "exec", Status: "sent", CreatedAt: now}
	if err := db.CreateC2Task(task); err != nil {
		t.Fatal(err)
	}
	report := TaskResultReport{TaskID: task.ID, Success: true, Output: "test-only-result"}
	for _, source := range [][2]string{{"listener", "other"}, {"foreign-listener", "session"}, {"foreign-listener", ""}, {"", "session"}} {
		if err := m.IngestTaskResultFromListener(source[0], source[1], report); err != ErrAuthFailed {
			t.Fatalf("source %v: %v", source, err)
		}
		saved, err := db.GetC2Task(task.ID)
		if err != nil || saved.Status != "sent" || saved.ResultText != "" {
			t.Fatalf("foreign result persisted: %#v %v", saved, err)
		}
	}
	if err := m.IngestTaskResultFromListener("listener", "session", report); err != nil {
		t.Fatal(err)
	}
	saved, _ := db.GetC2Task(task.ID)
	if saved.Status != "success" || saved.ResultText != report.Output {
		t.Fatalf("valid result failed: %#v", saved)
	}
}

func TestHTTPResultCannotUpdateAnotherListenerTask(t *testing.T) {
	m, db := terminalTestManager(t)
	task := &database.C2Task{ID: "t_foreign", SessionID: "session", TaskType: "exec", Status: "sent", CreatedAt: time.Now()}
	if err := db.CreateC2Task(task); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	l := &HTTPBeaconListener{rec: &database.C2Listener{ID: "http_other", EncryptionKey: key, ImplantToken: "test-only-token"}, manager: m, logger: zap.NewNop()}
	raw, _ := json.Marshal(TaskResultReport{TaskID: task.ID, Success: true, Output: "forged"})
	body, err := EncryptAESGCM(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/result", strings.NewReader(body))
	req.Header.Set("X-Implant-Token", "test-only-token")
	rr := httptest.NewRecorder()
	l.handleResult(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("accepted foreign listener result")
	}
	saved, _ := db.GetC2Task(task.ID)
	if saved.Status != "sent" || saved.ResultText != "" {
		t.Fatalf("foreign result persisted: %#v", saved)
	}
	req = httptest.NewRequest(http.MethodGet, "/tasks?session_id=session", nil)
	req.Header.Set("X-Implant-Token", "test-only-token")
	rr = httptest.NewRecorder()
	l.handleTasks(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("foreign session task request status: %d", rr.Code)
	}
}

func TestCheckInCannotMoveAnExistingSessionToAnotherListener(t *testing.T) {
	m, db := terminalTestManager(t)
	if _, err := m.IngestCheckIn("foreign-listener", ImplantCheckInRequest{ImplantUUID: "test-uuid", Hostname: "forged"}); err != ErrAuthFailed {
		t.Fatalf("expected rejection, got %v", err)
	}
	saved, err := db.GetC2Session("session")
	if err != nil || saved.ListenerID != "listener" || saved.Hostname == "forged" {
		t.Fatalf("session changed: %#v %v", saved, err)
	}
}
