package c2

import (
	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHTTPUploadEnforcesListenerOwnership(t *testing.T) {
	manager, db := terminalTestManager(t)
	secret := strings.Repeat("a", 43)
	installHTTPIdentityFixture(t, db, "listener", "test-uuid", secret)
	task := &database.C2Task{ID: "test-only-file-task", SessionID: "session", TaskType: "download", Status: "sent", CreatedAt: time.Now()}
	if err := db.CreateC2Task(task); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncryptAESGCM(key, []byte("test-only-upload"))
	if err != nil {
		t.Fatal(err)
	}
	dir, path, err := uploadPathForTask(manager.StorageDir(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	listener := &HTTPBeaconListener{rec: &database.C2Listener{ID: "foreign-listener", EncryptionKey: key, ImplantToken: "test-only-token"}, manager: manager, cfg: &ListenerConfig{BeaconFilePath: "/file/"}, logger: zap.NewNop()}
	for _, owned := range []bool{false, true} {
		if owned {
			listener.rec.ID = "listener"
		}
		upload := httptest.NewRequest(http.MethodPost, "/upload?task_id="+task.ID, strings.NewReader(body))
		upload.Header.Set("X-Implant-Token", "test-only-token")
		upload.Header.Set("X-Session-Token", secret)
		rr := httptest.NewRecorder()
		listener.handleUpload(rr, upload)
		expected := http.StatusNotFound
		if owned {
			expected = http.StatusOK
		}
		if rr.Code != expected {
			t.Fatalf("upload owned=%v: status=%d", owned, rr.Code)
		}
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		expectedContent := "original"
		if owned {
			expectedContent = "test-only-upload"
		}
		if string(saved) != expectedContent {
			t.Fatalf("unexpected file mutation owned=%v: %q", owned, saved)
		}

	}
}
