package c2

import (
	"crypto/sha256"
	"cyberstrike-ai/internal/database"
	"encoding/hex"
	"encoding/json"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTPSessionIdentityIsolatesCheckInTasksAndResults(t *testing.T) {
	manager, db := terminalTestManager(t)
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	listener := &HTTPBeaconListener{rec: &database.C2Listener{ID: "listener", EncryptionKey: key, ImplantToken: "test-only-listener-token"}, manager: manager, cfg: &ListenerConfig{DefaultSleep: 5}, logger: zap.NewNop()}
	secretA := strings.Repeat("a", 43)
	secretB := strings.Repeat("b", 43)
	checkIn := func(uuid, secret string) (int, string) {
		raw, _ := json.Marshal(ImplantCheckInRequest{ImplantUUID: uuid, Hostname: "test-only-host"})
		req := httptest.NewRequest(http.MethodPost, "/check_in", strings.NewReader(string(raw)))
		req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		req.Header.Set("X-Session-Token", secret)
		rr := httptest.NewRecorder()
		listener.handleCheckIn(rr, req)
		var response ImplantCheckInResponse
		if rr.Code == http.StatusOK {
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
		}
		return rr.Code, response.SessionID
	}
	code, sessionA := checkIn("test-only-identity-a", secretA)
	if code != http.StatusOK || sessionA == "" {
		t.Fatalf("valid checkin: %d", code)
	}
	code, sessionB := checkIn("test-only-identity-b", secretB)
	if code != http.StatusOK || sessionB == sessionA {
		t.Fatal("second identity failed")
	}
	if code, id := checkIn("test-only-identity-a", secretA); code != http.StatusOK || id != sessionA {
		t.Fatal("valid reconnect failed")
	}
	for _, secret := range []string{"", secretB} {
		if code, _ := checkIn("test-only-identity-a", secret); code != http.StatusNotFound {
			t.Fatal("foreign identity takeover accepted")
		}
	}
	task := &database.C2Task{ID: "test-only-owned-task", SessionID: sessionA, TaskType: "exec", Status: "queued", CreatedAt: time.Now()}
	if err := db.CreateC2Task(task); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/tasks?session_id="+sessionA, nil)
	req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
	req.Header.Set("X-Session-Token", secretB)
	rr := httptest.NewRecorder()
	listener.handleTasks(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatal("foreign tasks accepted")
	}
	saved, _ := db.GetC2Task(task.ID)
	if saved.Status != "queued" {
		t.Fatal("foreign poll dispatched task")
	}
	req.Header.Set("X-Session-Token", secretA)
	rr = httptest.NewRecorder()
	listener.handleTasks(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatal("valid task poll failed")
	}
	fileID := "test-only-downstream-file"
	if err := db.CreateC2Task(&database.C2Task{ID: "test-only-file-task", SessionID: sessionA, TaskType: "upload", Payload: map[string]interface{}{"file_id": fileID}, Status: "sent", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(manager.StorageDir(), "downstream")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileID+".bin"), []byte("test-only-downstream-content"), 0600); err != nil {
		t.Fatal(err)
	}
	listener.cfg.BeaconFilePath = "/file/"
	uploadBody, err := EncryptAESGCM(key, []byte("test-only-upload-content"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"", secretB, secretA} {
		req := httptest.NewRequest(http.MethodGet, "/file/"+fileID, nil)
		req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		req.Header.Set("X-Session-Token", secret)
		rr := httptest.NewRecorder()
		listener.handleFileServe(rr, req)
		expected := http.StatusNotFound
		if secret == secretA {
			expected = http.StatusOK
		}
		if rr.Code != expected {
			t.Fatalf("file read identity status %d expected %d", rr.Code, expected)
		}
		req = httptest.NewRequest(http.MethodPost, "/upload?task_id="+task.ID, strings.NewReader(uploadBody))
		req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		req.Header.Set("X-Session-Token", secret)
		rr = httptest.NewRecorder()
		listener.handleUpload(rr, req)
		if rr.Code != expected {
			t.Fatalf("file write identity status %d expected %d", rr.Code, expected)
		}
		_, path, err := uploadPathForTask(manager.StorageDir(), task.ID)
		if err != nil {
			t.Fatal(err)
		}
		content, readErr := os.ReadFile(path)
		if secret != secretA {
			if !os.IsNotExist(readErr) {
				t.Fatal("foreign file write mutated storage")
			}
		} else if readErr != nil || string(content) != "test-only-upload-content" {
			t.Fatal("valid file upload failed")
		}
	}
	raw, _ := json.Marshal(TaskResultReport{TaskID: task.ID, Success: true, Output: "test-only-result"})
	body, err := EncryptAESGCM(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{secretB, secretA} {
		req = httptest.NewRequest(http.MethodPost, "/result", strings.NewReader(body))
		req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		req.Header.Set("X-Session-Token", secret)
		rr = httptest.NewRecorder()
		listener.handleResult(rr, req)
		saved, _ = db.GetC2Task(task.ID)
		if secret == secretB {
			if rr.Code != http.StatusNotFound || saved.Status != "sent" || saved.ResultText != "" {
				t.Fatal("foreign result persisted")
			}
		} else if rr.Code != http.StatusOK || saved.Status != "success" {
			t.Fatal("valid result rejected")
		}
	}
}

func installHTTPIdentityFixture(t *testing.T, db *database.DB, listener, uuid, secret string) {
	t.Helper()
	hash := sha256.Sum256([]byte(secret))
	if _, err := db.Exec(`INSERT INTO c2_http_session_auth(implant_uuid,listener_id,token_hash) VALUES(?,?,?)`, uuid, listener, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPIdentityBindingDoesNotClaimLegacyOrExposeCredential(t *testing.T) {
	_, db := terminalTestManager(t)
	secret := strings.Repeat("test-only-secret-", 3)
	if ok, err := db.BindC2HTTPIdentity("listener", "test-uuid", secret); err != nil || ok {
		t.Fatalf("legacy identity claim: ok=%v err=%v", ok, err)
	}
	if ok, err := db.BindC2HTTPIdentity("listener", "test-only-new-identity", secret); err != nil || !ok {
		t.Fatalf("new identity binding: ok=%v err=%v", ok, err)
	}
	if ok, err := db.BindC2HTTPIdentity("listener", "test-only-new-identity", strings.Repeat("other", 12)); err != nil || ok {
		t.Fatalf("identity secret overwritten: ok=%v err=%v", ok, err)
	}
	var stored string
	if err := db.QueryRow(`SELECT token_hash FROM c2_http_session_auth WHERE implant_uuid=?`, "test-only-new-identity").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == secret || len(stored) != 64 {
		t.Fatal("raw credential stored instead of hash")
	}
	if ok, err := db.VerifyC2HTTPIdentity("foreign-listener", "test-only-new-identity", secret); err != nil || ok {
		t.Fatal("identity usable across listeners")
	}
}
