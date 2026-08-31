package c2

import (
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

// 回归：审批桥不可用（协调器关闭）时，危险任务必须 fail-closed 拒绝入队，
// 不允许恢复历史直通行为；结构上也不存在 BypassHITL 之类的绕行入口。
func TestEnqueueTaskFailsClosedWhenBridgeUnavailable(t *testing.T) {
	tmp := t.TempDir()
	db, err := database.NewDB(filepath.Join(tmp, "c2.sqlite"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mgr := NewManager(db, zap.NewNop(), tmp)
	listener, err := mgr.CreateListener(CreateListenerInput{
		Name: "t", Type: string(ListenerTypeHTTPBeacon), BindHost: "127.0.0.1", BindPort: 14444,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertC2Session(&database.C2Session{
		ID: "session-1", ListenerID: listener.ID, ImplantUUID: "uuid-1", Hostname: "h", Username: "u",
		OS: "Linux", Arch: "amd64", Status: string(SessionActive),
	}); err != nil {
		t.Fatal(err)
	}

	for _, taskType := range []TaskType{TaskTypeKillProc, TaskTypePersist, TaskTypeSelfDelete, TaskTypeLoadAssembly} {
		if _, err := mgr.EnqueueTask(EnqueueTaskInput{
			SessionID: "session-1", TaskType: taskType,
			Payload: map[string]interface{}{}, Source: "manual",
		}); err == nil {
			t.Fatalf("dangerous task %s must be rejected when approval bridge is unavailable", taskType)
		} else if common, ok := err.(*CommonError); !ok || common.Code != "approval_unavailable" {
			t.Fatalf("task %s error = %v, want approval_unavailable", taskType, err)
		}
	}
}
