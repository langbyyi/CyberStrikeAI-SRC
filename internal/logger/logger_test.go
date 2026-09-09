package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestDiagnosticFiltering(t *testing.T) {
	for _, level := range []string{"debug", "error"} {
		t.Run(level, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "log")
			log := New(level, filepath.Join(root, "primary.log"), DiagnosticOptions{Dir: dir})
			t.Cleanup(func() { _ = log.Close() })
			log.Debug("debug")
			log.Info("info")
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("ordinary logs created diagnostic directory: %v", err)
			}
			child := log.With(zap.String("conversation_id", "test-id"))
			child.Warn("retry", zap.Int("attempt", 2))
			child.Error("failed", zap.Error(fmt.Errorf("test failure")))
			files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
			if len(files) != 1 {
				t.Fatalf("files: %v", files)
			}
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != 2 {
				t.Fatalf("unexpected diagnostic records: %s", data)
			}
			for i, line := range lines {
				var record map[string]interface{}
				if err := json.Unmarshal([]byte(line), &record); err != nil {
					t.Fatal(err)
				}
				if record["conversation_id"] != "test-id" || record["timestamp"] == nil || record["caller"] == nil {
					t.Fatalf("missing diagnostic context: %v", record)
				}
				if i == 1 && (record["stacktrace"] == nil || record["error"] != "test failure") {
					t.Fatalf("missing error details: %v", record)
				}
			}
		})
	}
}

func TestDiagnosticDisabled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	log := New("error", os.DevNull, DiagnosticOptions{Dir: dir, Disabled: true})
	log.Error("failure")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("disabled diagnostics wrote files: %v", err)
	}
}

func TestDailyRotationRetentionAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	w := newDailyWriter(DiagnosticOptions{Dir: dir, RetentionDays: 2})
	now := time.Date(2026, 9, 8, 23, 59, 59, 0, time.Local)
	w.now = func() time.Time { return now }
	for _, name := range []string{"diagnostic-2026-09-06.log", "diagnostic-2026-09-07.log", "other.log", "diagnostic-invalid.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Write([]byte("before midnight\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "diagnostic-2026-09-06.log")); !os.IsNotExist(err) {
		t.Fatal("expired file remains")
	}
	now = now.Add(2 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.Write([]byte("after midnight\n")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for name, count := range map[string]int{"diagnostic-2026-09-08.log": 1, "diagnostic-2026-09-09.log": 50} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || strings.Count(string(data), "\n") != count {
			t.Fatalf("%s: %q, %v", name, data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "diagnostic-2026-09-07.log")); !os.IsNotExist(err) {
		t.Fatal("rotation did not expire old file")
	}
	for _, name := range []string{"other.log", "diagnostic-invalid.log"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiagnosticWriteFailureKeepsPrimaryOutput(t *testing.T) {
	root := t.TempDir()
	primary := filepath.Join(root, "primary.log")
	log := New("info", primary, DiagnosticOptions{Dir: filepath.Join(primary, "invalid")})
	t.Cleanup(func() { _ = log.Close() })
	log.Error("still visible")
	data, err := os.ReadFile(primary)
	if err != nil || !strings.Contains(string(data), "still visible") {
		t.Fatalf("primary output lost: %s, %v", data, err)
	}
}
