package logger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DiagnosticOptions controls the additional warn-and-above diagnostic output.
type DiagnosticOptions struct {
	Dir           string
	Disabled      bool
	RetentionDays int // Values <= 0 use the default of 14 calendar days.
}

// dailyWriter opens lazily: healthy runs create no diagnostic files. Opening
// per write also avoids keeping descriptors open across rotation or shutdown.
type dailyWriter struct {
	mu            sync.Mutex
	dir           string
	retentionDays int
	cleanedDay    string
	now           func() time.Time
}

func newDailyWriter(options DiagnosticOptions) *dailyWriter {
	if options.Dir == "" {
		options.Dir = "log"
	}
	if options.RetentionDays <= 0 {
		options.RetentionDays = 14
	}
	return &dailyWriter{dir: options.Dir, retentionDays: options.RetentionDays, now: time.Now}
}

func (w *dailyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	day := now.Format(time.DateOnly)
	if err := os.MkdirAll(w.dir, 0700); err != nil {
		return 0, fmt.Errorf("create diagnostic log directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(w.dir, "diagnostic-"+day+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 0, fmt.Errorf("open diagnostic log: %w", err)
	}
	n, writeErr := f.Write(p)
	closeErr := f.Close()
	var cleanupErr error
	if w.cleanedDay != day {
		cleanupErr = w.cleanup(now)
		if cleanupErr == nil {
			w.cleanedDay = day
		}
	}
	return n, errors.Join(writeErr, closeErr, cleanupErr)
}

// Writes are unbuffered and files are closed before Write returns.
func (w *dailyWriter) Sync() error { return nil }

func (w *dailyWriter) cleanup(now time.Time) error {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return err
	}
	cutoff := now.AddDate(0, 0, -(w.retentionDays - 1)).Format(time.DateOnly)
	var errs []error
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasPrefix(name, "diagnostic-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, "diagnostic-"), ".log")
		if _, err := time.Parse(time.DateOnly, day); err != nil || day >= cutoff {
			continue
		}
		if err := os.Remove(filepath.Join(w.dir, name)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove expired diagnostic log %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
