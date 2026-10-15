package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func spillFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, imageContentSpillDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read spill dir: %v", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, filepath.Join(dir, imageContentSpillDir, e.Name()))
		}
	}
	return out
}

func TestSpillImageContentWritesFileAndHintsPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	data := []byte("\x89PNG\r\n\x1a\nfake-image-bytes")
	text, ok := spillImageContent(data, "image/png; charset=binary")
	if !ok {
		t.Fatalf("want spilled, got hint %q", text)
	}
	if !strings.Contains(text, "image/png") {
		t.Errorf("hint should carry mime: %q", text)
	}
	files := spillFiles(t, dir)
	if len(files) != 1 {
		t.Fatalf("want 1 spilled file, got %v", files)
	}
	if filepath.Ext(files[0]) != ".png" {
		t.Errorf("ext = %q, want .png", filepath.Ext(files[0]))
	}
	if !strings.Contains(text, files[0]) {
		t.Errorf("hint should contain the saved path %q: %q", files[0], text)
	}
	got, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Errorf("spilled bytes mismatch")
	}
}

func TestSpillImageContentRejectsEmptyAndOversized(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if text, ok := spillImageContent(nil, "image/png"); ok || text != "" {
		t.Errorf("empty payload should not spill: ok=%v text=%q", ok, text)
	}
	big := make([]byte, imageContentMaxBytes+1)
	text, ok := spillImageContent(big, "image/jpeg")
	if ok {
		t.Fatalf("oversized payload should not spill")
	}
	if !strings.Contains(text, "超出单图上限") {
		t.Errorf("oversized hint should explain the limit: %q", text)
	}
	if files := spillFiles(t, dir); len(files) != 0 {
		t.Errorf("no file expected, got %v", files)
	}
}

func TestSpillImageContentPrunesExpired(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	root := filepath.Join(dir, imageContentSpillDir)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(root, "old.png")
	fresh := filepath.Join(root, "fresh.png")
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stale := time.Now().Add(-imageContentRetention - time.Hour)
	if err := os.Chtimes(old, stale, stale); err != nil {
		t.Fatal(err)
	}

	if _, ok := spillImageContent([]byte("new"), "image/png"); !ok {
		t.Fatal("spill failed")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("expired spill file should be pruned, stat err = %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh spill file must survive: %v", err)
	}
}

func TestSdkContentToOursKeepsTextAndSpillsImages(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	out := sdkContentToOurs([]sdkmcp.Content{
		&sdkmcp.TextContent{Text: "step 1 done"},
		&sdkmcp.ImageContent{Data: []byte("png-bytes"), MIMEType: "image/png"},
	})
	if len(out) != 2 {
		t.Fatalf("got %d items, want 2", len(out))
	}
	if out[0].Text != "step 1 done" {
		t.Errorf("text passthrough broken: %q", out[0].Text)
	}
	if !strings.Contains(out[1].Text, "已保存到服务器") || strings.Contains(out[1].Text, "png-bytes") {
		t.Errorf("image should be spilled to a path, not inlined: %q", out[1].Text)
	}
}

func TestSdkContentToOursEmptyImageGetsPlaceholder(t *testing.T) {
	out := sdkContentToOurs([]sdkmcp.Content{&sdkmcp.ImageContent{MIMEType: "image/png"}})
	if len(out) != 1 || !strings.Contains(out[0].Text, "无法落盘") {
		t.Fatalf("want placeholder, got %+v", out)
	}
}
