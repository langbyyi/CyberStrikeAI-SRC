package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readRepositoryFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestRunScriptRequiresGo125(t *testing.T) {
	script := readRepositoryFile(t, "run.sh")
	if !strings.Contains(script, "requires 1.25+") || !strings.Contains(script, `GO_MINOR" -lt 25`) {
		t.Fatal("run.sh must reject Go versions older than 1.25 and report the same requirement")
	}
}

func TestReadmeQuickStartDocumentsAutomaticConfigCreation(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	if !strings.Contains(readme, "首次启动会自动从 `config.example.yaml` 生成 `config.yaml`") {
		t.Fatal("README quick start must document automatic config creation")
	}
}
