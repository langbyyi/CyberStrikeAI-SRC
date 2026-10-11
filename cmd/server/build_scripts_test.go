package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every `go build` in this repository's scripts has to target the cmd/server package.
// Building the single file cmd/server/main.go was tried once and broke the password reset
// entry: the file-based form silently leaves out sibling files of package main (it was
// update_cli.go that disappeared), and only `run.sh --reset-admin-password` used that
// build path, so nothing noticed until an operator needed it in an emergency. Compiling
// the package can never have that failure mode.
func TestScriptsBuildThePackageNotASingleFile(t *testing.T) {
	root := filepath.Join("..", "..")
	scripts := []string{filepath.Join(root, "run.sh"), filepath.Join(root, "upgrade.sh")}
	more, err := filepath.Glob(filepath.Join(root, "scripts", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	scripts = append(scripts, more...)

	found := 0
	for _, script := range scripts {
		data, err := os.ReadFile(script)
		if err != nil {
			t.Fatalf("read %s: %v", script, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "go build") {
				continue
			}
			found++
			if strings.Contains(line, ".go") {
				t.Errorf("%s builds a single .go file; build ./cmd/server instead:\n  %s",
					script, strings.TrimSpace(line))
			}
		}
	}
	// A scan that finds no build command at all is looking in the wrong place, and a test
	// that cannot see the thing it guards passes for the wrong reason.
	if found == 0 {
		t.Fatal("no `go build` command found in the scripts")
	}
}

func TestUpgradeScriptUpdateConfigVersionPreservesDocumentAndMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("upgrade.sh requires a POSIX shell")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not available")
	}

	root := filepath.Join("..", "..")
	scriptPath := filepath.Join(root, "upgrade.sh")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	function := extractShellFunction(t, string(script), "update_config_version")
	command := "umask 022\n" + function + "\nCONFIG_FILE=$1\nupdate_config_version \"$2\"\n"

	for _, tc := range []struct {
		name              string
		original          string
		wantDocumentStart bool
	}{
		{name: "document start", original: "---\nserver:\n  port: 8088\n", wantDocumentStart: true},
		{name: "commented document start", original: "# local settings\n---\nserver:\n  port: 8088\n"},
		{name: "directive document start", original: "%YAML 1.1\n---\nserver:\n  port: 8088\n"},
		{name: "private mode", original: "version: \"v1.0.0\"\nserver:\n  port: 8088\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte(tc.original), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(configPath, 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(bash, "-c", command, "upgrade-version-test", configPath, "v1.2.3")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("update_config_version failed: %v\n%s", err, output)
			}
			got, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantDocumentStart && !strings.HasPrefix(string(got), "---\n") {
				t.Errorf("YAML document start must remain first: %q", got)
			}
			var parsed struct {
				Version string `yaml:"version"`
				Server  struct {
					Port int `yaml:"port"`
				} `yaml:"server"`
			}
			if err := yaml.Unmarshal(got, &parsed); err != nil {
				t.Fatalf("updated config is not valid YAML: %v\n%s", err, got)
			}
			if parsed.Version != "v1.2.3" {
				t.Errorf("version = %q, want v1.2.3", parsed.Version)
			}
			if parsed.Server.Port != 8088 {
				t.Errorf("server.port = %d, want 8088", parsed.Server.Port)
			}
			info, err := os.Stat(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("mode = %v, want 0600 preserved", info.Mode().Perm())
			}
		})
	}
}

func TestUpgradeScriptVersionRefusesUnsupportedYAML(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("upgrade.sh requires a POSIX shell")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	script, err := os.ReadFile(filepath.Join("..", "..", "upgrade.sh"))
	if err != nil {
		t.Fatal(err)
	}
	function := extractShellFunction(t, string(script), "update_config_version")
	for _, original := range []string{
		"--- {server: {port: 8088}}\n",
		"{server: {port: 8088}}\n",
		"version: \"old\n  version\"\nserver:\n  port: 8088\n",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(original), 0600); err != nil {
			t.Fatal(err)
		}
		command := function + "\nCONFIG_FILE=$1\nupdate_config_version v1.2.3\n"
		if output, err := exec.Command("bash", "-c", command, "test", path).CombinedOutput(); err != nil {
			t.Fatalf("writer failed: %v %s", err, output)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != original {
			t.Fatalf("unsupported YAML was changed: %q %v", got, err)
		}
	}
}

// The tarball path syncs with `rsync --delete`, so every artifact a one-click update writes
// at the install root has to be on its keep list. .gitignore is exactly that list of
// machine-local artifacts, so the assertion is derived from it: a new marker cannot be
// forgotten here and silently deleted by the next package upgrade.
func TestUpgradeScriptKeepsEveryOneClickUpdateArtifact(t *testing.T) {
	root := filepath.Join("..", "..")
	ignore, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(root, "upgrade.sh"))
	if err != nil {
		t.Fatal(err)
	}

	var artifacts []string
	inSection := false
	for _, line := range strings.Split(string(ignore), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# One-click update artifacts") {
			inSection = true
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(line, "#") {
			break
		}
		if line != "" {
			artifacts = append(artifacts, line)
		}
	}
	if len(artifacts) == 0 {
		t.Fatal("no update artifacts found in .gitignore: the section this test reads has moved")
	}

	// The script names the binary through a variable; compare against the literal name.
	keeps := strings.ReplaceAll(string(script), "${BINARY_NAME}", "cyberstrike-ai")
	for _, artifact := range artifacts {
		if !strings.Contains(keeps, "--exclude="+artifact) {
			t.Errorf("upgrade.sh syncs with rsync --delete but does not keep %s", artifact)
		}
	}
}

func extractShellFunction(t *testing.T, script, name string) string {
	t.Helper()
	startMarker := name + "() {"
	start := strings.Index(script, startMarker)
	if start < 0 {
		t.Fatalf("function %s not found", name)
	}
	lines := strings.Split(script[start:], "\n")
	for i := 1; i < len(lines); i++ {
		if lines[i] == "}" {
			return strings.Join(lines[:i+1], "\n")
		}
	}
	t.Fatalf("function %s has no closing brace", name)
	return ""
}
