//go:build linux

package project

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNetworkWorkspaceWritableByIsolatedUser(t *testing.T) {
	if os.Getenv("CYBERSTRIKE_NETWORK_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires opt-in privileged Linux workspace integration")
	}
	t.Setenv("CYBERSTRIKE_NETWORK_UID", "1000")
	t.Setenv("CYBERSTRIKE_NETWORK_GID", "1000")
	base := t.TempDir()
	if err := os.Chmod(filepath.Dir(base), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	workspace, err := EnsureWorkspace(filepath.Join(base, "projects", "synthetic-project"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--", "sh", "-c", "printf fixture > artifact.txt")
	cmd.Dir = workspace
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated user cannot write a newly created project workspace: %v: %s", err, output)
	}
	info, err := os.Stat(filepath.Join(workspace, "artifact.txt"))
	if err != nil || info.Sys().(*syscall.Stat_t).Uid != 1000 {
		t.Fatal("artifact was not written as the isolated user")
	}
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "redirect")); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureWorkspace(filepath.Join(base, "redirect")); err == nil {
		t.Fatal("ownership changes followed a workspace symlink")
	}
	info, err = os.Stat(outside)
	if err != nil || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("symlink destination ownership changed")
	}
}
