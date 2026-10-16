package update

import (
	"path/filepath"
	"testing"
)

// TestInstallBinaryPathIsTheInstallationsOwnBinary: a restart execs whatever this returns, so
// it has to be the file an update replaces - never os.Executable(), which after an update is
// the renamed-away binary and would put the replaced code back.
func TestInstallBinaryPathIsTheInstallationsOwnBinary(t *testing.T) {
	root := t.TempDir()
	if got, want := InstallBinaryPath(root), filepath.Join(root, Binary); got != want {
		t.Fatalf("InstallBinaryPath = %q, want %q", got, want)
	}
	// A relative root still names exactly one file: the caller's working directory does not
	// change across the handover, so the path does not have to be relative to survive.
	if got := InstallBinaryPath("."); !filepath.IsAbs(got) {
		t.Fatalf("InstallBinaryPath did not resolve a relative root: %q", got)
	}
	// No root, no binary. The caller treats the empty string as "cannot hand over".
	if got := InstallBinaryPath(""); got != "" {
		t.Fatalf("InstallBinaryPath without a root = %q, want empty", got)
	}
}
