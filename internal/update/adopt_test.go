package update

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newAdoptFixture builds the shape a tarball installation has: the upstream project's files
// on disk with the repository removed, plus operator content and one locally edited
// product file that the adoption is expected to name (and keep a copy of).
func newAdoptFixture(t *testing.T) (*tree, string) {
	t.Helper()
	tr := newTree(t)
	dir := filepath.Join(filepath.Dir(tr.upstream), "release")
	mustGit(t, filepath.Dir(tr.upstream), "clone", "-q", tr.upstream, dir)
	if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil {
		t.Fatal(err)
	}
	// Operator content: the live config (never in the repository), their own role, and an
	// edit to a shipped role.
	writeFile(t, filepath.Join(dir, "config.yaml"), "server:\n  port: 8088\n")
	writeFile(t, filepath.Join(dir, "roles", "mine.yaml"), "name: mine\n")
	writeFile(t, filepath.Join(dir, "roles", "shipped.yaml"), "name: shipped\ndescription: mine, do not touch\n")
	// A locally edited product file.
	writeFile(t, filepath.Join(dir, "run.sh"), "#!/bin/sh\necho hacked\n")
	return tr, dir
}

func TestPreviewNamesWhatAdoptionWouldReplaceWithoutTouchingTheDirectory(t *testing.T) {
	requireGit(t)
	tr, dir := newAdoptFixture(t)

	plan, err := Preview(context.Background(), Options{Root: dir, Repo: tr.upstream})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
		t.Fatal("a preview must not create a repository")
	}
	if plan.Incoming < 3 {
		t.Fatalf("incoming = %d, want at least the fixture's files", plan.Incoming)
	}
	if !contains(plan.Overwritten, "run.sh") {
		t.Errorf("the edited product file must be named: %v", plan.Overwritten)
	}
	if contains(plan.Overwritten, "roles/shipped.yaml") {
		t.Errorf("operator content must not be listed as replaced: %v", plan.Overwritten)
	}
	if !contains(plan.Protected, "roles/shipped.yaml") {
		t.Errorf("the edited shipped role must be listed as protected: %v", plan.Protected)
	}
	if got := readFile(t, filepath.Join(dir, "run.sh")); !strings.Contains(got, "hacked") {
		t.Errorf("preview must not change file contents: %q", got)
	}
}

func TestAdoptConnectsTheDirectoryAndKeepsOperatorContent(t *testing.T) {
	requireGit(t)
	tr, dir := newAdoptFixture(t)

	res, err := Adopt(context.Background(), Options{Root: dir, Repo: tr.upstream, BinaryName: "none"}, nil)
	if err != nil {
		t.Fatalf("adopt failed: %v\nresult: %+v", err, res)
	}
	if !res.Adopted || res.ToCommit == "" {
		t.Fatalf("res = %+v, want an adopted result", res)
	}
	// The directory is now a work tree tracking the chosen source.
	if got := mustGit(t, dir, "rev-parse", "--abbrev-ref", "HEAD"); got != "main" {
		t.Errorf("HEAD branch = %q, want main", got)
	}
	if got := mustGit(t, dir, "rev-parse", "--abbrev-ref", "@{upstream}"); got != "origin/main" {
		t.Errorf("upstream = %q, want origin/main - from here the tree tracks its source by itself", got)
	}
	// The target's content replaced the local edit; the local edit survives in the backup.
	if got := readFile(t, filepath.Join(dir, "run.sh")); !strings.Contains(got, "echo old") {
		t.Errorf("run.sh = %q, want the target's version", got)
	}
	if !contains(res.Overwritten, "run.sh") {
		t.Errorf("result must name the replaced file: %v", res.Overwritten)
	}
	if got := readFile(t, filepath.Join(res.BackupDir, "overwritten", "run.sh")); !strings.Contains(got, "hacked") {
		t.Errorf("the replaced file must be kept for recovery, got %q", got)
	}
	// Operator content survived: the live config untouched, their own role untouched, their
	// edit to a shipped role restored over the target's version.
	if got := readFile(t, filepath.Join(dir, "config.yaml")); !strings.Contains(got, "8088") {
		t.Errorf("config.yaml was disturbed: %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "roles", "mine.yaml")); !strings.Contains(got, "name: mine") {
		t.Errorf("the operator's own role must survive: %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "roles", "shipped.yaml")); !strings.Contains(got, "do not touch") {
		t.Errorf("the operator's edit to a shipped role must win: %q", got)
	}
	if !contains(res.KeptContent, "roles/shipped.yaml") {
		t.Errorf("keptContent = %v, want roles/shipped.yaml", res.KeptContent)
	}

	// From now on it is a normal installation: the next upstream commit updates it, and the
	// first real update writes the first rollback point.
	tr.upstreamCommit(t, "second: bump service", map[string]string{
		"internal_service.go": "package service\n\nconst Version = \"2\"\n",
	})
	snap, err := Check(context.Background(), Options{Root: dir, Repo: tr.upstream, BinaryName: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if snap.CheckError != "" || snap.Behind != 1 {
		t.Fatalf("the adopted tree must update like any other: checkError=%q behind=%d", snap.CheckError, snap.Behind)
	}
	res2, err := Apply(context.Background(), Options{Root: dir, Repo: tr.upstream, BinaryName: "none"}, nil)
	if err != nil {
		t.Fatalf("apply after adopt failed: %v", err)
	}
	if res2.ToCommit == "" || res2.Adopted {
		t.Fatalf("res2 = %+v", res2)
	}
	if _, ok := readState(dir); !ok {
		t.Error("the first real update must write a rollback point")
	}
	if got := readFile(t, filepath.Join(dir, "internal_service.go")); !strings.Contains(got, "Version = \"2\"") {
		t.Errorf("code after the first update = %q", got)
	}
}

func TestAdoptRefusesWhatItCannotHonestlyDo(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	// Already a work tree: that is an update, not an adoption.
	if _, err := Adopt(context.Background(), Options{Root: tr.install, Repo: tr.upstream, BinaryName: "none"}, nil); asReason(err) != "already_a_repo" {
		t.Errorf("err = %v, want already_a_repo", err)
	}
	// Nothing to adopt onto: the directory has to exist.
	plain := t.TempDir()
	missing := filepath.Join(plain, "not-a-directory")
	if _, err := Adopt(context.Background(), Options{Root: missing}, nil); asReason(err) != "bad_root" {
		t.Errorf("err = %v, want bad_root", err)
	}
	// An address git must never be handed. (An unset address is no longer an error: the
	// official repository is the default update source.)
	if _, err := Adopt(context.Background(), Options{Root: plain, Repo: "ext::sh -c true", BinaryName: "none"}, nil); asReason(err) != "bad_source" {
		t.Errorf("err = %v, want bad_source", err)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func asReason(err error) string {
	if ue, ok := err.(*Error); ok {
		return ue.Reason
	}
	return ""
}

func TestAdoptPreservesModeOfUnchangedProtectedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not available on Windows")
	}
	requireGit(t)
	tr, dir := newAdoptFixture(t)
	role := filepath.Join(dir, "roles", "shipped.yaml")
	writeFile(t, role, readFile(t, filepath.Join(tr.upstream, "roles", "shipped.yaml")))
	if err := os.Chmod(role, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Adopt(context.Background(), Options{Root: dir, Repo: tr.upstream, BinaryName: "none"}, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(role)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("adoption lost private permissions: %v %v", info, err)
	}
}
