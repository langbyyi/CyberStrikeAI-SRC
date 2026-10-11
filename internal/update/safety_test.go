package update

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyRefusesRepositorySubdirectory(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	sub := filepath.Join(tr.install, "settings")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	head := mustGit(t, tr.install, "rev-parse", "HEAD")
	tr.upstreamCommit(t, "second", map[string]string{"run.sh": "new script\n"})
	_, err := Apply(context.Background(), Options{Root: sub, Repo: tr.upstream, BinaryName: "none"}, nil)
	if err == nil {
		t.Fatal("updating a repository subdirectory must be refused")
	}
	if got := mustGit(t, tr.install, "rev-parse", "HEAD"); got != head {
		t.Fatal("refusal changed parent repository")
	}
}

func TestInstallLockReleasedWhenProcessIsKilled(t *testing.T) {
	if root := os.Getenv("CSAI_TEST_LOCK_ROOT"); root != "" {
		release, err := LockInstall(Options{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		fmt.Println("locked")
		time.Sleep(time.Hour)
		return
	}
	root := t.TempDir()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-test.run=^TestInstallLockReleasedWhenProcessIsKilled$")
	cmd.Env = append(os.Environ(), "CSAI_TEST_LOCK_ROOT="+root)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child did not acquire lock: %q %v", line, err)
	}
	if release, err := LockInstall(Options{Root: root}); err == nil {
		release()
		t.Fatal("parent acquired child's lock")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	release, err := LockInstall(Options{Root: root})
	if err != nil {
		t.Fatalf("crashed process left a stale lock: %v", err)
	}
	release()
}

func TestFirstBuildDoesNotUseAnUnrelatedPreviousBinary(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	scriptFakeGo(t)
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin+".prev", "unrelated old binary")
	tr.upstreamCommit(t, "second", map[string]string{"run.sh": "new script\n"})
	if _, err := Apply(context.Background(), buildOpts(tr), nil); err != nil {
		t.Fatal(err)
	}
	head := mustGit(t, tr.install, "rev-parse", "HEAD")
	if _, err := Rollback(context.Background(), buildOpts(tr)); err == nil {
		t.Fatal("first build must not roll back to an unrelated .prev")
	}
	if got := mustGit(t, tr.install, "rev-parse", "HEAD"); got != head {
		t.Fatal("refusal reset source")
	}
}

func TestInterruptedAdoptionCanResumeFromUnbornHead(t *testing.T) {
	requireGit(t)
	tr, dir := newAdoptFixture(t)
	scriptFakeGo(t)
	role := filepath.Join(dir, "roles", "shipped.yaml")
	original := readFile(t, role)
	mustGit(t, dir, "init", "-q")
	mustGit(t, dir, "remote", "add", "origin", tr.upstream)
	branch, _, _, err := fetchSource(context.Background(), dir, tr.upstream)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanAdoption(context.Background(), dir, dir, "origin/"+branch)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, ".update-backup", "interrupted")
	for _, rel := range append(scan.changed, scan.kept...) {
		dst := filepath.Join(backup, "overwritten", rel)
		if Protected(rel) {
			dst = filepath.Join(backup, rel)
		}
		if err := copyFile(filepath.Join(dir, rel), dst, 0644); err != nil {
			t.Fatal(err)
		}
	}
	target := mustGit(t, dir, "rev-parse", "origin/"+branch)
	if err := writeBuildPending(dir, buildPendingState{Commit: target, AdoptBranch: branch, BackupDir: backup, KeptContent: scan.kept, OverwrittenContent: scan.changed, PreviousBinaryAbsent: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), Options{Root: dir, Repo: tr.upstream}, nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := readFile(t, role); got != original {
		t.Fatalf("resume lost role: %q", got)
	}
	if buildPending(dir) {
		t.Fatal("resume left a pending marker")
	}
}

func TestInterruptedRollbackResumesAfterSourceReset(t *testing.T) {
	for _, swapped := range []bool{false, true} {
		t.Run(fmt.Sprint(swapped), func(t *testing.T) {
			requireGit(t)
			tr := newTree(t)
			scriptFakeGo(t)
			bin := filepath.Join(tr.install, Binary)
			writeFile(t, bin, "original binary")
			tr.upstreamCommit(t, "second", map[string]string{"run.sh": "new script\n"})
			if _, err := Apply(context.Background(), buildOpts(tr), nil); err != nil {
				t.Fatal(err)
			}
			st, _ := readState(tr.install)
			role := filepath.Join(tr.install, "roles", "shipped.yaml")
			writeFile(t, role, "name: operator edit after update\n")
			changes, _, _ := localChanges(context.Background(), tr.install)
			backup, kept, deleted, err := stashProtectedEdits(context.Background(), tr.install, st.PreviousCommit, changes)
			if err != nil {
				t.Fatal(err)
			}
			liveHash, _ := fileSHA256(bin)
			previousHash, _ := fileSHA256(bin + ".prev")
			pending := rollbackPendingState{State: st, BackupDir: backup, Kept: kept, Deleted: deleted, RestoreBinary: true, LiveSHA256: liveHash, PreviousSHA256: previousHash}
			if err := writeRollbackPending(tr.install, pending); err != nil {
				t.Fatal(err)
			}
			mustGit(t, tr.install, "reset", "--hard", st.PreviousCommit)
			if swapped {
				if err := restorePrevBinary(bin); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Apply(context.Background(), buildOpts(tr), nil); err == nil {
				t.Fatal("update must refuse an interrupted rollback")
			}
			if _, err := Rollback(context.Background(), buildOpts(tr)); err != nil {
				t.Fatalf("resume rollback: %v", err)
			}
			if got := readFile(t, bin); got != "original binary" {
				t.Fatalf("wrong binary after resume: %q", got)
			}
			if got := readFile(t, role); got != "name: operator edit after update\n" {
				t.Fatalf("role lost after resume: %q", got)
			}
			if pending, err := readRollbackPending(tr.install); err != nil || pending != nil {
				t.Fatal("rollback journal not cleared")
			}
		})
	}
}

func TestRollbackRemovesVersionInsertedIntoUnversionedConfig(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	scriptFakeGo(t)
	writeFile(t, filepath.Join(tr.install, Binary), "old binary")
	before := readFile(t, filepath.Join(tr.install, "config.yaml"))
	tr.upstreamCommit(t, "release", map[string]string{"config.example.yaml": "version: v2.0.0\n"})
	if _, err := Apply(context.Background(), buildOpts(tr), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(context.Background(), buildOpts(tr)); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(tr.install, "config.yaml")); got != before {
		t.Fatalf("rollback did not restore an unversioned config: %q", got)
	}
}

func TestApplyRefusesIgnoredSourceCollision(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	writeFile(t, filepath.Join(tr.install, ".git", "info", "exclude"), "local.go\n")
	writeFile(t, filepath.Join(tr.install, "local.go"), "package operator\n")
	head := mustGit(t, tr.install, "rev-parse", "HEAD")
	tr.upstreamCommit(t, "add source", map[string]string{"local.go": "package upstream\n"})
	if _, err := Apply(context.Background(), opts(tr), nil); err == nil {
		t.Fatal("ignored source collision must be refused")
	}
	if got := readFile(t, filepath.Join(tr.install, "local.go")); got != "package operator\n" {
		t.Fatal("ignored source was lost")
	}
	if got := mustGit(t, tr.install, "rev-parse", "HEAD"); got != head {
		t.Fatal("refusal changed HEAD")
	}
}

func TestBuildRefusesSourceChangesMadeAfterPreflight(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	scriptFakeGo(t)
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "old binary")
	tr.upstreamCommit(t, "second", map[string]string{"run.sh": "new script\n"})
	_, err := Apply(context.Background(), buildOpts(tr), func(step Step) {
		if step.Phase == "build" {
			writeFile(t, filepath.Join(tr.install, "run.sh"), "operator edit during build\n")
		}
	})
	if ue, ok := err.(*Error); !ok || ue.Reason != "local_source_edits" {
		t.Fatalf("want refusal of changed source, got %v", err)
	}
	if got := readFile(t, bin); got != "old binary" {
		t.Fatal("unmatched binary installed")
	}
	if !buildPending(tr.install) {
		t.Fatal("refusal must keep the recovery marker")
	}
}

func TestApplyKeepsProtectedDeletion(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	role := filepath.Join(tr.install, "roles", "shipped.yaml")
	if err := os.Remove(role); err != nil {
		t.Fatal(err)
	}
	tr.upstreamCommit(t, "rewrite role", map[string]string{"roles/shipped.yaml": "name: new upstream\n"})
	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(role); !os.IsNotExist(err) {
		t.Fatalf("deleted role resurrected: %v", err)
	}
}

func TestAdoptRefusesExistingInvalidGitMetadata(t *testing.T) {
	requireGit(t)
	tr, dir := newAdoptFixture(t)
	metadata := filepath.Join(dir, ".git", "operator-note")
	writeFile(t, metadata, "keep this metadata")
	_, err := Adopt(context.Background(), Options{Root: dir, Repo: tr.upstream, BinaryName: "none"}, nil)
	if err == nil {
		t.Fatal("existing .git must never be taken over")
	}
	if got := readFile(t, metadata); got != "keep this metadata" {
		t.Fatal("existing metadata changed")
	}
}

func TestAdoptionRefusesFileDirectoryConflict(t *testing.T) {
	requireGit(t)
	tr, dir := newAdoptFixture(t)
	if err := os.Remove(filepath.Join(dir, "run.sh")); err != nil {
		t.Fatal(err)
	}
	valuable := filepath.Join(dir, "run.sh", "local-note")
	writeFile(t, valuable, "operator content")
	if _, err := Preview(context.Background(), Options{Root: dir, Repo: tr.upstream}); err == nil {
		t.Fatal("preview must report a directory conflict")
	}
	if _, err := Adopt(context.Background(), Options{Root: dir, Repo: tr.upstream, BinaryName: "none"}, nil); err == nil {
		t.Fatal("adoption must refuse a directory conflict")
	}
	if got := readFile(t, valuable); got != "operator content" {
		t.Fatal("directory content lost")
	}
}

func TestApplyKeepsIgnoredConfigWhenUpstreamStartsTrackingIt(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	writeFile(t, filepath.Join(tr.install, ".git", "info", "exclude"), "config.yaml\n")
	before := readFile(t, filepath.Join(tr.install, "config.yaml"))
	tr.upstreamCommit(t, "track example config", map[string]string{"config.yaml": "server:\n  port: 9999\n"})
	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(tr.install, "config.yaml")); got != before {
		t.Fatalf("ignored config overwritten: %q", got)
	}
}

func TestUpdateOperationsShareInstallationLock(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	release, err := LockInstall(opts(tr))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, run := range []func() error{
		func() error { _, err := Check(context.Background(), opts(tr)); return err },
		func() error { _, err := Apply(context.Background(), opts(tr), nil); return err },
		func() error { _, err := Rollback(context.Background(), opts(tr)); return err },
		func() error { _, err := Adopt(context.Background(), opts(tr), nil); return err },
	} {
		if ue, ok := run().(*Error); !ok || ue.Reason != "update_busy" {
			t.Fatalf("concurrent operation was not refused: %v", ue)
		}
	}
}
