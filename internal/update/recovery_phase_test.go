package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackRecoveryRequiresActualBinaryAbsence(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	before := mustGit(t, tr.install, "rev-parse", "HEAD")
	tr.upstreamCommit(t, "next", map[string]string{"review.go": "package review\n"})
	mustGit(t, tr.install, "fetch", "origin")
	target := mustGit(t, tr.install, "rev-parse", "origin/main")
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "unrelated live binary")
	p := rollbackPendingState{State: State{PreviousCommit: before, UpdatedCommit: target, BinaryCommit: before, PreviousBinaryAbsent: true}, RestoreBinary: false}
	if err := writeRollbackPending(tr.install, p); err != nil {
		t.Fatal(err)
	}
	_, err := Rollback(context.Background(), buildOpts(tr))
	t.Logf("error=%v live=%q marker_exists=%v", err, readFile(t, bin), fileExists(filepath.Join(tr.install, rollbackPendingFile)))
	if err == nil || !fileExists(filepath.Join(tr.install, rollbackPendingFile)) {
		t.Fatal("contradictory absence evidence authorized cleanup")
	}
}
func TestBuildRecoveryBeforeMergeRequiresFileProof(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	before := mustGit(t, tr.install, "rev-parse", "HEAD")
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "old binary")
	oldHash, _ := fileSHA256(bin)
	tr.upstreamCommit(t, "next", map[string]string{"review.go": "package review\n"})
	mustGit(t, tr.install, "fetch", "origin")
	target := mustGit(t, tr.install, "rev-parse", "origin/main")
	p := buildPendingState{Commit: target, PreviousCommit: before, PreviousBinarySHA256: oldHash}
	if err := writeBuildPending(tr.install, p); err != nil {
		t.Fatal(err)
	}
	writeFile(t, bin, "unrelated live binary")
	err := finishPendingBuild(context.Background(), &Snapshot{Root: tr.install}, buildOpts(tr), &Result{}, func(string, string) {})
	_, statErr := os.Stat(buildPendingPath(tr.install))
	t.Logf("error=%v marker_stat=%v", err, statErr)
	if err == nil || os.IsNotExist(statErr) {
		t.Fatal("mismatching binary evidence authorized marker deletion")
	}
}

func TestLegacyRecoveryRejectsMalformedState(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	scriptFakeGo(t)
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "old binary")
	tr.upstreamCommit(t, "next", map[string]string{"review.go": "package review\n"})
	if _, err := Apply(context.Background(), buildOpts(tr), nil); err != nil {
		t.Fatal(err)
	}
	state := readFile(t, statePath(tr.install))
	state = state[:len(state)-2] + ",\"binary_sha256\":null}"
	writeFile(t, statePath(tr.install), state)
	writeFile(t, buildPendingPath(tr.install), "source is ahead of the binary")
	builds := 0
	_, err := Apply(context.Background(), buildOpts(tr), func(s Step) {
		if s.Phase == "build" {
			builds++
		}
	})
	t.Logf("error=%v builds=%d marker_exists=%v", err, builds, fileExists(buildPendingPath(tr.install)))
	if err == nil || builds != 0 || !fileExists(buildPendingPath(tr.install)) {
		t.Fatal("legacy marker authorized mutation with malformed state")
	}
}

func TestFreshRollbackRejectsMalformedState(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	scriptFakeGo(t)
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "old binary")
	tr.upstreamCommit(t, "next", map[string]string{"review.go": "package review\n"})
	if _, err := Apply(context.Background(), buildOpts(tr), nil); err != nil {
		t.Fatal(err)
	}
	writeFile(t, bin+".prev", "unrelated backup")
	wrong, _ := fileSHA256(bin + ".prev")
	state := readFile(t, statePath(tr.install))
	state = state[:len(state)-2] + fmt.Sprintf(",\"previous_binary_sha256\":%q}", wrong)
	writeFile(t, statePath(tr.install), state)
	_, err := Rollback(context.Background(), buildOpts(tr))
	t.Logf("error=%v binary=%q state_exists=%v", err, readFile(t, bin), fileExists(statePath(tr.install)))
	if err == nil || !fileExists(statePath(tr.install)) {
		t.Fatal("malformed state authorized wrong rollback")
	}
}

func TestRollbackAbsenceCannotHaveLiveHash(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	before := mustGit(t, tr.install, "rev-parse", "HEAD")
	tr.upstreamCommit(t, "next", map[string]string{"review.go": "package review\n"})
	mustGit(t, tr.install, "fetch", "origin")
	target := mustGit(t, tr.install, "rev-parse", "origin/main")
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "unrelated live binary")
	hash, _ := fileSHA256(bin)
	p := rollbackPendingState{State: State{PreviousCommit: before, UpdatedCommit: target, BinaryCommit: before, PreviousBinaryAbsent: true, BinarySHA256: hash}, LiveSHA256: hash, RestoreBinary: false}
	if err := writeRollbackPending(tr.install, p); err != nil {
		t.Fatal(err)
	}
	_, err := Rollback(context.Background(), buildOpts(tr))
	t.Logf("error=%v marker_exists=%v", err, fileExists(filepath.Join(tr.install, rollbackPendingFile)))
	if err == nil || !fileExists(filepath.Join(tr.install, rollbackPendingFile)) {
		t.Fatal("absent binary with a hash authorized cleanup")
	}
}

func TestBuildBeforeMergeRejectsPostSwap(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	scriptFakeGo(t)
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "old binary")
	tr.upstreamCommit(t, "next", map[string]string{"review.go": "package review\n"})
	if _, err := Apply(context.Background(), buildOpts(tr), nil); err != nil {
		t.Fatal(err)
	}
	st, _ := readState(tr.install)
	p := buildPendingState{Commit: st.UpdatedCommit, PreviousCommit: st.PreviousCommit, BinarySHA256: st.BinarySHA256, PreviousBinarySHA256: st.PreviousBinarySHA256}
	if err := writeBuildPending(tr.install, p); err != nil {
		t.Fatal(err)
	}
	mustGit(t, tr.install, "reset", "--hard", st.PreviousCommit)
	err := finishPendingBuild(context.Background(), &Snapshot{Root: tr.install}, buildOpts(tr), &Result{}, func(string, string) {})
	t.Logf("error=%v marker_exists=%v", err, fileExists(buildPendingPath(tr.install)))
	if err == nil || !fileExists(buildPendingPath(tr.install)) {
		t.Fatal("post-swap files with pre-merge HEAD authorized cleanup")
	}
}
