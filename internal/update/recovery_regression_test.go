package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildRecoveryRejectsAmbiguousEvidence(t *testing.T) {
	for _, kind := range []string{"valid_residual", "missing_hashes", "null_hashes", "conflicting_duplicate", "contradictory_prior_hash"} {
		t.Run(kind, func(t *testing.T) {
			requireGit(t)
			tr := newTree(t)
			scriptFakeGo(t)
			bin := filepath.Join(tr.install, Binary)
			writeFile(t, bin, "original binary")
			before := mustGit(t, tr.install, "rev-parse", "HEAD")
			tr.upstreamCommit(t, "release", map[string]string{"internal_service.go": "package service\nconst Version = \"2\"\n"})
			if _, err := Apply(context.Background(), buildOpts(tr), nil); err != nil {
				t.Fatal(err)
			}
			target := mustGit(t, tr.install, "rev-parse", "HEAD")
			st, _ := readState(tr.install)
			var marker string
			switch kind {
			case "valid_residual":
				marker = fmt.Sprintf(`{"commit":%q,"previous_commit":%q,"binary_sha256":%q,"previous_binary_sha256":%q}`, target, before, st.BinarySHA256, st.PreviousBinarySHA256)
			case "missing_hashes":
				marker = fmt.Sprintf(`{"commit":%q}`, target)
			case "null_hashes":
				marker = fmt.Sprintf(`{"commit":%q,"binary_sha256":null,"previous_binary_sha256":null}`, target)
			case "conflicting_duplicate":
				marker = fmt.Sprintf(`{"commit":%q,"previous_commit":%q,"previous_binary_sha256":%q,"previous_binary_sha256":%q}`, target, before, st.PreviousBinarySHA256, st.BinarySHA256)
			case "contradictory_prior_hash":
				marker = fmt.Sprintf(`{"commit":%q,"previous_commit":%q,"previous_binary_sha256":%q}`, target, before, st.BinarySHA256)
			}
			if err := os.WriteFile(buildPendingPath(tr.install), []byte(marker), 0644); err != nil {
				t.Fatal(err)
			}
			liveBefore := readFile(t, bin)
			stateBefore := readFile(t, statePath(tr.install))
			builds := 0
			res, err := Apply(context.Background(), buildOpts(tr), func(s Step) {
				if s.Phase == "build" {
					builds++
				}
			})
			t.Logf("recovery builds=%d error=%v result=%+v", builds, err, res)
			gotPrev := readFile(t, bin+".prev")
			if kind == "valid_residual" {
				if builds != 0 || gotPrev != "original binary" || err != nil {
					t.Fatalf("valid residual replay: builds=%d prev=%q err=%v", builds, gotPrev, err)
				}
				return
			}
			if err != nil && gotPrev == "original binary" && builds == 0 {
				if readFile(t, bin) != liveBefore || readFile(t, statePath(tr.install)) != stateBefore || readFile(t, buildPendingPath(tr.install)) != marker {
					t.Fatal("refusal changed live binary or recovery evidence")
				}
				return
			}
			if _, rbErr := Rollback(context.Background(), buildOpts(tr)); rbErr != nil {
				t.Logf("rollback error=%v", rbErr)
			} else {
				t.Logf("rollback HEAD=%s binary=%q", mustGit(t, tr.install, "rev-parse", "HEAD"), readFile(t, bin))
			}
			t.Fatalf("unsafe malformed recovery: builds=%d error=%v previous binary=%q (wanted refusal before build/swap; original binary preserved)", builds, err, gotPrev)
		})
	}
}

func TestBuildRecoveryBetweenBinaryRenames(t *testing.T) {
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
	pending := buildPendingState{Commit: st.UpdatedCommit, PreviousCommit: st.PreviousCommit, BinarySHA256: st.BinarySHA256, PreviousBinarySHA256: st.PreviousBinarySHA256}
	st.BinaryCommit = st.PreviousCommit
	st.BinarySHA256 = st.PreviousBinarySHA256
	if err := writeState(tr.install, st); err != nil {
		t.Fatal(err)
	}
	if err := writeBuildPending(tr.install, pending); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), buildOpts(tr), nil); err != nil {
		t.Fatal(err)
	}
	if readFile(t, bin+".prev") != "original binary" {
		t.Fatal("interrupted swap lost previous binary")
	}
	if _, err := Rollback(context.Background(), buildOpts(tr)); err != nil {
		t.Fatal(err)
	}
	if readFile(t, bin) != "original binary" {
		t.Fatal("rollback no longer restores original binary")
	}
}
