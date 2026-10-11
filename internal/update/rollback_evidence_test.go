package update

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackRecoveryRejectsAmbiguousEvidence(t *testing.T) {
	for _, variant := range []string{"valid", "missing_restore_binary", "missing_live_hash", "contradictory_previous_hash", "duplicate_restore_binary"} {
		t.Run(variant, func(t *testing.T) {
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
			live := readFile(t, bin)
			liveHash, _ := fileSHA256(bin)
			previousHash, _ := fileSHA256(bin + ".prev")
			pending := rollbackPendingState{State: st, RestoreBinary: true, LiveSHA256: liveHash, PreviousSHA256: previousHash}
			encoded, _ := json.Marshal(pending)
			var fields map[string]interface{}
			_ = json.Unmarshal(encoded, &fields)
			switch variant {
			case "missing_restore_binary":
				delete(fields, "restore_binary")
			case "missing_live_hash":
				delete(fields, "live_sha256")
			case "contradictory_previous_hash":
				writeFile(t, bin+".prev", "unrelated binary")
				wrongHash, _ := fileSHA256(bin + ".prev")
				fields["previous_sha256"] = wrongHash
			}
			encoded, _ = json.Marshal(fields)
			if variant == "duplicate_restore_binary" {
				encoded = append(encoded[:len(encoded)-1], []byte(",\"restore_binary\":false}")...)
			}
			if err := os.WriteFile(filepath.Join(tr.install, rollbackPendingFile), encoded, 0600); err != nil {
				t.Fatal(err)
			}
			mustGit(t, tr.install, "reset", "--hard", st.PreviousCommit)
			_, err := Rollback(context.Background(), buildOpts(tr))
			if variant == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if got := readFile(t, bin); got != "original binary" {
					t.Fatalf("valid rollback did not restore binary: %q", got)
				}
				return
			}
			if err == nil {
				t.Errorf("malformed/contradictory marker authorized recovery, live before=%q after=%q; state exists=%v marker exists=%v", live, readFile(t, bin), fileExists(statePath(tr.install)), fileExists(filepath.Join(tr.install, rollbackPendingFile)))
			}
			if got := readFile(t, bin); got != live {
				t.Errorf("invalid evidence mutated binary: %q => %q", live, got)
			}
			if !fileExists(statePath(tr.install)) || !fileExists(filepath.Join(tr.install, rollbackPendingFile)) {
				t.Error("invalid evidence deleted recovery records")
			}
		})
	}
}

func TestRollbackRecoveryAfterStateCleanup(t *testing.T) {
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
	pending := rollbackPendingState{State: st, RestoreBinary: true, LiveSHA256: st.BinarySHA256, PreviousSHA256: st.PreviousBinarySHA256}
	if err := writeRollbackPending(tr.install, pending); err != nil {
		t.Fatal(err)
	}
	mustGit(t, tr.install, "reset", "--hard", st.PreviousCommit)
	if err := restorePrevBinary(bin); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath(tr.install)); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(context.Background(), buildOpts(tr)); err != nil {
		t.Fatal(err)
	}
	if readFile(t, bin) != "original binary" {
		t.Fatal("cleanup retry changed restored binary")
	}
	if fileExists(filepath.Join(tr.install, rollbackPendingFile)) {
		t.Fatal("cleanup retry left journal")
	}
}
