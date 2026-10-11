package update

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecoveryJSONRefusesAmbiguousFields(t *testing.T) {
	for _, data := range []string{
		`null`, `[]`, `{} {}`, `{"commit":null}`, `{"commit":123}`,
		`{"commit":"a","commit":"a"}`, `{"commit":"a","commit":"b"}`,
		`{"Commit":"a"}`, `{"unknown":true}`, `{"previous_binary_absent":"true"}`,
		`{"previous_binary_absent":null}`, `{"kept_content":[null]}`,
	} {
		t.Run(data, func(t *testing.T) {
			var p buildPendingState
			if err := decodeRecoveryJSON([]byte(data), &p); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
	// Duplicate nested state fields must not overwrite the evidence either.
	var rollback rollbackPendingState
	if err := decodeRecoveryJSON([]byte(`{"state":{"binary_sha256":"a","binary_sha256":"b"}}`), &rollback); err == nil {
		t.Fatal("duplicate nested evidence accepted")
	}
}

func TestBuildEvidenceRequiresOldBinaryProof(t *testing.T) {
	for _, p := range []buildPendingState{
		{Commit: strings.Repeat("a", 40)},
		{Commit: strings.Repeat("a", 40), PreviousBinarySHA256: ""},
		{Commit: strings.Repeat("a", 40), PreviousBinarySHA256: "bad"},
		{Commit: strings.Repeat("a", 40), PreviousBinarySHA256: strings.Repeat("b", 64), PreviousBinaryAbsent: true},
		{Commit: strings.Repeat("a", 40), PreviousBinaryAbsent: true, BinarySHA256: "bad"},
	} {
		if err := validateBuildEvidence(t.TempDir(), p); err == nil {
			t.Fatalf("incomplete evidence accepted: %+v", p)
		}
	}
	for _, p := range []buildPendingState{
		{Commit: strings.Repeat("a", 40), PreviousBinaryAbsent: true},
		{Commit: strings.Repeat("a", 40), PreviousBinarySHA256: strings.Repeat("b", 64)},
	} {
		data, _ := json.Marshal(p)
		var decoded buildPendingState
		if err := decodeRecoveryJSON(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := validateBuildEvidence(t.TempDir(), decoded); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRollbackEvidenceWithoutDiskState(t *testing.T) {
	st := State{PreviousCommit: strings.Repeat("a", 40), UpdatedCommit: strings.Repeat("b", 40), BinaryCommit: strings.Repeat("a", 40), PreviousBinaryAbsent: true}
	p := rollbackPendingState{State: st}
	if err := validateRollbackEvidence(t.TempDir(), p); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{"bad", strings.Repeat("c", 64)} {
		p.State.PreviousBinarySHA256 = hash
		if err := validateRollbackEvidence(t.TempDir(), p); err == nil {
			t.Fatal("missing disk state bypassed embedded state validation")
		}
	}
	p.State = st
	p.State.PreviousBinaryAbsent = false
	if err := validateRollbackEvidence(t.TempDir(), p); err == nil {
		t.Fatal("missing live evidence accepted without binary absence")
	}
}
