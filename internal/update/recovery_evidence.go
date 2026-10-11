package update

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
)

// Recovery JSON authorizes filesystem mutations. Unlike encoding/json's default
// behavior, repeated keys, case aliases, unknown fields and null scalars must not
// silently replace or erase evidence. Slice nulls are emitted by our own writer.
func decodeRecoveryJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := checkRecoveryValue(dec, reflect.TypeOf(dst).Elem()); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing recovery data: %v", err)
	}
	return json.Unmarshal(data, dst)
}

func checkRecoveryValue(dec *json.Decoder, typ reflect.Type) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token == nil {
		if typ.Kind() == reflect.Slice {
			return nil
		}
		return fmt.Errorf("null recovery %s", typ)
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return fmt.Errorf("expected recovery object")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = f.Type
			}
		}
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("invalid recovery key")
			}
			ft, known := fields[name]
			if !known || seen[name] {
				return fmt.Errorf("unknown or duplicate recovery field %q", name)
			}
			seen[name] = true
			if err := checkRecoveryValue(dec, ft); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		_, err = dec.Token()
		return err
	case reflect.Slice:
		if token != json.Delim('[') {
			return fmt.Errorf("expected recovery array")
		}
		for dec.More() {
			if err := checkRecoveryValue(dec, typ.Elem()); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case reflect.String:
		if _, ok := token.(string); !ok {
			return fmt.Errorf("expected recovery string")
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return fmt.Errorf("expected recovery boolean")
		}
	default:
		return fmt.Errorf("unsupported recovery type %s", typ)
	}
	return nil
}

func validDigest(value string, sizes ...int) bool {
	for _, size := range sizes {
		if len(value) == size {
			_, err := hex.DecodeString(value)
			return err == nil && value == strings.ToLower(value)
		}
	}
	return false
}

// A State from the previous update may coexist with a newly written build
// marker. Read it strictly, and distinguish absent from damaged evidence.
func recoveryState(root string) (State, bool, error) {
	var st State
	data, err := os.ReadFile(statePath(root))
	if os.IsNotExist(err) {
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	if err := decodeRecoveryJSON(data, &st); err != nil {
		return st, true, err
	}
	return st, true, validateRecoveryState(st)
}

func validateRecoveryState(st State) error {
	if !validDigest(st.PreviousCommit, 40, 64) || !validDigest(st.UpdatedCommit, 40, 64) {
		return fmt.Errorf("invalid state commits")
	}
	for _, hash := range []string{st.BinarySHA256, st.PreviousBinarySHA256} {
		if hash != "" && !validDigest(hash, 64) {
			return fmt.Errorf("invalid state binary hash")
		}
	}
	if st.PreviousBinaryAbsent && st.BinaryCommit == st.PreviousCommit && st.BinarySHA256 != "" {
		return fmt.Errorf("absent previous binary has a live hash")
	}
	if st.PreviousBinaryAbsent && st.PreviousBinarySHA256 != "" {
		return fmt.Errorf("state contradicts binary absence")
	}
	return nil
}

func validateBuildEvidence(root string, p buildPendingState) error {
	if !validDigest(p.Commit, 40, 64) || (p.PreviousCommit != "" && (!validDigest(p.PreviousCommit, 40, 64) || p.PreviousCommit == p.Commit)) {
		return fmt.Errorf("invalid build commits")
	}
	if p.PreviousBinaryAbsent == (p.PreviousBinarySHA256 != "") {
		return fmt.Errorf("build record must prove previous binary hash or absence")
	}
	if p.PreviousBinarySHA256 != "" && !validDigest(p.PreviousBinarySHA256, 64) {
		return fmt.Errorf("invalid previous binary hash")
	}
	if p.BinarySHA256 != "" && !validDigest(p.BinarySHA256, 64) {
		return fmt.Errorf("invalid built binary hash")
	}
	st, present, err := recoveryState(root)
	if err != nil || !present {
		return err
	}
	if st.BinaryCommit != "" && st.BinaryCommit != st.PreviousCommit && st.BinaryCommit != st.UpdatedCommit {
		return fmt.Errorf("state binary commit is unrelated")
	}
	switch {
	case st.UpdatedCommit == p.Commit:
		if st.PreviousCommit != p.PreviousCommit || st.PreviousBinarySHA256 != p.PreviousBinarySHA256 || st.PreviousBinaryAbsent != p.PreviousBinaryAbsent {
			return fmt.Errorf("build record contradicts rollback state")
		}
		if st.BinaryCommit == p.PreviousCommit && st.BinarySHA256 != p.PreviousBinarySHA256 {
			return fmt.Errorf("pre-build state contradicts previous binary hash")
		}
		if st.BinaryCommit == p.Commit && (p.BinarySHA256 == "" || st.BinarySHA256 != p.BinarySHA256) {
			return fmt.Errorf("completed build lacks matching recovery hash")
		}
	case st.UpdatedCommit == p.PreviousCommit:
		if st.BinaryCommit != st.UpdatedCommit || st.BinarySHA256 == "" || st.BinarySHA256 != p.PreviousBinarySHA256 || p.PreviousBinaryAbsent {
			return fmt.Errorf("previous update does not prove the current binary")
		}
	default:
		return fmt.Errorf("build record belongs to a different update")
	}
	return nil
}

func validateBuildFiles(bin string, p buildPendingState) error {
	if p.Legacy {
		return nil
	} // The legacy path separately proves identity from State/VCS.
	live, err := fileSHA256(bin)
	if err == nil && p.BinarySHA256 != "" && live == p.BinarySHA256 {
		if !p.PreviousBinaryAbsent {
			previous, e := fileSHA256(bin + ".prev")
			if e != nil || previous != p.PreviousBinarySHA256 {
				return fmt.Errorf("completed swap has no matching rollback binary")
			}
		}
		return nil
	}
	if p.PreviousBinaryAbsent {
		if !os.IsNotExist(err) {
			return fmt.Errorf("binary exists despite recorded absence")
		}
		return nil
	}
	if err == nil && live == p.PreviousBinarySHA256 {
		return nil
	}
	// installBinary can crash between moving live to .prev and installing staged.
	if os.IsNotExist(err) && p.BinarySHA256 != "" {
		previous, e := fileSHA256(bin + ".prev")
		if e == nil && previous == p.PreviousBinarySHA256 {
			return nil
		}
	}
	return fmt.Errorf("live binary does not match build recovery evidence")
}

func validateRollbackEvidence(root string, p rollbackPendingState) error {
	st := p.State
	if err := validateRecoveryState(st); err != nil {
		return err
	}
	if !validDigest(st.PreviousCommit, 40, 64) || !validDigest(st.UpdatedCommit, 40, 64) || st.PreviousCommit == st.UpdatedCommit {
		return fmt.Errorf("invalid rollback commits")
	}
	if p.LiveSHA256 != "" && !validDigest(p.LiveSHA256, 64) {
		return fmt.Errorf("invalid live hash")
	}
	if p.RestoreBinary {
		if !validDigest(p.LiveSHA256, 64) || !validDigest(p.PreviousSHA256, 64) || st.PreviousBinaryAbsent {
			return fmt.Errorf("rollback lacks binary evidence")
		}
		if st.BinaryCommit != "" && st.BinaryCommit != st.UpdatedCommit {
			return fmt.Errorf("rollback binary decision contradicts state")
		}
		if st.PreviousBinarySHA256 != "" && p.PreviousSHA256 != st.PreviousBinarySHA256 {
			return fmt.Errorf("rollback previous hash contradicts state")
		}
	} else {
		if st.PreviousBinaryAbsent && p.LiveSHA256 != "" {
			return fmt.Errorf("rollback absence contradicts live hash")
		}
		if p.LiveSHA256 == "" && !st.PreviousBinaryAbsent {
			return fmt.Errorf("rollback lacks unchanged binary evidence")
		}
		if p.PreviousSHA256 != "" || st.BinaryCommit != st.PreviousCommit {
			return fmt.Errorf("rollback cannot skip binary restoration")
		}
	}
	if st.BinarySHA256 != "" && p.LiveSHA256 != st.BinarySHA256 {
		return fmt.Errorf("rollback live hash contradicts state")
	}
	disk, present, err := recoveryState(root)
	if err != nil {
		return err
	}
	if present && disk != st {
		return fmt.Errorf("rollback journal contradicts persisted state")
	}
	return nil
}
