package update

import (
	"cyberstrike-ai/internal/config"
	"fmt"
	"path/filepath"
)

// The release version travels with the code: config.example.yaml ships in the repository
// and upstream bumps its version field in the release commit, but the live config.yaml is
// the operator's file and no merge ever touches it. So without the steps below an updated
// installation keeps showing the version it was born with - the header badge and the
// static-asset cache buster would both say v-old while the tree runs v-new. The fix is
// deliberately small: read the version the new code carries, write it into the live
// config's version line (byte-for-byte otherwise untouched, atomic rename), and let a
// rollback put the old number back with the old code.

// liveConfigFile names the operator's configuration inside an install tree: the
// conventional config.yaml, then config.yml. Empty when neither exists (a source
// checkout, where there is nothing to sync).
func liveConfigFile(root string) string {
	for _, name := range []string{"config.yaml", "config.yml"} {
		path := filepath.Join(root, name)
		if fileExists(path) {
			return path
		}
	}
	return ""
}

// installVersion is the release version the code sitting in root carries, read from the
// shipped config.example.yaml; empty when the tree does not say.
func installVersion(root string) string {
	version, err := config.FileVersion(filepath.Join(root, "config.example.yaml"))
	if err != nil {
		return ""
	}
	return version
}

// syncVersionToConfig writes the code's release version into the live configuration and
// returns (before, after, error) - both empty when there was nothing to do. A tree
// without a live config, or without a shipped version, is left alone; a current value
// that already matches is not rewritten.
func syncVersionToConfig(root string) (before, after string, err error) {
	path := liveConfigFile(root)
	if path == "" {
		return "", "", nil
	}
	target := installVersion(root)
	if target == "" {
		return "", "", nil
	}
	current, err := config.FileVersion(path)
	if err != nil {
		return "", "", err
	}
	if current == target {
		return "", "", nil
	}
	changed, err := config.WriteVersion(path, target)
	if err != nil {
		return current, "", err
	}
	if !changed {
		return "", "", nil
	}
	return current, target, nil
}

// plannedVersionChange reports the change a sync is about to make, before it makes it: the
// live config's current number and the one the code on disk carries. Empty when there is
// nothing to do. An update records this in its pending marker *before* writing the config,
// so a crash between the two still leaves a rollback that can put the old number back.
func plannedVersionChange(root string) (before, after string) {
	path := liveConfigFile(root)
	if path == "" {
		return "", ""
	}
	target := installVersion(root)
	if target == "" {
		return "", ""
	}
	current, err := config.FileVersion(path)
	if err != nil || current == target {
		return "", ""
	}
	return current, target
}

// versionStep renders the sync outcome as one progress line; no lines for "nothing to
// do", a warning when the write failed (the update itself still stands).
func versionStep(step func(string, string), before, after string, err error) {
	if err != nil {
		step("version", "版本号写入 config.yaml 失败（不影响本次更新）："+err.Error())
		return
	}
	if after == "" {
		return
	}
	if before == "" {
		step("version", fmt.Sprintf("版本号随新代码写入 config.yaml：%s（重启后页头生效）", after))
		return
	}
	step("version", fmt.Sprintf("版本号已随新代码更新：%s → %s（config.yaml，重启后页头生效）", before, after))
}

// restoreVersionAfterRollback puts the old number back with the old code - but only while
// the live config still carries exactly what the update wrote: a version someone edited by
// hand after the update belongs to them, not to the rollback.
func restoreVersionAfterRollback(root string, st State) error {
	if st.VersionAfter == "" {
		return nil
	}
	path := liveConfigFile(root)
	if path == "" {
		return nil
	}
	current, err := config.FileVersion(path)
	if err != nil || current != st.VersionAfter {
		return nil
	}
	if st.VersionBefore == "" {
		_, err := config.RemoveVersion(path)
		return err
	}
	_, err = config.WriteVersion(path, st.VersionBefore)
	return err
}
