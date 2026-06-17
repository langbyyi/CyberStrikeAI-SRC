//go:build windows

package security

import "os/exec"

func prepareShellCmdSession(cmd *exec.Cmd) error {
	_ = cmd
	return nil
}

func terminateCmdTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
