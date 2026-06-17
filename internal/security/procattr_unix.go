//go:build !windows

package security

import (
	"os/exec"
	"syscall"
)

// prepareShellCmdSession 让 shell 子进程在独立会话中运行，便于超时/取消时整组 SIGKILL（含子进程）。
func prepareShellCmdSession(cmd *exec.Cmd) error {
	if cmd == nil {
		return nil
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	return nil
}

// terminateCmdTree 尽力终止 cmd 及其进程组（Unix 下 Setsid 后 PGID == 首进程 PID）。
func terminateCmdTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
