//go:build linux

package app

import (
	"fmt"
	"os"
	"syscall"
)

// restartInto runs the graceful shutdown and then replaces this process image with binary.
//
// On Linux an update can finish itself. exec keeps the same PID, so a service manager sees no
// exit at all and its Restart= policy never enters the picture - which matters because the
// alternative - exit(0) and hope a supervisor starts the process again - is only a restart
// where the unit says Restart=always. Under the Restart=on-failure this project's own
// deployment guide recommends, a successful update's clean exit is a service that stays down
// until somebody notices.
//
// binary comes from update.InstallBinaryPath rather than os.Executable: an update renames the
// running file aside to .prev before putting the new build in its place, so this process's own
// path is the old binary by now.
//
// It does not return. When exec itself fails there is nothing left to become the new binary
// with, so the older contract is the fallback - stand down - and a non-zero status is what
// makes an on-failure unit actually honour it.
func restartInto(shutdown func(), binary string) {
	shutdown()
	if err := syscall.Exec(binary, append([]string{binary}, os.Args[1:]...), os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "自动重启失败（%v）：退回由外部守护拉起新二进制\n", err)
		os.Exit(1)
	}
}
