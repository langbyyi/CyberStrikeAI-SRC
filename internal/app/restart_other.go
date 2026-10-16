//go:build !linux

package app

import "os"

// restartInto keeps the contract every non-Linux platform had: stand down, and let the thing
// that started this process start the new binary. Windows has no exec at all, and the service
// managers there are what bring a process back; a process that replaced itself would be the
// odd one out. binary is accepted so the caller reads the same on every platform.
func restartInto(shutdown func(), binary string) {
	shutdown()
	os.Exit(0)
}
