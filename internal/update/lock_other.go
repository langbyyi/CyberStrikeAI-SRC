//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package update

import (
	"fmt"
	"os"
)

func lockFile(f *os.File) error {
	return fmt.Errorf("installation locking is unavailable on this platform")
}
