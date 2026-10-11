//go:build !windows

package update

import "os"

func replaceBinary(src, dst string) error { return os.Rename(src, dst) }
