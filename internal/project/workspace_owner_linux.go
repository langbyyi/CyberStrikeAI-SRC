//go:build linux

package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func setWorkspaceOwner(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uidText, gidText := os.Getenv("CYBERSTRIKE_NETWORK_UID"), os.Getenv("CYBERSTRIKE_NETWORK_GID")
	if uidText == "" {
		uidText = os.Getenv("SUDO_UID")
	}
	if gidText == "" {
		gidText = os.Getenv("SUDO_GID")
	}
	if uidText == "" && gidText == "" {
		return nil
	}
	uid, uidErr := strconv.Atoi(uidText)
	gid, gidErr := strconv.Atoi(gidText)
	if uidErr != nil || gidErr != nil || uid <= 0 || gid < 0 || uint64(uid) >= 1<<32-1 || uint64(gid) >= 1<<32-1 {
		return fmt.Errorf("workspace ownership requires a valid non-root network UID and GID")
	}
	if !filepath.IsAbs(path) || filepath.Dir(path) == path {
		return fmt.Errorf("refusing workspace ownership for an invalid directory")
	}
	// Walk with pinned directory descriptors; never follow a symlink or change
	// ownership via a path which can be swapped between checking and chown.
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return fmt.Errorf("open workspace filesystem root: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	for _, part := range strings.Split(filepath.Clean(path), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return fmt.Errorf("open workspace directory without symlinks: %w", err)
		}
		_ = unix.Close(fd)
		fd = next
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("assign workspace to isolated user %d:%d: %w", uid, gid, err)
	}
	return nil
}
