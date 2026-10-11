package update

import (
	"os"
	"path/filepath"
	"time"
)

// BinaryStamp identifies the executable on disk: a rebuild, a rename-swap from an update,
// or a rollback that puts the previous build back all change it. Size plus nanosecond
// mtime is enough to tell two builds apart, and it costs one stat() on a request path -
// hashing the file would not.
type BinaryStamp struct {
	Exists  bool      `json:"exists"`
	Size    int64     `json:"size,omitempty"`
	ModTime time.Time `json:"modTime,omitempty"`
}

// StampBinary reads the install's binary as it is on disk right now. A missing file is a
// legitimate stamp rather than an error: a source checkout has no binary until the first
// update builds one.
func StampBinary(root string, opts Options) BinaryStamp {
	info, err := os.Stat(filepath.Join(root, opts.binaryName()))
	if err != nil {
		return BinaryStamp{}
	}
	return BinaryStamp{Exists: true, Size: info.Size(), ModTime: info.ModTime()}
}

// Same reports whether two stamps describe the same file. The comparison is deliberately
// stricter than "the disk file is newer": a rollback moves an older build back into place,
// and the process running the newer one still has to restart for the rollback to be real.
func (s BinaryStamp) Same(other BinaryStamp) bool {
	if s.Exists != other.Exists {
		return false
	}
	if !s.Exists {
		return true
	}
	return s.Size == other.Size && s.ModTime.Equal(other.ModTime)
}
