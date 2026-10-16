package update

import (
	"os"
	"path/filepath"
)

// LockInstall serializes CLI and HTTP operations on the same installation. The
// file stays in place: removing it would let another process lock a new inode.
// Kernel locks are released on exit, including a crash or SIGKILL.
func LockInstall(opts Options) (func(), error) {
	root, err := opts.installRoot()
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil, &Error{Reason: "bad_root", Message: "安装目录不存在或不是目录：" + root}
	}
	f, err := os.OpenFile(filepath.Join(root, ".update-lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, &Error{Reason: "lock_failed", Message: "无法锁定安装目录：" + err.Error()}
	}
	if err := lockFile(f); err != nil {
		f.Close()
		// The holder is usually another check that is still on the network, not a stuck
		// lock: saying how long that can take is the difference between "wait a moment"
		// and "this installation can never be updated again".
		return nil, &Error{Reason: "update_busy", Message: "此安装目录已有更新、检查或回滚正在执行（联网那一步最长 " +
			timeoutLabel() + "），等它结束后再点一次即可"}
	}
	return func() { f.Close() }, nil
}
