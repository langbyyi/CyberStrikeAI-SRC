package update

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateFilePath refuses directory/file and symlink conflicts before git can
// remove an untracked directory or backups can follow a link outside the install.
func validateFilePath(root, rel string) error {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	path := root
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return &Error{Reason: "content_path_conflict", Message: "文件路径不合法：" + rel}
		}
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		leaf := i == len(parts)-1
		if (leaf && !info.Mode().IsRegular()) || (!leaf && !info.IsDir()) {
			return &Error{Reason: "content_path_conflict", Message: fmt.Sprintf("%s 存在符号链接或目录/文件冲突，已保留本地内容，请先人工处理", rel), Items: []string{rel}}
		}
	}
	return nil
}
