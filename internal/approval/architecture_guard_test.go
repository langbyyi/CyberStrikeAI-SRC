package approval

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestGrantForTestingNeverUsedInProduction 是架构守护测试（蓝图 P8）：
// Grant 为 opaque 凭证，NewGrantForTesting 只允许出现在 *_test.go 中。
// 任何生产代码引用（伪造凭证的通道）都会让本测试失败。
func TestGrantForTestingNeverUsedInProduction(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source tree")
	}
	root := filepath.Dir(thisFile) // internal/approval
	pkgRoot := filepath.Dir(root)  // internal

	err := filepath.Walk(pkgRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// 跳过第三方/生成目录（如存在）
			name := info.Name()
			if name == "vendor" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for lineNo, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			// 定义点本身（grant.go 的函数声明与文档注释）合法；其余任何引用都
			// 是生产代码伪造凭证的通道。
			if !strings.Contains(trimmed, "NewGrantForTesting") {
				continue
			}
			if strings.HasPrefix(trimmed, "//") || strings.Contains(trimmed, "func NewGrantForTesting(") {
				continue
			}
			t.Errorf("production reference to NewGrantForTesting (grant forgery channel): %s:%d", path, lineNo+1)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestLegacyHITLTableOnlyUsedByMigration prevents retired runtime handlers,
// notification queries, or retention jobs from depending on the legacy table.
func TestLegacyHITLTableOnlyUsedByMigration(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source tree")
	}
	internalRoot := filepath.Dir(filepath.Dir(thisFile))
	allowed := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "migration.go"))

	err := filepath.Walk(internalRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || filepath.Clean(path) == allowed {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(raw), "hitl_interrupts") {
			t.Errorf("legacy HITL table used outside one-time migration: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
