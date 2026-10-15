package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// imageContentSpillDir 外部 MCP 工具返回图片内容时的落盘目录（相对进程工作目录）。
	// 图片不进模型上下文；工具结果里只留路径，主模型支持图片输入时可直接读该路径，
	// 否则由 analyze_image 旁路识图。
	imageContentSpillDir = "tmp/mcp-images"
	// imageContentMaxBytes 单张图片落盘上限，超过则不落盘、只回报元信息。
	imageContentMaxBytes = 15 << 20
	// imageContentRetention 落盘图片保留期：仅派生缓存，过期即清（无需配置项）。
	imageContentRetention = 7 * 24 * time.Hour
)

var imageContentExtByMIME = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
	"image/jpg":  ".jpg",
	"image/gif":  ".gif",
	"image/webp": ".webp",
	"image/bmp":  ".bmp",
	"image/tiff": ".tiff",
}

// spillImageContent 把 MCP 图片内容落盘，返回给模型的文本提示。
// 返回 ok=false 表示未落盘（数据为空或超出上限），调用方应回退为占位文本。
func spillImageContent(data []byte, mimeType string) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	mime := strings.ToLower(strings.TrimSpace(mimeType))
	if i := strings.Index(mime, ";"); i >= 0 {
		mime = strings.TrimSpace(mime[:i])
	}
	ext := imageContentExtByMIME[mime]
	if ext == "" {
		ext = ".png"
	}
	if len(data) > imageContentMaxBytes {
		return fmt.Sprintf("[MCP 图片内容未落盘：%s %dKB 超出单图上限 %dKB]",
			mimeOrDefault(mime), len(data)/1024, imageContentMaxBytes/1024), false
	}

	root := imageContentSpillDir
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Sprintf("[MCP 图片内容未落盘：创建目录失败 %v]", err), false
	}
	pruneImageSpillDir(root)

	name := fmt.Sprintf("%s_%s%s", time.Now().Format("20060102_150405"), randomHex(6), ext)
	abs, err := filepath.Abs(filepath.Join(root, name))
	if err != nil {
		return fmt.Sprintf("[MCP 图片内容未落盘：解析路径失败 %v]", err), false
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return fmt.Sprintf("[MCP 图片内容未落盘：写入失败 %v]", err), false
	}
	return fmt.Sprintf("[MCP 返回的图片已保存到服务器: %s (%s, %dKB)。主模型支持图片输入时用 read_file 读取该路径即可看图；否则用 analyze_image 工具识图]",
		abs, mimeOrDefault(mime), len(data)/1024), true
}

// pruneImageSpillDir 清掉超过保留期的落盘图片；失败只忽略（纯派生缓存）。
func pruneImageSpillDir(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-imageContentRetention)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(root, e.Name()))
	}
}

func mimeOrDefault(mime string) string {
	if mime == "" {
		return "image/unknown"
	}
	return mime
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
