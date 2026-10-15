package vision

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/disintegration/imaging"
)

// NativeImage 是多模态主模型可直接消费的图片载荷（base64 + MIME）。
//
// 与 ImagePayload 的区别：ImagePayload 供旁路 VL 模型单次识图（强压缩，≤512KB、detail 可 low）；
// NativeImage 供主模型原生读图，保留更高分辨率与质量，只做必要的上限裁剪。
type NativeImage struct {
	Path     string
	Base64   string
	MIMEType string
	Detail   string
	Width    int
	Height   int
	Bytes    int
}

const (
	// nativeMaxDimension 长边上限：Anthropic 标准档 1568px，OpenAI 也按此量级缩放，
	// 超过则本地预缩放，避免上游再缩放带来的二次失真与不可控计费。
	nativeMaxDimension = 1568
	// nativeMaxBytes 单图 base64 前的原始字节上限，超过则重编码。
	nativeMaxBytes = 4 << 20
	// nativeJPEGQuality 重编码质量：高于旁路的 82，保证截图文字可读。
	nativeJPEGQuality = 88
	// NativeMaxImages 单轮送入主模型的图片数量上限（与 handler 的附件上限对齐）。
	NativeMaxImages = 10
	// NativeMaxTotalBytes 单轮送入主模型的图片总字节预算（base64 前），超出部分退回流路径。
	NativeMaxTotalBytes = 12 << 20
	// NativeImageTokenEstimate 单图 token 估算（保守值，用于上下文预算与日志估算）。
	// 视觉 token 按 ⌈宽/28⌉×⌈高/28⌉ 计费；本仓库把长边压到 nativeMaxDimension 以内，
	// 标准档长边 1568px 约 1568 token，高分辨率档约 4784，取 1600 作为保守估值。
	NativeImageTokenEstimate = 1600
	// NativeDetailDefault detail 默认值；由提供商决定实际缩放策略。
	NativeDetailDefault = "auto"
)

// IsImagePath 判断路径是否为可送入模型的图片（按扩展名，不读文件）。
func IsImagePath(path string) bool {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(path)))
	_, ok := allowedImageExt[ext]
	return ok
}

// FilterImagePaths 过滤出图片路径并去重，最多 max 张（max<=0 时取 NativeMaxImages）。
func FilterImagePaths(paths []string, max int) []string {
	if max <= 0 {
		max = NativeMaxImages
	}
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || !IsImagePath(p) {
			continue
		}
		abs, err := filepath.Abs(filepath.Clean(p))
		if err != nil {
			continue
		}
		if _, dup := seen[abs]; dup {
			continue
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
		if len(out) >= max {
			break
		}
	}
	return out
}

// PrepareNativeImage 读取图片并编码为 base64；仅在超出长边/体积上限时缩放重编码。
// 失败返回错误，由调用方决定降级（例如退回「只给路径」的旧行为）。
func PrepareNativeImage(path string) (NativeImage, error) {
	abs, err := filepath.Abs(filepath.Clean(strings.TrimSpace(path)))
	if err != nil {
		return NativeImage{}, fmt.Errorf("resolve image path: %w", err)
	}
	if !IsImagePath(abs) {
		return NativeImage{}, fmt.Errorf("unsupported image extension %q", filepath.Ext(abs))
	}
	st, err := os.Stat(abs)
	if err != nil {
		return NativeImage{}, fmt.Errorf("stat image: %w", err)
	}
	if st.IsDir() {
		return NativeImage{}, fmt.Errorf("not a regular file")
	}

	w, h, format, err := imageDimensions(abs)
	if err != nil {
		return NativeImage{}, err
	}
	longEdge := w
	if h > longEdge {
		longEdge = h
	}
	mime := mimeFromImageFormat(format)

	// 尺寸与体积都在限内、且 MIME 可识别：原图直传，避免无谓重编码。
	if longEdge <= nativeMaxDimension && st.Size() <= nativeMaxBytes && mime != "" {
		raw, rerr := os.ReadFile(abs)
		if rerr != nil {
			return NativeImage{}, fmt.Errorf("read image: %w", rerr)
		}
		return NativeImage{
			Path:     abs,
			Base64:   base64.StdEncoding.EncodeToString(raw),
			MIMEType: mime,
			Detail:   NativeDetailDefault,
			Width:    w,
			Height:   h,
			Bytes:    len(raw),
		}, nil
	}

	src, err := imaging.Open(abs)
	if err != nil {
		return NativeImage{}, fmt.Errorf("decode image: %w", err)
	}
	dst := imaging.Fit(src, nativeMaxDimension, nativeMaxDimension, imaging.Lanczos)
	quality := nativeJPEGQuality
	for attempt := 0; attempt < 5; attempt++ {
		var buf bytes.Buffer
		if err := imaging.Encode(&buf, dst, imaging.JPEG, imaging.JPEGQuality(quality)); err != nil {
			return NativeImage{}, fmt.Errorf("encode jpeg: %w", err)
		}
		if buf.Len() <= nativeMaxBytes || quality <= 60 {
			b := dst.Bounds()
			return NativeImage{
				Path:     abs,
				Base64:   base64.StdEncoding.EncodeToString(buf.Bytes()),
				MIMEType: "image/jpeg",
				Detail:   NativeDetailDefault,
				Width:    b.Dx(),
				Height:   b.Dy(),
				Bytes:    buf.Len(),
			}, nil
		}
		quality -= 8
	}
	return NativeImage{}, fmt.Errorf("could not encode image %s under %d bytes", abs, nativeMaxBytes)
}
