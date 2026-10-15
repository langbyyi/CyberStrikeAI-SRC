package vision

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"testing"

	"github.com/disintegration/imaging"
)

// decodeNativeImageForTest 断言 base64 载荷可还原为可解码图片。
func decodeNativeImageForTest(b64 string) (image.Config, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return image.Config{}, err
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return image.Config{}, err
	}
	return cfg, nil
}

func writeTestImage(t *testing.T, dir, name string, w, h int, format imaging.Format) string {
	t.Helper()
	img := imaging.New(w, h, color.RGBA{R: 20, G: 40, B: 60, A: 255})
	path := filepath.Join(dir, name)
	if err := imaging.Save(img, path, imaging.JPEGQuality(95)); err != nil {
		if format == imaging.PNG {
			if err := imaging.Save(img, path); err != nil {
				t.Fatalf("save test image: %v", err)
			}
		} else {
			t.Fatalf("save test image: %v", err)
		}
	}
	return path
}

func TestIsImagePath(t *testing.T) {
	cases := map[string]bool{
		"/tmp/a.png":          true,
		"/tmp/a.JPEG":         true,
		"/tmp/a.webp":         true,
		"/tmp/a.txt":          false,
		"/tmp/a":              false,
		"":                    false,
		"/tmp/screenshot.PNG": true,
		"/tmp/report.pdf":     false,
	}
	for in, want := range cases {
		if got := IsImagePath(in); got != want {
			t.Errorf("IsImagePath(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFilterImagePaths(t *testing.T) {
	dir := t.TempDir()
	png := writeTestImage(t, dir, "a.png", 20, 20, imaging.PNG)
	jpg := writeTestImage(t, dir, "b.jpg", 20, 20, imaging.JPEG)
	txt := filepath.Join(dir, "c.txt")
	if err := os.WriteFile(txt, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := FilterImagePaths([]string{png, "", "  ", txt, jpg, png}, 0)
	if len(got) != 2 {
		t.Fatalf("want 2 images (dedup + filter), got %d: %v", len(got), got)
	}
	if got := FilterImagePaths([]string{png, jpg}, 1); len(got) != 1 {
		t.Fatalf("max=1 should cap, got %v", got)
	}
}

func TestPrepareNativeImagePassthrough(t *testing.T) {
	dir := t.TempDir()
	png := writeTestImage(t, dir, "small.png", 120, 60, imaging.PNG)
	st, err := os.Stat(png)
	if err != nil {
		t.Fatal(err)
	}
	img, err := PrepareNativeImage(png)
	if err != nil {
		t.Fatalf("PrepareNativeImage: %v", err)
	}
	if img.MIMEType != "image/png" {
		t.Errorf("mime = %q, want image/png", img.MIMEType)
	}
	if img.Width != 120 || img.Height != 60 {
		t.Errorf("size = %dx%d, want 120x60", img.Width, img.Height)
	}
	if int64(img.Bytes) != st.Size() {
		t.Errorf("bytes = %d, want original %d (passthrough)", img.Bytes, st.Size())
	}
	cfg, err := decodeNativeImageForTest(img.Base64)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if cfg.Width != 120 || cfg.Height != 60 {
		t.Errorf("decoded size = %dx%d", cfg.Width, cfg.Height)
	}
}

func TestPrepareNativeImageDownscalesOversized(t *testing.T) {
	dir := t.TempDir()
	big := writeTestImage(t, dir, "big.jpg", 3000, 1000, imaging.JPEG)
	img, err := PrepareNativeImage(big)
	if err != nil {
		t.Fatalf("PrepareNativeImage: %v", err)
	}
	if img.MIMEType != "image/jpeg" {
		t.Errorf("mime = %q, want image/jpeg", img.MIMEType)
	}
	long := img.Width
	if img.Height > long {
		long = img.Height
	}
	if long != nativeMaxDimension {
		t.Errorf("long edge = %d, want %d", long, nativeMaxDimension)
	}
	if img.Bytes > nativeMaxBytes {
		t.Errorf("bytes = %d, want <= %d", img.Bytes, nativeMaxBytes)
	}
	cfg, err := decodeNativeImageForTest(img.Base64)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if cfg.Width != img.Width || cfg.Height != img.Height {
		t.Errorf("decoded %dx%d != reported %dx%d", cfg.Width, cfg.Height, img.Width, img.Height)
	}
}

func TestPrepareNativeImageRejectsNonImage(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(txt, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareNativeImage(txt); err == nil {
		t.Fatal("want error for non-image extension")
	}
	if _, err := PrepareNativeImage(filepath.Join(dir, "missing.png")); err == nil {
		t.Fatal("want error for missing file")
	}
}
