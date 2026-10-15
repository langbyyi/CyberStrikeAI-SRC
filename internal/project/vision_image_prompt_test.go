package project

import (
	"strings"
	"testing"
)

func TestAppendVisionImageAnalysisIfReady(t *testing.T) {
	base := "你是安全测试助手。"

	if got := AppendVisionImageAnalysisIfReady(base, false, false); got != base {
		t.Errorf("both off: prompt should be unchanged, got %q", got)
	}

	toolOnly := AppendVisionImageAnalysisIfReady(base, true, false)
	if !strings.Contains(toolOnly, VisionImageSectionMarker) {
		t.Errorf("tool-only prompt should carry %q", VisionImageSectionMarker)
	}
	if !strings.Contains(toolOnly, "analyze_image") {
		t.Error("tool-only prompt should mention analyze_image")
	}

	native := AppendVisionImageAnalysisIfReady(base, true, true)
	if !strings.Contains(native, NativeImageInputSectionMarker) {
		t.Errorf("native prompt should carry %q", NativeImageInputSectionMarker)
	}
	if strings.Contains(native, VisionImageSectionMarker) {
		t.Error("native prompt should not claim images are unreadable")
	}
	if !strings.Contains(native, "read_file") {
		t.Error("native prompt should route on-disk images through read_file")
	}
	if strings.Contains(native, "analyze_image") {
		t.Error("native prompt must not route images through the out-of-band analyze_image tool")
	}
	if !strings.Contains(native, "看不到图片") {
		t.Error("native prompt should explicitly forbid the 'cannot see images' answer")
	}

	// 原生视觉与旁路工具同时可用时，仍以原生为主（工具仅供纯文本通道）
	if !strings.Contains(toolOnly, "analyze_image") {
		t.Error("text-only prompt should keep analyze_image as the fallback")
	}
	if strings.Contains(toolOnly, NativeImageInputSectionMarker) {
		t.Error("text-only prompt must not claim native image input")
	}
}
