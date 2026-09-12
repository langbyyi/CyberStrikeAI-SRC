package termout

import (
	"strings"
	"testing"
)

func TestDisplayWidthEmoji(t *testing.T) {
	if got := displayWidth("🚀"); got != 2 {
		t.Fatalf("displayWidth(emoji) = %d, want 2", got)
	}
	if got := displayWidth("ab"); got != 2 {
		t.Fatalf("displayWidth(ab) = %d, want 2", got)
	}
}

func TestDisplayWidthIgnoresANSI(t *testing.T) {
	s := New(nil)
	colored := s.Bold("admin")
	if got := displayWidth(colored); got != 5 {
		t.Fatalf("displayWidth colored = %d, want 5", got)
	}
}

func TestPadRightDisplay(t *testing.T) {
	got := padRightDisplay("pwd", 10)
	if displayWidth(got) != 10 {
		t.Fatalf("padded width = %d, want 10", displayWidth(got))
	}
}

func TestColorDisabledWithoutTTY(t *testing.T) {
	s := New(nil)
	if s.enabled {
		t.Fatal("expected colors disabled for nil writer")
	}
	if got := s.Cyan("x"); got != "x" {
		t.Fatalf("Cyan without TTY = %q, want plain text", got)
	}
}

func TestPrintBootstrapAdminCredentialsEmpty(t *testing.T) {
	PrintBootstrapAdminCredentials("   ")
}

func TestPrintStartupWebUIOptions(t *testing.T) {
	PrintStartupWebUI(StartupWebUIOptions{
		Scheme:       "https",
		Host:         "127.0.0.1",
		Port:         8080,
		SelfSigned:   true,
		HTTPRedirect: true,
	})
}

func TestBoxRowAlignedWidth(t *testing.T) {
	s := New(nil)
	rows := []string{
		s.Bold("CyberStrikeAI") + s.White(" is ready"),
		s.Dim("Web UI   ") + s.Bold("https://127.0.0.1:8080/"),
	}
	inner := maxDisplayWidth(rows...)
	for _, row := range rows {
		line := s.boxRow(inner, row)
		if !strings.Contains(line, "│") {
			t.Fatalf("box row missing border: %q", line)
		}
	}
}

func TestMaxDisplayWidth(t *testing.T) {
	short := "abc"
	long := "https://127.0.0.1:8080/"
	if got := maxDisplayWidth(short, long); got != displayWidth(long) {
		t.Fatalf("maxDisplayWidth = %d, want %d", got, displayWidth(long))
	}
}

// TestBannerHosts 验证启动 banner 的地址选择：
// 绑定具体 host 只显示该地址；全接口监听列出非环回 IPv4 并始终包含 127.0.0.1。
func TestBannerHosts(t *testing.T) {
	if got := bannerHosts("127.0.0.1"); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("绑定具体 host 应仅显示该地址: %v", got)
	}
	if got := bannerHosts("192.168.1.10"); len(got) != 1 || got[0] != "192.168.1.10" {
		t.Errorf("绑定具体 host 应仅显示该地址: %v", got)
	}

	for _, wildcard := range []string{"", "0.0.0.0", "::"} {
		got := bannerHosts(wildcard)
		if len(got) == 0 {
			t.Fatalf("全接口监听(%q)不应返回空列表", wildcard)
		}
		if got[len(got)-1] != "127.0.0.1" {
			t.Errorf("全接口监听(%q)应包含 127.0.0.1 兜底: %v", wildcard, got)
		}
		for _, h := range got {
			if h != "127.0.0.1" && strings.Contains(h, ":") {
				t.Errorf("banner 不应包含 IPv6/异常地址: %q in %v", h, got)
			}
		}
	}
}

// TestHostForURL 验证裸 IPv6 地址补方括号，IPv4 与已带方括号的地址原样返回。
func TestHostForURL(t *testing.T) {
	cases := map[string]string{
		"::1":          "[::1]",
		"fe80::1":      "[fe80::1]",
		"[::1]":        "[::1]",
		"127.0.0.1":    "127.0.0.1",
		"example.test": "example.test",
	}
	for in, want := range cases {
		if got := hostForURL(in); got != want {
			t.Errorf("hostForURL(%q) = %q, want %q", in, got, want)
		}
	}
}
