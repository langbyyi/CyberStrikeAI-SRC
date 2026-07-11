package multiagent

import (
	"strings"
	"testing"
)

func TestNormalizeCoverageTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, wantSub string
		noPort      string
	}{
		{"https://Example.COM:443/path", "example.com/path", "443"},
		{"http://Host.Test:80/a", "host.test/a", "80"},
		{"https://x.example.com:8443/p", "x.example.com:8443/p", ""},
		{"HTTPS://API.Example/v1", "api.example/v1", ""},
	}
	for _, tc := range cases {
		got := NormalizeCoverageTarget(tc.in)
		if !strings.Contains(got, strings.Split(tc.wantSub, "/")[0]) {
			t.Fatalf("NormalizeCoverageTarget(%q)=%q want host from %q", tc.in, got, tc.wantSub)
		}
		if tc.noPort != "" && strings.Contains(got, ":"+tc.noPort) {
			t.Fatalf("default port %s should be stripped: %q", tc.noPort, got)
		}
		if got != strings.ToLower(got) && strings.Contains(got, "example") {
			// host portion lowercased
			if strings.Contains(got, "Example") || strings.Contains(got, "HOST") {
				t.Fatalf("host should be lower: %q", got)
			}
		}
	}
}

func TestEstimateCoveragePriorityTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		vt, sev, want string
	}{
		{"sqli", "high", "P0"},
		{"SQL Injection", "critical", "P0"},
		{"rce", "", "P0"},
		{"auth bypass", "medium", "P0"}, // type elevates
		{"idor", "medium", "P2"},
		{"xss", "low", "P1"},
		{"info disclosure", "info", "P3"},
		{"missing headers", "low", "P2"},
		{"something", "medium", "P1"},
	}
	for _, tc := range cases {
		got := EstimateCoveragePriorityFromVuln(tc.vt, tc.sev)
		if got != tc.want {
			t.Fatalf("Estimate(%q,%q)=%s want %s", tc.vt, tc.sev, got, tc.want)
		}
	}
}

func TestCoveragePathFromCandidate_Normalized(t *testing.T) {
	t.Parallel()
	p := CoveragePathFromCandidate("https://Shop.Example:443/item", "id", "sqli", "")
	if !strings.Contains(p, "param:id") && !strings.Contains(p, "id") {
		t.Fatalf("param missing: %s", p)
	}
	// normalized host fragment should appear (lower, no :443)
	if strings.Contains(p, "443") {
		t.Fatalf("default port should not appear in path key: %s", p)
	}
	if !strings.Contains(strings.ToLower(p), "shop.example") && !strings.Contains(p, "shop_example") {
		t.Fatalf("normalized host expected in path: %s", p)
	}
}

func TestAutoUpsertAndPriorityRules(t *testing.T) {
	t.Parallel()
	conv := "test-auto-upsert-rules"
	ResetConversationExecutionStateForTest(conv)
	item := AutoUpsertCoverageFromCandidate(conv, "https://t.example/a", "token", "jwt", "", "medium", "alg none")
	if item.Status != "open" {
		t.Fatalf("status=%s", item.Status)
	}
	if item.Priority != "P1" {
		t.Fatalf("jwt medium → P1, got %s", item.Priority)
	}
	items := GetConversationExecutionState(conv).ListCoverage()
	if len(items) != 1 {
		t.Fatalf("count=%d", len(items))
	}
}
