package network

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetAndScope(t *testing.T) {
	scope := Scope{Targets: []string{"example.test", "*.example.test", "10.20.0.0/16", "2001:db8::/32"}, Exclude: []string{"blocked.example.test"}}
	for _, tc := range []struct {
		target string
		want   bool
	}{
		{"https://api.example.test/v1", true}, {"example.test", true}, {"10.20.1.2:8080", true},
		{"[2001:db8::1]:443", true}, {"blocked.example.test", false}, {"badexample.test", false},
		{"api.example.test.evil.test", false}, {"10.21.1.2", false},
	} {
		t.Run(tc.target, func(t *testing.T) {
			target, err := ParseTarget(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			if got := scope.Contains(target); got != tc.want {
				t.Fatalf("contains=%v want %v", got, tc.want)
			}
		})
	}
	for _, input := range []string{"", "*.example.test", "http://user:pass@example.test", "http://example.test\nother", "file:///etc/passwd"} {
		if _, err := ParseTarget(input); err == nil {
			t.Fatalf("accepted invalid target %q", input)
		}
	}
	target, _ := ParseTarget("example.test")
	if (Scope{Targets: []string{"*.example.test"}}).Contains(target) {
		t.Fatal("wildcard included apex")
	}
}

func TestFailedMutationRestoresFreshState(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.root = filepath.Join(s.root, "missing", "directory")
	if _, err = s.AddProxy("http://127.0.0.1:8080", "manual"); err == nil {
		t.Fatal("expected persistence failure")
	}
	if len(s.Nodes()) != 0 || len(s.state.Credentials) != 0 {
		t.Fatal("failed proxy write remained active in memory")
	}
	if _, err = s.SavePolicy("p", Policy{Mode: "auto"}, 0); err == nil {
		t.Fatal("expected policy persistence failure")
	}
	if s.Policy("p").Version != 0 {
		t.Fatal("failed policy write remained active")
	}
}

func TestEncryptedStoreAndRedaction(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n, err := s.AddProxy("socks5://user:synthetic-secret@127.0.0.1:1080", "manual")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(n)
	if strings.Contains(string(b), "synthetic-secret") || strings.Contains(string(b), "user:") {
		t.Fatal("credential exposed in node")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "synthetic-secret") || strings.Contains(string(raw), "127.0.0.1") {
		t.Fatal("state is not encrypted")
	}
	reloaded, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if len(reloaded.Nodes()) != 1 || reloaded.Nodes()[0].ID != n.ID {
		t.Fatal("node did not persist")
	}
	if _, err = s.AddProxy("http://127.0.0.1:99999", "manual"); err == nil {
		t.Fatal("accepted invalid port")
	}
}

func TestProjectProxyNeverEntersGlobalPool(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	node, err := s.AddProjectProxy("p1", "socks5://fixture:synthetic-password@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes()) != 0 {
		t.Fatal("project-assigned proxy leaked into global pool")
	}
	if _, err = s.ProjectProxy("p2", node.ID); err == nil {
		t.Fatal("other project accessed assigned node")
	}
}

func TestBindingsAreAutomaticButUserExclusionWins(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	scope := Scope{Targets: []string{"*.example.test"}}
	p, err := s.SavePolicy("p1", Policy{Mode: "fixed_proxy", ProxyID: "assigned", Targets: scope.Targets}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 {
		t.Fatal("missing policy version")
	}
	if _, err = s.SavePolicy("p1", p, 0); err == nil {
		t.Fatal("stale policy update accepted")
	}
	if _, err = s.BindAsset(context.Background(), "p1", "https://api.example.test", "observed API request from https://www.example.test", false, "agent", scope); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BindAsset(context.Background(), "p1", "https://api.example.test", "user exclusion", true, "user", scope); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BindAsset(context.Background(), "p1", "https://api.example.test", "observed again", false, "agent", scope); err == nil {
		t.Fatal("agent overrode user exclusion")
	}
	if _, err = s.BindAsset(context.Background(), "p1", "https://third-party.test", "page link", false, "agent", scope); err == nil {
		t.Fatal("out-of-scope asset was enrolled")
	}
	if len(s.Bindings("p2")) != 0 {
		t.Fatal("bindings leaked between projects")
	}
}
