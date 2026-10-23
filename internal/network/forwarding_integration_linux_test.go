//go:build linux

package network

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the service in a disposable router so the real host's FORWARD policy never changes.
func TestLinuxForwardingUnderDefaultDrop(t *testing.T) {
	linuxIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if endpoint := os.Getenv("CYBERSTRIKE_FORWARD_FIXTURE"); endpoint != "" {
		testForwardingChild(t, ctx, endpoint)
		return
	}
	suffix := strings.ReplaceAll(newID(), "-", "")[:10]
	router, hostIf, peerIf := "csf-"+suffix, "csx"+suffix, "csy"+suffix
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = runNetwork(cleanup, "", "ip", "netns", "delete", router)
		_ = runNetwork(cleanup, "", "ip", "link", "delete", hostIf)
	}()
	commands := [][]string{
		{"netns", "add", router},
		{"link", "add", hostIf, "type", "veth", "peer", "name", peerIf},
		{"link", "set", peerIf, "netns", router},
		{"addr", "add", "10.253.242.1/30", "dev", hostIf},
		{"link", "set", hostIf, "up"},
		{"-n", router, "addr", "add", "10.253.242.2/30", "dev", peerIf},
		{"-n", router, "link", "set", peerIf, "up"},
		{"-n", router, "link", "set", "lo", "up"},
		{"-n", router, "route", "add", "default", "via", "10.253.242.1"},
	}
	for _, args := range commands {
		if err := runNetwork(ctx, "", "ip", args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range [][]string{{"sysctl", "-q", "-w", "net.ipv4.ip_forward=1"}, {"iptables", "-P", "FORWARD", "DROP"}} {
		if err := runNetwork(ctx, "", "ip", append([]string{"netns", "exec", router}, command...)...); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp4", "10.253.242.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "forwarding-fixture") }))
	server.Listener = listener
	server.Start()
	defer server.Close()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", router, binary, "-test.run=^TestLinuxForwardingUnderDefaultDrop$", "-test.v")
	cmd.Env = append(os.Environ(), "CYBERSTRIKE_FORWARD_FIXTURE="+listener.Addr().String())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("service behind FORWARD DROP: %v\n%s", err, output)
	}
}

func testForwardingChild(t *testing.T, ctx context.Context, endpoint string) {
	before, err := exec.CommandContext(ctx, "iptables", "-S", "FORWARD").Output()
	if err != nil || !strings.Contains(string(before), "-P FORWARD DROP") {
		t.Fatal("fixture must begin with default DROP")
	}
	makeProject := func(project string) *linuxEnvironment {
		environment, err := newSystemEnvironment(ctx, t.TempDir(), project, Policy{Mode: "fixed_proxy"}, Scope{Targets: []string{"203.0.113.99"}}, Profile{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = environment.Close() })
		return environment.(*linuxEnvironment)
	}
	first, second := makeProject("forward-a"), makeProject("forward-b")
	host, _, _ := net.SplitHostPort(endpoint)
	request := func(e *linuxEnvironment) {
		t.Helper()
		if err := e.baseline(ctx, netip.MustParseAddr(host)); err != nil {
			t.Fatal(err)
		}
		probe, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		connection, err := dialNamespaceIP(probe, e.ns, "tcp", endpoint)
		if err != nil {
			t.Fatalf("owned project cannot forward through default DROP: %v", err)
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := fmt.Fprintf(connection, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(connection)
		if err != nil || !strings.Contains(string(body), "forwarding-fixture") {
			t.Fatal("forwarded request did not reach controlled server")
		}
	}
	request(first)
	request(second)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	request(second)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := exec.CommandContext(ctx, "iptables", "-S", "FORWARD").Output()
	if err != nil || string(before) != string(after) {
		t.Fatalf("project cleanup changed existing forwarding rules: %s", after)
	}
	// Fail the second insertion after the first succeeded, then verify setup rollback.
	iptables, err := exec.LookPath("iptables")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	script := "#!/bin/sh\nif [ \"$3\" = -I ] && [ \"$6\" = -o ]; then echo fixture-insertion-denied >&2; exit 1; fi\nif [ \"$3\" = -D ] && [ \"$CYBERSTRIKE_FORWARD_FAIL_DELETE\" = 1 ]; then echo fixture-removal-denied >&2; exit 1; fi\nexec '" + strings.ReplaceAll(iptables, "'", "'\\''") + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "iptables"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	if environment, err := newSystemEnvironment(ctx, t.TempDir(), "forward-rollback", Policy{Mode: "fixed_proxy"}, Scope{Targets: []string{"203.0.113.99"}}, Profile{}); err == nil {
		_ = environment.Close()
		t.Fatal("partial forwarding installation must fail")
	}
	after, err = exec.CommandContext(ctx, iptables, "-S", "FORWARD").Output()
	if err != nil || string(before) != string(after) {
		t.Fatalf("failed setup left a forwarding rule: %s", after)
	}
	// A failed rollback must be reported too. The parent deletes this disposable
	// router, including the deliberately stranded test rule, after the child exits.
	t.Setenv("CYBERSTRIKE_FORWARD_FAIL_DELETE", "1")
	environment, err := newSystemEnvironment(ctx, t.TempDir(), "forward-cleanup-error", Policy{Mode: "fixed_proxy"}, Scope{Targets: []string{"203.0.113.99"}}, Profile{})
	if environment != nil || err == nil || !strings.Contains(err.Error(), "fixture-insertion-denied") || !strings.Contains(err.Error(), "fixture-removal-denied") {
		t.Fatalf("setup hid installation or rollback failure: %v", err)
	}
}
