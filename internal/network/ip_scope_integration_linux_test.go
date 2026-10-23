//go:build linux

package network

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLinuxVPNInfrastructureRejectsTestSockets(t *testing.T) {
	if endpoint := os.Getenv("CYBERSTRIKE_INFRASTRUCTURE_PROBE"); endpoint != "" {
		connection, err := net.DialTimeout("tcp", endpoint, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
		return
	}
	linuxIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var host netip.Addr
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := device.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
				host = prefix.Addr()
				break
			}
		}
		if host.IsValid() {
			break
		}
	}
	if !host.IsValid() {
		t.Skip("controlled infrastructure fixture requires a host IPv4 interface")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(host.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	environment, err := newSystemEnvironment(ctx, t.TempDir(), "infrastructure-scope",
		Policy{Mode: "fixed_proxy"}, Scope{Targets: []string{"0.0.0.0/0"}}, Profile{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := environment.Close(); err != nil {
			t.Error(err)
		}
	}()
	e := environment.(*linuxEnvironment)
	// Model the transport address registered during VPN setup while no tunnel
	// exists. The endpoint is a listener on this host, never a real VPN/target.
	e.infrastructure[host.String()] = true
	if err := e.inside(ctx, "add element inet csai infrastructure4 { "+host.String()+" }\n", "nft", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if err := e.protectDestination(ctx, netip.PrefixFrom(host, 32), true); err == nil {
		t.Error("gateway accepted VPN transport as a data target inside a known target CIDR")
	}
	probe, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	control, err := dialNamespaceIP(probe, e.ns, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("privileged VPN control socket cannot reach baseline infrastructure: %v", err)
	}
	_ = control.Close()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, binary, "-test.run=^TestLinuxVPNInfrastructureRejectsTestSockets$", "-test.v")
	child.Env = append(os.Environ(), "CYBERSTRIKE_INFRASTRUCTURE_PROBE="+listener.Addr().String())
	if err := e.Prepare(child); err != nil {
		t.Fatal(err)
	}
	output, err := child.CombinedOutput()
	if err == nil {
		t.Fatalf("unprivileged test socket bypassed fixed VPN via transport address: %s", output)
	}
	if !strings.Contains(string(output), "dial tcp") {
		t.Fatalf("unprivileged probe failed before its socket attempt: %v: %s", err, output)
	}
}

// The controlled veth has the tunnel's interface name so real namespace rules
// decide whether a raw socket may reach it, without connecting an actual VPN.
func TestLinuxIPScopeInitializesRawTargetBeforeDNS(t *testing.T) {
	linuxIntegration(t)
	for _, test := range []struct{ name, rule string }{
		{"bare_ip", "198.18.241.10"},
		{"url_ip", "https://198.18.241.10:8443/api"},
		{"ip_port", "198.18.241.10:8443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			environment, err := newSystemEnvironment(ctx, t.TempDir(), "ip-scope-"+test.name,
				Policy{Mode: "fixed_proxy"}, Scope{
					Targets: []string{test.rule},
					Exclude: []string{"http://198.18.241.20:9000"},
				}, Profile{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := environment.Close(); err != nil {
					t.Error(err)
				}
			}()
			e := environment.(*linuxEnvironment)
			targetNS := "csi-" + strings.TrimPrefix(e.ns, "csn-")
			if err := runNetwork(ctx, "", "ip", "netns", "add", targetNS); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := runNetwork(cleanup, "", "ip", "netns", "delete", targetNS); err != nil {
					t.Error(err)
				}
			}()
			commands := [][]string{
				{"-n", e.ns, "link", "add", "csaitun", "type", "veth", "peer", "name", "iptestpeer"},
				{"-n", e.ns, "link", "set", "iptestpeer", "netns", targetNS},
				{"-n", e.ns, "addr", "add", "198.18.241.1/24", "dev", "csaitun"},
				{"-n", e.ns, "link", "set", "csaitun", "up"},
				{"-n", targetNS, "addr", "add", "198.18.241.10/24", "dev", "iptestpeer"},
				{"-n", targetNS, "link", "set", "iptestpeer", "up"},
				{"-n", targetNS, "link", "set", "lo", "up"},
			}
			for _, args := range commands {
				if err := runNetwork(ctx, "", "ip", args...); err != nil {
					t.Fatal(err)
				}
			}
			var listener net.Listener
			if err := inNamespace(targetNS, func() error {
				var err error
				listener, err = net.Listen("tcp4", "198.18.241.10:8443")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				connection, err := listener.Accept()
				if err == nil {
					defer connection.Close()
					_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
					_, _ = io.WriteString(connection, "raw-target-ready")
				}
			}()
			for _, set := range []struct{ name, address string }{
				{"protected4", "198.18.241.10"},
				{"excluded4", "198.18.241.20"},
			} {
				output, err := exec.CommandContext(ctx, "ip", "netns", "exec", e.ns, "nft", "get", "element", "inet", "csai", set.name, "{", set.address, "}").CombinedOutput()
				if err != nil {
					t.Errorf("initial %s missing %s for %q: %v: %s", set.name, set.address, test.rule, err, output)
				}
			}
			probe, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			connection, err := dialNamespaceIP(probe, e.ns, "tcp", "198.18.241.10:8443")
			if err != nil {
				t.Fatalf("raw target %q was not usable before any HTTP/DNS request: %v", test.rule, err)
			}
			defer connection.Close()
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			body, err := io.ReadAll(connection)
			if err != nil || string(body) != "raw-target-ready" {
				t.Fatalf("raw target response: %q, %v", body, err)
			}
		})
	}
}
