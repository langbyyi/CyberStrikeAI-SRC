//go:build linux

package network

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxPasswordVPNAuthenticationAndRotation(t *testing.T) {
	linuxIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	devices, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	host := ""
	for _, device := range devices {
		if device.Flags&net.FlagLoopback != 0 || device.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, _ := device.Addrs()
		for _, address := range addresses {
			ip, _, _ := net.ParseCIDR(address.String())
			if ip.To4() != nil {
				host = ip.String()
				break
			}
		}
		if host != "" {
			break
		}
	}
	if host == "" {
		t.Fatal("fixture needs a host IPv4 address")
	}
	udp, err := net.ListenPacket("udp4", host+":0")
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()
	dir := t.TempDir()
	ca, cert, key, _, _ := vpnCertificates(t)
	for name, data := range map[string]string{"ca.crt": ca, "server.crt": cert, "server.key": key, "check.sh": "#!/bin/sh\n[ \"$(sed -n '1p' \"$1\")\" = fixture-user ] && [ \"$(sed -n '2p' \"$1\")\" = synthetic-password ]\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0700); err != nil {
			t.Fatal(err)
		}
	}
	device := "csp" + strings.ReplaceAll(newID(), "-", "")[:8]
	config := fmt.Sprintf("local %s\nport %d\nproto udp4\ndev %s\ndev-type tun\nserver 10.253.241.0 255.255.255.0\ntopology subnet\nca %s/ca.crt\ncert %s/server.crt\nkey %s/server.key\ndh none\nverify-client-cert none\nusername-as-common-name\nauth-user-pass-verify %s/check.sh via-file\nscript-security 2\nverb 3\n", host, port, device, dir, dir, dir, dir)
	if err := os.WriteFile(filepath.Join(dir, "server.conf"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	server := exec.CommandContext(ctx, "openvpn", "--config", filepath.Join(dir, "server.conf"))
	log, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	server.Stdout = log
	server.Stderr = log
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = server.Process.Kill()
		_ = server.Wait()
		_ = log.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = runNetwork(cleanup, "", "ip", "link", "delete", device)
	}()
	ready := false
	for n := 0; n < 50; n++ {
		if _, err := net.InterfaceByName(device); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("password fixture VPN server did not start")
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "password-vpn-fixture") }))
	httpServer.Listener = listener
	httpServer.Start()
	defer httpServer.Close()
	target := fmt.Sprintf("http://10.253.241.1:%d", listener.Addr().(*net.TCPAddr).Port)
	s, err := Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw := fmt.Sprintf("client\ndev tun\nproto udp4\nremote %s %d\n<ca>\n%s</ca>\nns-cert-type server\nauth-user-pass\nredirect-gateway def1\n", host, port, ca)
	auth := VPNCredentials{Username: "fixture-user", Password: "synthetic-password"}
	scope := Scope{Targets: []string{"10.253.241.1"}}
	if _, err := s.SaveProjectProfile("password-project", raw, nil, scope.Targets, nil, 0, auth); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConnectVPN(ctx, "password-project", scope); err != nil {
		t.Fatalf("CA/password connection failed: %v", err)
	}
	transport := s.TargetHTTPTransport(Identity{ProjectID: "password-project", ConversationID: "fixture"}, scope, nil)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "password-vpn-fixture" {
		t.Fatal("password VPN did not reach the controlled target")
	}
	oldFiles, _ := filepath.Glob(filepath.Join(s.root, "runtime", "*", runtimeAuthFilename))
	if len(oldFiles) != 1 {
		t.Fatal("missing private runtime auth file")
	}
	if _, err := s.SaveProjectProfile("password-project", "", nil, nil, nil, 1, VPNCredentials{Username: auth.Username, Password: "synthetic-wrong"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldFiles[0]); !os.IsNotExist(err) {
		t.Fatal("old runtime credentials survived rotation")
	}
	state, err := s.ConnectVPN(ctx, "password-project", scope)
	if err == nil || state.State != "failed" || state.Attempts != 1 || state.Reason != vpnAuthenticationFailedReason {
		t.Fatalf("authentication rejection was not terminal and redacted: %+v %v", state, err)
	}
	if _, err := s.SaveProjectProfile("password-project", "", nil, nil, nil, 2, auth); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConnectVPN(ctx, "password-project", scope); err != nil {
		t.Fatal("valid rotation did not recover VPN")
	}
	if err := s.DisconnectVPN("password-project"); err != nil {
		t.Fatal(err)
	}
	remaining, _ := filepath.Glob(filepath.Join(s.root, "runtime", "*", runtimeAuthFilename))
	if len(remaining) != 0 {
		t.Fatal("runtime credentials survived disconnect")
	}
}
