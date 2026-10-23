//go:build linux

package network

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"cyberstrike-ai/internal/processguard"
	"golang.org/x/net/dns/dnsmessage"
)

func linuxIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("CYBERSTRIKE_NETWORK_INTEGRATION") != "1" {
		t.Skip("requires opt-in privileged Linux network integration environment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration requires root namespace manager")
	}
}

func TestLinuxExcludedCIDRClassification(t *testing.T) {
	e := &linuxEnvironment{scope: Scope{Targets: []string{"10.20.0.0/16"}, Exclude: []string{"10.20.1.0/24"}}}
	if e.targetHost("10.20.1.10") {
		t.Fatal("excluded CIDR classified as VPN target")
	}
}

func vpnCertificates(t *testing.T) (string, string, string, string, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-vpn-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	makePair := func(serial int64, usage x509.ExtKeyUsage) (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprintf("synthetic-vpn-%d", serial)}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	}
	serverCert, serverKey := makePair(2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := makePair(3, x509.ExtKeyUsageClientAuth)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), serverCert, serverKey, clientCert, clientKey
}

func TestLinuxOpenVPNTwoTunnelsAndFailClosed(t *testing.T) {
	linuxIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	host := ""
	for _, device := range interfaces {
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
		t.Fatal("integration needs a host IPv4 address")
	}
	udp, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()
	dir := t.TempDir()
	ca, serverCert, serverKey, clientCert, clientKey := vpnCertificates(t)
	for name, data := range map[string]string{"ca.crt": ca, "server.crt": serverCert, "server.key": serverKey} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	device := "csi" + strings.ReplaceAll(newID(), "-", "")[:8]
	serverConfig := fmt.Sprintf("local %s\nport %d\nproto udp4\ndev %s\ndev-type tun\nserver 10.253.240.0 255.255.255.0\ntopology subnet\nca %s/ca.crt\ncert %s/server.crt\nkey %s/server.key\ndh none\nduplicate-cn\nkeepalive 2 10\npush \"dhcp-option DNS 10.253.240.103\"\nverb 3\n", host, port, device, dir, dir, dir)
	configPath := filepath.Join(dir, "server.conf")
	if err = os.WriteFile(configPath, []byte(serverConfig), 0600); err != nil {
		t.Fatal(err)
	}
	server := exec.CommandContext(ctx, "openvpn", "--config", configPath)
	logPath := filepath.Join(dir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	server.Stdout = logFile
	server.Stderr = logFile
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = server.Process.Kill()
		_ = server.Wait()
		_ = logFile.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = runNetwork(cleanup, "", "ip", "link", "delete", device)
	}()
	ready := false
	for attempt := 0; attempt < 50; attempt++ {
		if _, e := net.InterfaceByName(device); e == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		data, _ := os.ReadFile(logPath)
		t.Fatalf("fixture OpenVPN server did not start: %s", data)
	}
	if err = runNetwork(ctx, "", "ip", "addr", "add", "10.253.240.129/32", "dev", device); err != nil {
		t.Fatal(err)
	}
	var changedAddress atomic.Bool
	for i, address := range []string{"10.253.240.100", "10.253.240.101", "10.253.240.102"} {
		if err = runNetwork(ctx, "", "ip", "addr", "add", address+"/32", "dev", device); err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			continue
		} // Reachable private resolver address with no DNS listener exercises failover.
		dnsServer, e := net.ListenPacket("udp4", net.JoinHostPort(address, "53"))
		if e != nil {
			t.Fatal(e)
		}
		defer dnsServer.Close()
		answer := byte(1)
		if i == 1 {
			answer = 100
		}
		go func(server net.PacketConn, last byte) {
			for {
				buffer := make([]byte, 4096)
				n, client, e := server.ReadFrom(buffer)
				if e != nil {
					return
				}
				var query dnsmessage.Message
				if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
					continue
				}
				query.Header.Response = true
				if query.Questions[0].Type == dnsmessage.TypeA {
					ip := last
					if strings.HasPrefix(query.Questions[0].Name.String(), "change.") && changedAddress.Load() {
						ip = 100
					}
					canonical := dnsmessage.MustNewName("backend.internal.test.")
					query.Answers = []dnsmessage.Resource{
						{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.CNAMEResource{CNAME: canonical}},
						{Header: dnsmessage.ResourceHeader{Name: canonical, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{10, 253, 240, ip}}},
					}
				}
				reply, e := query.Pack()
				if e == nil {
					_, _ = server.WriteTo(reply, client)
				}
			}
		}(dnsServer, answer)
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Fixture-Local", fmt.Sprint(r.Context().Value(http.LocalAddrContextKey)))
		w.Header().Set("X-Fixture-Host", r.Host)
		_, _ = w.Write([]byte(r.RemoteAddr))
	}))
	httpServer.Listener = listener
	httpServer.Start()
	defer httpServer.Close()
	target := fmt.Sprintf("10.253.240.1:%d", listener.Addr().(*net.TCPAddr).Port)
	service, err := Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	scope := Scope{Targets: []string{"10.253.240.0/24", "*.example.test"}, Exclude: []string{"10.253.240.128/25"}}
	raw := fmt.Sprintf("client\ndev tun\nproto udp4\nremote %s %d\nca ca.crt\ncert client.crt\nkey client.key\n", host, port)
	for _, project := range []string{"vpn-a", "vpn-b"} {
		profile, e := service.SaveProfile(project, raw, map[string]string{"ca.crt": ca, "client.crt": clientCert, "client.key": clientKey})
		if e != nil {
			t.Fatal(e)
		}
		dns := []string{"10.253.240.101"}
		if project == "vpn-a" {
			dns = []string{"10.253.240.102", "10.253.240.100"}
		}
		if _, e = service.SavePolicy(project, Policy{Mode: "fixed_vpn", VPNProfileID: profile.ID, Targets: scope.Targets, DNSServers: dns}, 0); e != nil {
			t.Fatal(e)
		}
		if _, e = service.ConnectVPN(ctx, project, scope); e != nil {
			t.Fatalf("connect %s: %v", project, e)
		}
		environment, e := service.environment(ctx, project, service.Policy(project), scope)
		if e != nil {
			t.Fatal(e)
		}
		linux := environment.(*linuxEnvironment)
		linux.mu.Lock()
		actualDNS := append([]string{}, linux.dnsServers...)
		linux.mu.Unlock()
		if strings.Join(actualDNS, ",") != strings.Join(dns, ",") {
			t.Fatalf("explicit project DNS was extended by server push: %v, want %v", actualDNS, dns)
		}
	}
	get := func(env Environment) error {
		transport := &http.Transport{DialContext: func(c context.Context, _, address string) (net.Conn, error) { return env.Dial(c, address) }}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, e := client.Get("http://" + target)
		if e == nil {
			response.Body.Close()
		}
		return e
	}
	a, err := service.environment(ctx, "vpn-a", service.Policy("vpn-a"), scope)
	if err != nil {
		t.Fatal(err)
	}
	b, err := service.environment(ctx, "vpn-b", service.Policy("vpn-b"), scope)
	if err != nil {
		t.Fatal(err)
	}
	if err = get(a); err != nil {
		t.Fatalf("tunnel A HTTP: %v", err)
	}
	if err = get(b); err != nil {
		t.Fatalf("tunnel B HTTP: %v", err)
	}
	assertDomain := func(client *http.Client, hostname, wantIP string) {
		t.Helper()
		address := net.JoinHostPort(hostname, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
		response, e := client.Get("http://" + address)
		if e != nil {
			t.Fatal(e)
		}
		_ = response.Body.Close()
		if response.Header.Get("X-Fixture-Local") != net.JoinHostPort(wantIP, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)) || response.Header.Get("X-Fixture-Host") != address {
			t.Fatalf("project DNS/Host mixed: local=%s host=%s", response.Header.Get("X-Fixture-Local"), response.Header.Get("X-Fixture-Host"))
		}
	}
	transportA := service.TargetHTTPTransport(Identity{ProjectID: "vpn-a", ConversationID: "same-task-a"}, scope, nil)
	defer transportA.CloseIdleConnections()
	clientA := &http.Client{Transport: transportA, Timeout: 10 * time.Second}
	transportB := service.TargetHTTPTransport(Identity{ProjectID: "vpn-b", ConversationID: "same-task-b"}, scope, nil)
	defer transportB.CloseIdleConnections()
	clientB := &http.Client{Transport: transportB, Timeout: 10 * time.Second}
	assertDomain(clientA, "api.example.test", "10.253.240.1")
	assertDomain(clientB, "api.example.test", "10.253.240.100")
	assertDomain(clientA, "change.example.test", "10.253.240.1")
	transportA.CloseIdleConnections()
	changedAddress.Store(true)
	assertDomain(clientA, "change.example.test", "10.253.240.100")
	// A domain-aware gateway can route a shared address even if a raw baseline lookup came first.
	sharedScope := Scope{Targets: []string{"api.example.test"}}
	profile, err := service.SaveProfile("vpn-shared", raw+"dhcp-option DNS 10.253.240.100\n", map[string]string{"ca.crt": ca, "client.crt": clientCert, "client.key": clientKey})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SavePolicy("vpn-shared", Policy{Mode: "fixed_vpn", VPNProfileID: profile.ID}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ConnectVPN(ctx, "vpn-shared", sharedScope); err != nil {
		t.Fatal(err)
	}
	shared, err := service.environment(ctx, "vpn-shared", service.Policy("vpn-shared"), sharedScope)
	if err != nil {
		t.Fatal(err)
	}
	if err = shared.(*linuxEnvironment).baseline(ctx, netip.MustParseAddr("10.253.240.1")); err != nil {
		t.Fatal(err)
	}
	sharedTransport := service.TargetHTTPTransport(Identity{ProjectID: "vpn-shared", ConversationID: "shared-task"}, sharedScope, nil)
	defer sharedTransport.CloseIdleConnections()
	assertDomain(&http.Client{Transport: sharedTransport, Timeout: 5 * time.Second}, "api.example.test", "10.253.240.1")
	rawCtx, stopRaw := context.WithTimeout(ctx, 300*time.Millisecond)
	connection, rawErr := dialNamespaceIP(rawCtx, shared.(*linuxEnvironment).ns, "tcp", target)
	stopRaw()
	if connection != nil {
		_ = connection.Close()
	}
	if rawErr == nil {
		t.Fatal("ambiguous raw shared-IP connection was allowed")
	}
	if err = service.DisconnectVPN("vpn-shared"); err != nil {
		t.Fatal(err)
	}
	linuxA := a.(*linuxEnvironment)
	excludedTarget := net.JoinHostPort("10.253.240.129", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	baseline, err := dialNamespaceIP(ctx, linuxA.ns, "tcp", excludedTarget)
	if err != nil {
		t.Fatalf("raw excluded CIDR baseline: %v", err)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://"+excludedTarget, nil)
	_ = request.Write(baseline)
	response, err := http.ReadResponse(bufio.NewReader(baseline), request)
	if err != nil {
		_ = baseline.Close()
		t.Fatal(err)
	}
	remote, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	_ = baseline.Close()
	if err != nil || !strings.HasPrefix(string(remote), linuxA.clientIP+":") {
		t.Fatalf("excluded raw connection used VPN: %q %v", remote, err)
	}
	pids, err := exec.CommandContext(ctx, "ip", "netns", "pids", linuxA.ns).Output()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(pids))
	if len(fields) != 1 {
		t.Fatalf("expected one owned VPN process, got %q", pids)
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	reconnected := false
	for attempt := 0; attempt < 100; attempt++ {
		state := a.Status()
		if state.Attempts >= 2 && state.State == "ready" {
			reconnected = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !reconnected {
		t.Fatalf("VPN did not automatically reconnect: %+v", a.Status())
	}
	if err = get(a); err != nil {
		t.Fatalf("HTTP after reconnect: %v", err)
	}
	if err = runNetwork(ctx, "", "ip", "-n", linuxA.ns, "route", "replace", "10.253.240.1/32", "via", linuxA.hostIP, "dev", linuxA.peerIf); err != nil {
		t.Fatal(err)
	}
	if err = get(a); err == nil {
		t.Fatal("protected target fell back to host baseline after route loss")
	}
	if err = get(b); err != nil {
		t.Fatalf("A failure affected B: %v", err)
	}
	if err = service.DisconnectVPN("vpn-a"); err != nil {
		t.Fatal(err)
	}
	if err = get(b); err != nil {
		t.Fatalf("disconnecting A affected B: %v", err)
	}
	if _, err = service.BindAsset(ctx, "vpn-b", "new.example.test", "fixture discovered API within wildcard scope", false, "agent", scope); err != nil {
		t.Fatal(err)
	}
	assertDomain(clientB, "new.example.test", "10.253.240.100")
	unused, err := net.ListenPacket("udp4", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	unusedPort := unused.LocalAddr().(*net.UDPAddr).Port
	_ = unused.Close()
	downConfig := strings.Replace(raw, fmt.Sprintf("remote %s %d", host, port), fmt.Sprintf("remote %s %d", host, unusedPort), 1)
	downProfile, err := service.SaveProfile("vpn-down", downConfig, map[string]string{"ca.crt": ca, "client.crt": clientCert, "client.key": clientKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SavePolicy("vpn-down", Policy{Mode: "fixed_vpn", VPNProfileID: downProfile.ID, Targets: []string{"api.example.test"}}, 0); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "id", "-u")
	if err = service.PrepareCommand(ctx, Identity{ProjectID: "vpn-down", ConversationID: "down-task"}, sharedScope, command); err != nil {
		t.Fatalf("unready VPN blocked command preparation: %v", err)
	}
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != os.Getenv("CYBERSTRIKE_NETWORK_UID") {
		t.Fatalf("unready VPN prevented unprivileged command: %q %v", output, err)
	}
	var gatewayURL string
	for _, variable := range command.Env {
		if strings.HasPrefix(variable, "HTTP_PROXY=") {
			gatewayURL = strings.TrimPrefix(variable, "HTTP_PROXY=")
		}
	}
	proxyURL, err := url.Parse(gatewayURL)
	if err != nil {
		t.Fatal(err)
	}
	downTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer downTransport.CloseIdleConnections()
	downClient := &http.Client{Transport: downTransport, Timeout: time.Second}
	baselineResponse, err := downClient.Get("http://" + net.JoinHostPort(host, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatalf("unready VPN blocked baseline HTTP: %v", err)
	}
	_ = baselineResponse.Body.Close()
	if baselineResponse.StatusCode != http.StatusOK {
		t.Fatalf("baseline blocked: %d", baselineResponse.StatusCode)
	}
	blocked, err := downClient.Get("http://api.example.test")
	if err == nil {
		_ = blocked.Body.Close()
		if blocked.StatusCode != http.StatusBadGateway {
			t.Fatalf("unready VPN target leaked: %d", blocked.StatusCode)
		}
	}
}

func TestLinuxNamespaceIsolationAndCleanup(t *testing.T) {
	linuxIntegration(t)
	before, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first, err := newSystemEnvironment(ctx, t.TempDir(), "fixture-a", Policy{Mode: "fixed_proxy"}, Scope{Targets: []string{"203.0.113.99"}}, Profile{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := newSystemEnvironment(ctx, t.TempDir(), "fixture-b", Policy{Mode: "fixed_proxy"}, Scope{Targets: []string{"203.0.113.99"}}, Profile{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	a := first.(*linuxEnvironment)
	b := second.(*linuxEnvironment)
	if a.ns == b.ns {
		t.Fatal("two projects share a namespace")
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", "id -u; readlink /proc/self/ns/net")
	cmd.Dir = "/tmp"
	if err = first.Prepare(cmd); err != nil {
		t.Fatal(err)
	}
	group, err := processguard.New(newID())
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close(context.Background())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	launch, err := group.Prepare(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer launch.Dispose()
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err = launch.Commit(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	err = cmd.Wait()
	out := output.Bytes()
	if err != nil {
		t.Fatalf("isolated child: %v: %s", err, out)
	}
	if !strings.HasPrefix(string(out), os.Getenv("CYBERSTRIKE_NETWORK_UID")+"\n") {
		t.Fatalf("child did not drop privileges: %s", out)
	}
	hostNS, _ := os.Readlink("/proc/self/ns/net")
	if strings.Contains(string(out), hostNS) {
		t.Fatal("child stayed in host namespace")
	}
	blocked, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if connection, err := dialNamespaceIP(blocked, a.ns, "tcp", "203.0.113.99:443"); err == nil {
		connection.Close()
		t.Fatal("protected raw target escaped through baseline")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if b.Status().State != "ready" {
		t.Fatal("closing project A stopped B")
	}
	if err = exec.Command("ip", "netns", "exec", a.ns, "true").Run(); err == nil {
		t.Fatal("namespace survived close")
	}
	after, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil || string(before) != string(after) {
		t.Fatal("host default route changed")
	}
}

func TestLinuxNamespaceDNSKeepsBaselineAnswersWithinPolicyLimits(t *testing.T) {
	linuxIntegration(t)
	upstream, err := net.ListenPacket("udp4", "127.0.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	aAnswer := func(query dnsmessage.Message, ip [4]byte) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: ip}}
	}
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, client, e := upstream.ReadFrom(buffer)
			if e != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			query.Header.Response = true
			name := strings.ToLower(strings.TrimSuffix(query.Questions[0].Name.String(), "."))
			switch {
			case name == "dual.baseline.test" && query.Questions[0].Type == dnsmessage.TypeAAAA:
				query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8}}}}
			case name == "dual.baseline.test":
				query.Answers = []dnsmessage.Resource{aAnswer(query, [4]byte{203, 0, 113, 7})}
			case name == "shared.baseline.test":
				query.Answers = []dnsmessage.Resource{aAnswer(query, [4]byte{198, 51, 100, 7})}
			case name == "target.example.test":
				query.Answers = []dnsmessage.Resource{aAnswer(query, [4]byte{198, 51, 100, 9})}
			case name == "excluded.example.test":
				query.Answers = []dnsmessage.Resource{aAnswer(query, [4]byte{198, 51, 100, 200})}
			}
			if reply, e := query.Pack(); e == nil {
				_, _ = upstream.WriteTo(reply, client)
			}
		}
	}()
	dir := t.TempDir()
	service, err := Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	scope := Scope{Targets: []string{"198.51.100.0/24", "*.example.test"}, Exclude: []string{"198.51.100.128/25"}}
	env, err := service.environment(context.Background(), "dns-baseline", Policy{Mode: "fixed_proxy", Version: 1}, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	project, ok := env.(*linuxEnvironment)
	if !ok {
		t.Fatal("unexpected environment implementation")
	}
	project.mu.Lock()
	project.baselineDNS = "127.0.0.2"
	project.mu.Unlock()
	ask := func(name string, kind dnsmessage.Type) dnsmessage.Message {
		t.Helper()
		request := dnsmessage.Message{Header: dnsmessage.Header{ID: 1, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: kind, Class: dnsmessage.ClassINET}}}
		raw, err := request.Pack()
		if err != nil {
			t.Fatal(err)
		}
		var replyBytes []byte
		err = inNamespace(project.ns, func() error {
			conn, e := net.Dial("udp4", "127.0.0.1:53")
			if e != nil {
				return e
			}
			defer conn.Close()
			if e = conn.SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
				return e
			}
			if _, e = conn.Write(raw); e != nil {
				return e
			}
			replyBytes = make([]byte, 4096)
			n, e := conn.Read(replyBytes)
			replyBytes = replyBytes[:n]
			return e
		})
		if err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
		var reply dnsmessage.Message
		if err = reply.Unpack(replyBytes); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	// A non-target host whose IPv4 lands inside a protected prefix keeps its answer;
	// the raw connection is what gets blocked, not the resolution.
	shared := ask("shared.baseline.test", dnsmessage.TypeA)
	if shared.Header.RCode != dnsmessage.RCodeSuccess || len(shared.Answers) != 1 {
		t.Fatalf("shared-IP baseline answer became an error: %+v", shared.Header)
	}
	project.routeMu.Lock()
	ambiguous := project.ambiguous["198.51.100.7"]
	project.routeMu.Unlock()
	if !ambiguous {
		t.Fatal("shared-IP address was not scheduled for raw-connection blocking")
	}
	// An unrelated dual-stack host must not lose its IPv6 (or IPv4) answer.
	dual6 := ask("dual.baseline.test", dnsmessage.TypeAAAA)
	if dual6.Header.RCode != dnsmessage.RCodeSuccess || len(dual6.Answers) != 1 {
		t.Fatalf("baseline AAAA answer became an error: %+v", dual6.Header)
	}
	dual4 := ask("dual.baseline.test", dnsmessage.TypeA)
	if dual4.Header.RCode != dnsmessage.RCodeSuccess || len(dual4.Answers) != 1 {
		t.Fatalf("baseline A answer became an error: %+v", dual4.Header)
	}
	// Target classification and fail-closed behaviour are unchanged.
	inScope := ask("target.example.test", dnsmessage.TypeA)
	if inScope.Header.RCode != dnsmessage.RCodeSuccess || len(inScope.Answers) != 1 {
		t.Fatalf("in-scope target answer became an error: %+v", inScope.Header)
	}
	excluded := ask("excluded.example.test", dnsmessage.TypeA)
	if excluded.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("excluded target must keep failing closed: %+v", excluded.Header)
	}
}
