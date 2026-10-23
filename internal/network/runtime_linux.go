//go:build linux

package network

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type linuxEnvironment struct {
	mu                                                       sync.Mutex
	routeMu                                                  sync.Mutex
	status                                                   VPNStatus
	scope                                                    Scope
	mode                                                     string
	ns, hostIf, peerIf, table, hostIP, clientIP, subnet, dir string
	uid, gid                                                 string
	cancel                                                   context.CancelFunc
	done                                                     chan struct{}
	dns                                                      net.PacketConn
	dnsServers                                               []string
	dnsOverride                                              bool
	infrastructure                                           map[string]bool
	baselineDNS                                              string
	closed                                                   bool
	closeOnce                                                sync.Once
	known                                                    map[string]bool
	baselineKnown                                            map[string]bool
	ambiguous                                                map[string]bool
	forwarding                                               *hostForwarding
	closeErr                                                 error
}

func runNetwork(ctx context.Context, stdin string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		reason := strings.TrimSpace(string(out))
		if len(reason) > 300 {
			reason = reason[:300]
		}
		return fmt.Errorf("network operation %s failed: %s", name, reason)
	}
	return nil
}
func (e *linuxEnvironment) inside(ctx context.Context, stdin string, name string, args ...string) error {
	return runNetwork(ctx, stdin, "ip", append([]string{"netns", "exec", e.ns, name}, args...)...)
}
func newSystemEnvironment(_ context.Context, root, project string, p Policy, scope Scope, profile Profile) (_ Environment, resultErr error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("project network isolation requires a privileged Linux service; direct fallback is disabled")
	}
	for _, binary := range []string{"ip", "nft", "iptables", "setpriv"} {
		if _, err := exec.LookPath(binary); err != nil {
			return nil, fmt.Errorf("required Linux runtime tool %s is missing", binary)
		}
	}
	if p.Mode == "fixed_vpn" {
		if _, err := exec.LookPath("openvpn"); err != nil {
			return nil, fmt.Errorf("OpenVPN is not installed")
		}
	}
	forward, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || strings.TrimSpace(string(forward)) != "1" {
		return nil, fmt.Errorf("Linux IPv4 forwarding must already be enabled; this service does not change host sysctls")
	}
	uid := os.Getenv("CYBERSTRIKE_NETWORK_UID")
	if uid == "" {
		uid = os.Getenv("SUDO_UID")
	}
	gid := os.Getenv("CYBERSTRIKE_NETWORK_GID")
	if gid == "" {
		gid = os.Getenv("SUDO_GID")
	}
	uidNum, ue := strconv.ParseUint(uid, 10, 32)
	_, ge := strconv.ParseUint(gid, 10, 32)
	if ue != nil || ge != nil || uidNum == 0 {
		return nil, fmt.Errorf("set non-root CYBERSTRIKE_NETWORK_UID/GID (or start using sudo from the testing user)")
	}
	dnsServers, err := configuredDNSServers(p, profile)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(project + newID()))
	suffix := fmt.Sprintf("%x", hash[:5])
	octet := int(hash[5] & 252)
	prefix := fmt.Sprintf("169.254.%d.", hash[6])
	ctx, cancel := context.WithCancel(context.Background())
	e := &linuxEnvironment{scope: scope, mode: p.Mode, ns: "csn-" + suffix, hostIf: "csh" + suffix, peerIf: "csp" + suffix, table: "csn" + suffix, hostIP: prefix + strconv.Itoa(octet+1), clientIP: prefix + strconv.Itoa(octet+2), subnet: prefix + strconv.Itoa(octet) + "/30", uid: uid, gid: gid, cancel: cancel, done: make(chan struct{}), known: map[string]bool{}, infrastructure: map[string]bool{}, dnsServers: dnsServers}
	e.dnsOverride = len(p.DNSServers) > 0
	e.baselineKnown = map[string]bool{}
	e.status = VPNStatus{State: "connecting", Environment: e.ns}
	e.dir = filepath.Join(root, "runtime", e.ns)
	setup, stopSetup := context.WithTimeout(ctx, 20*time.Second)
	defer stopSetup()
	success := false
	defer func() {
		if !success {
			cancel()
			close(e.done)
			resultErr = errors.Join(resultErr, e.Close())
		}
	}()
	for _, server := range e.dnsServers {
		if _, err = netip.ParseAddr(server); err != nil {
			return nil, fmt.Errorf("project DNS servers must be IP addresses")
		}
	}
	commands := [][]string{{"ip", "netns", "add", e.ns}, {"ip", "link", "add", e.hostIf, "type", "veth", "peer", "name", e.peerIf}, {"ip", "link", "set", e.peerIf, "netns", e.ns}, {"ip", "addr", "add", e.hostIP + "/30", "dev", e.hostIf}, {"ip", "link", "set", e.hostIf, "up"}, {"ip", "-n", e.ns, "link", "set", "lo", "up"}, {"ip", "-n", e.ns, "addr", "add", e.clientIP + "/30", "dev", e.peerIf}, {"ip", "-n", e.ns, "link", "set", e.peerIf, "up"}, {"ip", "-n", e.ns, "route", "add", "default", "via", e.hostIP, "dev", e.peerIf}}
	for _, command := range commands {
		if err = runNetwork(setup, "", command[0], command[1:]...); err != nil {
			return nil, err
		}
	}
	nat := fmt.Sprintf("add table ip %s\nadd chain ip %s postrouting { type nat hook postrouting priority srcnat; policy accept; }\nadd rule ip %s postrouting ip saddr %s/32 masquerade\n", e.table, e.table, e.table, e.clientIP)
	if err = runNetwork(setup, nat, "nft", "-f", "-"); err != nil {
		return nil, err
	}
	rules := namespaceFirewall(e.hostIP)
	if err = e.inside(setup, rules, "nft", "-f", "-"); err != nil {
		return nil, err
	}
	for _, rule := range scope.Exclude {
		if prefix, ok := ipRulePrefix(rule); ok {
			set := "excluded4"
			if prefix.Addr().Is6() {
				set = "excluded6"
			}
			if err = e.inside(setup, fmt.Sprintf("add element inet csai %s { %s }\n", set, prefix.String()), "nft", "-f", "-"); err != nil {
				return nil, err
			}
		}
	}
	if err = e.routeExclusions(setup); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Join("/etc/netns", e.ns), 0700); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join("/etc/netns", e.ns, "resolv.conf"), []byte("nameserver 127.0.0.1\noptions timeout:2 attempts:2\n"), 0644); err != nil {
		return nil, err
	}
	if data, readErr := os.ReadFile("/etc/resolv.conf"); readErr == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				e.baselineDNS = f[1]
				break
			}
		}
	}
	if e.baselineDNS == "" {
		return nil, fmt.Errorf("host baseline DNS is unavailable")
	}
	if p.Mode == "fixed_vpn" {
		for _, line := range strings.Split(profile.Config, "\n") {
			f := strings.Fields(line)
			if len(f) > 1 && strings.TrimPrefix(f[0], "--") == "remote" {
				e.infrastructure[strings.ToLower(f[1])] = true
				addresses, resolveErr := net.DefaultResolver.LookupNetIP(setup, "ip4", f[1])
				if resolveErr != nil {
					return nil, fmt.Errorf("resolve VPN transport endpoint failed")
				}
				for _, address := range addresses {
					address = address.Unmap()
					e.infrastructure[address.String()] = true
					if err = e.inside(setup, fmt.Sprintf("add element inet csai infrastructure4 { %s }\n", address.String()), "nft", "-f", "-"); err != nil {
						return nil, err
					}
					if err = runNetwork(setup, "", "ip", "-n", e.ns, "route", "replace", address.String()+"/32", "via", e.hostIP, "dev", e.peerIf); err != nil {
						return nil, err
					}
				}
			}
		}
		if err = writeRuntimeProfile(profile, e.dir); err != nil {
			return nil, err
		}
	}
	e.dns, err = listenNamespaceDNS(e.ns)
	if err != nil {
		return nil, fmt.Errorf("start project DNS: %w", err)
	}
	go e.serveDNS(ctx)
	// URL, host:port and bare-IP rules normalize to address prefixes so raw
	// sockets reach the target before any DNS or HTTP request (5.6).
	for _, rule := range scope.Targets {
		if prefix, ok := ipRulePrefix(rule); ok && !e.excludedPrefix(prefix) {
			if err = e.protect(setup, prefix); err != nil {
				return nil, err
			}
		}
	}
	if err = e.enableHostForwarding(setup); err != nil {
		return nil, err
	}
	if p.Mode == "fixed_vpn" {
		go e.runVPN(ctx)
	} else {
		e.mu.Lock()
		e.status.State = "ready"
		e.mu.Unlock()
		go func() { <-ctx.Done(); close(e.done) }()
	}
	success = true
	return e, nil
}
func (e *linuxEnvironment) Status() VPNStatus { e.mu.Lock(); defer e.mu.Unlock(); return e.status }
func (e *linuxEnvironment) Wait(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		state := e.Status()
		switch state.State {
		case "ready":
			return nil
		case "failed", "stopped":
			return fmt.Errorf("project network %s: %s", state.State, state.Reason)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (e *linuxEnvironment) BindAddress() string { return net.JoinHostPort(e.hostIP, "0") }
func (e *linuxEnvironment) Prepare(cmd *exec.Cmd) error {
	state := e.Status().State
	// The namespace firewall is installed before creation returns. VPN readiness is checked per target connection.
	if state == "stopped" || e.mode != "fixed_vpn" && state != "ready" {
		return fmt.Errorf("project network is not ready")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	original := append([]string{cmd.Path}, cmd.Args[1:]...)
	cmd.Path = ip
	cmd.Args = append([]string{ip, "netns", "exec", e.ns, "setpriv", "--reuid=" + e.uid, "--regid=" + e.gid, "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--"}, original...)
	return nil
}
func (e *linuxEnvironment) protect(ctx context.Context, prefix netip.Prefix) error {
	return e.protectDestination(ctx, prefix, false)
}

func (e *linuxEnvironment) protectDestination(ctx context.Context, prefix netip.Prefix, gateway bool) error {
	if e.excludedPrefix(prefix) {
		return fmt.Errorf("resolved target is explicitly excluded from project VPN")
	}
	e.routeMu.Lock()
	defer e.routeMu.Unlock()
	key := prefix.String()
	for address := range e.baselineKnown {
		if prefix.Contains(netip.MustParseAddr(address)) {
			if err := e.rejectAmbiguousRaw(ctx, netip.MustParseAddr(address)); err != nil {
				return err
			}
			if !gateway {
				return fmt.Errorf("shared IP requires domain-aware forwarding; raw target path is ambiguous")
			}
		}
	}
	// The transport endpoint stays infrastructure even when a wider target prefix
	// already covers it; control sockets reach it via routes, never as data.
	for host := range e.infrastructure {
		if ip, err := netip.ParseAddr(host); err == nil && prefix.Bits() == ip.BitLen() && prefix.Contains(ip) {
			return fmt.Errorf("VPN transport address cannot be a routed test target")
		}
	}
	if e.known[key] {
		return nil
	}
	for existing := range e.known {
		if old, err := netip.ParsePrefix(existing); err == nil && old.Bits() <= prefix.Bits() && old.Contains(prefix.Addr()) {
			return nil
		}
	}
	set := "protected4"
	if prefix.Addr().Is6() {
		set = "protected6"
	}
	var remove strings.Builder
	for existing := range e.known {
		if old, err := netip.ParsePrefix(existing); err == nil && prefix.Bits() < old.Bits() && prefix.Contains(old.Addr()) {
			fmt.Fprintf(&remove, "delete element inet csai %s { %s }\n", set, existing)
			delete(e.known, existing)
		}
	}
	if err := e.inside(ctx, remove.String()+fmt.Sprintf("add element inet csai %s { %s }\n", set, key), "nft", "-f", "-"); err != nil {
		return err
	}
	e.known[key] = true
	if e.mode == "fixed_vpn" && e.Status().State == "ready" {
		return e.routeVPN(ctx, prefix)
	}
	return nil
}

// Called under routeMu. Only privileged gateway sockets may use an address classified both ways.
func (e *linuxEnvironment) rejectAmbiguousRaw(ctx context.Context, ip netip.Addr) error {
	if e.ambiguous == nil {
		e.ambiguous = map[string]bool{}
	}
	if e.ambiguous[ip.String()] {
		return nil
	}
	set := "ambiguous4"
	if ip.Is6() {
		set = "ambiguous6"
	}
	if err := e.inside(ctx, fmt.Sprintf("add element inet csai %s { %s }\n", set, ip.String()), "nft", "-f", "-"); err != nil {
		return err
	}
	e.ambiguous[ip.String()] = true
	return nil
}
func (e *linuxEnvironment) routeVPN(ctx context.Context, prefix netip.Prefix) error {
	if prefix.Addr().Is6() {
		return runNetwork(ctx, "", "ip", "-6", "-n", e.ns, "route", "replace", prefix.String(), "dev", "csaitun")
	}
	return runNetwork(ctx, "", "ip", "-n", e.ns, "route", "replace", prefix.String(), "dev", "csaitun")
}

func ipRulePrefix(rule string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(rule); err == nil {
		return prefix.Masked(), true
	}
	t, err := ParseTarget(rule)
	if err != nil {
		return netip.Prefix{}, false
	}
	ip, err := netip.ParseAddr(t.Host)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(ip, ip.BitLen()), true
}
func (e *linuxEnvironment) excludedPrefix(prefix netip.Prefix) bool {
	for _, rule := range e.scope.Exclude {
		if exclude, ok := ipRulePrefix(rule); ok && exclude.Bits() <= prefix.Bits() && exclude.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
func (e *linuxEnvironment) routeExclusions(ctx context.Context) error {
	for _, rule := range e.scope.Exclude {
		prefix, ok := ipRulePrefix(rule)
		if !ok || prefix.Addr().Is6() {
			continue
		}
		if err := runNetwork(ctx, "", "ip", "-n", e.ns, "route", "replace", prefix.String(), "via", e.hostIP, "dev", e.peerIf); err != nil {
			return err
		}
	}
	return nil
}

var pushedDNS = regexp.MustCompile(`dhcp-option DNS6? ([0-9a-fA-F:.]+)`)

func (e *linuxEnvironment) acceptPushedDNS(line string) {
	if e.dnsOverride {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, match := range pushedDNS.FindAllStringSubmatch(line, -1) {
		ip, err := netip.ParseAddr(match[1])
		if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		present := false
		for _, server := range e.dnsServers {
			present = present || server == ip.String()
		}
		if !present && len(e.dnsServers) < 8 {
			e.dnsServers = append(e.dnsServers, ip.String())
		}
	}
}

func (e *linuxEnvironment) runVPN(ctx context.Context) {
	defer close(e.done)
	for attempt := 1; attempt <= 5; attempt++ {
		if ctx.Err() != nil {
			return
		}
		e.mu.Lock()
		e.status.Attempts = attempt
		e.status.State = "connecting"
		e.mu.Unlock()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", e.ns, "openvpn", "--config", filepath.Join(e.dir, "managed.ovpn"))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			e.fail("could not open VPN status pipe")
			return
		}
		cmd.Stderr = cmd.Stdout
		if err = cmd.Start(); err != nil {
			e.fail("could not start OpenVPN")
			return
		}
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 128<<10)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "AUTH_FAILED") {
				e.fail(vpnAuthenticationFailedReason)
				_ = cmd.Process.Kill()
				break
			}
			if strings.Contains(line, "SIGUSR1") || strings.Contains(line, "Restart pause") {
				e.mu.Lock()
				e.status.State = "reconnecting"
				e.status.Reason = "VPN reconnecting; target traffic remains blocked"
				e.mu.Unlock()
			}
			e.acceptPushedDNS(line)
			if strings.Contains(line, "Initialization Sequence Completed") {
				if err = e.markReady(ctx); err != nil {
					e.fail(err.Error())
					_ = cmd.Process.Kill()
					break
				}
			}
		}
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return
		}
		if e.Status().State == "failed" {
			return
		}
		e.mu.Lock()
		e.status.State = "reconnecting"
		e.status.Reason = "VPN connection ended; target traffic remains blocked"
		e.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(1<<uint(attempt-1)) * time.Second):
		}
	}
	e.fail("OpenVPN reconnect budget exhausted; next target operation can retry")
}
func (e *linuxEnvironment) markReady(ctx context.Context) error {
	if err := runNetwork(ctx, "", "ip", "-n", e.ns, "link", "show", "csaitun"); err != nil {
		return err
	}
	e.mu.Lock()
	servers := append([]string{}, e.dnsServers...)
	e.mu.Unlock()
	for _, server := range servers {
		ip, err := netip.ParseAddr(server)
		if err != nil {
			return fmt.Errorf("invalid pushed project DNS")
		}
		prefix := netip.PrefixFrom(ip, ip.BitLen())
		if err = e.protect(ctx, prefix); err != nil {
			return err
		}
	}
	e.routeMu.Lock()
	keys := make([]string, 0, len(e.known))
	for key := range e.known {
		keys = append(keys, key)
	}
	e.routeMu.Unlock()
	for _, key := range keys {
		if err := e.routeVPN(ctx, netip.MustParsePrefix(key)); err != nil {
			return err
		}
	}
	if err := e.routeExclusions(ctx); err != nil {
		return err
	}
	e.mu.Lock()
	e.status.State = "ready"
	e.status.Reason = ""
	e.mu.Unlock()
	return nil
}
func (e *linuxEnvironment) fail(reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status.State = "failed"
	e.status.Reason = reason
}
func (e *linuxEnvironment) Close() error {
	e.closeOnce.Do(func() {
		e.cancel()
		if e.dns != nil {
			_ = e.dns.Close()
		}
		select {
		case <-e.done:
		case <-time.After(5 * time.Second):
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		e.closeErr = e.removeHostForwarding(ctx)
		_ = runNetwork(ctx, "", "nft", "delete", "table", "ip", e.table)
		_ = runNetwork(ctx, "", "ip", "netns", "delete", e.ns)
		_ = runNetwork(ctx, "", "ip", "link", "delete", e.hostIf)
		_ = os.Remove(filepath.Join("/etc/netns", e.ns, "resolv.conf"))
		_ = os.Remove(filepath.Join("/etc/netns", e.ns))
		if strings.HasPrefix(filepath.Base(e.dir), "csn-") {
			_ = os.RemoveAll(e.dir)
		}
		e.mu.Lock()
		e.status.State = "stopped"
		e.mu.Unlock()
	})
	return e.closeErr
}

func (e *linuxEnvironment) targetHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil && e.excludedPrefix(netip.PrefixFrom(ip, ip.BitLen())) {
		return false
	}
	for _, rule := range e.scope.Exclude {
		r, _ := ParseTarget(rule)
		if r.Host == host || strings.HasPrefix(rule, "*.") && strings.HasSuffix(host, rule[1:]) {
			return false
		}
	}
	for _, rule := range e.scope.Targets {
		if strings.HasPrefix(rule, "*.") && strings.HasSuffix(host, rule[1:]) && host != rule[2:] {
			return true
		}
		r, err := ParseTarget(rule)
		if err == nil && r.Host == host {
			return true
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if prefix, err := netip.ParsePrefix(rule); err == nil && prefix.Contains(ip) {
				return true
			}
		}
	}
	return false
}
func (e *linuxEnvironment) exchangeDNS(ctx context.Context, raw []byte, host string) ([]byte, error) {
	e.mu.Lock()
	servers := append([]string{}, e.dnsServers...)
	e.mu.Unlock()
	throughVPN := e.mode == "fixed_vpn" && e.targetHost(host) && !e.infrastructure[host]
	if throughVPN {
		if e.Status().State != "ready" {
			return nil, fmt.Errorf("VPN is not ready")
		}
		if len(servers) == 0 {
			return nil, fmt.Errorf("VPN has not provided DNS; supply the project's DNS server in advanced network settings")
		}
		return exchangeProjectDNS(ctx, raw, servers, func(ctx context.Context, protocol, address string) (net.Conn, error) {
			return dialNamespaceMarkedIP(ctx, e.ns, protocol, address, gatewaySocketMark)
		})
	}
	return exchangeProjectDNS(ctx, raw, []string{e.baselineDNS}, (&net.Dialer{Timeout: 2 * time.Second}).DialContext)
}
func (e *linuxEnvironment) serveDNS(ctx context.Context) {
	semaphore := make(chan struct{}, 16)
	for {
		buffer := make([]byte, 4096)
		n, address, err := e.dns.ReadFrom(buffer)
		if err != nil {
			return
		}
		select {
		case semaphore <- struct{}{}:
		default:
			continue
		}
		go func(raw []byte, client net.Addr) {
			defer func() { <-semaphore }()
			var message dnsmessage.Message
			if message.Unpack(raw) != nil || len(message.Questions) != 1 {
				return
			}
			host := strings.ToLower(strings.TrimSuffix(message.Questions[0].Name.String(), "."))
			reply, err := e.exchangeDNS(ctx, raw, host)
			if err == nil && !e.infrastructure[host] {
				var decoded dnsmessage.Message
				if decoded.Unpack(reply) == nil {
					for _, answer := range decoded.Answers {
						var ip netip.Addr
						switch body := answer.Body.(type) {
						case *dnsmessage.AResource:
							ip = netip.AddrFrom4(body.A)
						case *dnsmessage.AAAAResource:
							ip = netip.AddrFrom16(body.AAAA)
						}
						if ip.IsValid() {
							if e.targetHost(host) {
								if err = e.protect(ctx, netip.PrefixFrom(ip, ip.BitLen())); err != nil {
									break
								}
							} else if err = e.baseline(ctx, ip); err != nil {
								if !errors.Is(err, errBaselinePolicyLimit) {
									break
								}
								// Shared-IP and raw-IPv6 limits are enforced when the
								// client connects, so a resolved baseline answer stays valid.
								err = nil
							}
						}
					}
				}
			}
			if err != nil {
				message.Header.Response = true
				message.Header.RCode = dnsmessage.RCodeServerFailure
				message.Answers = nil
				message.Authorities = nil
				message.Additionals = nil
				reply, _ = message.Pack()
			}
			_, _ = e.dns.WriteTo(reply, client)
		}(buffer[:n], address)
	}
}

// errBaselinePolicyLimit marks a deliberate baseline restriction (shared target IP,
// raw IPv6 without a gateway). The connection path already blocks such traffic, so
// DNS resolution must keep the upstream answer instead of failing the whole lookup.
var errBaselinePolicyLimit = errors.New("baseline address is policy-limited")

func (e *linuxEnvironment) baseline(ctx context.Context, ip netip.Addr) error {
	e.routeMu.Lock()
	defer e.routeMu.Unlock()
	if e.baselineKnown[ip.String()] {
		return nil
	}
	for prefix := range e.known {
		if netip.MustParsePrefix(prefix).Contains(ip) {
			if err := e.rejectAmbiguousRaw(ctx, ip); err != nil {
				return err
			}
			return fmt.Errorf("%w: shared IP requires domain-aware forwarding; raw non-target traffic was blocked", errBaselinePolicyLimit)
		}
	}
	set := "baseline4"
	if ip.Is6() {
		return fmt.Errorf("%w: raw baseline IPv6 is unavailable in the isolated network; use the HTTP gateway", errBaselinePolicyLimit)
	}
	// A specific baseline route prevents VPN interface subnets from capturing unrelated traffic.
	if err := runNetwork(ctx, "", "ip", "-n", e.ns, "route", "replace", ip.String()+"/32", "via", e.hostIP, "dev", e.peerIf); err != nil {
		return err
	}
	if err := e.inside(ctx, fmt.Sprintf("add element inet csai %s { %s }\n", set, ip.String()), "nft", "-f", "-"); err != nil {
		return err
	}
	e.baselineKnown[ip.String()] = true
	return nil
}
func (e *linuxEnvironment) Dial(ctx context.Context, address string) (net.Conn, error) {
	if err := e.Wait(ctx); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	addresses := []netip.Addr{ip.Unmap()}
	if err != nil {
		addresses, err = resolveProjectAddresses(ctx, host, e.exchangeDNS)
		if err != nil {
			return nil, err
		}
	}
	var lastErr error
	for _, candidate := range addresses {
		if err = e.protectDestination(ctx, netip.PrefixFrom(candidate, candidate.BitLen()), true); err != nil {
			return nil, err
		}
		conn, dialErr := dialNamespaceMarkedIP(ctx, e.ns, "tcp", net.JoinHostPort(candidate.String(), port), gatewaySocketMark)
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, fmt.Errorf("connect project target %s: %w", address, lastErr)
}
