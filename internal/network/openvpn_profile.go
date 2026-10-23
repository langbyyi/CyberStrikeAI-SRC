package network

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path"
	"strconv"
	"strings"
)

var vpnAllowed = map[string]bool{"client": true, "disable-dco": true, "tls-client": true, "dev": true, "dev-type": true, "proto": true, "remote": true, "remote-random": true, "resolv-retry": true, "nobind": true, "persist-key": true, "persist-tun": true, "ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true, "key-direction": true, "remote-cert-tls": true, "verify-x509-name": true, "auth": true, "auth-nocache": true, "cipher": true, "data-ciphers": true, "data-ciphers-fallback": true, "ncp-ciphers": true, "verb": true, "mute": true, "reneg-sec": true, "explicit-exit-notify": true, "keepalive": true, "ping": true, "ping-restart": true, "connect-retry": true, "connect-retry-max": true, "connect-timeout": true, "tun-mtu": true, "mssfix": true, "allow-compression": true, "compress": true, "comp-lzo": true, "sndbuf": true, "rcvbuf": true, "fast-io": true, "float": true, "pull": true, "route": true, "route-ipv6": true, "route-nopull": true, "redirect-gateway": true, "redirect-private": true, "dhcp-option": true, "block-outside-dns": true, "user": true, "group": true}
var vpnFiles = map[string]bool{"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true}

func configuredDNSServers(p Policy, profile Profile) ([]string, error) {
	if len(p.DNSServers) > 0 {
		return append([]string{}, p.DNSServers...), validateDNSServers(p.DNSServers)
	}
	servers := []string{}
	seen := map[string]bool{}
	block := false
	for _, line := range strings.Split(profile.Config, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "</") {
			block = false
			continue
		}
		if strings.HasPrefix(trim, "<") {
			block = true
			continue
		}
		if block {
			continue
		}
		fields := strings.Fields(trim)
		if len(fields) < 2 || strings.TrimPrefix(fields[0], "--") != "dhcp-option" || (fields[1] != "DNS" && fields[1] != "DNS6") {
			continue
		}
		if len(fields) < 3 {
			return nil, fmt.Errorf("OpenVPN DNS directive is missing an address")
		}
		address := strings.Trim(fields[2], "\"")
		if !seen[address] {
			servers = append(servers, address)
			seen[address] = true
		}
	}
	if err := validateDNSServers(servers); err != nil {
		return nil, fmt.Errorf("invalid OpenVPN DNS configuration: %w", err)
	}
	return servers, nil
}

func ValidateProfile(project, raw string, files map[string]string, credentials ...VPNCredentials) (Profile, error) {
	p := Profile{ID: newID(), ProjectID: project, Config: raw, Files: map[string]string{}}
	if project == "" || len(raw) == 0 || len(raw) > 2<<20 || strings.ContainsRune(raw, 0) {
		return p, fmt.Errorf("invalid OpenVPN project or configuration size")
	}
	total := len(raw)
	for name, value := range files {
		if !safeProfileFile(name) || name == runtimeAuthFilename || name == "managed.ovpn" || len(value) > 1<<20 {
			return p, fmt.Errorf("invalid certificate filename or size")
		}
		total += len(value)
		p.Files[name] = value
	}
	if total > 4<<20 {
		return p, fmt.Errorf("OpenVPN profile exceeds 4 MiB")
	}
	blocks := map[string]string{}
	block := ""
	var body strings.Builder
	remote := false
	passwordAuth := false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		trim := strings.TrimSpace(line)
		if block != "" {
			if trim == "</"+block+">" {
				blocks[block] = body.String()
				body.Reset()
				block = ""
			} else {
				body.WriteString(line + "\n")
			}
			continue
		}
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, "<") && strings.HasSuffix(trim, ">") {
			tag := strings.TrimSuffix(strings.TrimPrefix(trim, "<"), ">")
			if !vpnFiles[tag] || blocks[tag] != "" {
				return p, fmt.Errorf("unsupported or duplicate inline block")
			}
			block = tag
			continue
		}
		fields := strings.Fields(trim)
		name := strings.TrimPrefix(fields[0], "--")
		if name == "auth-user-pass" {
			if len(fields) != 1 {
				return p, fmt.Errorf("configure VPN username/password in project settings instead of an auth-user-pass file reference")
			}
			passwordAuth = true
			continue
		}
		if name == "ns-cert-type" {
			if len(fields) != 2 || fields[1] != "server" {
				return p, fmt.Errorf("only legacy ns-cert-type server is supported")
			}
			continue
		}
		if !vpnAllowed[name] {
			return p, fmt.Errorf("unsupported OpenVPN directive %q; scripts, plugins and management endpoints are not permitted", name)
		}
		if name == "dev" && len(fields) > 1 && fields[1] != "tun" {
			return p, fmt.Errorf("only OpenVPN TUN profiles are supported")
		}
		if name == "dev-type" && (len(fields) != 2 || fields[1] != "tun") {
			return p, fmt.Errorf("only TUN device type is supported")
		}
		if name == "remote" {
			if len(fields) < 2 || len(fields) > 4 {
				return p, fmt.Errorf("invalid OpenVPN remote")
			}
			if _, e := ParseTarget(fields[1]); e != nil {
				return p, fmt.Errorf("invalid OpenVPN remote host")
			}
			if len(fields) > 2 {
				port, e := strconv.Atoi(fields[2])
				if e != nil || port < 1 || port > 65535 {
					return p, fmt.Errorf("invalid OpenVPN remote port")
				}
			}
			remote = true
		}
		if vpnFiles[name] {
			if len(fields) < 2 {
				return p, fmt.Errorf("missing %s certificate reference", name)
			}
			file := strings.Trim(fields[1], "\"")
			if !safeProfileFile(file) {
				return p, fmt.Errorf("unsafe certificate path")
			}
			value, ok := p.Files[file]
			if !ok {
				return p, fmt.Errorf("certificate file %q was not uploaded", file)
			}
			blocks[name] = value
		}
	}
	if block != "" || !remote {
		return p, fmt.Errorf("unterminated inline block or missing VPN remote")
	}
	if len(credentials) > 1 {
		return p, fmt.Errorf("only one VPN credential pair can be configured")
	}
	if passwordAuth {
		if len(credentials) != 1 {
			return p, fmt.Errorf("this OpenVPN profile requires a VPN username and password")
		}
		if err := credentials[0].validate(); err != nil {
			return p, err
		}
		value := credentials[0]
		p.Credentials = &value
	}
	if blocks["ca"] == "" || (!passwordAuth && (blocks["cert"] == "" || blocks["key"] == "")) {
		return p, fmt.Errorf("OpenVPN requires a CA and either client certificate/private key or username/password authentication")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(blocks["ca"])) {
		return p, fmt.Errorf("invalid CA certificate PEM")
	}
	if blocks["cert"] != "" || blocks["key"] != "" {
		if _, err := tls.X509KeyPair([]byte(blocks["cert"]), []byte(blocks["key"])); err != nil {
			return p, fmt.Errorf("client certificate and private key are invalid or do not match")
		}
	}
	if _, err := configuredDNSServers(Policy{}, p); err != nil {
		return p, err
	}
	return p, nil
}
func safeProfileFile(name string) bool {
	return name != "" && name != "." && name != ".." && path.Base(name) == name && !strings.ContainsAny(name, "\\/:\r\n\x00\"") && !strings.HasPrefix(name, "-")
}

func RuntimeProfile(p Profile, dir string) (string, error) {
	if _, err := ValidateProfile(p.ProjectID, p.Config, p.Files, profileCredentials(p)...); err != nil {
		return "", err
	}
	var out strings.Builder
	block := ""
	for _, line := range strings.Split(strings.ReplaceAll(p.Config, "\r\n", "\n"), "\n") {
		trim := strings.TrimSpace(line)
		if block != "" {
			out.WriteString(line + "\n")
			if trim == "</"+block+">" {
				block = ""
			}
			continue
		}
		if strings.HasPrefix(trim, "<") && strings.HasSuffix(trim, ">") {
			block = strings.Trim(trim, "<>")
			out.WriteString(line + "\n")
			continue
		}
		fields := strings.Fields(trim)
		if len(fields) == 0 || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		name := strings.TrimPrefix(fields[0], "--")
		if name == "auth-user-pass" {
			out.WriteString("auth-user-pass \"" + path.Join(dir, runtimeAuthFilename) + "\"\n")
			continue
		}
		switch name {
		case "disable-dco", "ns-cert-type", "dev", "dev-type", "route", "route-ipv6", "route-nopull", "redirect-gateway", "redirect-private", "dhcp-option", "block-outside-dns", "user", "group", "verb", "connect-retry", "connect-retry-max", "connect-timeout", "persist-tun", "persist-key":
			continue
		}
		if vpnFiles[name] {
			fields[1] = "\"" + path.Join(dir, strings.Trim(fields[1], "\"")) + "\""
			out.WriteString(strings.Join(fields, " ") + "\n")
		} else {
			out.WriteString(trim + "\n")
		}
	}
	// Kernel offload packets do not retain the userspace socket ownership that
	// the namespace firewall uses to distinguish VPN transport from test traffic.
	out.WriteString("disable-dco\ndev csaitun\ndev-type tun\nroute-nopull\nremote-cert-tls server\nverb 3\nconnect-retry 1 16\nconnect-retry-max 1\nconnect-timeout 10\nauth-nocache\nauth-retry none\n")
	return out.String(), nil
}
func (s *Service) SaveProfile(project, raw string, files map[string]string, credentials ...VPNCredentials) (Profile, error) {
	p, err := ValidateProfile(project, raw, files, credentials...)
	if err != nil {
		return p, err
	}
	err = s.mutate(func() error { s.state.Profiles[p.ID] = p; return nil })
	return p, err
}

// Persist the profile and its policy revision together so a stale upload cannot replace newer settings.
func (s *Service) SaveProjectProfile(project, raw string, files map[string]string, targets, dns []string, expected int64, credentials ...VPNCredentials) (Profile, error) {
	s.mu.RLock()
	previous := s.state.Profiles[s.state.Policies[project].VPNProfileID]
	s.mu.RUnlock()
	if previous.ProjectID == project {
		if len(credentials) == 0 {
			credentials = profileCredentials(previous)
		}
		if raw == "" && len(credentials) > 0 && len(files) == 0 {
			raw, files = previous.Config, previous.Files
		}
	}
	profile, err := ValidateProfile(project, raw, files, credentials...)
	if err != nil {
		return profile, err
	}
	if err = validateDNSServers(dns); err != nil {
		return profile, err
	}
	if err = (Scope{Targets: targets}).Validate(); err != nil {
		return profile, err
	}
	err = s.mutate(func() error {
		policy := s.state.Policies[project]
		if policy.Version != expected {
			return fmt.Errorf("network policy version conflict; reload before uploading")
		}
		oldProfileID := policy.VPNProfileID
		policy.Mode, policy.ProxyID, policy.VPNProfileID = "fixed_vpn", "", profile.ID
		if targets != nil {
			policy.Targets = append([]string{}, targets...)
		}
		if dns != nil {
			policy.DNSServers = append([]string{}, dns...)
		}
		policy.Version = expected + 1
		s.state.Profiles[profile.ID] = profile
		s.state.Policies[project] = policy
		if old := s.state.Profiles[oldProfileID]; old.ID != profile.ID && old.ProjectID == project {
			delete(s.state.Profiles, oldProfileID)
		}
		return nil
	})
	if err == nil {
		_ = s.DisconnectVPN(project)
	}
	return profile, err
}
