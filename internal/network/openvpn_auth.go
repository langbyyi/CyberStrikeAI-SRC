package network

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const runtimeAuthFilename = "auth.credentials"
const vpnAuthenticationFailedReason = "VPN authentication failed; update project VPN credentials"

// Only serialized inside the encrypted store or accepted as write-only input.
type VPNCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c VPNCredentials) validate() error {
	if strings.TrimSpace(c.Username) == "" || c.Password == "" || len(c.Username) > 1024 || len(c.Password) > 4096 || strings.ContainsAny(c.Username+c.Password, "\r\n\x00") {
		return fmt.Errorf("VPN username and password are both required, must be single-line, and must fit the supported length")
	}
	return nil
}

func profileCredentials(p Profile) []VPNCredentials {
	if p.Credentials == nil {
		return nil
	}
	return []VPNCredentials{*p.Credentials}
}

func (s *Service) ProfileHasAuth(project string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.state.Profiles[s.state.Policies[project].VPNProfileID]
	return p.ProjectID == project && p.Credentials != nil
}

func writeRuntimeProfile(p Profile, dir string) error {
	managed, err := RuntimeProfile(p, dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create private VPN runtime directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("restrict VPN runtime directory: %w", err)
	}
	files := make(map[string]string, len(p.Files)+2)
	for name, data := range p.Files {
		files[name] = data
	}
	files["managed.ovpn"] = managed
	if p.Credentials != nil {
		files[runtimeAuthFilename] = p.Credentials.Username + "\n" + p.Credentials.Password + "\n"
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			return fmt.Errorf("write private VPN runtime file: %w", err)
		}
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("restrict VPN runtime file: %w", err)
		}
	}
	return nil
}
