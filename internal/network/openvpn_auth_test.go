package network

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type authRejectedEnvironment struct{ fixtureEnvironment }

func (e *authRejectedEnvironment) Status() VPNStatus {
	return VPNStatus{State: "failed", Reason: "VPN authentication failed; update project VPN credentials"}
}
func (e *authRejectedEnvironment) Wait(context.Context) error {
	return fmt.Errorf("VPN authentication failed")
}

func TestPasswordVPNAuthenticationFailureRequiresExplicitRetry(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "p"}
	_, _ = s.SavePolicy("p", Policy{Mode: "fixed_vpn", VPNProfileID: "profile"}, 0)
	created := 0
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		created++
		return &authRejectedEnvironment{}, nil
	}
	scope := Scope{Targets: []string{"api.example.test"}}
	for n := 0; n < 3; n++ {
		if _, err := s.ConnectVPN(context.Background(), "p", scope); err == nil {
			t.Fatal("authentication failure ignored")
		}
	}
	if created != 1 {
		t.Fatalf("wrong credentials retried automatically: %d", created)
	}
	_ = s.DisconnectVPN("p")
	_, _ = s.ConnectVPN(context.Background(), "p", scope)
	if created != 2 {
		t.Fatal("explicit retry remained blocked")
	}
}

func passwordProfileFixture(t *testing.T) string {
	t.Helper()
	ca, _ := certificateFixture(t)
	return "client\ndev tun\nproto udp\nremote vpn.example.test 1194\n<ca>\n" + ca + "</ca>\nns-cert-type server\ncomp-lzo\nauth-user-pass\nredirect-gateway def1\n"
}

func TestPasswordVPNProfileKeepsOriginalAndUsesPrivateRuntimeFile(t *testing.T) {
	raw := passwordProfileFixture(t)
	auth := VPNCredentials{Username: "fixture-user", Password: "synthetic-password"}
	p, err := ValidateProfile("project", raw, nil, auth)
	if err != nil {
		t.Fatal(err)
	}
	if p.Config != raw {
		t.Fatal("rewrote the original VPN profile")
	}
	dir := filepath.Join(t.TempDir(), "runtime")
	if err := writeRuntimeProfile(p, dir); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(dir, "managed.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ns-cert-type", "redirect-gateway", auth.Username, auth.Password} {
		if strings.Contains(string(config), forbidden) {
			t.Fatalf("managed config contains forbidden data: %s", forbidden)
		}
	}
	for _, required := range []string{"route-nopull", "remote-cert-tls server", "auth-user-pass \"", "auth-retry none"} {
		if !strings.Contains(string(config), required) {
			t.Fatalf("managed config missing %s", required)
		}
	}
	secret, err := os.ReadFile(filepath.Join(dir, runtimeAuthFilename))
	if err != nil || string(secret) != auth.Username+"\n"+auth.Password+"\n" {
		t.Fatal("runtime credentials missing or malformed")
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{dir, filepath.Join(dir, runtimeAuthFilename)} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm()&0077 != 0 {
				t.Fatal("runtime credentials have group/other access")
			}
		}
	}
}

func TestPasswordVPNRejectsMissingOrInjectedCredentialsAndPartialClientPair(t *testing.T) {
	raw := passwordProfileFixture(t)
	for _, auth := range []VPNCredentials{{}, {Username: "fixture"}, {Password: "synthetic"}, {Username: "fixture\ninjected", Password: "synthetic"}, {Username: "fixture", Password: "synthetic\x00secret"}, {Username: "fixture", Password: strings.Repeat("s", 4097)}} {
		if _, err := ValidateProfile("p", raw, nil, auth); err == nil {
			t.Fatal("accepted missing or multiline credentials")
		}
	}
	auth := VPNCredentials{Username: "fixture", Password: "synthetic"}
	for _, suffix := range []string{"auth-user-pass credentials.txt\n", "ns-cert-type client\n", "cert client.crt\n"} {
		ca, _ := certificateFixture(t)
		if _, err := ValidateProfile("p", raw+suffix, map[string]string{"client.crt": ca}, auth); err == nil {
			t.Fatalf("accepted invalid profile addition: %s", suffix)
		}
	}
	if _, err := ValidateProfile("p", raw, map[string]string{runtimeAuthFilename: "untrusted"}, auth); err == nil {
		t.Fatal("runtime credential filename can be overridden")
	}
}

func TestPasswordVPNWithExternalCAAndClientCertificate(t *testing.T) {
	cert, key := certificateFixture(t)
	raw := "client\ndev tun\nremote vpn.example.test 1194\nca ca.crt\ncert client.crt\nkey client.key\nauth-user-pass\n"
	auth := VPNCredentials{Username: "fixture-user", Password: "synthetic-password"}
	profile, err := ValidateProfile("p", raw, map[string]string{"ca.crt": cert, "client.crt": cert, "client.key": key}, auth)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := RuntimeProfile(profile, "/managed")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"ca \"/managed/ca.crt\"", "cert \"/managed/client.crt\"", "key \"/managed/client.key\"", "auth-user-pass \"/managed/auth.credentials\""} {
		if !strings.Contains(managed, required) {
			t.Fatalf("combined authentication lost %s", required)
		}
	}
}

func TestPasswordVPNRetentionRotationIsolationAndEncryptedPersistence(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	auth := VPNCredentials{Username: "fixture-account", Password: "synthetic-old-password"}
	raw := passwordProfileFixture(t)
	first, err := s.SaveProjectProfile("p", raw, nil, []string{"api.example.test"}, []string{"10.20.0.53"}, 0, auth)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.SaveProjectProfile("p", raw, nil, nil, nil, 1)
	if err != nil || second.Credentials == nil || *second.Credentials != auth {
		t.Fatal("replacement upload lost existing project credentials")
	}
	rotated := VPNCredentials{Username: "fixture-account", Password: "synthetic-new-password"}
	third, err := s.SaveProjectProfile("p", "", nil, nil, nil, 2, rotated)
	if err != nil || third.Config != raw || third.Credentials == nil || *third.Credentials != rotated {
		t.Fatal("credential-only rotation lost configuration")
	}
	if _, err := s.SaveProjectProfile("p", "", nil, nil, nil, 2, auth); err == nil {
		t.Fatal("stale credential update accepted")
	}
	if s.state.Profiles[s.Policy("p").VPNProfileID].Credentials.Password != rotated.Password {
		t.Fatal("stale update changed credentials")
	}
	if _, err := s.SaveProjectProfile("other", raw, nil, nil, nil, 0); err == nil {
		t.Fatal("another project borrowed saved credentials")
	}
	if _, err := s.SaveProjectProfile("other", "", nil, nil, nil, 0, auth); err == nil {
		t.Fatal("another project borrowed a profile")
	}
	if !s.ProfileHasAuth("p") || s.ProfileHasAuth("other") {
		t.Fatal("configured indicator crosses projects")
	}
	if first.ID == third.ID {
		t.Fatal("credential rotation reused an active profile identity")
	}
	if len(s.state.Profiles) != 1 || len(s.Policy("p").DNSServers) != 1 {
		t.Fatal("credential rotation retained obsolete secrets or lost DNS configuration")
	}
	data, err := os.ReadFile(filepath.Join(root, "state.enc"))
	if err != nil || bytes.Contains(data, []byte(rotated.Password)) || bytes.Contains(data, []byte(rotated.Username)) {
		t.Fatal("credentials persisted as plaintext")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reopened.ProfileHasAuth("p") || reopened.state.Profiles[reopened.Policy("p").VPNProfileID].Credentials.Password != rotated.Password {
		t.Fatal("encrypted credentials did not survive reopen")
	}
}
