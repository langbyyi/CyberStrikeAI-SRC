package network

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeStageForSeparatesFaultClasses(t *testing.T) {
	wrapped := func(err error) error { return &url.Error{Op: "Head", URL: "https://target.invalid", Err: err} }
	cases := []struct {
		name          string
		err           error
		connectStatus int
		want          string
	}{
		{"proxy auth", wrapped(fmt.Errorf("connect refused")), http.StatusProxyAuthRequired, "proxy_auth"},
		{"proxy rate limit", wrapped(fmt.Errorf("limited")), http.StatusTooManyRequests, "rate_limited"},
		{"proxy http status", wrapped(fmt.Errorf("denied")), http.StatusForbidden, "http_status"},
		{"dns", wrapped(&net.DNSError{Err: "no such host", Name: "proxy.invalid", IsNotFound: true}), 0, "dns_failed"},
		{"tls cert", wrapped(&tls.CertificateVerificationError{Err: errors.New("unknown authority")}), 0, "tls_failed"},
		{"tls record", wrapped(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}), 0, "tls_failed"},
		{"TLS after CONNECT success", wrapped(&tls.CertificateVerificationError{Err: errors.New("unknown authority")}), http.StatusOK, "tls_failed"},
		{"timeout after CONNECT success", wrapped(context.DeadlineExceeded), http.StatusOK, "target_unreachable"},
		{"timeout", wrapped(fmt.Errorf("dial tcp: i/o timeout")), 0, "connect"},
		{"deadline", wrapped(context.DeadlineExceeded), 0, "target_unreachable"},
		{"plain connect", wrapped(fmt.Errorf("connection refused")), 0, "connect"},
	}
	for _, c := range cases {
		if got := probeStageFor(c.err, c.connectStatus); got != c.want {
			t.Errorf("%s: stage %q, want %q", c.name, got, c.want)
		}
	}
	var timedOut net.Error = &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}
	if got := probeStageFor(wrapped(timedOut), 0); got != "target_unreachable" {
		t.Errorf("net timeout: stage %q, want target_unreachable", got)
	}
}

func TestObservationTTLFromEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CYBERSTRIKE_NETWORK_OBSERVATION_TTL", "45s")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.observationTTL != 45*time.Second {
		t.Fatalf("ttl %s, want 45s", s.observationTTL)
	}
	t.Setenv("CYBERSTRIKE_NETWORK_OBSERVATION_TTL", "not-a-duration")
	other, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if other.observationTTL != 5*time.Minute {
		t.Fatalf("invalid ttl must keep default, got %s", other.observationTTL)
	}
	t.Setenv("CYBERSTRIKE_NETWORK_OBSERVATION_TTL", "2h")
	clamped, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer clamped.Close()
	if clamped.observationTTL != 5*time.Minute {
		t.Fatalf("out-of-range ttl must be ignored, got %s", clamped.observationTTL)
	}
}

func TestStateKeyFromEnvironmentStaysOutOfStateDirectory(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv("CYBERSTRIKE_NETWORK_STATE_KEY", hex.EncodeToString(key))
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AddProxy("http://127.0.0.1:18081", "manual"); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "state.key")); !os.IsNotExist(err) {
		t.Fatal("environment key must not materialize a state.key file")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.Nodes()) != 1 {
		t.Fatal("state encrypted with the environment key is unreadable after reopen")
	}
	t.Setenv("CYBERSTRIKE_NETWORK_STATE_KEY", "short")
	if _, err = Open(t.TempDir()); err == nil {
		t.Fatal("malformed environment key must be rejected")
	}
}

func TestEnvironmentRebuildInvalidatesObservationContext(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	identity := Identity{UserID: "u", ProjectID: "p", ConversationID: "c"}
	before := s.contextKey(identity)
	s.mu.Lock()
	s.generations["p"]++
	s.mu.Unlock()
	if s.contextKey(identity) == before {
		t.Fatal("environment rebuild did not rotate the observation context")
	}
}
