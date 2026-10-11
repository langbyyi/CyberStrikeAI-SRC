package c2

import "testing"

func TestCallbackHostValidation(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "2001:db8::1", "localhost", "example.com", "host.docker.internal", "example.com."} {
		if err := ValidateBeaconDialHost(host); err != nil {
			t.Errorf("valid %q: %v", host, err)
		}
	}
	for _, host := range []string{"", "bad host/abc", "https://example.com", "example.com:443", "999.1.1.1", "-bad.example", "bad_.example", "a..example", "x';echo test", "$(echo test)", "example.\ncom"} {
		if err := ValidateBeaconDialHost(host); err == nil {
			t.Errorf("invalid %q accepted", host)
		}
		for _, kind := range AllOnelinerKinds() {
			result, err := GenerateOneliner(OnelinerInput{Kind: kind, Host: host, Port: 8080, HTTPBaseURL: "http://example.com:8080", ImplantToken: "test-only-token"})
			if err == nil || result != "" {
				t.Errorf("%s generated output for invalid host %q", kind, host)
			}
		}
	}
}
