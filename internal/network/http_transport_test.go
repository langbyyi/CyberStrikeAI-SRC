package network

import (
	"net/url"
	"os/exec"
	"strings"
	"time"

	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type unavailableVPNEnvironment struct{ fixtureEnvironment }

func (e *unavailableVPNEnvironment) Wait(context.Context) error {
	return fmt.Errorf("synthetic VPN not ready")
}

func TestVPNNotReadyKeepsBaselineAndGlobalProxyCommandsAvailable(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		return &unavailableVPNEnvironment{}, nil
	}
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "p"}
	_, _ = s.SavePolicy("p", Policy{Mode: "fixed_vpn", VPNProfileID: "profile", Targets: []string{"private.test"}}, 0)
	baseline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "baseline") }))
	defer baseline.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "global") }))
	defer proxy.Close()
	n, _ := s.AddProxy(proxy.URL, "manual")
	i := Identity{ProjectID: "p", ConversationID: "c"}
	scope := Scope{Targets: []string{"private.test", "public.test", "127.0.0.1"}}
	if _, err := s.Acquire(context.Background(), i, scope, AcquireRequest{Target: "http://public.test", NodeID: n.ID}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unused")
	if err := s.PrepareCommand(context.Background(), i, scope, cmd); err != nil {
		t.Fatalf("VPN blocked non-target command: %v", err)
	}
	var gateway string
	for _, value := range cmd.Env {
		if strings.HasPrefix(value, "HTTP_PROXY=") {
			gateway = strings.TrimPrefix(value, "HTTP_PROXY=")
		}
	}
	u, _ := url.Parse(gateway)
	transport := &http.Transport{Proxy: http.ProxyURL(u)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for target, want := range map[string]string{baseline.URL: "baseline", "http://public.test": "global"} {
		response, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != want {
			t.Fatalf("%s returned %q, want %q", target, body, want)
		}
	}
	response, err := client.Get("http://private.test")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("unready VPN target was not blocked: %d", response.StatusCode)
	}
}

func TestTargetHTTPTransportFixedSubsetAndGlobalSelection(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	upstream := func(label string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, label) }))
	}
	fixedProxy := upstream("fixed")
	defer fixedProxy.Close()
	globalProxy := upstream("global")
	defer globalProxy.Close()
	baseline := upstream("baseline")
	defer baseline.Close()
	fixed, _ := s.AddProjectProxy("p", fixedProxy.URL)
	global, _ := s.AddProxy(globalProxy.URL, "manual")
	_, err := s.SavePolicy("p", Policy{Mode: "fixed_proxy", ProxyID: fixed.ID, Targets: []string{"private.test"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	i := Identity{ProjectID: "p", ConversationID: "c", UserID: "u"}
	scope := Scope{Targets: []string{"private.test", "public.test", "127.0.0.1"}}
	_, err = s.Acquire(context.Background(), i, scope, AcquireRequest{Target: "http://public.test", NodeID: global.ID})
	if err != nil {
		t.Fatal(err)
	}
	transport := s.TargetHTTPTransport(i, scope, http.DefaultTransport.(*http.Transport).Clone())
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for target, want := range map[string]string{"http://private.test": "fixed", "http://public.test": "global", baseline.URL: "baseline"} {
		response, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != want {
			t.Fatalf("%s routed as %q, expected %q", target, body, want)
		}
	}
	if err = s.SetNode(fixed.ID, false); err != nil {
		t.Fatal(err)
	}
	if response, err := client.Get("http://private.test"); err == nil {
		response.Body.Close()
		t.Fatal("disabled fixed proxy fell back")
	}
}

func TestPreparedVPNGatewayKeepsScopeAndConnectionsStable(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "vpn") }))
	defer target.Close()
	created := 0
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		created++
		return &fixtureEnvironment{}, nil
	}
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "p"}
	scope := Scope{Targets: []string{"127.0.0.1"}}
	_, err := s.SavePolicy("p", Policy{Mode: "fixed_vpn", VPNProfileID: "profile", Exclude: []string{"excluded.test"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.BindAsset(context.Background(), "p", target.URL, "fixture application endpoint", false, "agent", scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConnectVPN(context.Background(), "p", scope); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unused")
	if err = s.PrepareCommand(context.Background(), Identity{ProjectID: "p", ConversationID: "c"}, scope, cmd); err != nil {
		t.Fatal(err)
	}
	var gateway string
	for _, item := range cmd.Env {
		if strings.HasPrefix(item, "HTTP_PROXY=") {
			gateway = strings.TrimPrefix(item, "HTTP_PROXY=")
		}
	}
	proxyURL, _ := url.Parse(gateway)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || string(body) != "vpn" || created != 1 {
		t.Fatalf("gateway replaced its own namespace: status=%d body=%s created=%d", response.StatusCode, body, created)
	}
}
