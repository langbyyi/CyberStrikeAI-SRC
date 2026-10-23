package network

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestProxyCommandFixtureWorker(t *testing.T) {
	if os.Getenv("CYBERSTRIKE_PROXY_COMMAND_FIXTURE") != "1" {
		return
	}
	gateway, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || gateway.Host == "" {
		t.Fatal("command did not inherit a usable proxy gateway")
	}
	transport := &http.Transport{Proxy: http.ProxyURL(gateway)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	var targets map[string]string
	if err = json.Unmarshal([]byte(os.Getenv("CYBERSTRIKE_PROXY_FIXTURE_TARGETS")), &targets); err != nil {
		t.Fatal(err)
	}
	for target, want := range targets {
		response, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != want {
			t.Fatalf("command target %s returned %q, want %q: %v", target, body, want, err)
		}
	}
}

func TestCommandProxyRoutesMultipleLeasesAndBaseline(t *testing.T) {
	s := validationService(t)
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		return &fixtureEnvironment{}, nil
	}
	server := func(marker string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, marker) }))
	}
	one, two, baseline := server("node-one"), server("node-two"), server("baseline")
	defer one.Close()
	defer two.Close()
	defer baseline.Close()
	nodeOne, err := s.AddProxy(one.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	nodeTwo, err := s.AddProxy(two.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	i := Identity{UserID: "fixture", ConversationID: "task", RunID: "run"}
	for target, nodeID := range map[string]string{"http://one.test/": nodeOne.ID, "http://two.test/": nodeTwo.ID} {
		if _, err = s.Acquire(context.Background(), i, Scope{}, AcquireRequest{Target: target, NodeID: nodeID}); err != nil {
			t.Fatal(err)
		}
	}
	targets, _ := json.Marshal(map[string]string{"http://one.test/": "node-one", "http://two.test/": "node-two", baseline.URL: "baseline"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProxyCommandFixtureWorker$", "-test.count=1")
	command.Env = append(os.Environ(), "CYBERSTRIKE_PROXY_COMMAND_FIXTURE=1", "CYBERSTRIKE_PROXY_FIXTURE_TARGETS="+string(targets))
	if err = s.PrepareCommand(ctx, i, Scope{}, command); err != nil {
		t.Fatal(err)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("prepared command failed: %s, %v", output, err)
	}
	s.ReleaseTask(i)
	if _, ok := s.SelectedLease(i); ok {
		t.Fatal("command task retained proxy leases after cleanup")
	}
	s.mu.RLock()
	remaining := len(s.gateways) + len(s.environments)
	s.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("command task retained %d temporary network resources", remaining)
	}
}
