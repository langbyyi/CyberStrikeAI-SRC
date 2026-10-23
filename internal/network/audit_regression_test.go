package network

import (
	"reflect"

	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"
)

func TestProxy407IsNotReachableTarget(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusProxyAuthRequired) }))
	defer proxy.Close()
	n, _ := s.AddProxy(proxy.URL, "manual")
	for _, target := range []string{"http://target.test", "https://target.test"} {
		observed, err := s.Diagnose(context.Background(), Identity{}, Scope{}, target, []string{n.ID})
		if err != nil || len(observed) != 1 || observed[0].Reachable {
			t.Fatalf("407 accepted for %s: %+v %v", target, observed, err)
		}
	}
}

func TestFixedPolicyOnlyMatchesConfiguredTargets(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer proxy.Close()
	global, _ := s.AddProxy(proxy.URL, "manual")
	fixed, _ := s.AddProjectProxy("p", proxy.URL)
	_, err := s.SavePolicy("p", Policy{Mode: "fixed_proxy", ProxyID: fixed.ID, Targets: []string{"private.test"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Acquire(context.Background(), Identity{ProjectID: "p", ConversationID: "c"}, Scope{Targets: []string{"private.test", "public.test"}}, AcquireRequest{Target: "http://public.test", NodeID: global.ID})
	if err != nil {
		t.Fatalf("public target incorrectly forced through private proxy: %v", err)
	}
}

func TestDomainBindingExclusionCoversEveryPort(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	scope := Scope{Targets: []string{"*.example.test"}}
	if _, err := s.BindAsset(context.Background(), "p", "api.example.test", "user excludes host", true, "user", scope); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindAsset(context.Background(), "p", "http://api.example.test", "observed API", false, "agent", scope); err == nil {
		t.Fatal("agent restored excluded host on port80")
	}
	if _, err := s.BindAsset(context.Background(), "p", "*.blocked.example.test", "exclude wildcard", true, "user", scope); err != nil {
		t.Fatalf("wildcard exclusion unsupported: %v", err)
	}
	if _, err := s.BindAsset(context.Background(), "p", "10.20.1.0/24", "exclude subnet", true, "user", scope); err != nil {
		t.Fatalf("CIDR exclusion unsupported: %v", err)
	}
}

func TestInheritedScopeChangeRetiresCachedEnvironment(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	var created []*fixtureEnvironment
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		f := &fixtureEnvironment{}
		created = append(created, f)
		return f, nil
	}
	s.state.Profiles["v"] = Profile{ID: "v", ProjectID: "p"}
	_, err := s.SavePolicy("p", Policy{Mode: "fixed_vpn", VPNProfileID: "v"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"a.test", "b.test"} {
		if _, err = s.ConnectVPN(context.Background(), "p", Scope{Targets: []string{target}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(created) != 2 || !created[0].stopped {
		t.Fatal("project scope edit reused stale namespace")
	}
}

func TestLeaseRetirementClosesAutomaticEnvironment(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "disable", true: "expiry"}[expiry], func(t *testing.T) {
			s, _ := Open(t.TempDir())
			defer s.Close()
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
			defer proxy.Close()
			n, _ := s.AddProxy(proxy.URL, "manual")
			f := &fixtureEnvironment{}
			s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) { return f, nil }
			i := Identity{UserID: "u", ConversationID: "c", RunID: "run"}
			lease, err := s.Acquire(context.Background(), i, Scope{}, AcquireRequest{Target: "http://target.test", NodeID: n.ID})
			if err != nil {
				t.Fatal(err)
			}
			if err = s.PrepareCommand(context.Background(), i, Scope{}, exec.Command("unused")); err != nil {
				t.Fatal(err)
			}
			if expiry {
				s.mu.Lock()
				l := s.leases[lease.ID]
				l.ExpiresAt = time.Now().Add(-time.Second)
				s.leases[lease.ID] = l
				s.mu.Unlock()
				s.SelectedLease(i)
			} else {
				if err = s.SetNode(n.ID, false); err != nil {
					t.Fatal(err)
				}
			}
			if !f.stopped {
				t.Fatal("retired lease left namespace active")
			}
		})
	}
}

func TestProxyEditingAndDeletionRetireUsage(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	n, _ := s.AddProxy("http://fixture:old@127.0.0.1:8080", "manual")
	updated, err := s.UpdateProxy(n.ID, "socks5://fixture:new@127.0.0.1:1080", true)
	if err != nil || updated.ID != n.ID || updated.Version <= n.Version || updated.Scheme != "socks5" || updated.Port != "1080" {
		t.Fatalf("edit failed: %+v %v", updated, err)
	}
	_, _, err = s.proxyURL(n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteProxy(n.ID); err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes()) != 0 || len(s.state.Credentials) != 0 {
		t.Fatal("deleted proxy retained credentials")
	}
}

func TestProfileUploadRevisionIsAtomic(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	cert, key := certificateFixture(t)
	raw := "client\ndev tun\nremote vpn.test 1194\nca ca.crt\ncert client.crt\nkey client.key\n"
	files := map[string]string{"ca.crt": cert, "client.crt": cert, "client.key": key}
	_, err := s.SaveProjectProfile("p", raw, files, []string{"a.test"}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SaveProjectProfile("p", raw, files, []string{"b.test"}, nil, 0)
	if err == nil {
		t.Fatal("stale profile upload overwrote current policy")
	}
	if len(s.state.Profiles) != 1 || s.Policy("p").Targets[0] != "a.test" {
		t.Fatal("stale upload persisted an orphan profile or changed policy")
	}
}

func TestEffectiveScopeIsIdempotent(t *testing.T) {
	policy := Policy{Targets: []string{"*.example.test"}, Exclude: []string{"skip.example.test"}}
	scope := Scope{Targets: []string{"*.example.test"}, Exclude: []string{"outside.test"}}
	bindings := []Binding{{Target: "api.example.test"}, {Target: "skip.example.test", Excluded: true}}
	once := effectiveScope(policy, scope, bindings)
	twice := effectiveScope(policy, once, bindings)
	if !reflect.DeepEqual(once, twice) {
		t.Fatalf("scope changed when prepared twice: %#v %#v", once, twice)
	}
}

func TestDisconnectProjectRetiresAutomaticLeaseEnvironments(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer proxy.Close()
	node, _ := s.AddProxy(proxy.URL, "manual")
	f := &fixtureEnvironment{}
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) { return f, nil }
	identity := Identity{ProjectID: "p", UserID: "u", ConversationID: "c"}
	if _, err := s.Acquire(context.Background(), identity, Scope{Targets: []string{"target.test"}}, AcquireRequest{Target: "http://target.test", NodeID: node.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareCommand(context.Background(), identity, Scope{Targets: []string{"target.test"}}, exec.Command("unused")); err != nil {
		t.Fatal(err)
	}
	if err := s.DisconnectVPN("p"); err != nil {
		t.Fatal(err)
	}
	if !f.stopped || len(s.environments) != 0 || len(s.gateways) != 0 {
		t.Fatal("project disconnect left automatic lease resources")
	}
}
