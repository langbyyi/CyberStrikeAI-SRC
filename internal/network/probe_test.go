package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAcquireHonorsProjectExclusionsWithoutTargetsBeforeProbing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		projectID string
		scope     Scope
		target    string
		denied    bool
	}{
		{name: "project exact exclusion", projectID: "project", scope: Scope{Exclude: []string{"blocked.example.test"}}, target: "blocked.example.test", denied: true},
		{name: "project wildcard exclusion", projectID: "project", scope: Scope{Exclude: []string{"*.blocked.example.test"}}, target: "api.blocked.example.test", denied: true},
		{name: "project default allows other targets", projectID: "project", scope: Scope{Exclude: []string{"blocked.example.test"}}, target: "allowed.example.test"},
		{name: "unbound empty scope uses global pool", target: "blocked.example.test"},
		{name: "unbound scope behavior is unchanged", scope: Scope{Exclude: []string{"blocked.example.test"}}, target: "blocked.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			var requests atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer proxy.Close()
			node, err := service.AddProxy(proxy.URL, "manual")
			if err != nil {
				t.Fatal(err)
			}
			identity := Identity{UserID: "fixture", ProjectID: tc.projectID, ConversationID: "task"}
			lease, err := service.Acquire(context.Background(), identity, tc.scope, AcquireRequest{Target: "http://" + tc.target, NodeID: node.ID})
			if tc.denied {
				if err == nil || !strings.Contains(err.Error(), "outside the project testing scope") || lease.ID != "" {
					t.Errorf("excluded target acquired a lease: %+v %v", lease, err)
				}
				if requests.Load() != 0 {
					t.Errorf("excluded target was probed before rejection: requests=%d", requests.Load())
				}
				return
			}
			if err != nil || lease.NodeID != node.ID || requests.Load() != 1 {
				t.Fatalf("default global-pool routing changed: lease=%+v requests=%d error=%v", lease, requests.Load(), err)
			}
		})
	}
}

func TestHTTPSProxyConnectRejectionsRemainDistinctFromTargetResponses(t *testing.T) {
	for _, status := range []int{407, 403, 429} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			const username, password = "synthetic-user", "synthetic-password"
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodConnect {
					t.Errorf("expected CONNECT, got %s", r.Method)
				}
				connection, buffer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer connection.Close()
				_, _ = buffer.WriteString("HTTP/1.1 " + strconv.Itoa(status) + " " + username + ":" + password + "\r\nContent-Length: 0\r\n\r\n")
				_ = buffer.Flush()
			}))
			defer proxy.Close()
			endpoint, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			endpoint.User = url.UserPassword(username, password)
			node, err := s.AddProxy(endpoint.String(), "manual")
			if err != nil {
				t.Fatal(err)
			}
			results, err := s.Diagnose(context.Background(), Identity{}, Scope{}, "https://target.invalid", []string{node.ID})
			if err != nil || len(results) != 1 {
				t.Fatalf("diagnose CONNECT rejection: %+v %v", results, err)
			}
			observation := results[0]
			stage := "http_status"
			if status == 407 {
				stage = "proxy_auth"
			}
			if status == 429 {
				stage = "rate_limited"
			}
			if observation.Reachable || observation.HTTPStatus != status || observation.Stage != stage {
				t.Errorf("proxy rejection classified as target response or network failure: %+v", observation)
			}
			if strings.Contains(observation.Reason, username) || strings.Contains(observation.Reason, password) {
				t.Error("proxy error exposed credentials")
			}
			if _, err = s.Acquire(context.Background(), Identity{}, Scope{}, AcquireRequest{Target: "https://target.invalid", NodeID: node.ID}); err == nil {
				t.Error("proxy CONNECT rejection acquired a reachable lease")
			}
		})
	}
}

func TestProbeAndAcquireSpecificNode(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Hostname() == "target-a.test" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(502)
		}
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	badURL := bad.URL
	bad.Close()
	p1, _ := s.AddProxy(badURL, "manual")
	p2, _ := s.AddProxy(good.URL, "manual")
	identity := Identity{UserID: "u1", ConversationID: "c1"}
	observed, err := s.Diagnose(context.Background(), identity, Scope{}, "http://target-a.test", []string{p1.ID, p2.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 2 || observed[0].Reachable || !observed[1].Reachable || observed[1].HTTPStatus != 200 {
		t.Fatalf("incorrect per-node diagnosis: %+v", observed)
	}
	lease, err := s.Acquire(context.Background(), identity, Scope{}, AcquireRequest{Target: "http://target-a.test", NodeID: p2.ID})
	if err != nil {
		t.Fatal(err)
	}
	if lease.NodeID != p2.ID {
		t.Fatal("explicit node ignored")
	}
	if err = s.Release(Identity{UserID: "other", ConversationID: "c2"}, lease.ID); err == nil {
		t.Fatal("other task stole lease")
	}
	if err = s.Release(identity, lease.ID); err != nil {
		t.Fatal(err)
	}
}

func TestTargetDenialRateLimitAndFailureAreIndependent(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Hostname() == "unreachable.test" {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		if r.URL.Hostname() == "blocked.test" {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(429)
	}))
	defer proxy.Close()
	node, _ := s.AddProxy(proxy.URL, "manual")
	for target, status := range map[string]int{"http://blocked.test": 403, "http://limited.test": 429, "http://unreachable.test": 0} {
		observations, err := s.Diagnose(context.Background(), Identity{}, Scope{}, target, []string{node.ID})
		if err != nil || len(observations) != 1 || observations[0].HTTPStatus != status || observations[0].Reachable {
			t.Fatalf("target observation mixed: %s %+v %v", target, observations, err)
		}
	}
	for target, status := range map[string]int{"http://blocked.test": 403, "http://limited.test": 429, "http://unreachable.test": 0} {
		candidates, err := s.Candidates(Identity{}, target)
		if err != nil || len(candidates) != 1 || candidates[0].Observation == nil || candidates[0].Observation.HTTPStatus != status || !candidates[0].Node.Enabled {
			t.Fatalf("target-specific failure affected another target or disabled node: %s %+v %v", target, candidates, err)
		}
	}
}

func TestExplicitDiagnosisCannotBorrowPrivateNode(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	called := false
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }))
	defer proxy.Close()
	node, err := s.AddProjectProxy("owner", proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, project := range []string{"", "other"} {
		_, err = s.Diagnose(context.Background(), Identity{UserID: "other", ProjectID: project}, Scope{}, "http://example.test", []string{node.ID})
		if err == nil || called {
			t.Fatalf("private node used from project %q", project)
		}
	}
}

func TestAcquireAllFailBoundedAndProjectFixedWins(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	raw := dead.URL
	dead.Close()
	for i := 0; i < 5; i++ {
		n, c, _ := NormalizeProxy(raw)
		n.ID = string(rune('a' + i))
		n.Enabled = true
		n.Version = 1
		s.state.Nodes[n.ID] = n
		s.state.Credentials[n.ID] = c
	}
	id := Identity{UserID: "u", ConversationID: "c"}
	_, err := s.Acquire(context.Background(), id, Scope{}, AcquireRequest{Target: "http://target.test"})
	failure, ok := err.(*AcquireError)
	if !ok || len(failure.Attempts) != 3 {
		t.Fatalf("attempt budget not respected: %v", err)
	}
	_, err = s.SavePolicy("p", Policy{Mode: "fixed_proxy", ProxyID: "a", Targets: []string{"target.test"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	id.ProjectID = "p"
	_, err = s.Acquire(context.Background(), id, Scope{Targets: []string{"target.test"}}, AcquireRequest{Target: "http://target.test", NodeID: "b"})
	if err == nil || !strings.Contains(err.Error(), "fixed") {
		t.Fatalf("project fixed proxy was bypassed: %v", err)
	}
}

func TestProxyValidationAndCandidateEligibility(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	n, _ := s.AddProxy("socks5://127.0.0.1:1080", "fofa")
	if _, err := s.Acquire(context.Background(), Identity{}, Scope{}, AcquireRequest{Target: "http://target.test", NodeID: n.ID}); err == nil {
		t.Fatal("unapproved search candidate used")
	}
	for _, raw := range []string{"http://127.0.0.1", "ftp://127.0.0.1:21", "http://127.0.0.1:80/path", "socks5://127.0.0.1:0"} {
		if _, _, err := NormalizeProxy(raw); err == nil {
			t.Fatalf("invalid proxy accepted: %s", raw)
		}
	}
}

func TestDisabledProxyRevokesLeaseAndRunIsolation(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()
	n, _ := s.AddProxy(upstream.URL, "manual")
	i := Identity{UserID: "u", ConversationID: "c", RunID: "run-a"}
	lease, err := s.Acquire(context.Background(), i, Scope{}, AcquireRequest{Target: "http://target.test", NodeID: n.ID})
	if err != nil {
		t.Fatal(err)
	}
	other := i
	other.RunID = "run-b"
	if _, ok := s.SelectedLease(other); ok {
		t.Fatal("a new task inherited a previous task's proxy")
	}
	if err = s.SetNode(n.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.SelectedLease(i); ok {
		t.Fatalf("disabled proxy kept active lease %s", lease.ID)
	}
}

func TestReleaseOneLeaseKeepsOtherTaskLease(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer proxy.Close()
	n, _ := s.AddProxy(proxy.URL, "manual")
	i := Identity{UserID: "u", ConversationID: "c"}
	one, err := s.Acquire(context.Background(), i, Scope{}, AcquireRequest{Target: "http://one.test", NodeID: n.ID})
	if err != nil {
		t.Fatal(err)
	}
	two, err := s.Acquire(context.Background(), i, Scope{}, AcquireRequest{Target: "http://two.test", NodeID: n.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Release(i, one.ID); err != nil {
		t.Fatal(err)
	}
	selected, ok := s.SelectedLease(i)
	if !ok || selected.ID != two.ID {
		t.Fatal("releasing one lease removed another lease")
	}
}

func TestAcquireFailureListsAlternativeCandidates(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	raw := dead.URL
	dead.Close()
	for i := 0; i < 5; i++ {
		n, c, _ := NormalizeProxy(raw)
		n.ID = string(rune('a' + i))
		n.Enabled = true
		n.Version = 1
		s.state.Nodes[n.ID] = n
		s.state.Credentials[n.ID] = c
	}
	_, err := s.Acquire(context.Background(), Identity{UserID: "u", ConversationID: "c"}, Scope{}, AcquireRequest{Target: "http://target.test", NodeID: "a"})
	failure, ok := err.(*AcquireError)
	if !ok || len(failure.Attempts) != 1 {
		t.Fatalf("explicit node failure shape: %v", err)
	}
	if len(failure.Alternatives) == 0 {
		t.Fatal("explicit failure returned no alternatives")
	}
	for _, alternative := range failure.Alternatives {
		if alternative == "a" {
			t.Fatal("failed node listed as its own alternative")
		}
	}
	_, err = s.Acquire(context.Background(), Identity{UserID: "u", ConversationID: "c"}, Scope{}, AcquireRequest{Target: "http://target.test"})
	failure, ok = err.(*AcquireError)
	if !ok || len(failure.Attempts) != 3 || len(failure.Alternatives) == 0 {
		t.Fatalf("bounded failure shape: attempts=%d alternatives=%v err=%v", len(failure.Attempts), failure.Alternatives, err)
	}
	for _, attempted := range failure.Attempts {
		for _, alternative := range failure.Alternatives {
			if attempted.NodeID == alternative {
				t.Fatalf("attempted node %s also listed as alternative", alternative)
			}
		}
	}
}
