package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"sync/atomic"
	"testing"
)

func TestAssessmentContextKeySurvivesEmptyPolicyJSONRoundTrip(t *testing.T) {
	before := ScopeAssessmentContext{ProjectID: "p", Targets: []string{}, Exclude: []string{}}
	after := ScopeAssessmentContext{ProjectID: "p"}
	if before.Key() != after.Key() {
		t.Fatal("empty optional policy lists invalidate persisted assessments after restart")
	}
}

func TestRestoringUnapprovedExclusionCannotCreatePositiveRoute(t *testing.T) {
	for _, target := range []string{"unexpected.example.test", "0.0.0.0/0", "::/0"} {
		t.Run(target, func(t *testing.T) {
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err := s.BindAsset(context.Background(), "p", target, "user exclusion", true, "user", Scope{}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.BindAsset(context.Background(), "p", target, "user restores", false, "user", Scope{}); err == nil {
				t.Fatal("an exclusion was promoted to an unapproved positive route")
			}
			for _, binding := range s.Bindings("p") {
				if !binding.Excluded {
					t.Fatal("unapproved restore was persisted")
				}
			}
		})
	}
}

func TestAssessedAssetsPersistAndDoNotReconnectOnRepeatedRegistration(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "p"}
	if _, err = s.SavePolicy("p", Policy{Mode: "fixed_vpn", VPNProfileID: "profile"}, 0); err != nil {
		t.Fatal(err)
	}
	base := Scope{}
	key := (ScopeAssessmentContext{ProjectID: "p", Description: "authorized app backend"}).Key()
	bind := func() Binding {
		t.Helper()
		b, err := s.BindAssessedAsset(context.Background(), "p", "api.backend.test", "observed owned API", "project specification permits owned backend", key, base)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := bind()
	var created []*fixtureEnvironment
	s.factory = func(_ context.Context, _ string, _ Policy, scope Scope, _ Profile) (Environment, error) {
		parsed, _ := ParseTarget("api.backend.test")
		if !scope.Contains(parsed) {
			t.Fatal("command environment lost assessed asset")
		}
		env := &fixtureEnvironment{ready: true}
		created = append(created, env)
		return env, nil
	}
	scope := s.AssessedScope("p", base, key)
	identity := Identity{ProjectID: "p", ConversationID: "c", RunID: "run"}
	if err := s.PrepareCommand(context.Background(), identity, scope, exec.Command("unused")); err != nil {
		t.Fatal(err)
	}
	second := bind()
	if second.Revision != first.Revision || len(created) != 1 || created[0].stopped {
		t.Fatal("duplicate registration retired an active VPN")
	}
	// A legacy call for an already approved asset must retain its revocation context.
	if _, err := s.BindAsset(context.Background(), "p", "api.backend.test", "observed again", false, "agent", scope); err != nil {
		t.Fatal(err)
	}
	if s.Bindings("p")[0].ScopeContext != key {
		t.Fatal("rebind discarded assessment context")
	}
	if _, err := s.BindAsset(context.Background(), "p", "api.backend.test", "user excludes backend", true, "user", scope); err != nil {
		t.Fatal(err)
	}
	excludedScope := s.AssessedScope("p", base, key)
	parsedExcluded, _ := ParseTarget("api.backend.test")
	if excludedScope.Contains(parsedExcluded) {
		t.Fatal("user exclusion remains allowed in shared network scope")
	}
	global, err := s.AddProxy("http://127.0.0.1:9", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Acquire(context.Background(), identity, excludedScope, AcquireRequest{Target: "http://api.backend.test", NodeID: global.ID}); err == nil {
		t.Fatal("user-excluded target used global proxy")
	}
	if _, err := s.BindAssessedAsset(context.Background(), "p", "api.backend.test", "observed again", "authorized backend", key, scope); err == nil {
		t.Fatal("Agent overrode user exclusion")
	}
	if _, err := s.BindAsset(context.Background(), "p", "api.backend.test", "user restores backend", false, "user", excludedScope); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	parsed, _ := ParseTarget("api.backend.test")
	active := reloaded.AssessedScope("p", base, key)
	if !effectiveScope(reloaded.Policy("p"), active, reloaded.Bindings("p")).Contains(parsed) {
		t.Fatal("encrypted reload lost valid assessment")
	}
	stale := reloaded.AssessedScope("p", base, "changed-project-context")
	if effectiveScope(reloaded.Policy("p"), stale, reloaded.Bindings("p")).Contains(parsed) {
		t.Fatal("empty scope revived an obsolete assessment")
	}
	if reloaded.AssessedScope("another-project", base, key).Contains(parsed) {
		t.Fatal("assessment crossed project boundary")
	}
}

func TestUserExcludedAssetNeverFallsBackToBaseline(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := Scope{Targets: []string{"portal.example.test"}}
	key := (ScopeAssessmentContext{ProjectID: "p", Description: "owned backend permitted"}).Key()
	if _, err := s.BindAssessedAsset(context.Background(), "p", "api.backend.test", "observed API", "authorized backend", key, base); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindAsset(context.Background(), "p", "api.backend.test", "user excludes backend", true, "user", s.AssessedScope("p", base, key)); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	baseline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(http.StatusOK) }))
	defer baseline.Close()
	proxyURL, _ := url.Parse(baseline.URL)
	transport := s.TargetHTTPTransport(Identity{ProjectID: "p"}, s.AssessedScope("p", base, key), &http.Transport{Proxy: http.ProxyURL(proxyURL)})
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get("http://api.backend.test/")
	if response != nil {
		response.Body.Close()
	}
	if err == nil || hits.Load() != 0 {
		t.Fatalf("excluded target reached baseline: hits=%d err=%v", hits.Load(), err)
	}
}
