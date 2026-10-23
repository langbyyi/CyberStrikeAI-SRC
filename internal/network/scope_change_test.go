package network

import (
	"context"
	"os/exec"
	"reflect"
	"testing"
)

func TestEffectiveScopeIntersectsSavedAssetsWithCurrentProjectScope(t *testing.T) {
	policy := Policy{Mode: "fixed_vpn", Targets: []string{"*.example.test", "10.20.0.0/16", "2001:db8::/32"}}
	bindings := []Binding{{Target: "retired.example.test"}, {Target: "api.example.test"}, {Target: "blocked.example.test", Excluded: true}}
	current := Scope{Targets: []string{"api.example.test", "10.20.1.0/24", "2001:db8:1::/48"}, Exclude: []string{"10.20.1.9"}}
	got := effectiveScope(policy, current, bindings)
	want := []string{"10.20.1.0/24", "2001:db8:1::/48", "api.example.test"}
	if !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("saved network assets escaped narrowed project scope: %v", got.Targets)
	}
	for _, target := range []string{"retired.example.test", "other.example.test", "10.20.2.1", "10.20.1.9", "2001:db8:2::1"} {
		parsed, err := ParseTarget(target)
		if err != nil || got.Contains(parsed) {
			t.Fatalf("revoked or excluded target remains routed: %s", target)
		}
	}
	portScope := effectiveScope(Policy{Targets: []string{"https://api.example.test:8443"}}, Scope{Targets: []string{"*.example.test"}}, nil)
	if !reflect.DeepEqual(portScope.Targets, []string{"https://api.example.test:8443"}) {
		t.Fatal("intersection broadened the configured target port")
	}
}

func TestProjectScopeNarrowingRemovesSavedAssetsFromCommandEnvironment(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "p"}
	if _, err = s.SavePolicy("p", Policy{Mode: "fixed_vpn", VPNProfileID: "profile", Targets: []string{"*.example.test"}}, 0); err != nil {
		t.Fatal(err)
	}
	old := Scope{Targets: []string{"*.example.test"}}
	if _, err = s.BindAsset(context.Background(), "p", "retired.example.test", "synthetic in-scope discovery", false, "agent", old); err != nil {
		t.Fatal(err)
	}
	var scopes []Scope
	var environments []*fixtureEnvironment
	s.factory = func(_ context.Context, _ string, _ Policy, scope Scope, _ Profile) (Environment, error) {
		scopes = append(scopes, scope)
		env := &fixtureEnvironment{ready: true}
		environments = append(environments, env)
		return env, nil
	}
	i := Identity{ProjectID: "p", ConversationID: "c", RunID: "run"}
	for _, scope := range []Scope{old, {Targets: []string{"api.example.test"}}} {
		if err = s.PrepareCommand(context.Background(), i, scope, exec.Command("unused")); err != nil {
			t.Fatal(err)
		}
	}
	if len(scopes) != 2 || !environments[0].stopped {
		t.Fatal("scope narrowing did not retire old command environment")
	}
	if !reflect.DeepEqual(scopes[1].Targets, []string{"api.example.test"}) {
		t.Fatalf("new command kept old policy or bindings: %v", scopes[1].Targets)
	}
}
