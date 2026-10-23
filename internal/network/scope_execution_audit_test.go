package network

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnvironmentAdmissionRejectsQueuedOldScope(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "p"}
	policy, err := s.SavePolicy("p", Policy{Mode: "fixed_vpn", VPNProfileID: "profile"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Bool
	current.Store(true)
	scope := Scope{Targets: []string{"api.backend.test"}}.WithCurrentValidation(func() error {
		if !current.Load() {
			return fmt.Errorf("project scope changed")
		}
		return nil
	})
	created := 0
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		created++
		return &fixtureEnvironment{ready: true}, nil
	}
	current.Store(false)
	if _, err := s.environment(context.Background(), "p", policy, scope); err == nil || created != 0 {
		t.Fatalf("retired scope created environment: created=%d err=%v", created, err)
	}
}

func TestAcquireCannotPublishLeaseAfterScopeOrPolicyRevocation(t *testing.T) {
	for _, change := range []string{"scope", "policy", "disconnect", "exclude"} {
		t.Run(change, func(t *testing.T) {
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			entered, resume := make(chan struct{}), make(chan struct{})
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { close(entered); <-resume; w.WriteHeader(http.StatusOK) }))
			defer proxy.Close()
			defer func() {
				select {
				case <-resume:
				default:
					close(resume)
				}
			}()
			node, err := s.AddProjectProxy("p", proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.SavePolicy("p", Policy{Mode: "fixed_proxy", ProxyID: node.ID}, 0); err != nil {
				t.Fatal(err)
			}
			var current atomic.Bool
			current.Store(true)
			scope := Scope{Targets: []string{"api.example.test"}}.WithCurrentValidation(func() error {
				if !current.Load() {
					return fmt.Errorf("project scope changed")
				}
				return nil
			})
			identity := Identity{ProjectID: "p", ConversationID: "task"}
			finished := make(chan error, 1)
			go func() {
				_, err := s.Acquire(context.Background(), identity, scope, AcquireRequest{Target: "http://api.example.test", NodeID: node.ID})
				finished <- err
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("probe did not start")
			}
			if change == "scope" {
				current.Store(false)
				err = s.DisconnectVPN("p")
			} else if change == "policy" {
				_, err = s.SavePolicy("p", Policy{Mode: "auto"}, 1)
			} else if change == "exclude" {
				_, err = s.BindAsset(context.Background(), "p", "api.example.test", "user excludes asset", true, "user", scope)
			} else {
				err = s.DisconnectVPN("p")
			}
			if err != nil {
				t.Fatal(err)
			}
			close(resume)
			if err := <-finished; err == nil {
				t.Error("probe published a lease after revocation")
			}
			if _, ok := s.SelectedLease(identity); ok {
				t.Error("revoked project retained a selected lease")
			}
		})
	}
}

func TestGlobalLeaseCommandPreservesScopeValidationAtAdmission(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	node, err := s.AddProxy("http://127.0.0.1:9", "manual")
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{ProjectID: "p", ConversationID: "task"}
	s.leases["fixture"] = Lease{ID: "fixture", NodeID: node.ID, ProjectID: "p", Target: "http://api.example.test:80", Mode: "proxy", Owner: identity.Key(), ExpiresAt: time.Now().Add(time.Minute)}
	var checks atomic.Int32
	scope := Scope{Targets: []string{"api.example.test"}}.WithCurrentValidation(func() error {
		if checks.Add(1) > 1 {
			return fmt.Errorf("project scope changed")
		}
		return nil
	})
	created := 0
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		created++
		return &fixtureEnvironment{ready: true}, nil
	}
	if err := s.PrepareCommand(context.Background(), identity, scope, exec.Command("unused")); err == nil || created != 0 {
		t.Fatalf("lease environment discarded scope validation: created=%d err=%v", created, err)
	}
}

func TestRetiredEnvironmentCannotReturnSuccessfulCreation(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "p"}
	policy, err := s.SavePolicy("p", Policy{Mode: "fixed_vpn", VPNProfileID: "profile"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-resume:
		default:
			close(resume)
		}
	}()
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		close(entered)
		<-resume
		return &fixtureEnvironment{ready: true}, nil
	}
	finished := make(chan error, 1)
	go func() {
		_, err := s.environment(context.Background(), "p", policy, Scope{Targets: []string{"api.backend.test"}})
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("creation did not enter factory")
	}
	disconnected := make(chan error, 1)
	go func() { disconnected <- s.DisconnectVPN("p") }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.RLock()
		pending := len(s.environments)
		s.mu.RUnlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disconnect did not retire pending environment")
		}
		time.Sleep(time.Millisecond)
	}
	close(resume)
	if err := <-finished; err == nil {
		t.Fatal("retired creation returned success to its caller")
	}
	if err := <-disconnected; err != nil {
		t.Fatal(err)
	}
}
