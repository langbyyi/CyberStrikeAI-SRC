package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestRuntimeRetriesFailedEnvironmentOnNextOperation(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "p"}
	_, _ = s.SavePolicy("p", Policy{Mode: "fixed_vpn", VPNProfileID: "profile"}, 0)
	created := 0
	var previous *fixtureEnvironment
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		created++
		if created == 1 {
			return nil, fmt.Errorf("synthetic temporary setup failure")
		}
		previous = &fixtureEnvironment{}
		return previous, nil
	}
	scope := Scope{Targets: []string{"private.test"}}
	if _, err := s.ConnectVPN(context.Background(), "p", scope); err == nil {
		t.Fatal("fixture setup must fail first")
	}
	if _, err := s.ConnectVPN(context.Background(), "p", scope); err != nil {
		t.Fatalf("initial failure remained cached: %v", err)
	}
	previous.mu.Lock()
	previous.failed = true
	previous.mu.Unlock()
	if _, err := s.ConnectVPN(context.Background(), "p", scope); err != nil || created != 3 {
		t.Fatalf("failed environment stayed cached: created=%d err=%v", created, err)
	}
	_ = previous.Close()
	if _, err := s.ConnectVPN(context.Background(), "p", scope); err != nil || created != 4 || previous.stopped {
		t.Fatalf("stopped environment reused instead of recreated: created=%d err=%v", created, err)
	}
}

func TestRuntimeConnectsDifferentProjectsConcurrently(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		return &fixtureEnvironment{}, nil
	}
	const count = 32
	for index := 0; index < count; index++ {
		project := fmt.Sprintf("parallel-%d", index)
		s.state.Profiles[project] = Profile{ID: project, ProjectID: project}
		if _, err := s.SavePolicy(project, Policy{Mode: "fixed_vpn", VPNProfileID: project}, 0); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	errors := make(chan error, count)
	for index := 0; index < count; index++ {
		go func(project string) {
			<-start
			_, err := s.ConnectVPN(context.Background(), project, Scope{Targets: []string{"api.example.test"}})
			errors <- err
		}(fmt.Sprintf("parallel-%d", index))
	}
	close(start)
	for index := 0; index < count; index++ {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < count; index++ {
		if state := s.VPNStatus(fmt.Sprintf("parallel-%d", index)); state.State != "ready" {
			t.Fatalf("project %d did not become ready: %+v", index, state)
		}
	}
}

func TestRuntimeCanceledConnectDoesNotCreateEnvironment(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "project"}
	if _, err := s.SavePolicy("project", Policy{Mode: "fixed_vpn", VPNProfileID: "profile"}, 0); err != nil {
		t.Fatal(err)
	}
	created := false
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		created = true
		return &fixtureEnvironment{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.ConnectVPN(ctx, "project", Scope{Targets: []string{"api.example.test"}})
	if err != context.Canceled || created || s.VPNStatus("project").State != "stopped" {
		t.Fatalf("cancelled connection created a background VPN: error=%v created=%v state=%+v", err, created, s.VPNStatus("project"))
	}
}

func TestRuntimeRejectsRetiredNetworkSnapshots(t *testing.T) {
	for _, mode := range []string{"fixed_proxy", "fixed_vpn", "retired_lease", "closed_service"} {
		t.Run(mode, func(t *testing.T) {
			s := validationService(t)
			created := false
			s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
				created = true
				return &fixtureEnvironment{ready: true}, nil
			}
			project := "project"
			policy := Policy{Mode: "fixed_proxy", ProxyID: "old-node", Version: 1}
			switch mode {
			case "fixed_proxy", "fixed_vpn":
				policy.Mode = mode
				if mode == "fixed_vpn" {
					s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: project}
					policy.VPNProfileID = "profile"
				}
				var err error
				policy, err = s.SavePolicy(project, policy, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.SavePolicy(project, Policy{Mode: "auto"}, policy.Version); err != nil {
					t.Fatal(err)
				}
			case "retired_lease":
				project = "lease-expired-snapshot"
			case "closed_service":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			_, err := s.environment(context.Background(), project, policy, Scope{Targets: []string{"api.example.test"}})
			s.mu.RLock()
			remaining := len(s.environments)
			s.mu.RUnlock()
			if err == nil || created || remaining != 0 {
				t.Fatalf("retired snapshot registered a network environment: created=%v environments=%d error=%v", created, remaining, err)
			}
		})
	}
}

type fixtureEnvironment struct {
	ready   bool
	failed  bool
	stopped bool
	mu      sync.Mutex
}

type gatewayBarrierEnvironment struct {
	fixtureEnvironment
	entered chan struct{}
	resume  chan struct{}
}

func (f *gatewayBarrierEnvironment) BindAddress() string {
	close(f.entered)
	<-f.resume
	return "127.0.0.1:0"
}

func TestCommandDoesNotRegisterGatewayAfterNetworkRetirement(t *testing.T) {
	for _, change := range []string{"disconnect", "policy", "close", "release_lease"} {
		t.Run(change, func(t *testing.T) {
			s := validationService(t)
			i := Identity{UserID: "fixture", ProjectID: "project", ConversationID: "task", RunID: "run"}
			env := &gatewayBarrierEnvironment{entered: make(chan struct{}), resume: make(chan struct{})}
			defer func() {
				select {
				case <-env.resume:
				default:
					close(env.resume)
				}
			}()
			s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) { return env, nil }
			var policy Policy
			if change == "release_lease" {
				node, err := s.AddProxy("http://127.0.0.1:8080", "manual")
				if err != nil {
					t.Fatal(err)
				}
				s.leases["pending"] = Lease{ID: "pending", NodeID: node.ID, Owner: i.Key(), Mode: "proxy", Target: "http://api.example.test:80", ExpiresAt: time.Now().Add(time.Minute)}
			} else {
				s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "project"}
				var err error
				policy, err = s.SavePolicy("project", Policy{Mode: "fixed_vpn", VPNProfileID: "profile"}, 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			finished := make(chan error, 1)
			go func() {
				finished <- s.PrepareCommand(context.Background(), i, Scope{Targets: []string{"api.example.test"}}, exec.Command("unused"))
			}()
			select {
			case <-env.entered:
			case err := <-finished:
				t.Fatalf("command did not reach gateway creation: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("gateway creation did not start")
			}
			var err error
			switch change {
			case "disconnect":
				err = s.DisconnectVPN("project")
			case "policy":
				_, err = s.SavePolicy("project", Policy{Mode: "auto"}, policy.Version)
			case "close":
				err = s.Close()
			case "release_lease":
				err = s.Release(i, "pending")
			}
			close(env.resume)
			if err != nil {
				t.Fatal(err)
			}
			err = <-finished
			s.mu.RLock()
			remaining := len(s.gateways)
			s.mu.RUnlock()
			if err == nil || remaining != 0 {
				t.Fatalf("retired command registered a late gateway: gateways=%d error=%v", remaining, err)
			}
		})
	}
}

func TestReleaseTaskCleansAllProjectResourcesForOnlyThatRun(t *testing.T) {
	s := validationService(t)
	node, err := s.AddProxy("http://127.0.0.1:8080", "manual")
	if err != nil {
		t.Fatal(err)
	}
	owner := Identity{UserID: "fixture", ConversationID: "task", RunID: "ending-run"}
	identities := []Identity{
		{UserID: "fixture", ProjectID: "old-project", ConversationID: "task", RunID: owner.RunID},
		{UserID: "fixture", ProjectID: "other-project", ConversationID: "task", RunID: owner.RunID},
		{UserID: "fixture", ProjectID: "old-project", ConversationID: "task", RunID: "newer-run"},
		{UserID: "another-user", ProjectID: "old-project", ConversationID: "task", RunID: owner.RunID},
	}
	gateways := make([]*Gateway, len(identities))
	for index, identity := range identities {
		gateway, err := s.NewGateway(node.ID, Scope{Targets: []string{"target.example.test"}}, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		gateway.owner = identity.Key()
		gateways[index] = gateway
		s.gateways[identity.ProjectID+"/"+identity.Key()] = gateway
		s.leases[identity.Key()] = Lease{ID: identity.Key(), Owner: identity.Key(), Mode: "proxy", ExpiresAt: time.Now().Add(time.Minute)}
	}
	s.ReleaseTask(owner)
	for index, identity := range identities {
		_, exists := s.SelectedLease(identity)
		connection, dialErr := net.DialTimeout("tcp", gateways[index].listener.Addr().String(), time.Second)
		if connection != nil {
			_ = connection.Close()
		}
		if index < 2 && (exists || dialErr == nil) {
			t.Fatalf("old project resources survived task cleanup: project=%s lease=%v listener=%v", identity.ProjectID, exists, dialErr)
		}
		if index >= 2 && (!exists || dialErr != nil) {
			t.Fatalf("cleanup affected another owner or run: identity=%+v lease=%v listener=%v", identity, exists, dialErr)
		}
	}
}

func TestGatewayCloseBeforeServeClosesBoundListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	g := &Gateway{listener: listener, server: &http.Server{}, selected: &http.Transport{}, baseline: &http.Transport{}, tunnels: map[net.Conn]bool{}}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if connection != nil {
		connection.Close()
	}
	if err == nil {
		t.Fatal("gateway close left a listener bound before Serve registered it")
	}
}

func (f *fixtureEnvironment) Status() VPNStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	state := "connecting"
	if f.ready {
		state = "ready"
	}
	if f.failed {
		state = "failed"
	}
	if f.stopped {
		state = "stopped"
	}
	return VPNStatus{State: state}
}
func (f *fixtureEnvironment) Wait(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ready = true
	return nil
}
func (f *fixtureEnvironment) BindAddress() string { return "127.0.0.1:0" }
func (f *fixtureEnvironment) Dial(ctx context.Context, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", address)
}
func (f *fixtureEnvironment) Prepare(cmd *exec.Cmd) error {
	cmd.Env = append(cmd.Env, "NETWORK_FIXTURE=1")
	return nil
}
func (f *fixtureEnvironment) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	return nil
}

func TestRuntimeTwoProjectsAndFixedVPN(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	created := map[string]*fixtureEnvironment{}
	s.factory = func(ctx context.Context, project string, p Policy, scope Scope, profile Profile) (Environment, error) {
		f := &fixtureEnvironment{}
		created[project] = f
		return f, nil
	}
	for _, project := range []string{"a", "b"} {
		s.state.Profiles[project] = Profile{ID: project, ProjectID: project}
		if _, err := s.SavePolicy(project, Policy{Mode: "fixed_vpn", VPNProfileID: project, Targets: []string{"target.test"}}, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ConnectVPN(context.Background(), project, Scope{Targets: []string{"target.test"}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(created) != 2 {
		t.Fatal("projects shared one VPN environment")
	}
	if err := s.DisconnectVPN("a"); err != nil {
		t.Fatal(err)
	}
	if !created["a"].stopped || created["b"].stopped {
		t.Fatal("stopping A affected B")
	}
	_, err := s.Acquire(context.Background(), Identity{ProjectID: "b", ConversationID: "cb"}, Scope{Targets: []string{"target.test"}}, AcquireRequest{Target: "https://target.test"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRoutingChangesRetireOldEnvironment(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var created []*fixtureEnvironment
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		f := &fixtureEnvironment{}
		created = append(created, f)
		return f, nil
	}
	s.state.Profiles["profile"] = Profile{ID: "profile", ProjectID: "project"}
	p, err := s.SavePolicy("project", Policy{Mode: "fixed_vpn", VPNProfileID: "profile", Targets: []string{"*.example.test"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Targets: []string{"*.example.test"}}
	if _, err = s.ConnectVPN(context.Background(), "project", scope); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BindAsset(context.Background(), "project", "https://api.example.test", "discovered in authorized API configuration", false, "agent", scope); err != nil {
		t.Fatal(err)
	}
	if !created[0].stopped {
		t.Fatal("asset change kept old routing environment alive")
	}
	if _, err = s.ConnectVPN(context.Background(), "project", scope); err != nil {
		t.Fatal(err)
	}
	p.Exclude = []string{"api.example.test"}
	if _, err = s.SavePolicy("project", p, p.Version); err != nil {
		t.Fatal(err)
	}
	if !created[1].stopped {
		t.Fatal("policy change kept old routing environment alive")
	}
}

func TestCommandCannotUseAnotherProjectsVPNProfile(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	called := false
	s.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
		called = true
		return &fixtureEnvironment{}, nil
	}
	s.state.Profiles["private"] = Profile{ID: "private", ProjectID: "owner"}
	_, err = s.SavePolicy("other", Policy{Mode: "fixed_vpn", VPNProfileID: "private", Targets: []string{"example.test"}}, 0)
	if err != nil {
		return
	}
	err = s.PrepareCommand(context.Background(), Identity{ProjectID: "other", ConversationID: "conversation"}, Scope{Targets: []string{"example.test"}}, exec.Command("unused"))
	if err == nil || called {
		t.Fatal("foreign VPN profile reached runtime factory")
	}
}
