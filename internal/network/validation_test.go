package network

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validationService(t *testing.T) *Service {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestManagedValidationPauseKeepsCompletedBatch(t *testing.T) {
	s := validationService(t)
	control := NewJobControl()
	ctx, cancel := context.WithCancel(WithJobControl(context.Background(), control))
	defer cancel()
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			control.Pause()
		}
		w.WriteHeader(204)
	}))
	defer proxy.Close()
	for index := 0; index < 9; index++ {
		if _, err := s.AddProxy(strings.Replace(proxy.URL, "http://", "http://user"+fmt.Sprint(index)+":synthetic@", 1), "manual"); err != nil {
			t.Fatal(err)
		}
	}
	saveValidation(t, s, ValidationSettings{Target: "http://target.invalid"})
	done := make(chan error, 1)
	go func() {
		_, err := s.ValidatePoolWithSettings(ctx, Identity{}, nil, s.ValidationSettings())
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		state, p := control.Snapshot()
		if state == "paused" {
			if p.Completed != 8 || len(s.PoolObservations()) != 8 || requests.Load() != 8 {
				t.Fatalf("pause lost committed batch: %+v requests=%d", p, requests.Load())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("validation did not pause")
		}
		time.Sleep(time.Millisecond)
	}
	control.Resume()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("validation did not resume")
	}
	if requests.Load() != 9 || len(s.PoolObservations()) != 9 {
		t.Fatal("resume repeated or skipped completed validation")
	}
}

func TestValidationMakesOneTargetGETWithoutProxyPreflight(t *testing.T) {
	s := validationService(t)
	var calls atomic.Int32
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Hostname() != "target.invalid" || r.URL.Path != "/health" {
			t.Errorf("validation must request the target directly through proxy: %s %s", r.Method, r.URL)
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(204)
	})
	saveValidation(t, s, ValidationSettings{Target: "http://target.invalid/health"})
	result, err := s.ValidatePool(context.Background(), Identity{}, []string{n.ID})
	if err != nil || result.Passed != 1 || calls.Load() != 1 {
		t.Fatalf("pool validation used a preflight or failed target GET: %+v calls=%d err=%v", result, calls.Load(), err)
	}
	observations, err := s.Diagnose(context.Background(), Identity{}, Scope{}, "http://target.invalid/health", []string{n.ID})
	if err != nil || len(observations) != 1 || !observations[0].Reachable || calls.Load() != 2 {
		t.Fatalf("target diagnosis used a preflight or failed target GET: %+v calls=%d err=%v", observations, calls.Load(), err)
	}
}

func TestTargetRejectionIsNotUsableForAcquire(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := validationService(t)
			n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
			observations, err := s.Diagnose(context.Background(), Identity{}, Scope{}, "http://target.invalid", []string{n.ID})
			if err != nil || len(observations) != 1 || observations[0].Reachable || observations[0].HTTPStatus != status || observations[0].Reason == "" {
				t.Fatalf("HTTP rejection marked target usable: %+v %v", observations, err)
			}
			if _, err = s.Acquire(context.Background(), Identity{}, Scope{}, AcquireRequest{Target: "http://target.invalid", NodeID: n.ID}); err == nil {
				t.Fatal("target-rejected proxy acquired")
			}
		})
	}
}

func TestTargetSuccessAndRedirectNeedNoExtraRequest(t *testing.T) {
	for _, status := range []int{200, 204, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := validationService(t)
			var calls atomic.Int32
			n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodGet || r.URL.Hostname() != "target.invalid" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				w.Header().Set("Location", "http://unrelated.invalid/redirect")
				w.WriteHeader(status)
			})
			saveValidation(t, s, ValidationSettings{Target: "http://target.invalid"})
			result, err := s.ValidatePool(context.Background(), Identity{}, []string{n.ID})
			if err != nil || result.Passed != 1 || result.Observations[0].HTTPStatus != status || calls.Load() != 1 {
				t.Fatalf("successful target response mishandled or redirect followed: %+v calls=%d err=%v", result, calls.Load(), err)
			}
		})
	}
}

func TestLegacyConnectivityCacheIsNotReusedAsTargetUsability(t *testing.T) {
	s := validationService(t)
	var calls atomic.Int32
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) })
	identity := Identity{ConversationID: "task"}
	target, _ := ParseTarget("http://target.invalid")
	legacyContext := strings.Replace(s.contextKey(identity), "/target-get-v1", "", 1) + fmt.Sprintf("/%d", n.Version)
	s.state.Observations = append(s.state.Observations, Observation{NodeID: n.ID, Target: target.Key(), Context: legacyContext, Reachable: true, HTTPStatus: 403, ExpiresAt: time.Now().Add(time.Minute)})
	lease, err := s.Acquire(context.Background(), identity, Scope{}, AcquireRequest{Target: target.URL(), NodeID: n.ID})
	if err != nil || lease.NodeID != n.ID || calls.Load() != 1 {
		t.Fatalf("legacy connectivity was reused without target GET: %+v calls=%d err=%v", lease, calls.Load(), err)
	}
}

func TestTargetUsabilityCacheSeparatesPathsAndQueries(t *testing.T) {
	for _, pair := range [][2]string{{"/ok", "/blocked"}, {"/query?allow=1", "/query?allow=0"}, {"/encoded%2Fpart?allow=1", "/encoded/part?allow=1"}} {
		t.Run(pair[0], func(t *testing.T) {
			s := validationService(t)
			var calls atomic.Int32
			n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.RequestURI() == pair[0] {
					w.WriteHeader(200)
				} else {
					w.WriteHeader(403)
				}
			})
			good, bad := "http://target.invalid"+pair[0], "http://target.invalid"+pair[1]
			observations, err := s.Diagnose(context.Background(), Identity{}, Scope{}, good, []string{n.ID})
			if err != nil || len(observations) != 1 || !observations[0].Reachable {
				t.Fatalf("GET did not preserve actual target URL: %+v %v", observations, err)
			}
			if _, err = s.Acquire(context.Background(), Identity{}, Scope{}, AcquireRequest{Target: bad, NodeID: n.ID}); err == nil || calls.Load() != 2 {
				t.Fatalf("different target URL reused a successful observation: calls=%d err=%v", calls.Load(), err)
			}
		})
	}
}

func validationProxy(t *testing.T, s *Service, handler http.HandlerFunc) Node {
	t.Helper()
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)
	n, err := s.AddProxy(proxy.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func saveValidation(t *testing.T, s *Service, settings ValidationSettings) {
	t.Helper()
	if _, err := s.SaveValidationSettings(settings); err != nil {
		t.Fatal(err)
	}
}

func TestPoolValidationSettingsPersistAndValidate(t *testing.T) {
	s := validationService(t)
	defaults := s.ValidationSettings()
	if defaults.FailureAction != "keep" || defaults.FailureThreshold != 3 {
		t.Fatalf("defaults: %+v", defaults)
	}
	for _, bad := range []ValidationSettings{{Target: "tcp://test.invalid"}, {Target: "http://test.invalid", FailureAction: "purge"}, {FailureThreshold: 11}, {FailureThreshold: -1}} {
		if _, err := s.SaveValidationSettings(bad); err == nil {
			t.Fatalf("accepted invalid settings: %+v", bad)
		}
	}
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid/health", Contains: "synthetic-secret-marker", FailureAction: "disable", FailureThreshold: 2})
	raw, err := os.ReadFile(filepath.Join(s.root, "state.enc"))
	if err != nil || strings.Contains(string(raw), "synthetic-secret-marker") {
		t.Fatalf("settings not encrypted: %v", err)
	}
	reopened, err := Open(s.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got := reopened.ValidationSettings()
	if got.Target != "http://test.invalid:80/health" || got.Contains != "synthetic-secret-marker" || got.FailureThreshold != 2 {
		t.Fatalf("reopened: %+v", got)
	}
}

func TestPoolValidationEmptyTargetAndPrivateIsolation(t *testing.T) {
	s := validationService(t)
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = fmt.Fprint(w, "ok") }))
	defer proxy.Close()
	shared, _ := s.AddProxy(proxy.URL, "manual")
	private, _ := s.AddProjectProxy("private-project", proxy.URL)
	saveValidation(t, s, ValidationSettings{Target: ""})
	result, err := s.ValidatePool(context.Background(), Identity{}, nil)
	if err != nil || result.Checked != 0 || result.Skipped < 1 || hits.Load() != 0 {
		t.Fatalf("empty target result: %+v %v", result, err)
	}
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid"})
	result, err = s.ValidatePool(context.Background(), Identity{ProjectID: "private-project"}, []string{private.ID, "missing"})
	if err != nil || result.Checked != 0 || result.Skipped != 2 || hits.Load() != 0 {
		t.Fatalf("private leaked/probed or fallback used: %+v %v", result, err)
	}
	result, err = s.ValidatePool(context.Background(), Identity{}, []string{shared.ID})
	if err != nil || result.Passed != 1 || hits.Load() != 1 {
		t.Fatalf("shared failed: %+v %v", result, err)
	}
}

func TestPoolValidationContentDoesNotPoisonAcquire(t *testing.T) {
	s := validationService(t)
	var getCalls, headCalls atomic.Int32
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getCalls.Add(1)
		} else {
			headCalls.Add(1)
		}
		_, _ = fmt.Fprint(w, "expected marker")
	})
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid/path", Contains: "expected"})
	result, err := s.ValidatePool(context.Background(), Identity{}, []string{n.ID})
	if err != nil || result.Passed != 1 || getCalls.Load() != 1 {
		t.Fatalf("content match: %+v %v", result, err)
	}
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid/path", Contains: "missing", FailureAction: "delete", FailureThreshold: 1})
	result, err = s.ValidatePool(context.Background(), Identity{}, []string{n.ID})
	if err != nil || result.Failed != 1 || result.Deleted != 0 || result.Observations[0].Stage != "content" {
		t.Fatalf("content mismatch: %+v %v", result, err)
	}
	lease, err := s.Acquire(context.Background(), Identity{}, Scope{}, AcquireRequest{Target: "http://test.invalid/path", NodeID: n.ID})
	if err != nil || lease.NodeID != n.ID || headCalls.Load() != 0 || getCalls.Load() != 3 {
		t.Fatalf("pool mismatch poisoned connectivity: %+v %v", lease, err)
	}
}

func TestPoolValidationResponseStatusesNeverPrune(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := validationService(t)
			n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
			saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: "delete", FailureThreshold: 1})
			result, err := s.ValidatePool(context.Background(), Identity{}, nil)
			if err != nil || result.Passed != 0 || result.Failed != 1 || result.Deleted != 0 || result.Observations[0].Reachable || result.Observations[0].HTTPStatus != status {
				t.Fatalf("response mistaken for dead proxy: %+v %v", result, err)
			}
			if _, err = s.ProjectProxy("", n.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPoolValidationCancellation(t *testing.T) {
	s := validationService(t)
	started := make(chan struct{}, 1)
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	})
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: "delete", FailureThreshold: 1})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.ValidatePool(ctx, Identity{}, []string{n.ID}); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("validation ignored cancellation")
	}
	if _, err := s.ProjectProxy("", n.ID); err != nil {
		t.Fatal("cancel pruned node", err)
	}
}

func deadValidationProxy(t *testing.T, s *Service) Node {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	address := proxy.URL
	proxy.Close()
	n, err := s.AddProxy(address, "manual")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPoolValidationConsecutiveFailuresAndResets(t *testing.T) {
	s := validationService(t)
	good := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	bad := deadValidationProxy(t, s)
	settings := ValidationSettings{Target: "http://test.invalid", FailureAction: "disable", FailureThreshold: 2}
	saveValidation(t, s, settings)
	for run := 0; run < 2; run++ {
		result, err := s.ValidatePool(context.Background(), Identity{}, []string{good.ID, bad.ID})
		if err != nil || result.Failed != 1 || result.Disabled != run {
			t.Fatalf("failure streak run %d: %+v %v", run, result, err)
		}
	}
	if err := s.SetNode(bad.ID, true); err != nil {
		t.Fatal(err)
	}
	result, err := s.ValidatePool(context.Background(), Identity{}, nil)
	if err != nil || result.Disabled != 0 {
		t.Fatalf("node edit did not reset streak: %+v %v", result, err)
	}
	settings.Target = "http://other.invalid"
	saveValidation(t, s, settings)
	result, err = s.ValidatePool(context.Background(), Identity{}, nil)
	if err != nil || result.Disabled != 0 {
		t.Fatalf("settings did not reset streak: %+v %v", result, err)
	}
	reopened, err := Open(s.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	result, err = reopened.ValidatePool(context.Background(), Identity{}, nil)
	if err != nil || result.Disabled != 1 {
		t.Fatalf("failure streak not persisted: %+v %v", result, err)
	}
}

func TestPoolValidationPruningProtectsReferencesAndAllFailingTarget(t *testing.T) {
	for _, action := range []string{"disable", "delete"} {
		t.Run(action, func(t *testing.T) {
			s := validationService(t)
			bad := deadValidationProxy(t, s)
			saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: action, FailureThreshold: 1})
			result, err := s.ValidatePool(context.Background(), Identity{}, nil)
			if err != nil || !result.PruningSuppressed || result.Disabled != 0 || result.Deleted != 0 {
				t.Fatalf("mass pruning: %+v %v", result, err)
			}
			validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
			if _, err := s.SavePolicy("project", Policy{Mode: "fixed_proxy", ProxyID: bad.ID}, 0); err != nil {
				t.Fatal(err)
			}
			result, err = s.ValidatePool(context.Background(), Identity{}, nil)
			if err != nil || result.Disabled != 0 || result.Deleted != 0 {
				t.Fatalf("project reference pruned: %+v %v", result, err)
			}
			n, err := s.ProjectProxy("", bad.ID)
			if err != nil || !n.Enabled {
				t.Fatalf("project reference changed: %+v %v", n, err)
			}
			if _, err := s.SavePolicy("project", Policy{Mode: "auto"}, 1); err != nil {
				t.Fatal(err)
			}
			result, err = s.ValidatePool(context.Background(), Identity{}, nil)
			if err != nil || result.Disabled+result.Deleted != 1 {
				t.Fatalf("opt-in cleanup did not run: %+v %v", result, err)
			}
		})
	}
}

func TestPoolValidationEditedCredentialDuringProbeIsProtected(t *testing.T) {
	s := validationService(t)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { started <- struct{}{}; <-release; w.WriteHeader(407) })
	validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: "delete", FailureThreshold: 1})
	done := make(chan PoolValidationResult, 1)
	go func() { result, _ := s.ValidatePool(context.Background(), Identity{}, nil); done <- result }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	address := strings.Replace(n.Address, "://", "://synthetic:replacement@", 1)
	if _, err := s.UpdateProxy(n.ID, address, true); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case result := <-done:
		if result.Deleted != 0 {
			t.Fatalf("edited node pruned: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("validation did not finish")
	}
	if _, err := s.ProjectProxy("", n.ID); err != nil {
		t.Fatal(err)
	}
}

func TestPoolValidationContentReadBounded(t *testing.T) {
	s := validationService(t)
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, strings.Repeat("x", (1<<20)+1)+"needle")
	})
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", Contains: "needle", FailureAction: "delete", FailureThreshold: 1})
	result, err := s.ValidatePool(context.Background(), Identity{}, []string{n.ID})
	if err != nil || result.Failed != 1 || result.Deleted != 0 || result.Observations[0].Stage != "content" {
		t.Fatalf("unbounded content assertion: %+v %v", result, err)
	}
}

func TestPoolValidationResponsiveRunResetsCleanupFailures(t *testing.T) {
	s := validationService(t)
	var failing atomic.Bool
	failing.Store(true)
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(407)
			return
		}
		w.WriteHeader(403)
	})
	validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: "delete", FailureThreshold: 2})
	for index, fail := range []bool{true, false, true, true} {
		failing.Store(fail)
		result, err := s.ValidatePool(context.Background(), Identity{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Deleted > 0 {
			if index != 3 {
				t.Fatalf("proxy deleted before consecutive failures: run=%d %+v", index, result)
			}
			if _, err := s.ProjectProxy("", n.ID); err == nil {
				t.Fatal("cleanup not persisted")
			}
			return
		}
		if _, err := s.ProjectProxy("", n.ID); err != nil {
			t.Fatal("node deleted before consecutive threshold", err)
		}
	}
	t.Fatal("proxy-auth failure did not trigger opt-in cleanup")
}

func TestPoolValidationWorkersAndRunSizeAreBounded(t *testing.T) {
	s := validationService(t)
	var active, peak, hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		for prior := peak.Load(); current > prior; prior = peak.Load() {
			if peak.CompareAndSwap(prior, current) {
				break
			}
		}
		hits.Add(1)
		time.Sleep(time.Millisecond)
		active.Add(-1)
		w.WriteHeader(204)
	}))
	defer proxy.Close()
	// Synthetic encrypted state fixture avoids 1001 unrelated disk writes during setup.
	base, credential, err := NormalizeProxy(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = s.mutate(func() error {
		for index := 0; index < 1001; index++ {
			n := base
			n.ID = fmt.Sprintf("synthetic-%04d", index)
			n.Version = 1
			n.Enabled = true
			s.state.Nodes[n.ID] = n
			s.state.Credentials[n.ID] = credential
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid"})
	result, err := s.ValidatePool(context.Background(), Identity{}, nil)
	if err != nil || result.Checked != 1000 || result.Skipped != 1 || hits.Load() != 1000 || peak.Load() > 8 {
		t.Fatalf("unbounded validation: checked=%d skipped=%d hits=%d peak=%d err=%v", result.Checked, result.Skipped, hits.Load(), peak.Load(), err)
	}
}

func TestValidationDefaultsToBaiduAndExplicitEmptyRemainsEmpty(t *testing.T) {
	s := validationService(t)
	if s.ValidationSettings().Target != "https://www.baidu.com:443" {
		t.Fatalf("unexpected default: %+v", s.ValidationSettings())
	}
	if _, err := s.SaveValidationSettings(ValidationSettings{Target: ""}); err != nil {
		t.Fatal(err)
	}
	if s.ValidationSettings().Target != "" {
		t.Fatal("explicit empty target was replaced")
	}
	reopened, err := Open(s.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.ValidationSettings().Target != "" {
		t.Fatal("explicit empty target was not persisted")
	}
	result, err := reopened.ValidatePool(context.Background(), Identity{}, nil)
	if err != nil || result.Checked != 0 || result.Reason == "" {
		t.Fatalf("empty target not skipped: %+v %v", result, err)
	}
}
