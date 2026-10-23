package network

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestBulkUpdateProxiesProtectsPrivateAndReferencedNodes(t *testing.T) {
	s := validationService(t)
	shared, _ := s.AddProxy("http://127.0.0.1:19001", "manual")
	protected, _ := s.AddProxy("http://127.0.0.1:19002", "manual")
	private, _ := s.AddProjectProxy("project", "http://127.0.0.1:19003")
	if _, err := s.SavePolicy("project", Policy{Mode: "fixed_proxy", ProxyID: protected.ID}, 0); err != nil {
		t.Fatal(err)
	}
	result, err := s.BulkUpdateProxies([]string{shared.ID, protected.ID, private.ID, "missing"}, "delete")
	if err != nil || result.Updated != 1 || result.Skipped != 3 {
		t.Fatalf("bulk delete: %+v %v", result, err)
	}
	if _, err := s.ProjectProxy("", shared.ID); err == nil {
		t.Fatal("shared node not deleted")
	}
	if _, err := s.ProjectProxy("project", private.ID); err != nil {
		t.Fatal("private node deleted", err)
	}
	if _, err := s.ProjectProxy("", protected.ID); err != nil {
		t.Fatal("reference deleted", err)
	}
}

func TestInactiveProjectProxyReferenceDoesNotBlockPoolCleanup(t *testing.T) {
	for _, action := range []string{"bulk_delete", "validation_delete", "validation_disable"} {
		t.Run(action, func(t *testing.T) {
			s := validationService(t)
			n := validationProxy(t, s, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(407) })
			validationProxy(t, s, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
			policy, err := s.SavePolicy("project", Policy{Mode: "fixed_proxy", ProxyID: n.ID}, 0)
			if err != nil {
				t.Fatal(err)
			}
			policy.Mode = "auto"
			if _, err := s.SavePolicy("project", policy, policy.Version); err != nil {
				t.Fatal(err)
			}
			if action == "bulk_delete" {
				result, err := s.BulkUpdateProxies([]string{n.ID}, "delete")
				if err != nil || result.Updated != 1 {
					t.Fatalf("inactive project reference prevented bulk deletion: %+v %v", result, err)
				}
				return
			}
			cleanup := "delete"
			if action == "validation_disable" {
				cleanup = "disable"
			}
			saveValidation(t, s, ValidationSettings{Target: "http://target.example.test", FailureAction: cleanup, FailureThreshold: 1})
			result, err := s.ValidatePool(context.Background(), Identity{}, nil)
			if err != nil || result.Deleted+result.Disabled != 1 {
				t.Fatalf("inactive project reference prevented validation cleanup: %+v %v", result, err)
			}
		})
	}
}

func TestBulkUpdateProxiesValidationAndVersionInvalidation(t *testing.T) {
	s := validationService(t)
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid"})
	if _, err := s.ValidatePool(context.Background(), Identity{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(s.PoolObservations()) != 1 {
		t.Fatal("pool observation missing")
	}
	for _, action := range []string{"disable", "enable"} {
		old, _ := s.ProjectProxy("", n.ID)
		result, err := s.BulkUpdateProxies([]string{n.ID}, action)
		updated, _ := s.ProjectProxy("", n.ID)
		if err != nil || result.Updated != 1 || updated.Version != old.Version+1 || len(s.PoolObservations()) != 0 {
			t.Fatalf("bulk %s: %+v %+v %v", action, result, updated, err)
		}
	}
	for _, ids := range [][]string{nil, make([]string, 1001)} {
		if _, err := s.BulkUpdateProxies(ids, "delete"); err == nil {
			t.Fatal("accepted unbounded bulk request")
		}
	}
	if _, err := s.BulkUpdateProxies([]string{n.ID}, "purge"); err == nil {
		t.Fatal("accepted unknown action")
	}
	if _, err := s.ProjectProxy("", n.ID); err != nil {
		t.Fatal("invalid action mutated nodes")
	}
}

func TestPoolObservationRetainsAutomaticDisableReason(t *testing.T) {
	s := validationService(t)
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(407) })
	validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: "disable", FailureThreshold: 1})
	result, err := s.ValidatePool(context.Background(), Identity{}, nil)
	if err != nil || result.Disabled != 1 {
		t.Fatalf("auto-disable: %+v %v", result, err)
	}
	observations := s.PoolObservations()
	if observation, ok := observations[n.ID]; !ok || observation.Stage != "proxy_auth" || observation.Reachable || observation.Reason == "" {
		t.Fatalf("automatic disable hid its reason: %+v", observations)
	}
}

func TestPoolValidationSettingsSnapshotRejectsChangedConfiguration(t *testing.T) {
	s := validationService(t)
	var hits int
	validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(204) })
	saveValidation(t, s, ValidationSettings{Target: "http://first.invalid"})
	snapshot := s.ValidationSettings()
	saveValidation(t, s, ValidationSettings{Target: "http://second.invalid"})
	result, err := s.ValidatePoolWithSettings(context.Background(), Identity{}, nil, snapshot)
	if err == nil || result.Checked != 0 || hits != 0 {
		t.Fatalf("old job probed new target: %+v hits=%d error=%v", result, hits, err)
	}
}

func TestBulkUpdateProxiesRollsBackOnPersistenceFailure(t *testing.T) {
	s := validationService(t)
	first, _ := s.AddProxy("http://127.0.0.1:19011", "manual")
	second, _ := s.AddProxy("http://127.0.0.1:19012", "manual")
	s.root = filepath.Join(t.TempDir(), "missing-state-directory")
	result, err := s.BulkUpdateProxies([]string{first.ID, second.ID}, "disable")
	if err == nil || result.Updated != 0 {
		t.Fatalf("failed bulk save claimed updates: %+v %v", result, err)
	}
	for _, old := range []Node{first, second} {
		current, err := s.ProjectProxy("", old.ID)
		if err != nil || current != old {
			t.Fatalf("partial bulk update escaped rollback: old=%+v current=%+v %v", old, current, err)
		}
	}
}

func TestPoolValidationBatchesShareTargetHealthBeforePruning(t *testing.T) {
	s := validationService(t)
	bad := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(407) })
	good := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	ids := []string{}
	if err := s.mutate(func() error {
		delete(s.state.Nodes, bad.ID)
		delete(s.state.Nodes, good.ID)
		for index := 0; index < 1000; index++ {
			n := bad
			n.ID = fmt.Sprintf("a-%04d", index)
			s.state.Nodes[n.ID] = n
			ids = append(ids, n.ID)
		}
		good.ID = "z-healthy"
		s.state.Nodes[good.ID] = good
		ids = append(ids, good.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: "delete", FailureThreshold: 1})
	result, err := s.ValidatePoolWithSettings(context.Background(), Identity{}, ids, s.ValidationSettings())
	if err != nil || result.Checked != 1001 || result.Deleted != 1000 || result.PruningSuppressed || len(s.Nodes()) != 1 {
		t.Fatalf("per-batch target-health decision prevented cleanup: checked=%d deleted=%d suppressed=%v remaining=%d error=%v", result.Checked, result.Deleted, result.PruningSuppressed, len(s.Nodes()), err)
	}
}

func TestPoolValidationCONNECTHTTPResponsesAreNotTransportFailures(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := validationService(t)
			denied := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodConnect {
					t.Error("expected HTTPS CONNECT")
				}
				w.WriteHeader(status)
			})
			validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(407) })
			saveValidation(t, s, ValidationSettings{Target: "https://test.invalid", FailureAction: "delete", FailureThreshold: 1})
			result, err := s.ValidatePool(context.Background(), Identity{}, nil)
			if err != nil || result.Deleted != 1 {
				t.Fatalf("CONNECT classification: %+v %v", result, err)
			}
			if _, err := s.ProjectProxy("", denied.ID); err != nil {
				t.Fatal("responsive denied proxy was deleted", err)
			}
			for _, observation := range result.Observations {
				if observation.NodeID == denied.ID && (observation.HTTPStatus != status || observation.Stage != "http_status") {
					t.Fatalf("CONNECT response status lost: %+v", observation)
				}
			}
		})
	}
}

func TestPoolValidationCanceledLaterBatchPreservesObservationsWithoutPruning(t *testing.T) {
	s := validationService(t)
	bad := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(407) })
	good := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	started := make(chan struct{})
	release := make(chan struct{})
	slow := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	// Unblock the fixture before httptest.Server.Close even when setup times out.
	t.Cleanup(func() { close(release) })
	ids := []string{}
	if err := s.mutate(func() error {
		delete(s.state.Nodes, bad.ID)
		delete(s.state.Nodes, good.ID)
		delete(s.state.Nodes, slow.ID)
		for index := 0; index < 999; index++ {
			n := bad
			n.ID = fmt.Sprintf("a-%04d", index)
			s.state.Nodes[n.ID] = n
			ids = append(ids, n.ID)
		}
		good.ID = "b-healthy"
		s.state.Nodes[good.ID] = good
		ids = append(ids, good.ID)
		slow.ID = "z-slow"
		s.state.Nodes[slow.ID] = slow
		ids = append(ids, slow.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: "delete", FailureThreshold: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		result PoolValidationResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := s.ValidatePoolWithSettings(ctx, Identity{}, ids, s.ValidationSettings())
		done <- outcome{result, err}
	}()
	select {
	case <-started:
	// These 1000 loopback requests are setup; cancellation below still has a 1s deadline.
	case <-time.After(15 * time.Second):
		t.Fatal("later batch did not start")
	}
	cancel()
	select {
	case outcome := <-done:
		if !errors.Is(outcome.err, context.Canceled) || outcome.result.Deleted != 0 || len(s.Nodes()) != 1001 || len(s.PoolObservations()) != 1000 {
			t.Fatalf("cancellation pruned or lost completed batch: deleted=%d remaining=%d saved=%d err=%v", outcome.result.Deleted, len(s.Nodes()), len(s.PoolObservations()), outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop later batch")
	}
}

func TestPoolValidationOlderFailureCannotOverwriteNewerSuccess(t *testing.T) {
	s := validationService(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			w.WriteHeader(407)
			return
		}
		w.WriteHeader(204)
	})
	validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: "delete", FailureThreshold: 1})
	settings := s.ValidationSettings()
	done := make(chan error, 1)
	go func() {
		_, err := s.ValidatePoolWithSettings(context.Background(), Identity{}, nil, settings)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("older probe did not start")
	}
	if result, err := s.ValidatePoolWithSettings(context.Background(), Identity{}, nil, settings); err != nil || result.Passed != 2 {
		t.Fatalf("newer validation: %+v %v", result, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProjectProxy("", n.ID); err != nil {
		t.Fatal("older failed probe deleted a newer working proxy", err)
	}
	if observation := s.PoolObservations()[n.ID]; !observation.Reachable {
		t.Fatalf("older failure replaced newer success: %+v", observation)
	}
}

func TestPoolValidationGenerationContinuesAfterReopen(t *testing.T) {
	s := validationService(t)
	var failing atomic.Bool
	n := validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(407)
			return
		}
		w.WriteHeader(204)
	})
	validationProxy(t, s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	saveValidation(t, s, ValidationSettings{Target: "http://test.invalid", FailureAction: "delete", FailureThreshold: 1})
	for run := 0; run < 3; run++ {
		if _, err := s.ValidatePool(context.Background(), Identity{}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	failing.Store(true)
	result, err := reopened.ValidatePool(context.Background(), Identity{}, nil)
	if err != nil || result.Deleted != 1 {
		t.Fatalf("persisted health rejected reopened generation: %+v %v", result, err)
	}
	if _, err := reopened.ProjectProxy("", n.ID); err == nil {
		t.Fatal("new failure ignored after reopen")
	}
}
