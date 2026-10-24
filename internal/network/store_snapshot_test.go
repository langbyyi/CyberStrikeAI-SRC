package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFailedMutationRestoresNestedNetworkState(t *testing.T) {
	for _, failure := range []string{"mutation", "persistence"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			s, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			if err := s.mutate(func() error {
				s.state.Nodes["node"] = Node{ID: "node", Enabled: true, Version: 1}
				s.state.Credentials["node"] = Credential{Username: "fixture", Password: "synthetic"}
				s.state.Policies["project"] = Policy{Mode: "fixed_vpn", Targets: []string{"owned.test"}, Exclude: []string{"blocked.test"}, DNSServers: []string{"192.0.2.53"}}
				s.state.Bindings["project"] = []Binding{{Target: "api.owned.test", Evidence: "synthetic", UpdatedAt: at}}
				s.state.Profiles["profile"] = Profile{ID: "profile", Files: map[string]string{"ca.crt": "synthetic certificate"}, Credentials: &VPNCredentials{Username: "fixture", Password: "synthetic"}}
				s.state.Sources["source"] = Source{ID: "source", Kind: "fofa", Query: "synthetic"}
				s.state.Observations = []Observation{{NodeID: "node", Reachable: true, ObservedAt: at}}
				s.state.PoolHealth = map[string]PoolHealth{"node": {Version: 1}}
				s.state.Events = []NetworkEvent{{Kind: "synthetic", At: at}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(s.state)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "persistence" {
				s.root = filepath.Join(root, "missing")
			}
			err = s.mutate(func() error {
				delete(s.state.Nodes, "node")
				s.state.Credentials["node"] = Credential{}
				policy := s.state.Policies["project"]
				policy.Targets[0], policy.Exclude[0], policy.DNSServers[0] = "changed.test", "changed.test", "192.0.2.54"
				s.state.Policies["project"] = policy
				s.state.Bindings["project"][0].Target = "changed.test"
				profile := s.state.Profiles["profile"]
				profile.Files["ca.crt"] = "changed"
				profile.Credentials.Password = "changed"
				s.state.Sources["source"] = Source{}
				s.state.Observations[0].Reachable = false
				s.state.PoolHealth["node"] = PoolHealth{}
				s.state.Events[0].Kind = "changed"
				s.state.Validation.Target = "https://changed.test"
				s.state.ValidationGeneration++
				if failure == "mutation" {
					return errors.New("synthetic mutation failure")
				}
				return nil
			})
			if err == nil {
				t.Fatal("expected transaction failure")
			}
			after, err := json.Marshal(s.state)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("failed transaction changed nested state: %v", err)
			}
			reopened, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			onDisk, err := json.Marshal(reopened.state)
			if err != nil || !bytes.Equal(before, onDisk) {
				t.Fatalf("failed transaction changed persisted state: %v", err)
			}
		})
	}
}
