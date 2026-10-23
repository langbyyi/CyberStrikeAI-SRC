package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEventRingStaysBoundedAndSanitized(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < maxNetworkEvents+50; i++ {
		s.recordEvent("lease_acquired", "p", "", "node", 3, "synthetic")
	}
	events := s.Events()
	if len(events) != maxNetworkEvents {
		t.Fatalf("event ring holds %d, want %d", len(events), maxNetworkEvents)
	}
	if events[0].Kind != "lease_acquired" || !events[0].At.After(events[len(events)-1].At) {
		t.Fatal("ring is not newest-first")
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"http://", "socks5://", "password", "@"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("event log leaked address-shaped data via %q", leak)
		}
	}
}

func TestLeaseAndRetirementEventsRecorded(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()
	n, _ := s.AddProxy(upstream.URL, "manual")
	i := Identity{UserID: "u", ConversationID: "c"}
	lease, err := s.Acquire(context.Background(), i, Scope{}, AcquireRequest{Target: "http://target.test", NodeID: n.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Release(i, lease.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BulkUpdateProxies([]string{n.ID}, "disable"); err != nil {
		t.Fatal(err)
	}
	kinds := []string{}
	for _, e := range s.Events() {
		kinds = append(kinds, e.Kind)
		if e.From == upstream.URL || e.To == upstream.URL {
			t.Fatalf("event carries the raw address: %+v", e)
		}
	}
	for _, want := range []string{"lease_acquired", "lease_released", "node_retired"} {
		found := false
		for _, kind := range kinds {
			if kind == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s event; got %v", want, kinds)
		}
	}
}

func TestPolicyUpdateEventCarriesVersions(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	if _, err := s.SavePolicy("p", Policy{Mode: "auto"}, 0); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range s.Events() {
		if e.Kind == "policy_updated" && e.Project == "p" && e.From == "v0" && e.To == "v1" && e.Version == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy transition not recorded: %+v", s.Events())
	}
}
