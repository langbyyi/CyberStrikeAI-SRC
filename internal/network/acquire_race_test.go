package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAcquireCannotLeaseNodeChangedDuringProbe(t *testing.T) {
	for _, change := range []string{"disable", "credentials"} {
		t.Run(change, func(t *testing.T) {
			s := validationService(t)
			started, resume := make(chan struct{}), make(chan struct{})
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(started)
				<-resume
				w.WriteHeader(http.StatusOK)
			}))
			defer proxy.Close()
			node, err := s.AddProxy(proxy.URL, "manual")
			if err != nil {
				t.Fatal(err)
			}
			identity := Identity{UserID: "fixture", ConversationID: "task"}
			finished := make(chan error, 1)
			go func() {
				_, err := s.Acquire(context.Background(), identity, Scope{}, AcquireRequest{Target: "http://target.test", NodeID: node.ID})
				finished <- err
			}()
			<-started
			if change == "disable" {
				err = s.SetNode(node.ID, false)
			} else {
				_, err = s.UpdateProxy(node.ID, "http://fixture:updated-synthetic-secret@"+proxy.Listener.Addr().String(), true)
			}
			close(resume)
			if err != nil {
				t.Fatal(err)
			}
			if err = <-finished; err == nil {
				t.Fatal("acquire accepted a stale reachability check after the node changed")
			}
			if _, ok := s.SelectedLease(identity); ok {
				t.Fatal("changed node retained a task lease")
			}
		})
	}
}
