package network

import (
	"fmt"
	"strings"
	"testing"
)

type cleanupFailedEnvironment struct {
	fixtureEnvironment
	attempted bool
}

func (e *cleanupFailedEnvironment) Close() error {
	e.attempted = true
	return fmt.Errorf("synthetic forwarding cleanup failure")
}

func TestDisconnectReportsCleanupFailuresAndClosesEveryEnvironment(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, second := &cleanupFailedEnvironment{}, &cleanupFailedEnvironment{}
	for key, env := range map[string]*cleanupFailedEnvironment{"first": first, "second": second} {
		done := make(chan struct{})
		close(done)
		s.environments[key] = &environmentEntry{project: "p", env: env, done: done}
	}
	err = s.DisconnectVPN("p")
	if err == nil || !strings.Contains(err.Error(), "forwarding cleanup failure") || !first.attempted || !second.attempted {
		t.Fatalf("disconnect hid cleanup failures or stopped early: %v", err)
	}
}
