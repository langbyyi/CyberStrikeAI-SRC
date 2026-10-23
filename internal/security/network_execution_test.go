package security

import (
	"context"
	"errors"
	"os/exec"
	"sync/atomic"
	"testing"
)

func TestNetworkPreparationFailsBeforeCommandStart(t *testing.T) {
	sentinel := errors.New("fixture network is unavailable")
	SetNetworkCommandPreparer(func(context.Context, *exec.Cmd) error { return sentinel })
	defer SetNetworkCommandPreparer(nil)
	started := false
	_, err := startShellSessionContext(context.Background(), exec.Command("unused"), func() error { started = true; return nil })
	if !errors.Is(err, sentinel) || started {
		t.Fatalf("command started before network was ready: %v", err)
	}
}

func TestNetworkTaskCleanupOnScopeClose(t *testing.T) {
	scope := NewProcessScope()
	ctx := WithProcessScope(context.Background(), scope)
	calls := 0
	SetNetworkTaskCloser(func(context.Context) { calls++ })
	defer SetNetworkTaskCloser(nil)
	SetNetworkCommandPreparer(func(context.Context, *exec.Cmd) error { return errors.New("not ready") })
	defer SetNetworkCommandPreparer(nil)
	_, _ = startShellSessionContext(ctx, exec.Command("unused"), func() error { return nil })
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("network cleanup called %d times", calls)
	}
}

// A scope can seal while a command is still preparing its network. Close spends its
// one-shot cleanup before that preparation finishes, so the preparation must release
// the environment and gateway it created for a task that will never start.
func TestNetworkTaskCleanupReleasesWorkPreparedDuringClose(t *testing.T) {
	scope := NewProcessScope()
	ctx := WithProcessScope(context.Background(), scope)
	entered := make(chan struct{})
	release := make(chan struct{})
	var closes int32
	SetNetworkTaskCloser(func(context.Context) { atomic.AddInt32(&closes, 1) })
	defer SetNetworkTaskCloser(nil)
	SetNetworkCommandPreparer(func(context.Context, *exec.Cmd) error {
		close(entered)
		<-release
		return nil
	})
	defer SetNetworkCommandPreparer(nil)

	result := make(chan error, 1)
	go func() {
		_, err := startShellSessionContext(ctx, exec.Command("unused"), func() error { return nil })
		result <- err
	}()
	<-entered
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrProcessScopeClosed) {
		t.Fatalf("command prepared a network for a sealed scope: %v", err)
	}
	if got := atomic.LoadInt32(&closes); got != 2 {
		t.Fatalf("network prepared during close was not released: cleanup called %d times, want 2", got)
	}
}
