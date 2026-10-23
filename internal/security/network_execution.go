package security

import (
	"context"
	"os/exec"
	"sync"
)

var networkCommandHook struct {
	sync.RWMutex
	prepare   func(context.Context, *exec.Cmd) error
	closeTask func(context.Context)
}

func SetNetworkTaskCloser(closeTask func(context.Context)) {
	networkCommandHook.Lock()
	networkCommandHook.closeTask = closeTask
	networkCommandHook.Unlock()
}
func closeTaskNetwork(ctx context.Context) {
	networkCommandHook.RLock()
	closeTask := networkCommandHook.closeTask
	networkCommandHook.RUnlock()
	if closeTask != nil {
		closeTask(ctx)
	}
}

func SetNetworkCommandPreparer(prepare func(context.Context, *exec.Cmd) error) {
	networkCommandHook.Lock()
	networkCommandHook.prepare = prepare
	networkCommandHook.Unlock()
}
func prepareCommandNetwork(ctx context.Context, cmd *exec.Cmd) error {
	networkCommandHook.RLock()
	prepare := networkCommandHook.prepare
	networkCommandHook.RUnlock()
	if prepare == nil {
		return nil
	}
	return prepare(ctx, cmd)
}
