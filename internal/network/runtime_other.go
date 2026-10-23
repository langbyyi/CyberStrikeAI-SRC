//go:build !linux

package network

import (
	"context"
	"fmt"
)

func newSystemEnvironment(context.Context, string, string, Policy, Scope, Profile) (Environment, error) {
	return nil, fmt.Errorf("isolated project proxy/OpenVPN execution requires Linux, iproute2, nftables and OpenVPN; direct fallback is disabled")
}
