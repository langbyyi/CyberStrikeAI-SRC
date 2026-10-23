//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

var ownedNamespaceName = regexp.MustCompile(`^csn-[0-9a-f]{10}$`)

type hostForwarding struct {
	rules     [][]string
	installed int
}

func (e *linuxEnvironment) enableHostForwarding(ctx context.Context) error {
	ip, err := netip.ParseAddr(e.clientIP)
	if err != nil || !ip.Is4() || !ip.IsLinkLocalUnicast() || !ownedNamespaceName.MatchString(e.ns) || e.hostIf != "csh"+e.ns[4:] {
		return fmt.Errorf("refusing host forwarding for an invalid project interface or address")
	}
	comment := []string{"-m", "comment", "--comment", "cyberstrike:" + e.ns, "-j", "ACCEPT"}
	// The namespace firewall remains responsible for destination scope. Host rules
	// only bridge this owned interface across pre-existing default DROP policies.
	e.forwarding = &hostForwarding{rules: [][]string{
		append([]string{"-i", e.hostIf, "-s", ip.String() + "/32", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED"}, comment...),
		append([]string{"-o", e.hostIf, "-d", ip.String() + "/32", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"}, comment...),
	}}
	for _, rule := range e.forwarding.rules {
		if err := runNetwork(ctx, "", "iptables", append([]string{"-w", "2", "-I", "FORWARD", "1"}, rule...)...); err != nil {
			return fmt.Errorf("allow project interface %s forwarding: %w", e.hostIf, err)
		}
		e.forwarding.installed++
	}
	return nil
}

func (e *linuxEnvironment) removeHostForwarding(ctx context.Context) error {
	if e.forwarding == nil {
		return nil
	}
	var failures []error
	for n := e.forwarding.installed - 1; n >= 0; n-- {
		if err := runNetwork(ctx, "", "iptables", append([]string{"-w", "2", "-D", "FORWARD"}, e.forwarding.rules[n]...)...); err != nil {
			failures = append(failures, fmt.Errorf("remove project interface %s forwarding: %w", e.hostIf, err))
		}
	}
	return errors.Join(failures...)
}
