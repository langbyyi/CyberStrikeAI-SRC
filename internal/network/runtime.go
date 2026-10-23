package network

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type VPNStatus struct {
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
	Environment string `json:"environment,omitempty"`
	Attempts    int    `json:"attempts"`
}
type Environment interface {
	Status() VPNStatus
	Wait(context.Context) error
	BindAddress() string
	Dial(context.Context, string) (net.Conn, error)
	Prepare(*exec.Cmd) error
	Close() error
}
type EnvironmentFactory func(context.Context, string, Policy, Scope, Profile) (Environment, error)
type environmentEntry struct {
	done    chan struct{}
	env     Environment
	err     error
	project string
	version int64
}

func effectiveScope(p Policy, scope Scope, bindings []Binding) Scope {
	out := scope
	out.Targets, out.Exclude = append([]string{}, scope.Targets...), append([]string{}, scope.Exclude...)
	if len(p.Targets) > 0 {
		out.Targets = append([]string{}, p.Targets...)
	}
	out.Exclude = append(out.Exclude, p.Exclude...)
	for _, b := range bindings {
		// A semantic decision is active only when the caller resolved it against
		// current project instructions. Empty scopes must not revive old decisions.
		if !b.Excluded && b.ScopeContext != "" && !scope.containsRule(b.Target) {
			continue
		}
		if b.Excluded {
			out.Exclude = append(out.Exclude, b.Target)
		} else {
			out.Targets = append(out.Targets, b.Target)
		}
	}
	// Saved policies and discovered bindings can outlive a project-scope edit.
	// Intersect them again at execution time so revoked assets cannot be restored.
	if len(scope.Targets) > 0 {
		var targets []string
		for _, candidate := range out.Targets {
			for _, allowed := range scope.Targets {
				switch {
				case ruleCovers(allowed, candidate):
					targets = append(targets, candidate)
				case ruleCovers(candidate, allowed):
					targets = append(targets, allowed)
				}
			}
		}
		out.Targets = targets
	}
	canonical := func(items []string) []string {
		unique := map[string]bool{}
		for _, item := range items {
			unique[item] = true
		}
		result := make([]string, 0, len(unique))
		for item := range unique {
			result = append(result, item)
		}
		sort.Strings(result)
		return result
	}
	out.Targets, out.Exclude = canonical(out.Targets), canonical(out.Exclude)
	return out
}
func (s *Service) environment(ctx context.Context, project string, p Policy, scope Scope) (Environment, error) {
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("network service is closed")
	}
	// Admission is serialized with DisconnectVPN. A queued job cannot recreate a
	// revoked environment using a scope read before the project edit completed.
	if err := s.checkScopeCurrentLocked(scope); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if current, exists := s.state.Policies[project]; exists && current.Version != p.Version {
		s.mu.Unlock()
		return nil, fmt.Errorf("project network policy changed; retry using the current configuration")
	}
	if leaseID, leased := strings.CutPrefix(project, "lease-"); leased {
		lease, exists := s.leases[leaseID]
		if !exists || lease.NodeID != p.ProxyID || !time.Now().Before(lease.ExpiresAt) {
			s.mu.Unlock()
			return nil, fmt.Errorf("network lease is no longer active")
		}
	}
	routeScope := effectiveScope(p, scope, s.state.Bindings[project])
	encoded, _ := json.Marshal(routeScope)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(encoded))
	key := fmt.Sprintf("%s/%d/%s", project, p.Version, fingerprint)
	profile := s.state.Profiles[p.VPNProfileID]
	if p.Mode == "fixed_vpn" && (profile.ID == "" || profile.ProjectID != project) {
		s.mu.Unlock()
		return nil, fmt.Errorf("VPN profile does not belong to this project")
	}
	entry := s.environments[key]
	if entry != nil {
		select {
		case <-entry.done:
			// A new operation may retry a terminated environment; each creation still has a bounded reconnect budget.
			if entry.err != nil {
				entry = nil
			} else if status := entry.env.Status(); status.State == "stopped" || status.State == "failed" && status.Reason != vpnAuthenticationFailedReason {
				entry = nil
			}
		default:
		}
	}
	if entry == nil {
		var stale []*environmentEntry
		for oldKey, old := range s.environments {
			if old.project == project {
				stale = append(stale, old)
				delete(s.environments, oldKey)
			}
		}
		var gateways []*Gateway
		for oldKey, g := range s.gateways {
			if strings.HasPrefix(oldKey, project+"/") {
				gateways = append(gateways, g)
				delete(s.gateways, oldKey)
			}
		}
		entry = &environmentEntry{done: make(chan struct{}), project: project, version: p.Version}
		s.environments[key] = entry
		s.generations[project]++
		generation := s.generations[project]
		factory := s.factory
		replaced := len(stale)
		s.mu.Unlock()
		s.recordEvent("environment_rebuilt", project, "", fmt.Sprintf("gen-%d", generation), p.Version, fmt.Sprintf("replaced %d previous environment(s); running tasks on the old generation were disconnected", replaced))
		for _, g := range gateways {
			_ = g.Close()
		}
		for _, old := range stale {
			<-old.done
			if old.env != nil {
				_ = old.env.Close()
			}
		}
		entry.env, entry.err = factory(context.Background(), project, p, routeScope, profile)
		close(entry.done)
	} else {
		s.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-entry.done:
	}
	s.mu.Lock()
	if s.closed || s.environments[key] != entry || s.state.Policies[project].Version != p.Version && !strings.HasPrefix(project, "lease-") {
		s.mu.Unlock()
		return nil, fmt.Errorf("project network changed while creating environment; retry using the current scope")
	}
	if err := s.checkScopeCurrentLocked(scope); err != nil {
		delete(s.environments, key)
		s.mu.Unlock()
		if entry.env != nil {
			_ = entry.env.Close()
		}
		return nil, err
	}
	s.mu.Unlock()
	if entry.err != nil {
		return nil, entry.err
	}
	return entry.env, nil
}
func (s *Service) ConnectVPN(ctx context.Context, project string, scope Scope) (VPNStatus, error) {
	if err := s.checkExecutionScope(Identity{ProjectID: project}, scope); err != nil {
		return VPNStatus{}, err
	}
	p := s.Policy(project)
	if p.Mode != "fixed_vpn" {
		return VPNStatus{}, fmt.Errorf("project is not configured for OpenVPN")
	}
	s.mu.RLock()
	profile, exists := s.state.Profiles[p.VPNProfileID]
	s.mu.RUnlock()
	if !exists || profile.ProjectID != project {
		return VPNStatus{}, fmt.Errorf("VPN profile does not belong to this project")
	}
	if len(effectiveScope(p, scope, s.Bindings(project)).Targets) == 0 {
		return VPNStatus{}, fmt.Errorf("project testing targets are required before connecting VPN")
	}
	env, err := s.environment(ctx, project, p, scope)
	if err != nil {
		return VPNStatus{State: "failed", Reason: err.Error()}, err
	}
	if err = env.Wait(ctx); err != nil {
		return env.Status(), err
	}
	return env.Status(), nil
}
func (s *Service) VPNStatus(project string) VPNStatus {
	s.mu.RLock()
	var entry *environmentEntry
	for _, e := range s.environments {
		if e.project == project && (entry == nil || e.version > entry.version) {
			entry = e
		}
	}
	s.mu.RUnlock()
	if entry == nil {
		return VPNStatus{State: "stopped"}
	}
	select {
	case <-entry.done:
		if entry.err != nil {
			return VPNStatus{State: "failed", Reason: entry.err.Error()}
		}
		return entry.env.Status()
	default:
		return VPNStatus{State: "connecting"}
	}
}
func (s *Service) DisconnectVPN(project string) error {
	s.mu.Lock()
	if s.retirements == nil {
		s.retirements = map[string]uint64{}
	}
	s.retirements[project]++
	projects := map[string]bool{project: true}
	for id, l := range s.leases {
		if l.ProjectID == project {
			projects["lease-"+id] = true
			s.retirements["lease-"+id]++
			delete(s.leases, id)
		}
	}
	entries := []*environmentEntry{}
	for key, entry := range s.environments {
		if projects[entry.project] {
			entries = append(entries, entry)
			delete(s.environments, key)
		}
	}
	gateways := []*Gateway{}
	for key, g := range s.gateways {
		owner, _, _ := strings.Cut(key, "/")
		if projects[owner] {
			gateways = append(gateways, g)
			delete(s.gateways, key)
		}
	}
	s.mu.Unlock()
	var failures []error
	for _, g := range gateways {
		if err := g.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	for _, entry := range entries {
		<-entry.done
		if entry.env != nil {
			if err := entry.env.Close(); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}
func proxyEnvironment(env []string, gateway string) []string {
	if env == nil {
		env = os.Environ()
	}
	out := make([]string, 0, len(env)+8)
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		switch strings.ToLower(key) {
		case "http_proxy", "https_proxy", "all_proxy", "no_proxy":
			continue
		}
		out = append(out, item)
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		out = append(out, name+"="+gateway)
	}
	return append(out, "NO_PROXY=", "no_proxy=")
}
func (s *Service) PrepareCommand(ctx context.Context, i Identity, scope Scope, cmd *exec.Cmd) error {
	if err := s.checkExecutionScope(i, scope); err != nil {
		return err
	}
	p := s.Policy(i.ProjectID)
	lease, selected := s.SelectedLease(i)
	if p.Mode == "auto" && !selected {
		return nil
	}
	if i.ConversationID == "" {
		return fmt.Errorf("network-routed command requires a trusted conversation context")
	}
	if len(scope.Targets) == 0 && len(p.Targets) == 0 && p.Mode != "auto" {
		return fmt.Errorf("fixed project network requires resolved testing targets; first assess the user's scope and call network_bind_asset(target, evidence, scope_basis), then retry this command")
	}
	project := i.ProjectID
	routeScope := effectiveScope(p, scope, s.Bindings(project))
	nodeID := p.ProxyID
	key := project + "/" + fmt.Sprint(p.Version) + "/" + i.Key()
	scopeBytes, _ := json.Marshal(routeScope)
	key = project + "/" + fmt.Sprint(p.Version) + "/" + fmt.Sprintf("%x", sha256.Sum256(scopeBytes)) + "/" + i.Key()
	envPolicy := p
	if p.Mode == "auto" {
		project = "lease-" + lease.ID
		routeScope = scope
		routeScope.Targets, routeScope.Exclude = []string{lease.Target}, append([]string{}, scope.Exclude...)
		nodeID = lease.NodeID
		key = project + "/" + i.Key()
		envPolicy = Policy{Mode: "fixed_proxy", ProxyID: nodeID, Targets: routeScope.Targets, Version: 1}
	}
	env, err := s.environment(ctx, project, envPolicy, routeScope)
	if err != nil {
		return fmt.Errorf("prepare isolated test network: %w", err)
	}
	if p.Mode != "fixed_vpn" {
		if err = env.Wait(ctx); err != nil {
			return err
		}
	}
	s.mu.Lock()
	g := s.gateways[key]
	s.mu.Unlock()
	if g == nil {
		if p.Mode == "fixed_vpn" {
			g, err = newVPNGateway(routeScope, env.BindAddress(), env.Dial)
		} else {
			g, err = s.NewGateway(nodeID, routeScope, env.BindAddress())
		}
		if err != nil {
			return err
		}
		g.owner = i.Key()
		g.routing = s.TargetHTTPTransport(i, scope, g.baseline)
		g.mu.Lock()
		g.allowed = func(t Target) bool {
			if p.Mode == "auto" {
				s.mu.RLock()
				current, exists := s.leases[lease.ID]
				s.mu.RUnlock()
				return exists && time.Now().Before(current.ExpiresAt)
			}
			return true
		}
		g.mu.Unlock()
		s.mu.Lock()
		currentEnvironment := false
		for _, entry := range s.environments {
			if entry.project != project {
				continue
			}
			select {
			case <-entry.done:
				currentEnvironment = entry.err == nil && entry.env == env
			default:
			}
		}
		currentLease := true
		if p.Mode == "auto" {
			active, exists := s.leases[lease.ID]
			currentLease = exists && active.Owner == i.Key() && active.NodeID == nodeID && time.Now().Before(active.ExpiresAt)
		}
		// Gateway listeners are created without the store lock. Cleanup may have
		// retired their environment while binding, so validate again at registration.
		if s.closed || ctx.Err() != nil || !currentEnvironment || !currentLease || s.state.Policies[i.ProjectID].Version != p.Version {
			s.mu.Unlock()
			_ = g.Close()
			return fmt.Errorf("project network changed while preparing command; retry using the current configuration")
		}
		if existing := s.gateways[key]; existing != nil {
			s.mu.Unlock()
			_ = g.Close()
			g = existing
		} else {
			s.gateways[key] = g
			s.mu.Unlock()
		}
	}
	cmd.Env = proxyEnvironment(cmd.Env, g.URL())
	if err = env.Prepare(cmd); err != nil {
		return fmt.Errorf("attach command to project network: %w", err)
	}
	return nil
}

func (s *Service) ReleaseTask(i Identity) {
	s.mu.Lock()
	ids := []string{}
	for id, lease := range s.leases {
		if i.ownsTask(lease.Owner) {
			ids = append(ids, id)
			delete(s.leases, id)
		}
	}
	gateways := []*Gateway{}
	for key, g := range s.gateways {
		if i.ownsTask(g.owner) || g.owner == "" && strings.HasSuffix(key, "/"+i.Key()) {
			gateways = append(gateways, g)
			delete(s.gateways, key)
		}
	}
	s.mu.Unlock()
	for _, g := range gateways {
		_ = g.Close()
	}
	for _, id := range ids {
		_ = s.DisconnectVPN("lease-" + id)
	}
}
func (s *Service) acquireVPN(ctx context.Context, i Identity, scope Scope, t Target) (Lease, error) {
	s.mu.RLock()
	version, retirement := s.state.Policies[i.ProjectID].Version, s.retirements[i.ProjectID]
	s.mu.RUnlock()
	ready, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if _, err := s.ConnectVPN(ready, i.ProjectID, scope); err != nil {
		return Lease{}, err
	}
	lease := Lease{ID: newID(), ProjectID: i.ProjectID, Target: t.Key(), Mode: "vpn", Owner: i.Key(), ExpiresAt: time.Now().Add(30 * time.Minute)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ready.Err(); err != nil {
		return Lease{}, err
	}
	if err := s.checkScopeCurrentLocked(scope); err != nil {
		return Lease{}, err
	}
	if s.closed || s.state.Policies[i.ProjectID].Version != version || s.retirements[i.ProjectID] != retirement || s.excludedLocked(i, scope, t) {
		return Lease{}, fmt.Errorf("project network changed while connecting VPN; resolve the current scope and retry")
	}
	s.leases[lease.ID] = lease
	return lease, nil
}
