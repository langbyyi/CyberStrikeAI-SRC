package network

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Candidate struct {
	Node        Node         `json:"node"`
	Observation *Observation `json:"observation,omitempty"`
}
type AcquireRequest struct {
	Target string `json:"target"`
	NodeID string `json:"node_id,omitempty"`
}
type AcquireError struct {
	Attempts     []Observation `json:"attempts"`
	Alternatives []string      `json:"alternatives,omitempty"`
}

func (e *AcquireError) Error() string {
	return fmt.Sprintf("no proxy was usable for the target after %d attempts; inspect per-node results", len(e.Attempts))
}

// A responding proxy is insufficient: success requires an accepted target response.
func targetResponse(o *Observation, status int) {
	o.HTTPStatus = status
	o.Reachable = status >= 200 && status < 400
	o.Stage, o.Reason = "http", ""
	if o.Reachable {
		return
	}
	o.Stage = "http_status"
	o.Reason = fmt.Sprintf("target returned HTTP %d %s", status, http.StatusText(status))
	if status == http.StatusTooManyRequests {
		o.Stage = "rate_limited"
	}
	if status == http.StatusProxyAuthRequired {
		o.Stage = "proxy_auth"
		o.Reason = "proxy authentication required or rejected"
	}
}

// probeStageFor maps a failed probe onto the fault classes the design separates:
// DNS, proxy authentication, TCP reachability, TLS, HTTP denial and rate limiting
// stay distinct so one class never stands in for another (§6).
func probeStageFor(err error, connectStatus int) string {
	var dnsErr *net.DNSError
	var tlsRecordErr tls.RecordHeaderError
	var tlsCertErr *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case connectStatus == http.StatusProxyAuthRequired:
		return "proxy_auth"
	case connectStatus == http.StatusTooManyRequests:
		return "rate_limited"
	case connectStatus != 0 && connectStatus != http.StatusOK:
		return "http_status"
	case errors.As(err, &dnsErr):
		return "dns_failed"
	case errors.As(err, &tlsCertErr), errors.As(err, &tlsRecordErr):
		return "tls_failed"
	case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return "target_unreachable"
	default:
		return "connect"
	}
}

func (s *Service) proxyURL(id string) (*url.URL, Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.state.Nodes[id]
	if !ok {
		return nil, n, fmt.Errorf("proxy node not found")
	}
	u, err := url.Parse(n.Address)
	if err != nil {
		return nil, n, fmt.Errorf("invalid saved proxy")
	}
	c := s.state.Credentials[id]
	if n.HasAuth {
		u.User = url.UserPassword(c.Username, c.Password)
	}
	return u, n, nil
}
func (s *Service) contextKey(i Identity) string {
	p := s.Policy(i.ProjectID)
	// The generation increments on every environment rebuild, so a VPN reconnect
	// or resolver change invalidates private-network observations instead of
	// letting a new context reuse stale results (§3.2 network_context_id).
	s.mu.RLock()
	generation := s.generations[i.ProjectID]
	s.mu.RUnlock()
	return fmt.Sprintf("%s/%s/%d/gen-%d/target-get-v1", i.RunnerID, i.ProjectID, p.Version, generation)
}
func (s *Service) Candidates(i Identity, raw string) ([]Candidate, error) {
	t, err := ParseTarget(raw)
	if err != nil {
		return nil, err
	}
	key := s.contextKey(i)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Candidate{}
	for _, n := range s.state.Nodes {
		if n.ProjectID != "" && n.ProjectID != i.ProjectID {
			continue
		}
		c := Candidate{Node: n}
		for j := len(s.state.Observations) - 1; j >= 0; j-- {
			o := s.state.Observations[j]
			if o.NodeID == n.ID && o.Target == t.URL() && o.Context == key+fmt.Sprintf("/%d", n.Version) {
				copy := o
				c.Observation = &copy
				break
			}
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(a, b int) bool {
		rank := func(c Candidate) int {
			if !c.Node.Enabled {
				return 4
			}
			if c.Observation == nil || time.Now().After(c.Observation.ExpiresAt) {
				return 1
			}
			if c.Observation.Reachable {
				return 0
			}
			return 2
		}
		ra, rb := rank(out[a]), rank(out[b])
		if ra == rb {
			return out[a].Node.ID < out[b].Node.ID
		}
		return ra < rb
	})
	return out, nil
}

func (s *Service) allowed(i Identity, scope Scope, t Target) error {
	if err := s.checkExecutionScope(i, scope); err != nil {
		return err
	}
	if i.ProjectID == "" {
		return nil
	}
	if s.excluded(i, scope, t) {
		return fmt.Errorf("target %s is outside the project testing scope", t.Host)
	}
	if len(scope.Targets) > 0 && !scope.Contains(t) {
		return fmt.Errorf("target %s is outside the project testing scope", t.Host)
	}
	return nil
}

func (s *Service) checkExecutionScope(i Identity, scope Scope) error {
	s.mu.RLock()
	err := s.checkScopeCurrentLocked(scope)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if scope.policyScope != nil && scope.policyScope.project != i.ProjectID {
		return fmt.Errorf("network scope belongs to another project")
	}
	p := s.Policy(i.ProjectID)
	if p.Mode != "auto" && len(scope.Targets) == 0 && len(p.Targets) == 0 {
		return fmt.Errorf("fixed project network requires resolved testing targets; call network_status and network_bind_asset before testing")
	}
	return nil
}

func (s *Service) excluded(i Identity, scope Scope, target Target) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.excludedLocked(i, scope, target)
}

func (s *Service) excludedLocked(i Identity, scope Scope, target Target) bool {
	for _, rule := range append(append([]string{}, scope.Exclude...), s.state.Policies[i.ProjectID].Exclude...) {
		if matchRule(rule, target) {
			return true
		}
	}
	for _, binding := range s.state.Bindings[i.ProjectID] {
		if binding.Excluded && matchRule(binding.Target, target) {
			return true
		}
	}
	return false
}

func (s *Service) policyForTarget(i Identity, scope Scope, t Target) Policy {
	p := s.Policy(i.ProjectID)
	if p.Mode != "auto" && !effectiveScope(p, scope, s.Bindings(i.ProjectID)).Contains(t) {
		p.Mode = "auto"
	}
	return p
}

// TargetPolicy reports the same effective policy used by target execution, without connecting.
func (s *Service) TargetPolicy(i Identity, scope Scope, t Target) Policy {
	return s.policyForTarget(i, scope, t)
}

func (s *Service) probe(ctx context.Context, i Identity, id string, t Target) (Observation, error) {
	u, n, err := s.proxyURL(id)
	if err != nil {
		return Observation{}, err
	}
	if n.ProjectID != "" && n.ProjectID != i.ProjectID {
		return Observation{}, fmt.Errorf("proxy node does not belong to this project")
	}
	if !n.Enabled {
		return Observation{}, fmt.Errorf("proxy node is disabled")
	}
	start := time.Now()
	o := Observation{NodeID: id, Target: t.URL(), Context: s.contextKey(i) + fmt.Sprintf("/%d", n.Version), ObservedAt: start.UTC(), ExpiresAt: start.Add(s.observationTTL).UTC(), Stage: "connect"}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tr := &http.Transport{Proxy: http.ProxyURL(u), TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	connectStatus := 0
	tr.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, response *http.Response) error {
		connectStatus = response.StatusCode
		return nil
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, t.URL(), nil)
	if e == nil {
		var response *http.Response
		response, e = client.Do(req)
		if e == nil {
			targetResponse(&o, response.StatusCode)
			response.Body.Close()
		}
	}
	if e != nil {
		reason := e.Error()
		reason = strings.ReplaceAll(reason, u.String(), n.Address)
		if u.User != nil {
			if password, ok := u.User.Password(); ok && password != "" {
				reason = strings.ReplaceAll(reason, password, "[redacted]")
			}
		}
		o.Reason = reason
		o.Stage = probeStageFor(e, connectStatus)
		if o.Stage == "proxy_auth" || o.Stage == "http_status" || o.Stage == "rate_limited" && connectStatus == http.StatusTooManyRequests {
			o.HTTPStatus = connectStatus
			o.Reason = "proxy CONNECT returned an HTTP error response"
			if o.Stage == "proxy_auth" {
				o.Reason = "proxy authentication required or rejected"
			}
		}
	}
	o.LatencyMS = time.Since(start).Milliseconds()
	if err = s.mutate(func() error {
		s.state.Observations = append(s.state.Observations, o)
		if len(s.state.Observations) > 2000 {
			s.state.Observations = append([]Observation{}, s.state.Observations[len(s.state.Observations)-2000:]...)
		}
		return nil
	}); err != nil {
		return o, err
	}
	return o, nil
}

func (s *Service) Diagnose(ctx context.Context, i Identity, scope Scope, raw string, ids []string) ([]Observation, error) {
	t, err := ParseTarget(raw)
	if err != nil {
		return nil, err
	}
	if err = s.allowed(i, scope, t); err != nil {
		return nil, err
	}
	p := s.policyForTarget(i, scope, t)
	if p.Mode == "fixed_vpn" {
		if len(ids) > 0 {
			return nil, fmt.Errorf("project fixed VPN cannot be overridden by proxy probes")
		}
		_, err := s.ConnectVPN(ctx, i.ProjectID, scope)
		if err != nil {
			return nil, err
		}
		env, err := s.environment(ctx, i.ProjectID, p, scope)
		if err != nil {
			return nil, err
		}
		started := time.Now()
		transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _ string, address string) (net.Conn, error) { return env.Dial(ctx, address) }}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.URL(), nil)
		response, e := client.Do(req)
		o := Observation{NodeID: p.VPNProfileID, Target: t.URL(), Context: s.contextKey(i), ObservedAt: started.UTC(), ExpiresAt: started.Add(s.observationTTL), LatencyMS: time.Since(started).Milliseconds(), Stage: "connect"}
		if e != nil {
			o.Reason = "project VPN could not reach target"
		} else {
			targetResponse(&o, response.StatusCode)
			response.Body.Close()
		}
		return []Observation{o}, nil
	}
	if p.Mode == "fixed_proxy" {
		for _, id := range ids {
			if id != p.ProxyID {
				return nil, fmt.Errorf("project fixed proxy cannot be overridden")
			}
		}
		ids = []string{p.ProxyID}
	}
	if len(ids) > 8 {
		return nil, fmt.Errorf("diagnosis is limited to 8 explicit nodes per call")
	}
	if len(ids) == 0 {
		candidates, e := s.Candidates(i, raw)
		if e != nil {
			return nil, e
		}
		for _, c := range candidates {
			if c.Node.Enabled {
				ids = append(ids, c.Node.ID)
				if len(ids) == 3 {
					break
				}
			}
		}
	}
	results := make([]Observation, 0, len(ids))
	reportJobProgress(ctx, JobProgress{Kind: "validation", Stage: "validating", Total: len(ids)})
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return results, err
		}
		finish, e := beginJobUnit(ctx)
		if e != nil {
			return results, e
		}
		o, e := s.probe(ctx, i, id, t)
		if e == nil {
			progress := JobProgress{Kind: "validation", Stage: "validating", Completed: 1}
			if o.Reachable {
				progress.Passed = 1
			} else {
				progress.Failed = 1
			}
			reportJobProgress(ctx, progress)
		}
		finish()
		if e != nil {
			return results, e
		}
		results = append(results, o)
	}
	return results, nil
}

func (s *Service) Acquire(ctx context.Context, i Identity, scope Scope, req AcquireRequest) (Lease, error) {
	t, err := ParseTarget(req.Target)
	if err != nil {
		return Lease{}, err
	}
	if err = s.allowed(i, scope, t); err != nil {
		return Lease{}, err
	}
	s.mu.RLock()
	retirement := s.retirements[i.ProjectID]
	s.mu.RUnlock()
	p := s.policyForTarget(i, scope, t)
	if p.Mode == "fixed_proxy" {
		if req.NodeID != "" && req.NodeID != p.ProxyID {
			return Lease{}, fmt.Errorf("project fixed proxy cannot be overridden")
		}
		req.NodeID = p.ProxyID
	}
	if p.Mode == "fixed_vpn" {
		if req.NodeID != "" {
			return Lease{}, fmt.Errorf("project fixed VPN cannot be overridden by a proxy node")
		}
		return s.acquireVPN(ctx, i, scope, t)
	}
	candidates, err := s.Candidates(i, req.Target)
	if err != nil {
		return Lease{}, err
	}
	failure := &AcquireError{Attempts: []Observation{}}
	for _, c := range candidates {
		if req.NodeID != "" && c.Node.ID != req.NodeID {
			continue
		}
		if p.Mode == "auto" && c.Node.ProjectID != "" {
			continue
		}
		if !c.Node.Enabled {
			continue
		}
		if err = ctx.Err(); err != nil {
			return Lease{}, err
		}
		o := c.Observation
		if o == nil || time.Now().After(o.ExpiresAt) {
			value, e := s.probe(ctx, i, c.Node.ID, t)
			if e != nil {
				return Lease{}, e
			}
			o = &value
		}
		if o.Reachable {
			lease := Lease{ID: newID(), NodeID: c.Node.ID, ProjectID: i.ProjectID, Target: t.Key(), Mode: "proxy", Owner: i.Key(), ExpiresAt: time.Now().Add(30 * time.Minute).UTC()}
			s.mu.Lock()
			if err := ctx.Err(); err != nil {
				s.mu.Unlock()
				return Lease{}, err
			}
			if s.closed {
				s.mu.Unlock()
				return Lease{}, fmt.Errorf("network service is closed")
			}
			if err := s.checkScopeCurrentLocked(scope); err != nil {
				s.mu.Unlock()
				return Lease{}, err
			}
			if s.state.Policies[i.ProjectID].Version != p.Version || s.retirements[i.ProjectID] != retirement || i.ProjectID != "" && s.excludedLocked(i, scope, t) {
				s.mu.Unlock()
				return Lease{}, fmt.Errorf("project network changed during target validation; resolve the current scope and retry")
			}
			// Probes run without the store lock; a page edit can revoke this
			// version before its result arrives. Never lease an unverified revision.
			current, exists := s.state.Nodes[c.Node.ID]
			if !exists || !current.Enabled || current.Version != c.Node.Version {
				s.mu.Unlock()
				return Lease{}, fmt.Errorf("proxy node changed during target validation; diagnose the current node again")
			}
			s.leases[lease.ID] = lease
			s.recordEventLocked("lease_acquired", i.ProjectID, "", c.Node.ID, p.Version, "lease "+lease.ID)
			s.mu.Unlock()
			return lease, nil
		}
		failure.Attempts = append(failure.Attempts, *o)
		if req.NodeID != "" || len(failure.Attempts) >= 3 {
			break
		}
	}
	if req.NodeID != "" && len(failure.Attempts) == 0 {
		return Lease{}, fmt.Errorf("selected proxy is missing, disabled or an unapproved candidate")
	}
	tried := map[string]bool{}
	for _, o := range failure.Attempts {
		tried[o.NodeID] = true
	}
	for _, c := range candidates {
		if tried[c.Node.ID] || !c.Node.Enabled {
			continue
		}
		if p.Mode == "auto" && c.Node.ProjectID != "" {
			continue
		}
		failure.Alternatives = append(failure.Alternatives, c.Node.ID)
		if len(failure.Alternatives) == 3 {
			break
		}
	}
	return Lease{}, failure
}
func (s *Service) Release(i Identity, id string) error {
	s.mu.Lock()
	l, ok := s.leases[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("network lease not found")
	}
	if l.Owner != i.Key() {
		s.mu.Unlock()
		return fmt.Errorf("network lease belongs to another task")
	}
	delete(s.leases, id)
	s.recordEventLocked("lease_released", l.ProjectID, l.NodeID, "", 0, "lease "+id+" released by its owner")
	s.mu.Unlock()
	if l.Mode == "proxy" {
		_ = s.DisconnectVPN("lease-" + id)
	}
	return nil
}
func (s *Service) SelectedLease(i Identity) (Lease, bool) {
	s.mu.Lock()
	var retired []Lease
	var found Lease
	for id, l := range s.leases {
		if time.Now().After(l.ExpiresAt) {
			retired = append(retired, l)
			delete(s.leases, id)
			continue
		}
		if l.Owner == i.Key() && (found.ID == "" || l.ExpiresAt.After(found.ExpiresAt)) {
			found = l
		}
	}
	for _, l := range retired {
		s.recordEventLocked("lease_expired", l.ProjectID, l.NodeID, "", 0, "lease "+l.ID+" passed its expiry")
	}
	s.mu.Unlock()
	for _, l := range retired {
		_ = s.DisconnectVPN("lease-" + l.ID)
	}
	return found, found.ID != ""
}

// SelectedLeaseForTarget mirrors target HTTP routing without creating a gateway or connecting.
func (s *Service) SelectedLeaseForTarget(identity Identity, target Target) (Lease, bool) {
	s.SelectedLease(identity)
	s.mu.RLock()
	defer s.mu.RUnlock()
	var selected Lease
	now := time.Now()
	for _, lease := range s.leases {
		if lease.Owner != identity.Key() || lease.Mode != "proxy" || !now.Before(lease.ExpiresAt) {
			continue
		}
		leased, err := ParseTarget(lease.Target)
		if err == nil && leased.Host == target.Host && leased.Port == target.Port && (selected.ID == "" || lease.ExpiresAt.After(selected.ExpiresAt)) {
			selected = lease
		}
	}
	return selected, selected.ID != ""
}
