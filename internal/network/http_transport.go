package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
)

// TargetTransport applies the same destination policy to in-process HTTP and local gateways.
type TargetTransport struct {
	service  *Service
	identity Identity
	scope    Scope
	baseline *http.Transport
	mu       sync.Mutex
	paths    map[string]*http.Transport
}

type targetPath struct {
	key   string
	proxy *url.URL
	vpn   Environment
}

func (s *Service) TargetHTTPTransport(i Identity, scope Scope, baseline *http.Transport) *TargetTransport {
	if baseline == nil {
		baseline = http.DefaultTransport.(*http.Transport).Clone()
	}
	return &TargetTransport{service: s, identity: i, scope: scope, baseline: baseline, paths: map[string]*http.Transport{}}
}

func (t *TargetTransport) path(ctx context.Context, target Target) (targetPath, error) {
	s := t.service
	if err := s.checkExecutionScope(t.identity, t.scope); err != nil {
		return targetPath{}, err
	}
	if s.excluded(t.identity, t.scope, target) {
		return targetPath{}, fmt.Errorf("target %s is outside the project testing scope", target.Host)
	}
	p := s.policyForTarget(t.identity, t.scope, target)
	if p.Mode == "fixed_vpn" {
		if err := s.allowed(t.identity, t.scope, target); err != nil {
			return targetPath{}, err
		}
		env, err := s.environment(ctx, t.identity.ProjectID, p, t.scope)
		if err != nil {
			return targetPath{}, err
		}
		if err = env.Wait(ctx); err != nil {
			return targetPath{}, err
		}
		return targetPath{key: fmt.Sprintf("vpn/%s/%d/%p", t.identity.ProjectID, p.Version, env), vpn: env}, nil
	}
	nodeID := p.ProxyID
	if p.Mode == "auto" {
		selected, _ := s.SelectedLeaseForTarget(t.identity, target)
		nodeID = selected.NodeID
	}
	if nodeID == "" {
		return targetPath{}, nil
	}
	if err := s.allowed(t.identity, t.scope, target); err != nil {
		return targetPath{}, err
	}
	u, node, err := s.proxyURL(nodeID)
	if err != nil {
		return targetPath{}, err
	}
	if node.ProjectID != "" && node.ProjectID != t.identity.ProjectID {
		return targetPath{}, fmt.Errorf("proxy does not belong to this project")
	}
	if !node.Enabled {
		return targetPath{}, fmt.Errorf("selected proxy is disabled or unavailable")
	}
	return targetPath{key: fmt.Sprintf("proxy/%s/%d", node.ID, node.Version), proxy: u}, nil
}

func (t *TargetTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	target, err := ParseTarget(request.URL.String())
	if err != nil {
		return nil, err
	}
	path, err := t.path(request.Context(), target)
	if err != nil {
		return nil, err
	}
	if path.key == "" {
		return t.baseline.RoundTrip(request)
	}
	t.mu.Lock()
	transport := t.paths[path.key]
	if transport == nil {
		transport = t.baseline.Clone()
		transport.DialTLS = nil
		transport.DialTLSContext = nil
		if path.proxy != nil {
			transport.Proxy = http.ProxyURL(path.proxy)
		} else {
			transport.Proxy = nil
			transport.DialContext = func(ctx context.Context, _ string, address string) (net.Conn, error) {
				return path.vpn.Dial(ctx, address)
			}
		}
		t.paths[path.key] = transport
	}
	t.mu.Unlock()
	return transport.RoundTrip(request)
}

func (t *TargetTransport) Dial(ctx context.Context, target Target) (net.Conn, error) {
	path, err := t.path(ctx, target)
	if err != nil {
		return nil, err
	}
	if path.vpn != nil {
		return path.vpn.Dial(ctx, target.Address())
	}
	if path.proxy != nil {
		return dialProxy(ctx, path.proxy, target.Address())
	}
	var proxyURL *url.URL
	if t.baseline.Proxy != nil {
		proxyURL, err = t.baseline.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: target.Address()}})
	}
	if err != nil {
		return nil, err
	}
	return dialProxy(ctx, proxyURL, target.Address())
}

func (t *TargetTransport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.baseline.CloseIdleConnections()
	for _, transport := range t.paths {
		transport.CloseIdleConnections()
	}
}
