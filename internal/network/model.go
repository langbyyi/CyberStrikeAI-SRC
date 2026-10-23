package network

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

type Target struct {
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Path     string `json:"path,omitempty"`
	RawPath  string `json:"raw_path,omitempty"`
	RawQuery string `json:"raw_query,omitempty"`
}

func (t Target) Address() string { return net.JoinHostPort(t.Host, t.Port) }
func (t Target) URL() string {
	return (&url.URL{Scheme: t.Scheme, Host: t.Address(), Path: t.Path, RawPath: t.RawPath, RawQuery: t.RawQuery}).String()
}
func (t Target) Key() string { return t.Scheme + "://" + t.Address() }

func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n\x00\t ") || strings.Contains(raw, "*") {
		return Target{}, fmt.Errorf("parse target: invalid host or URL")
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		raw = net.JoinHostPort(ip.String(), "443")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "tcp") {
		return Target{}, fmt.Errorf("parse target: expected HTTP(S), TCP or host address")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return Target{}, fmt.Errorf("parse target: scoped IPv6 is unsupported")
		}
		host = ip.Unmap().String()
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return Target{}, fmt.Errorf("parse target hostname: %w", err)
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return Target{}, fmt.Errorf("parse target: invalid DNS label")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
					return Target{}, fmt.Errorf("parse target: invalid hostname character")
				}
			}
		}
		if len(host) > 253 {
			return Target{}, fmt.Errorf("parse target: hostname too long")
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return Target{}, fmt.Errorf("parse target: invalid port")
	}
	return Target{Scheme: u.Scheme, Host: host, Port: strconv.Itoa(p), Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}, nil
}

type Scope struct {
	Targets         []string `json:"targets"`
	Exclude         []string `json:"exclude,omitempty"`
	validateCurrent func() error
	policyScope     *scopePolicySnapshot
}

type scopePolicySnapshot struct {
	project string
	targets []string
	exclude []string
}

func (s Scope) WithPolicyScope(project string, policy Policy) Scope {
	s.policyScope = &scopePolicySnapshot{project: project, targets: append([]string{}, policy.Targets...), exclude: append([]string{}, policy.Exclude...)}
	return s
}

// WithCurrentValidation attaches a trusted, read-only document check. It is not
// serialized into runner rules and must not acquire the network service lock.
func (s Scope) WithCurrentValidation(validate func() error) Scope {
	s.validateCurrent = validate
	return s
}

func (s Scope) CheckCurrent() error {
	if s.validateCurrent != nil {
		return s.validateCurrent()
	}
	return nil
}

func matchRule(rule string, t Target) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	if prefix, err := netip.ParsePrefix(rule); err == nil {
		ip, e := netip.ParseAddr(t.Host)
		return e == nil && prefix.Contains(ip)
	}
	if strings.HasPrefix(rule, "*.") {
		suffix := strings.TrimSuffix(rule[1:], ".")
		return strings.HasSuffix(t.Host, suffix) && len(t.Host) > len(suffix)
	}
	r, err := ParseTarget(rule)
	if err != nil {
		return false
	}
	if r.Host != t.Host {
		return false
	}
	if strings.Contains(rule, "://") || strings.Contains(rule, "]:") || net.ParseIP(rule) == nil && strings.Contains(rule, ":") {
		if r.Port != t.Port {
			return false
		}
	}
	return true
}
func (s Scope) Contains(t Target) bool {
	for _, r := range s.Exclude {
		if matchRule(r, t) {
			return false
		}
	}
	for _, r := range s.Targets {
		if matchRule(r, t) {
			return true
		}
	}
	return false
}
func (s Scope) Validate() error {
	for _, r := range append(append([]string{}, s.Targets...), s.Exclude...) {
		if _, err := netip.ParsePrefix(strings.TrimSpace(r)); err == nil {
			continue
		}
		raw := strings.TrimPrefix(strings.TrimSpace(r), "*.")
		if _, err := ParseTarget(raw); err != nil {
			return fmt.Errorf("invalid network scope %q: %w", r, err)
		}
	}
	return nil
}

func normalizeRule(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix.Masked().String(), nil
	}
	if strings.HasPrefix(raw, "*.") {
		base, err := ParseTarget(raw[2:])
		if err != nil {
			return "", err
		}
		if strings.ContainsAny(raw[2:], "/:") {
			return "", fmt.Errorf("wildcard rule must be a hostname")
		}
		return "*." + base.Host, nil
	}
	t, err := ParseTarget(raw)
	if err != nil {
		return "", err
	}
	if strings.Contains(raw, "://") || net.ParseIP(raw) == nil && strings.Contains(raw, ":") && !strings.HasPrefix(raw, "[") || strings.Contains(raw, "]:") {
		return t.Key(), nil
	}
	return t.Host, nil
}

func ruleCovers(parent, child string) bool {
	p, err := normalizeRule(parent)
	if err != nil {
		return false
	}
	c, err := normalizeRule(child)
	if err != nil {
		return false
	}
	if p == c {
		return true
	}
	if cp, e := netip.ParsePrefix(c); e == nil {
		pp, e := netip.ParsePrefix(p)
		return e == nil && pp.Bits() <= cp.Bits() && pp.Contains(cp.Addr())
	}
	if strings.HasPrefix(c, "*.") {
		return strings.HasPrefix(p, "*.") && strings.HasSuffix(c[1:], p[1:])
	}
	t, e := ParseTarget(c)
	if e != nil {
		return false
	}
	if strings.Contains(p, "://") && !strings.Contains(c, "://") {
		return false
	}
	return matchRule(p, t)
}

func (s Scope) containsRule(rule string) bool {
	for _, excluded := range s.Exclude {
		if ruleCovers(excluded, rule) {
			return false
		}
	}
	for _, allowed := range s.Targets {
		if ruleCovers(allowed, rule) {
			return true
		}
	}
	return false
}

// Network routing may narrow declared testing scope, but cannot grant a wider scope.
func (s Scope) ValidateSubset(targets []string) error {
	if len(s.Targets) == 0 {
		return nil
	}
	for _, rule := range targets {
		if !s.containsRule(rule) {
			return fmt.Errorf("network target %q is outside the project testing scope", rule)
		}
	}
	return nil
}

type Node struct {
	ProjectID string `json:"project_id,omitempty"`
	ID        string `json:"id"`
	Address   string `json:"address"`
	Scheme    string `json:"scheme"`
	Host      string `json:"host"`
	Port      string `json:"port"`
	HasAuth   bool   `json:"has_auth"`
	Enabled   bool   `json:"enabled"`
	Source    string `json:"source"`
	Version   int64  `json:"version"`
}
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Policy struct {
	Mode         string   `json:"mode"`
	ProxyID      string   `json:"proxy_id,omitempty"`
	VPNProfileID string   `json:"vpn_profile_id,omitempty"`
	Targets      []string `json:"targets,omitempty"`
	Exclude      []string `json:"exclude,omitempty"`
	DNSServers   []string `json:"dns_servers,omitempty"`
	Version      int64    `json:"version"`
}
type Binding struct {
	ScopeBasis   string    `json:"scope_basis,omitempty"`
	ScopeOrigin  string    `json:"scope_origin,omitempty"`
	ScopeContext string    `json:"scope_context,omitempty"`
	Target       string    `json:"target"`
	Evidence     string    `json:"evidence"`
	Excluded     bool      `json:"excluded"`
	Source       string    `json:"source"`
	Revision     int64     `json:"revision"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type Observation struct {
	NodeID     string    `json:"node_id"`
	Target     string    `json:"target"`
	Context    string    `json:"context"`
	Reachable  bool      `json:"reachable"`
	Stage      string    `json:"stage"`
	HTTPStatus int       `json:"http_status,omitempty"`
	LatencyMS  int64     `json:"latency_ms"`
	Reason     string    `json:"reason,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type Identity struct {
	RunID          string
	UserID         string
	ProjectID      string
	ConversationID string
	RunnerID       string
}

func (i Identity) Key() string {
	return i.UserID + "/" + i.ProjectID + "/" + i.ConversationID + "/" + i.RunID
}

func (i Identity) ownsTask(owner string) bool {
	if i.RunID == "" {
		return owner == i.Key()
	}
	return strings.HasPrefix(owner, i.UserID+"/") && strings.HasSuffix(owner, "/"+i.ConversationID+"/"+i.RunID)
}

type Lease struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id,omitempty"`
	ProjectID string    `json:"project_id,omitempty"`
	Target    string    `json:"target"`
	Mode      string    `json:"mode"`
	ExpiresAt time.Time `json:"expires_at"`
	Owner     string    `json:"-"`
}
