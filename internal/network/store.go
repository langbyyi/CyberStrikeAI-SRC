package network

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type diskState struct {
	Version              int                   `json:"version"`
	Nodes                map[string]Node       `json:"nodes"`
	Credentials          map[string]Credential `json:"credentials"`
	Policies             map[string]Policy     `json:"policies"`
	Bindings             map[string][]Binding  `json:"bindings"`
	Observations         []Observation         `json:"observations"`
	Profiles             map[string]Profile    `json:"profiles"`
	Sources              map[string]Source     `json:"sources"`
	Validation           ValidationSettings    `json:"validation"`
	PoolHealth           map[string]PoolHealth `json:"pool_health,omitempty"`
	ValidationGeneration uint64                `json:"validation_generation,omitempty"`
	Events               []NetworkEvent        `json:"events,omitempty"`
}

// maxNetworkEvents bounds the in-state operations log; entries carry resource IDs
// and reasons only, never addresses or credentials.
const maxNetworkEvents = 200

// NetworkEvent records egress-relevant transitions (environment rebuilds, lease
// movements, node retirement) so a later node switch is never mistaken for a
// public-IP change and failures can be traced to the policy version in force.
type NetworkEvent struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Project string    `json:"project,omitempty"`
	From    string    `json:"from,omitempty"`
	To      string    `json:"to,omitempty"`
	Version int64     `json:"policy_version,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

// recordEvent keeps the newest entries first; the ring is trimmed to
// maxNetworkEvents. Callers must not hold s.mu.
func (s *Service) recordEvent(kind, project, from, to string, version int64, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordEventLocked(kind, project, from, to, version, reason)
}

func (s *Service) recordEventLocked(kind, project, from, to string, version int64, reason string) {
	s.state.Events = append([]NetworkEvent{{At: time.Now().UTC(), Kind: kind, Project: project, From: from, To: to, Version: version, Reason: reason}}, s.state.Events...)
	if len(s.state.Events) > maxNetworkEvents {
		s.state.Events = s.state.Events[:maxNetworkEvents]
	}
}

// Events returns the bounded operations log, newest first.
func (s *Service) Events() []NetworkEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NetworkEvent, len(s.state.Events))
	copy(out, s.state.Events)
	return out
}

type Profile struct {
	ID          string            `json:"id"`
	ProjectID   string            `json:"project_id"`
	Config      string            `json:"config"`
	Files       map[string]string `json:"files,omitempty"`
	Credentials *VPNCredentials   `json:"credentials,omitempty"`
}
type Source struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Query string `json:"query,omitempty"`
	URL   string `json:"url,omitempty"`
	Limit int    `json:"limit"`
}
type Service struct {
	mu             sync.RWMutex
	root           string
	key            []byte
	state          diskState
	leases         map[string]Lease
	closed         bool
	factory        EnvironmentFactory
	environments   map[string]*environmentEntry
	gateways       map[string]*Gateway
	generations    map[string]int64
	retirements    map[string]uint64
	observationTTL time.Duration
}

func newID() string { return uuid.NewString() }

func Open(root string) (*Service, error) {
	resolved, resolveErr := filepath.Abs(root)
	if resolveErr != nil {
		return nil, resolveErr
	}
	root = resolved
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create network state directory: %w", err)
	}
	s := &Service{root: root, leases: map[string]Lease{}, environments: map[string]*environmentEntry{}, gateways: map[string]*Gateway{}, generations: map[string]int64{}, observationTTL: 5 * time.Minute}
	if raw := strings.TrimSpace(os.Getenv("CYBERSTRIKE_NETWORK_OBSERVATION_TTL")); raw != "" {
		if ttl, err := time.ParseDuration(raw); err == nil && ttl >= 30*time.Second && ttl <= time.Hour {
			s.observationTTL = ttl
		}
	}
	s.factory = func(ctx context.Context, project string, p Policy, scope Scope, profile Profile) (Environment, error) {
		return newSystemEnvironment(ctx, s.root, project, p, scope, profile)
	}
	keyPath := filepath.Join(root, "state.key")
	dataPath := filepath.Join(root, "state.enc")
	var key []byte
	// A deployment-provided key keeps the master secret out of the state directory,
	// so leaking the data directory alone cannot decrypt the state.
	if envKey := strings.TrimSpace(os.Getenv("CYBERSTRIKE_NETWORK_STATE_KEY")); envKey != "" {
		decoded, decodeErr := hex.DecodeString(envKey)
		if decodeErr != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("CYBERSTRIKE_NETWORK_STATE_KEY must be 64 hex characters (32 bytes)")
		}
		key = decoded
	} else if data, readErr := os.ReadFile(keyPath); readErr == nil {
		key = data
	} else if errors.Is(readErr, os.ErrNotExist) {
		if _, statErr := os.Stat(dataPath); statErr == nil {
			return nil, fmt.Errorf("network state key missing; refusing to replace encrypted state")
		}
		key = make([]byte, 32)
		if _, randErr := rand.Read(key); randErr != nil {
			return nil, randErr
		}
		f, e := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		_, writeErr := f.Write(key)
		closeErr := f.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	} else {
		return nil, fmt.Errorf("read network state key: %w", readErr)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid network state key length")
	}
	s.key = key
	s.state = diskState{Version: 1, Nodes: map[string]Node{}, Credentials: map[string]Credential{}, Policies: map[string]Policy{}, Bindings: map[string][]Binding{}, Profiles: map[string]Profile{}, Sources: map[string]Source{}}
	raw, err := os.ReadFile(dataPath)
	if err == nil {
		plain, e := s.decrypt(raw)
		if e != nil {
			return nil, fmt.Errorf("decrypt network state: %w", e)
		}
		if e = json.Unmarshal(plain, &s.state); e != nil {
			return nil, fmt.Errorf("decode network state: %w", e)
		}
		if s.state.Version != 1 {
			return nil, fmt.Errorf("unsupported network state version")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}
func (s *Service) decrypt(raw []byte) ([]byte, error) {
	b, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if len(raw) < g.NonceSize() {
		return nil, fmt.Errorf("truncated state")
	}
	return g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("cyberstrike-network-v1"))
}
func (s *Service) persistLocked() error {
	plain, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	b, err := aes.NewCipher(s.key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	raw := g.Seal(nonce, nonce, plain, []byte("cyberstrike-network-v1"))
	f, err := os.CreateTemp(s.root, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), filepath.Join(s.root, "state.enc"))
}
func (s *Service) mutate(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("network service is closed")
	}
	before, _ := json.Marshal(s.state)
	var previous diskState
	if err := json.Unmarshal(before, &previous); err != nil {
		return fmt.Errorf("snapshot network state: %w", err)
	}
	if err := fn(); err != nil {
		s.state = previous
		return err
	}
	if err := s.persistLocked(); err != nil {
		s.state = previous
		return fmt.Errorf("persist network state: %w", err)
	}
	return nil
}
func (s *Service) Close() error {
	s.mu.Lock()
	s.closed = true
	gateways := s.gateways
	envs := s.environments
	s.gateways = map[string]*Gateway{}
	s.environments = map[string]*environmentEntry{}
	s.mu.Unlock()
	for _, g := range gateways {
		_ = g.Close()
	}
	for _, entry := range envs {
		<-entry.done
		if entry.env != nil {
			_ = entry.env.Close()
		}
	}
	return nil
}
func (s *Service) Nodes() []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Node, 0, len(s.state.Nodes))
	for _, n := range s.state.Nodes {
		if n.ProjectID != "" {
			continue
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (s *Service) Policy(project string) Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.state.Policies[project]
	if p.Mode == "" {
		p.Mode = "auto"
	}
	p.Targets = append([]string{}, p.Targets...)
	p.Exclude = append([]string{}, p.Exclude...)
	p.DNSServers = append([]string{}, p.DNSServers...)
	return p
}
func (s *Service) SavePolicy(project string, p Policy, expected int64) (Policy, error) {
	if project == "" {
		return p, fmt.Errorf("save project network policy: project is required")
	}
	if p.Mode != "auto" && p.Mode != "fixed_proxy" && p.Mode != "fixed_vpn" {
		return p, fmt.Errorf("invalid network mode")
	}
	if err := (Scope{Targets: p.Targets, Exclude: p.Exclude}).Validate(); err != nil {
		return p, err
	}
	if err := validateDNSServers(p.DNSServers); err != nil {
		return p, err
	}
	if p.Mode == "fixed_proxy" && p.ProxyID == "" || p.Mode == "fixed_vpn" && p.VPNProfileID == "" {
		return p, fmt.Errorf("fixed mode requires a connection profile")
	}
	err := s.mutate(func() error {
		if s.state.Policies[project].Version != expected {
			return fmt.Errorf("network policy version conflict; reload before saving")
		}
		p.Version = expected + 1
		s.state.Policies[project] = p
		s.recordEventLocked("policy_updated", project, fmt.Sprintf("v%d", expected), fmt.Sprintf("v%d", p.Version), p.Version, "policy saved; project network environments are rebuilt")
		return nil
	})
	if err == nil {
		_ = s.DisconnectVPN(project)
	}
	return p, err
}
func (s *Service) Bindings(project string) []Binding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Binding{}, s.state.Bindings[project]...)
}
func (s *Service) BindAsset(ctx context.Context, project, raw, evidence string, excluded bool, source string, scope Scope) (Binding, error) {
	return s.bindAsset(ctx, project, raw, evidence, excluded, source, scope, "", "", "")
}
func (s *Service) bindAsset(ctx context.Context, project, raw, evidence string, excluded bool, source string, scope Scope, basis, assessmentKey, origin string) (Binding, error) {
	if err := ctx.Err(); err != nil {
		return Binding{}, err
	}
	if project == "" || len(evidence) > 4096 || strings.TrimSpace(evidence) == "" {
		return Binding{}, fmt.Errorf("bind network asset: project and evidence are required")
	}
	if source != "agent" && source != "user" && source != "dns" {
		return Binding{}, fmt.Errorf("invalid asset binding source")
	}
	rule, err := normalizeRule(raw)
	if err != nil {
		return Binding{}, err
	}
	restoringUserExclusion := false
	if source == "user" && !excluded {
		for _, old := range s.Bindings(project) {
			if old.Target == rule && old.Source == "user" && old.Excluded && old.ScopeContext != "" && old.ScopeBasis != "" {
				restoringUserExclusion = true
				break
			}
		}
	}
	if !excluded && assessmentKey == "" && !scope.containsRule(rule) && !restoringUserExclusion {
		return Binding{}, fmt.Errorf("asset %s is outside the project testing scope", rule)
	}
	b := Binding{Target: rule, Evidence: evidence, Excluded: excluded, Source: source, ScopeBasis: basis, ScopeContext: assessmentKey, ScopeOrigin: origin, UpdatedAt: time.Now().UTC()}
	routingChanged := false
	err = s.mutate(func() error {
		if err := s.checkScopeCurrentLocked(scope); err != nil {
			return err
		}
		items := s.state.Bindings[project]
		for i, old := range items {
			if old.Source == "user" && old.Excluded && source != "user" && !excluded && (ruleCovers(old.Target, b.Target) || ruleCovers(b.Target, old.Target)) {
				return fmt.Errorf("asset is explicitly excluded by user")
			}
			if old.Target == b.Target {
				if old.Source == "user" && old.Excluded && source != "user" {
					return fmt.Errorf("asset is explicitly excluded by user")
				}
				if assessmentKey == "" {
					b.ScopeBasis, b.ScopeContext, b.ScopeOrigin = old.ScopeBasis, old.ScopeContext, old.ScopeOrigin
				}
				if old.Evidence == b.Evidence && old.Excluded == b.Excluded && old.Source == b.Source && old.ScopeBasis == b.ScopeBasis && old.ScopeContext == b.ScopeContext && old.ScopeOrigin == b.ScopeOrigin {
					b = old
					return nil
				}
				routingChanged = old.Excluded != b.Excluded || old.ScopeContext != b.ScopeContext
				b.Revision = old.Revision + 1
				items[i] = b
				s.state.Bindings[project] = items
				return nil
			}
		}
		b.Revision = 1
		routingChanged = true
		s.state.Bindings[project] = append(items, b)
		return nil
	})
	if err == nil && routingChanged {
		_ = s.DisconnectVPN(project)
	}
	return b, err
}
func (s *Service) AddProxy(raw, source string) (Node, error) {
	n, c, err := NormalizeProxy(raw)
	if err != nil {
		return n, err
	}
	n.ID = uuid.NewString()
	n.Source = source
	n.Enabled = true
	n.Version = 1
	err = s.mutate(func() error {
		for id, old := range s.state.Nodes {
			if old.ProjectID == "" && old.Address == n.Address && s.state.Credentials[id] == c {
				n = old
				return nil
			}
		}
		s.state.Nodes[n.ID] = n
		s.state.Credentials[n.ID] = c
		return nil
	})
	return n, err
}
func (s *Service) SetNode(id string, enabled bool) error {
	_, err := s.UpdateProxy(id, "", enabled)
	return err
}
func (s *Service) UpdateProxy(id, raw string, enabled bool) (Node, error) {
	var replacement Node
	var credentials Credential
	var err error
	if strings.TrimSpace(raw) != "" {
		replacement, credentials, err = NormalizeProxy(raw)
		if err != nil {
			return Node{}, err
		}
	}
	var updated Node
	err = s.mutate(func() error {
		n, ok := s.state.Nodes[id]
		if !ok {
			return fmt.Errorf("proxy node not found")
		}
		n.Enabled = enabled
		if replacement.Address != "" {
			n.Address, n.Scheme = replacement.Address, replacement.Scheme
			n.Host, n.Port, n.HasAuth = replacement.Host, replacement.Port, replacement.HasAuth
			s.state.Credentials[id] = credentials
		}
		n.Version++
		s.state.Nodes[id] = n
		updated = n
		delete(s.state.PoolHealth, id)
		return nil
	})
	if err == nil {
		s.retireNodeUsage(id)
	}
	return updated, err
}
func (s *Service) DeleteProxy(id string) error {
	err := s.mutate(func() error {
		if _, ok := s.state.Nodes[id]; !ok {
			return fmt.Errorf("proxy node not found")
		}
		for _, policy := range s.state.Policies {
			if policy.Mode == "fixed_proxy" && policy.ProxyID == id {
				return fmt.Errorf("proxy node is still referenced by a fixed project policy")
			}
		}
		delete(s.state.Nodes, id)
		delete(s.state.Credentials, id)
		delete(s.state.PoolHealth, id)
		return nil
	})
	if err == nil {
		s.retireNodeUsage(id)
	}
	return err
}
func (s *Service) retireNodeUsage(id string) {
	s.mu.Lock()
	var retired []string
	var projects []string
	for project, policy := range s.state.Policies {
		if policy.Mode == "fixed_proxy" && policy.ProxyID == id {
			projects = append(projects, project)
		}
	}
	for key, lease := range s.leases {
		if lease.NodeID == id {
			retired = append(retired, key)
			delete(s.leases, key)
		}
	}
	gateways := []*Gateway{}
	for key, g := range s.gateways {
		if g.nodeID == id {
			gateways = append(gateways, g)
			delete(s.gateways, key)
		}
	}
	s.mu.Unlock()
	s.recordEvent("node_retired", "", id, "", 0, fmt.Sprintf("node disabled or removed; %d lease(s) cancelled, %d referencing project(s) retired", len(retired), len(projects)))
	for _, g := range gateways {
		_ = g.Close()
	}
	for _, leaseID := range retired {
		_ = s.DisconnectVPN("lease-" + leaseID)
	}
	for _, project := range projects {
		_ = s.DisconnectVPN(project)
	}
}

func (s *Service) AddProjectProxy(project, raw string) (Node, error) {
	if project == "" {
		return Node{}, fmt.Errorf("project is required")
	}
	n, c, err := NormalizeProxy(raw)
	if err != nil {
		return n, err
	}
	n.ID = newID()
	n.ProjectID = project
	n.Source = "project"
	n.Enabled = true
	n.Version = 1
	err = s.mutate(func() error {
		for id, old := range s.state.Nodes {
			if old.ProjectID == project && old.Address == n.Address && s.state.Credentials[id] == c {
				n = old
				return nil
			}
		}
		s.state.Nodes[n.ID] = n
		s.state.Credentials[n.ID] = c
		return nil
	})
	return n, err
}
func (s *Service) ProjectProxy(project, id string) (Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.state.Nodes[id]
	if !ok || n.ProjectID != "" && n.ProjectID != project {
		return Node{}, fmt.Errorf("proxy does not belong to this project")
	}
	return n, nil
}
