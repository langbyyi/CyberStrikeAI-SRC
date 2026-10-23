package network

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ScopeAssessmentContext ties an Agent decision to the user's current instructions,
// rather than turning a past routing decision into permanent authorization.
type ScopeAssessmentContext struct {
	ProjectID     string
	Description   string
	ScopeJSON     string
	Specification string
	Targets       []string
	Exclude       []string
}

// BindingView reports whether a saved decision still participates in routing.
// The state is derived on read and never becomes persisted authorization.
type BindingView struct {
	Binding
	ScopeState string `json:"scope_state"`
}

func (s *Service) BindingViews(project string, scope Scope, key string) []BindingView {
	bindings := s.Bindings(project)
	views := make([]BindingView, 0, len(bindings))
	for _, binding := range bindings {
		state := "active"
		switch {
		case binding.Excluded:
			state = "excluded"
		case binding.ScopeContext != "" && binding.ScopeContext != key:
			state = "needs_reassessment"
		case !scope.containsRule(binding.Target):
			state = "out_of_scope"
		}
		views = append(views, BindingView{Binding: binding, ScopeState: state})
	}
	return views
}

func (c ScopeAssessmentContext) Key() string {
	if len(c.Targets) == 0 {
		c.Targets = nil
	}
	if len(c.Exclude) == 0 {
		c.Exclude = nil
	}
	raw, _ := json.Marshal(c)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func (s *Service) AssessedScope(project string, base Scope, key string) Scope {
	out := base
	out.Targets, out.Exclude = slices.Clone(base.Targets), slices.Clone(base.Exclude)
	for _, binding := range s.Bindings(project) {
		if binding.Excluded {
			if !slices.Contains(out.Exclude, binding.Target) {
				out.Exclude = append(out.Exclude, binding.Target)
			}
			continue
		}
		if key != "" && binding.ScopeContext == key && binding.ScopeBasis != "" && !slices.Contains(out.Targets, binding.Target) {
			out.Targets = append(out.Targets, binding.Target)
		}
	}
	return out
}

// BindAssessedAsset accepts the Agent's semantic judgment, not a server-side
// guess from a domain suffix. Evidence and scope basis have distinct purposes.
func (s *Service) BindAssessedAsset(ctx context.Context, project, raw, evidence, basis, key string, scope Scope, origins ...string) (Binding, error) {
	basis = strings.TrimSpace(basis)
	if basis == "" || len(basis) > 4096 || len(key) != sha256.Size*2 {
		return Binding{}, fmt.Errorf("assess network asset: current scope context and authorization basis are required (maximum 4096 bytes)")
	}
	rule, err := normalizeRule(raw)
	if err != nil {
		return Binding{}, err
	}
	origin := "discovered"
	if len(origins) > 0 && origins[0] != "" {
		origin = origins[0]
	}
	if origin != "discovered" && origin != "declared" {
		return Binding{}, fmt.Errorf("scope_origin must be discovered or declared")
	}
	prefix, prefixErr := netip.ParsePrefix(rule)
	if prefixErr == nil && prefix.Bits() == 0 {
		return Binding{}, fmt.Errorf("assess network asset: a default route cannot be used as a testing target")
	}
	if origin != "declared" && (prefixErr == nil || strings.HasPrefix(rule, "*.")) {
		return Binding{}, fmt.Errorf("assess network asset: register a concrete domain or IP; wildcard and network expansion require explicit project rules")
	}
	for _, excluded := range append(slices.Clone(scope.Exclude), s.Policy(project).Exclude...) {
		if ruleCovers(excluded, rule) {
			return Binding{}, fmt.Errorf("asset %s is explicitly excluded by project policy", rule)
		}
	}
	return s.bindAsset(ctx, project, rule, evidence, false, "agent", scope, basis, key, origin)
}
