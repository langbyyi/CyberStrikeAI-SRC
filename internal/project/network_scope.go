package project

import (
	"encoding/json"
	"fmt"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/network"
)

// NetworkScope keeps project APIs and tool execution on the same current rules.
func NetworkScope(p *database.Project, service *network.Service, databases ...*database.DB) (network.Scope, string, error) {
	scope, key, err := DeclaredNetworkScope(p, service, databases...)
	if err != nil {
		return scope, key, err
	}
	return service.AssessedScope(p.ID, scope, key), key, nil
}

// DeclaredNetworkScope excludes Agent judgments so a derived asset cannot be
// re-registered through the legacy API as permanent, unversioned authorization.
func DeclaredNetworkScope(p *database.Project, service *network.Service, databases ...*database.DB) (network.Scope, string, error) {
	var scope network.Scope
	if p.ScopeJSON != "" {
		if err := json.Unmarshal([]byte(p.ScopeJSON), &scope); err != nil {
			return scope, "", fmt.Errorf("project scope is invalid JSON: %w", err)
		}
	}
	policy := service.Policy(p.ID)
	scope = scope.WithPolicyScope(p.ID, policy)
	if len(scope.Targets) == 0 {
		scope.Targets = policy.Targets
	}
	scope.Exclude = append(scope.Exclude, policy.Exclude...)
	context := network.ScopeAssessmentContext{ProjectID: p.ID, Description: p.Description, ScopeJSON: p.ScopeJSON, Targets: policy.Targets, Exclude: policy.Exclude}
	if p.TestingSpecification != nil {
		context.Specification = p.TestingSpecification.Content
	}
	key := context.Key()
	if len(databases) > 0 && databases[0] != nil {
		db := databases[0]
		id, expected := p.ID, networkScopeDocumentKey(p)
		scope = scope.WithCurrentValidation(func() error {
			current, err := db.GetProject(id)
			if err != nil {
				return fmt.Errorf("project scope changed or is unavailable: %w", err)
			}
			if networkScopeDocumentKey(current) != expected {
				return fmt.Errorf("project scope changed; resolve the current scope before executing")
			}
			return nil
		})
	}
	return scope, key, nil
}

func networkScopeDocumentKey(p *database.Project) string {
	context := network.ScopeAssessmentContext{ProjectID: p.ID, Description: p.Description, ScopeJSON: p.ScopeJSON}
	if p.TestingSpecification != nil {
		context.Specification = p.TestingSpecification.Content
	}
	return context.Key()
}
