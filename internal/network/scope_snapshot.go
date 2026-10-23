package network

import (
	"fmt"
	"slices"
)

// Callers hold the service lock; document validation only reads the project DB.
func (s *Service) checkScopeCurrentLocked(scope Scope) error {
	if err := scope.CheckCurrent(); err != nil {
		return err
	}
	if snapshot := scope.policyScope; snapshot != nil {
		current := s.state.Policies[snapshot.project]
		if !slices.Equal(snapshot.targets, current.Targets) || !slices.Equal(snapshot.exclude, current.Exclude) {
			return fmt.Errorf("project network scope changed; resolve the current scope before executing")
		}
	}
	return nil
}
