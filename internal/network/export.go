package network

import (
	"fmt"
	"net/url"
	"sort"
)

// ExportProxies is a credential-bearing management operation, separate from safe node listings.
func (s *Service) ExportProxies() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lines := make([]string, 0, len(s.state.Nodes))
	for id, node := range s.state.Nodes {
		if node.ProjectID != "" {
			continue
		}
		endpoint, err := url.Parse(node.Address)
		if err != nil {
			return nil, fmt.Errorf("export proxy %s: invalid saved address", id)
		}
		if node.HasAuth {
			credential, ok := s.state.Credentials[id]
			if !ok {
				return nil, fmt.Errorf("export proxy %s: saved credentials are unavailable", id)
			}
			endpoint.User = url.UserPassword(credential.Username, credential.Password)
		}
		lines = append(lines, endpoint.String())
	}
	sort.Strings(lines)
	return lines, nil
}
