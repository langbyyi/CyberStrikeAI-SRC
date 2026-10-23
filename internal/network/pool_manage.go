package network

import "fmt"

type BulkProxyResult struct {
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
}

func (s *Service) BulkUpdateProxies(ids []string, action string) (BulkProxyResult, error) {
	result := BulkProxyResult{}
	if len(ids) == 0 || len(ids) > 1000 {
		return result, fmt.Errorf("bulk proxy update requires between 1 and 1000 node IDs")
	}
	if action != "enable" && action != "disable" && action != "delete" {
		return result, fmt.Errorf("bulk proxy action must be enable, disable or delete")
	}
	retired := []string{}
	err := s.mutate(func() error {
		seen := map[string]bool{}
		for _, id := range ids {
			n, ok := s.state.Nodes[id]
			if seen[id] || !ok || n.ProjectID != "" {
				result.Skipped++
				continue
			}
			seen[id] = true
			if action == "delete" {
				referenced := false
				for _, policy := range s.state.Policies {
					if policy.Mode == "fixed_proxy" && policy.ProxyID == id {
						referenced = true
						break
					}
				}
				if referenced {
					result.Skipped++
					continue
				}
				delete(s.state.Nodes, id)
				delete(s.state.Credentials, id)
			} else {
				old := n
				switch action {
				case "enable":
					n.Enabled = true
				case "disable":
					n.Enabled = false
				}
				if old == n {
					result.Skipped++
					continue
				}
				n.Version++
				s.state.Nodes[id] = n
			}
			delete(s.state.PoolHealth, id)
			retired = append(retired, id)
			result.Updated++
		}
		return nil
	})
	if err != nil {
		return BulkProxyResult{}, err
	}
	for _, id := range retired {
		s.retireNodeUsage(id)
	}
	return result, nil
}

func (s *Service) PoolObservations() map[string]Observation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := map[string]Observation{}
	settings, err := s.validationSettingsLocked()
	if err != nil || settings.Target == "" {
		return result
	}
	fingerprint := validationFingerprint(settings)
	for id, health := range s.state.PoolHealth {
		n, ok := s.state.Nodes[id]
		if ok && n.ProjectID == "" && n.Version == health.Version && health.Configuration == fingerprint {
			result[id] = health.Observation
		}
	}
	return result
}
