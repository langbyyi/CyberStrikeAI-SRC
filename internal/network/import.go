package network

import (
	"encoding/json"
	"fmt"
)

const MaxProxyImport = 10000

type ImportResult struct {
	Imported    int            `json:"imported"`
	Skipped     int            `json:"skipped"`
	Unsupported map[string]int `json:"unsupported,omitempty"`
	Nodes       []Node         `json:"nodes"`
}

func (s *Service) ImportProxyText(raw, source string) (ImportResult, error) {
	parsed, err := ParseProxyInput(raw, MaxProxyImport)
	if err != nil {
		return ImportResult{}, err
	}
	return s.importParsedProxies(parsed, source)
}

func (s *Service) importParsedProxies(parsed ProxyInput, source string) (ImportResult, error) {
	return s.importParsedProxiesChecked(parsed, source, nil)
}

// Source fetches run without the state lock; validate their snapshot in the
// same transaction that writes nodes so an edited or deleted source stays revoked.
func (s *Service) importParsedProxiesChecked(parsed ProxyInput, source string, check func() error) (ImportResult, error) {
	result := ImportResult{Skipped: parsed.Invalid, Unsupported: parsed.Unsupported, Nodes: []Node{}}
	for _, count := range parsed.Unsupported {
		result.Skipped += count
	}
	type entry struct {
		node       Node
		credential Credential
	}
	entries := make([]entry, 0, len(parsed.Addresses))
	for _, raw := range parsed.Addresses {
		n, c, err := NormalizeProxy(raw)
		if err != nil {
			result.Skipped++
			continue
		}
		n.ID, n.Source, n.Enabled, n.Version = newID(), source, true, 1
		entries = append(entries, entry{n, c})
	}
	if len(entries) == 0 && check == nil {
		return result, nil
	}
	key := func(node Node, c Credential) string {
		raw, _ := json.Marshal([]interface{}{node.Address, node.HasAuth, c.Username, c.Password})
		return string(raw)
	}
	err := s.mutate(func() error {
		if check != nil {
			if err := check(); err != nil {
				return err
			}
		}
		existing := map[string]Node{}
		for id, n := range s.state.Nodes {
			if n.ProjectID == "" {
				existing[key(n, s.state.Credentials[id])] = n
			}
		}
		for _, item := range entries {
			k := key(item.node, item.credential)
			if old, ok := existing[k]; ok {
				result.Nodes = append(result.Nodes, old)
				continue
			}
			s.state.Nodes[item.node.ID] = item.node
			s.state.Credentials[item.node.ID] = item.credential
			existing[k] = item.node
			result.Nodes = append(result.Nodes, item.node)
			result.Imported++
		}
		return nil
	})
	if err != nil {
		return ImportResult{}, fmt.Errorf("save proxy import: %w", err)
	}
	return result, nil
}
