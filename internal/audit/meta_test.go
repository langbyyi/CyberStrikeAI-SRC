package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkMutationMetadata(t *testing.T) {
	routes := map[string][]string{
		"/api/network/export":  {"GET"},
		"/api/network/proxies": {"POST"}, "/api/network/proxies/:node": {"PUT", "DELETE"},
		"/api/network/proxies/bulk": {"POST"}, "/api/network/validation": {"PUT"}, "/api/network/validate": {"POST"},
		"/api/network/subscriptions/import": {"POST"}, "/api/network/sources/sync": {"POST"},
		"/api/network/sources": {"POST"}, "/api/network/sources/:source": {"DELETE"},
		"/api/network/sources/:source/sync": {"POST"}, "/api/network/jobs/:job/cancel": {"POST"},
		"/api/network/jobs/:job/pause": {"POST"}, "/api/network/jobs/:job/resume": {"POST"},
		"/api/network/diagnose": {"POST"}, "/api/projects/:id/network-policy": {"PUT"},
		"/api/projects/:id/vpn-profile": {"POST"}, "/api/projects/:id/vpn/connect": {"POST"},
		"/api/projects/:id/vpn/disconnect": {"POST"}, "/api/projects/:id/network-assets": {"POST"},
	}
	for route, methods := range routes {
		for _, method := range methods {
			entry, ok := NetworkMutationMeta(method, route, "synthetic-resource")
			if !ok || entry.Category != "network" || entry.Action == "" || entry.ResourceType == "" || entry.Message == "" {
				t.Errorf("missing audit metadata: %s %s", method, route)
			}
			if entry.ResourceID != "synthetic-resource" {
				t.Errorf("lost resource ID: %s", route)
			}
			if len(entry.Detail) != 2 || entry.Detail["method"] != method || entry.Detail["route"] != route {
				t.Errorf("unsafe/unexpected detail: %#v", entry.Detail)
			}
			raw, _ := json.Marshal(entry)
			for _, secret := range []string{"password", "proxy_address", "private_key", "BEGIN PRIVATE", "request_body"} {
				if strings.Contains(string(raw), secret) {
					t.Errorf("secret field %s in metadata", secret)
				}
			}
		}
	}
	for _, route := range []string{"/api/network/proxies", "/api/projects/:id/vpn/status", "/api/projects/:id", "/api/network/unknown?token=synthetic-secret"} {
		if _, ok := NetworkMutationMeta("GET", route, ""); ok {
			t.Errorf("read-only route classified as mutation: %s", route)
		}
	}
	if _, ok := NetworkMutationMeta("POST", "/api/network/unknown?token=synthetic-secret", ""); ok {
		t.Error("unregistered route accepted")
	}
}
