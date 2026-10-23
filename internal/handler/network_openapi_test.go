package handler

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAPIDocumentsNetworkContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/openapi.json", NewOpenAPIHandler(nil, nil, nil, nil).GetOpenAPISpec)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	var spec map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]interface{})
	want := map[string][]string{
		"/api/network/proxies": {"get", "post"}, "/api/network/proxies/{node}": {"put", "delete"},
		"/api/network/proxies/bulk": {"post"}, "/api/network/validation": {"get", "put"}, "/api/network/validate": {"post"},
		"/api/network/subscriptions/import": {"post"}, "/api/network/sources/sync": {"post"},
		"/api/network/export": {"get"}, "/api/network/sources": {"get", "post"},
		"/api/network/sources/{source}": {"delete"}, "/api/network/sources/{source}/sync": {"post"},
		"/api/network/jobs/{job}": {"get"}, "/api/network/jobs/{job}/cancel": {"post"}, "/api/network/diagnose": {"post"},
		"/api/network/jobs": {"get"}, "/api/network/jobs/{job}/pause": {"post"}, "/api/network/jobs/{job}/resume": {"post"},
		"/api/projects/{id}/network-policy": {"get", "put"}, "/api/projects/{id}/vpn-profile": {"post"},
		"/api/projects/{id}/vpn/connect": {"post"}, "/api/projects/{id}/vpn/disconnect": {"post"},
		"/api/projects/{id}/vpn/status": {"get"}, "/api/projects/{id}/network-assets": {"post"},
	}
	for path, methods := range want {
		item, ok := paths[path].(map[string]interface{})
		if !ok {
			t.Errorf("missing network path %s", path)
			continue
		}
		for _, method := range methods {
			operation, ok := item[method].(map[string]interface{})
			if !ok {
				t.Errorf("missing %s %s", method, path)
				continue
			}
			if operation["operationId"] == "" {
				t.Errorf("missing operation ID: %s %s", method, path)
			}
			if _, anonymous := operation["security"]; anonymous {
				t.Errorf("network operation must inherit authentication: %s", path)
			}
			responses := operation["responses"].(map[string]interface{})
			if _, ok := responses["403"]; !ok {
				t.Errorf("missing permission failure: %s", path)
			}
		}
	}
	schemas := spec["components"].(map[string]interface{})["schemas"].(map[string]interface{})
	for _, name := range []string{"NetworkNode", "NetworkPolicy", "NetworkSource", "NetworkJob", "NetworkProfileUploadRequest"} {
		if _, ok := schemas[name]; !ok {
			t.Errorf("missing schema %s", name)
		}
	}
	if node, ok := schemas["NetworkNode"].(map[string]interface{}); ok {
		properties := node["properties"].(map[string]interface{})
		for _, secret := range []string{"username", "password", "config", "files"} {
			if _, ok := properties[secret]; ok {
				t.Errorf("response exposes secret property %s", secret)
			}
		}
	}
	if profile, ok := schemas["NetworkProfileUploadRequest"].(map[string]interface{}); ok {
		properties := profile["properties"].(map[string]interface{})
		for _, name := range []string{"config", "files", "credentials"} {
			field := properties[name].(map[string]interface{})
			if field["writeOnly"] != true {
				t.Errorf("profile %s must be write-only", name)
			}
			if _, ok := field["example"]; ok {
				t.Errorf("profile %s must not contain secret examples", name)
			}
		}
		if _, ok := properties["version"]; !ok {
			t.Error("profile upload missing optimistic revision")
		}
	}
}

func TestOpenAPIPoolCredentialAndLimitContract(t *testing.T) {
	schemas := networkOpenAPISchemas()
	source := schemas["NetworkSource"].(map[string]interface{})["properties"].(map[string]interface{})
	for _, name := range []string{"api_key", "api_url", "has_api_key", "authorized"} {
		if _, ok := source[name]; ok {
			t.Errorf("source schema still carries removed credential field %s", name)
		}
	}
	if source["limit"].(map[string]interface{})["maximum"] != 10000 {
		t.Error("source limit contract stale")
	}
	for _, name := range []string{"NetworkValidationSettings", "NetworkPoolValidationResult", "NetworkBulkProxyRequest", "NetworkSubscriptionImportRequest", "NetworkSourceSyncRequest"} {
		if _, ok := schemas[name]; !ok {
			t.Errorf("missing pool schema %s", name)
		}
	}
}
