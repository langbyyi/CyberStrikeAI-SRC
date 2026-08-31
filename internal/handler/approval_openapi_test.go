package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestOpenAPIDocumentsUnifiedApprovalContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/openapi.json", NewOpenAPIHandler(nil, nil, nil, nil).GetOpenAPISpec)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]any)
	wantMethods := map[string][]string{
		"/api/approvals":               {"get"},
		"/api/approvals/ledger":        {"get"},
		"/api/approvals/{id}":          {"get"},
		"/api/approvals/{id}/decision": {"post"},
		"/api/approval-config":         {"get", "put"},
		"/api/approval-rules":          {"get", "post", "delete"},
	}
	for path, methods := range wantMethods {
		item, ok := paths[path].(map[string]any)
		if !ok {
			t.Errorf("OpenAPI missing path %s", path)
			continue
		}
		for _, method := range methods {
			if _, ok := item[method]; !ok {
				t.Errorf("OpenAPI missing %s %s", method, path)
			}
		}
	}
	components := spec["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	for _, name := range []string{"ApprovalRequest", "ApprovalConfig", "ApprovalRule", "ApprovalDecisionRequest", "ApprovalLedgerEvent"} {
		if _, ok := schemas[name]; !ok {
			t.Errorf("OpenAPI missing schema %s", name)
		}
	}
	requestSchema := schemas["ApprovalRequest"].(map[string]any)
	requestProperties := requestSchema["properties"].(map[string]any)
	for _, field := range []string{"invocationHash", "messageId", "expiresAt", "executionId"} {
		if _, ok := requestProperties[field]; !ok {
			t.Errorf("ApprovalRequest schema missing field %s", field)
		}
	}
	if _, ok := requestProperties["claimedAt"]; ok {
		t.Error("ApprovalRequest schema exposes legacy claimedAt")
	}
	ruleSchema := schemas["ApprovalRule"].(map[string]any)
	ruleProperties := ruleSchema["properties"].(map[string]any)
	for _, legacyField := range []string{"revision", "builtin", "locked"} {
		if _, ok := ruleProperties[legacyField]; ok {
			t.Errorf("ApprovalRule schema exposes retired field %s", legacyField)
		}
	}
	for _, legacyField := range []string{"matchedRuleRevisions"} {
		if _, ok := requestProperties[legacyField]; ok {
			t.Errorf("ApprovalRequest schema exposes retired field %s", legacyField)
		}
	}
	if _, ok := requestProperties["matchedPolicies"]; !ok {
		t.Error("ApprovalRequest schema missing matchedPolicies")
	}
}
