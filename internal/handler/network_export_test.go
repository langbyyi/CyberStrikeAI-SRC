package handler

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/network"
)

func TestNetworkFullExportRequiresAdminAndNeverExportsProjectCredentials(t *testing.T) {
	_, viewer := poolHandler(t, false)
	if w := poolRequest(viewer, "GET", "/api/network/export", nil); w.Code != 403 {
		t.Fatalf("viewer accepted: %d", w.Code)
	}
	h, router := poolHandler(t, true)
	n, err := h.Service.AddProxy("http://fixture:synthetic-export-pass@127.0.0.1:18001", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Service.UpdateProxy(n.ID, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Service.AddProjectProxy("private-project", "http://private:private-secret@127.0.0.1:18002"); err != nil {
		t.Fatal(err)
	}
	w := poolRequest(router, "GET", "/api/network/export", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "fixture:synthetic-export-pass@") || strings.Contains(w.Body.String(), "private-secret") {
		t.Fatalf("incorrect export: status %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Disposition"), "proxies.txt") {
		t.Fatal("unsafe export headers")
	}
}

func TestNetworkEventsRequireAdminAndStaySanitized(t *testing.T) {
	_, viewer := poolHandler(t, false)
	if w := poolRequest(viewer, "GET", "/api/network/events", nil); w.Code != 403 {
		t.Fatalf("viewer accepted: %d", w.Code)
	}
	h, router := poolHandler(t, true)
	if _, err := h.Service.SavePolicy("p", network.Policy{Mode: "auto"}, 0); err != nil {
		t.Fatal(err)
	}
	w := poolRequest(router, "GET", "/api/network/events", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"kind":"policy_updated"`) {
		t.Fatalf("events endpoint: %d %s", w.Code, w.Body.String())
	}
}
