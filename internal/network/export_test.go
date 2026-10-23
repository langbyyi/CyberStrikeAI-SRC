package network

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestProxyExportRoundTripsCredentialsAndIncludesDisabledSharedNodes(t *testing.T) {
	s := validationService(t)
	endpoint := &url.URL{Scheme: "socks5", Host: "[2001:db8::1]:1080", User: url.UserPassword("fixture:user", "synthetic@:/?# password")}
	n, err := s.AddProxy(endpoint.String(), "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdateProxy(n.ID, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AddProxy("http://127.0.0.1:18001", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AddProjectProxy("private-project", "http://private:private-secret@127.0.0.1:18002"); err != nil {
		t.Fatal(err)
	}
	lines, err := s.ExportProxies()
	if err != nil || len(lines) != 2 {
		t.Fatalf("export count: %d %v", len(lines), err)
	}
	if strings.Contains(strings.Join(lines, "\n"), "private-secret") {
		t.Fatal("project credentials leaked")
	}
	copy := validationService(t)
	if _, err = copy.ImportProxyText(strings.Join(lines, "\n"), "import"); err != nil {
		t.Fatal(err)
	}
	again, err := copy.ExportProxies()
	if err != nil || !reflect.DeepEqual(lines, again) {
		t.Fatal("credentials lost during export/import round trip")
	}
}
