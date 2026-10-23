package network

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSourceProviderSecretsAndLargeCollectionLimit(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.SaveSource(Source{Name: "oversized", Kind: "fofa", Query: "fixture", Limit: MaxProxyImport + 1}); err == nil {
		t.Fatal("collection limit above the maximum was accepted")
	}
	original := "https://provider.example/subscription/synthetic-path-secret?token=synthetic-query-secret"
	if _, err = s.SaveSource(Source{Name: "subscription fixture", Kind: "subscription", URL: original, Limit: 100}); err != nil {
		t.Fatal(err)
	}
	listed := s.Sources()[0]
	raw, _ := json.Marshal(listed)
	if strings.Contains(string(raw), "synthetic-path-secret") || strings.Contains(string(raw), "synthetic-query-secret") {
		t.Fatal("source response exposes subscription credentials")
	}
}

func TestProxyTextImportIsDeduplicatedAndKeepsDisabledNodes(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	first, err := s.ImportProxyText("http://fixture:synthetic@127.0.0.1:8080\nhttp://fixture:synthetic@127.0.0.1:8080\ninvalid", "manual")
	if err != nil || first.Imported != 1 || first.Skipped != 1 {
		t.Fatalf("import counts: %+v %v", first, err)
	}
	if strings.Contains(first.Nodes[0].Address, "synthetic") {
		t.Fatal("response contains proxy password")
	}
	if err := s.SetNode(first.Nodes[0].ID, false); err != nil {
		t.Fatal(err)
	}
	second, err := s.ImportProxyText("http://fixture:synthetic@127.0.0.1:8080", "manual")
	if err != nil || second.Imported != 0 || second.Skipped != 0 || len(second.Nodes) != 1 || second.Nodes[0].ID != first.Nodes[0].ID {
		t.Fatalf("reimport must return existing node without reporting an addition or invalid input: %+v %v", second, err)
	}
	if err != nil || second.Nodes[0].Enabled || len(s.Nodes()) != 1 {
		t.Fatal("reimport duplicated or reenabled node")
	}
}

func TestProxyTextImportCountsOnlyAdditionsInMixedBatch(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.AddProxy("http://127.0.0.1:18001", "manual"); err != nil {
		t.Fatal(err)
	}
	result, err := s.ImportProxyText("http://127.0.0.1:18001\nhttp://127.0.0.1:18002\ninvalid\nvmess://unsupported", "manual")
	if err != nil || result.Imported != 1 || result.Skipped != 2 || len(result.Nodes) != 2 || len(s.Nodes()) != 2 {
		t.Fatalf("mixed import counts: %+v %v", result, err)
	}
}

func TestProxyTextImportKeepsExplicitEmptyAuthenticationDistinct(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	result, err := s.ImportProxyText("http://proxy.example:80\nhttp://:@proxy.example:80", "manual")
	if err != nil || result.Imported != 2 || len(s.Nodes()) != 2 {
		t.Fatalf("empty proxy authentication merged with anonymous proxy: %+v err=%v", result, err)
	}
}
