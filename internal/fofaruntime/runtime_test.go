package fofaruntime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestSearchUsesCredentialsOwnedByEachFallbackEndpoint(t *testing.T) {
	var primaryKey, primaryEmail, primaryAuth string
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryKey = r.URL.Query().Get("key")
		primaryEmail = r.URL.Query().Get("email")
		primaryAuth = r.Header.Get("Authorization")
		http.Error(w, "temporary", http.StatusBadGateway)
	}))
	defer primary.Close()

	var fallbackKey, fallbackEmail, fallbackAuth string
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackKey = r.URL.Query().Get("key")
		fallbackEmail = r.URL.Query().Get("email")
		fallbackAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":1,"total":1,"results":[["https://example.com"]]}`))
	}))
	defer fallback.Close()

	runtime, err := New(config.FofaConfig{Endpoints: []config.FofaEndpointConfig{
		{BaseURL: primary.URL, AuthMode: "bearer", BearerToken: "primary-token", AllowInsecureHTTP: true},
		{BaseURL: fallback.URL, AuthMode: "key", APIKey: "fallback-key", Email: "fallback@example.com", AllowInsecureHTTP: true},
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	response, err := runtime.Search(context.Background(), SearchRequest{Query: `domain="example.com"`, Size: 10, Page: 1, Fields: "host"})
	if err != nil || response == nil || response.Total != 1 {
		t.Fatalf("fallback search failed: response=%#v err=%v", response, err)
	}
	if primaryAuth != "Bearer primary-token" || primaryKey != "" || primaryEmail != "" {
		t.Fatalf("primary bearer endpoint leaked key auth: auth=%q key=%q email=%q", primaryAuth, primaryKey, primaryEmail)
	}
	if fallbackAuth != "" || fallbackKey != "fallback-key" || fallbackEmail != "fallback@example.com" {
		t.Fatalf("fallback endpoint did not use its own key auth: auth=%q key=%q email=%q", fallbackAuth, fallbackKey, fallbackEmail)
	}
}

func TestConcurrentUpdateAndSearchNeverMixesEndpointAndCredential(t *testing.T) {
	server := func(wantKey string, mismatches *int, mu *sync.Mutex) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("key") != wantKey {
				mu.Lock()
				*mismatches++
				mu.Unlock()
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":false,"size":1,"results":[["ok"]]}`))
		}))
	}
	var mu sync.Mutex
	mismatches := 0
	a := server("key-a", &mismatches, &mu)
	defer a.Close()
	b := server("key-b", &mismatches, &mu)
	defer b.Close()
	configFor := func(baseURL, key string) config.FofaConfig {
		return config.FofaConfig{Endpoints: []config.FofaEndpointConfig{{
			BaseURL: baseURL, AuthMode: "key", APIKey: key, AllowInsecureHTTP: true,
		}}}
	}
	runtime, err := New(configFor(a.URL, "key-a"), "")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			cfg := configFor(a.URL, "key-a")
			if i%2 == 1 {
				cfg = configFor(b.URL, "key-b")
			}
			if err := runtime.Update(cfg, ""); err != nil {
				t.Errorf("Update: %v", err)
			}
		}(i)
		go func() {
			defer wg.Done()
			_, _ = runtime.Search(context.Background(), SearchRequest{Query: "test", Size: 1, Page: 1, Fields: "host"})
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if mismatches != 0 {
		t.Fatalf("observed %d mixed endpoint/credential snapshots", mismatches)
	}
}

func TestSnapshotOwnsReusableHTTPClientPerEndpoint(t *testing.T) {
	snapshot, err := buildSnapshot(config.FofaConfig{Endpoints: []config.FofaEndpointConfig{{
		BaseURL: "http://127.0.0.1:1", AuthMode: "key", APIKey: "key", AllowInsecureHTTP: true,
	}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.endpoints) != 1 || snapshot.endpoints[0].client == nil {
		t.Fatalf("配置快照必须持有可复用 HTTP client: %#v", snapshot.endpoints)
	}
}

func TestSearchNormalizesTransitStationFieldSemantics(t *testing.T) {
	// 中转站：无 total，size=总匹配数，results 长度=返回条数
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":52,"page":1,"results":[["a"],["b"]]}`))
	}))
	defer srv.Close()

	runtime, err := New(config.FofaConfig{BaseURL: srv.URL, APIKey: "k"}, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := runtime.Search(context.Background(), SearchRequest{Query: "x", Size: 2, Page: 1, Fields: "host"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Total != 52 {
		t.Fatalf("total = %d, want 52 (transit station size carries total)", resp.Total)
	}
	if resp.Size != 2 {
		t.Fatalf("size = %d, want 2 (should be results length)", resp.Size)
	}
}

func TestSearchKeepsOfficialFieldSemantics(t *testing.T) {
	// 官方：size=返回条数，total=总匹配数
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":2,"total":52,"page":1,"results":[["a"],["b"]]}`))
	}))
	defer srv.Close()

	runtime, err := New(config.FofaConfig{BaseURL: srv.URL, APIKey: "k"}, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := runtime.Search(context.Background(), SearchRequest{Query: "x", Size: 2, Page: 1, Fields: "host"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Total != 52 || resp.Size != 2 {
		t.Fatalf("official semantics broken: total=%d size=%d, want 52/2", resp.Total, resp.Size)
	}
}
