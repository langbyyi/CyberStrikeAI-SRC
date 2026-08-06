package fofaruntime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
)

// TestSearchByProviderQuakeNative proves quake goes through its NATIVE protocol
// (POST JSON + X-QuakeToken header), not the FOFA qbase64+key GET.
func TestSearchByProviderQuakeNative(t *testing.T) {
	var gotMethod, gotToken, gotQBase64, gotKey string
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotToken = r.Header.Get("X-QuakeToken")
		gotKey = r.URL.Query().Get("key")
		gotQBase64 = r.URL.Query().Get("qbase64")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","total_count":2,"data":[{"ip":"1.1.1.1","port":443,"service":{"http":{"title":"x"}}}],"meta":{"pagination":{"total":2}}}`))
	}))
	defer srv.Close()

	rt, err := New(config.FofaConfig{BaseURL: srv.URL, APIKey: "quake-token"}, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.SearchByProvider(context.Background(), "quake", SearchRequest{
		Query: `service.name:"http"`, Size: 10, Page: 1, Fields: "ip,port,service.http.title",
	})
	if err != nil {
		t.Fatalf("quake search: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("quake must use POST (native), got %q", gotMethod)
	}
	if gotToken != "quake-token" {
		t.Fatalf("quake must send X-QuakeToken header, got %q", gotToken)
	}
	if gotKey != "" || gotQBase64 != "" {
		t.Fatalf("quake must NOT use FOFA key/qbase64 params, got key=%q qbase64=%q", gotKey, gotQBase64)
	}
	if body["query"] != `service.name:"http"` || body["size"] != float64(10) || body["start"] != float64(0) {
		t.Fatalf("quake body wrong: %#v", body)
	}
	if inc, ok := body["include"].([]interface{}); !ok || len(inc) != 3 {
		t.Fatalf("quake include fields wrong: %#v", body["include"])
	}
	if resp.Provider != "quake" || resp.Total != 2 || resp.ResultsCount != 1 {
		t.Fatalf("quake normalized response wrong: %#v", resp)
	}
	title, _ := resp.Results[0]["service.http.title"].(string)
	if title != "x" {
		t.Fatalf("dot-path projection failed: %#v", resp.Results[0])
	}
}

// TestSearchByProviderShodanNative proves shodan uses NATIVE GET /shodan/host/search
// with key/query/page params (and pagination), not FOFA protocol.
func TestSearchByProviderShodanNative(t *testing.T) {
	var paths []string
	var gotQBase64 string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path+"?page="+r.URL.Query().Get("page"))
		if r.URL.Query().Get("qbase64") != "" {
			gotQBase64 = r.URL.Query().Get("qbase64")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":5,"matches":[{"ip_str":"2.2.2.2","port":80}]}`))
	}))
	defer srv.Close()

	rt, err := New(config.FofaConfig{BaseURL: srv.URL, APIKey: "shodan-key"}, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.SearchByProvider(context.Background(), "shodan", SearchRequest{
		Query: "product:nginx", Size: 1, Page: 1, Fields: "ip_str,port",
	})
	if err != nil {
		t.Fatalf("shodan search: %v", err)
	}
	if len(paths) == 0 || !strings.HasPrefix(paths[0], "/shodan/host/search") {
		t.Fatalf("shodan must hit /shodan/host/search, got %v", paths)
	}
	if gotQBase64 != "" {
		t.Fatalf("shodan must NOT use FOFA qbase64, got %q", gotQBase64)
	}
	if resp.Provider != "shodan" || resp.Total != 5 || resp.ResultsCount != 1 {
		t.Fatalf("shodan normalized response wrong: %#v", resp)
	}
}

// TestSearchByProviderZoomEyeNative proves zoomeye uses NATIVE POST + API-KEY header
// + qbase64 body (code==60000 success), not FOVA GET.
func TestSearchByProviderZoomEyeNative(t *testing.T) {
	var gotMethod, gotAPIKey, gotKey string
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAPIKey = r.Header.Get("API-KEY")
		gotKey = r.URL.Query().Get("key")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":60000,"message":"ok","total":3,"page":1,"pagesize":10,"data":[{"ip":"3.3.3.3","port":22}]}`))
	}))
	defer srv.Close()

	rt, err := New(config.FofaConfig{BaseURL: srv.URL, APIKey: "zmkey"}, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.SearchByProvider(context.Background(), "zoomeye", SearchRequest{
		Query: `app="nginx"`, Size: 10, Page: 1, Fields: "ip,port",
	})
	if err != nil {
		t.Fatalf("zoomeye search: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("zoomeye must use POST (native), got %q", gotMethod)
	}
	if gotAPIKey != "zmkey" {
		t.Fatalf("zoomeye must send API-KEY header, got %q", gotAPIKey)
	}
	if gotKey != "" {
		t.Fatalf("zoomeye must NOT use FOFA key param, got %q", gotKey)
	}
	if body["qbase64"] == nil || body["pagesize"] != float64(10) {
		t.Fatalf("zoomeye body wrong: %#v", body)
	}
	if resp.Provider != "zoomeye" || resp.Total != 3 || resp.ResultsCount != 1 {
		t.Fatalf("zoomeye normalized response wrong: %#v", resp)
	}
}

// TestSearchByProviderZoomEyeErrorCode surfaces the upstream message on code!=60000.
func TestSearchByProviderZoomEyeErrorCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":10010,"message":"invalid credential"}`))
	}))
	defer srv.Close()
	rt, err := New(config.FofaConfig{BaseURL: srv.URL, APIKey: "zmkey"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.SearchByProvider(context.Background(), "zoomeye", SearchRequest{Query: "x", Size: 1, Page: 1}); err == nil {
		t.Fatal("expected error for zoomeye non-success code")
	} else if !strings.Contains(err.Error(), "invalid credential") {
		t.Fatalf("error should carry upstream message, got %v", err)
	}
}

// TestSearchByProviderFofaStillWorks ensures the fofa branch still routes to the
// existing FOFA protocol (qbase64+key GET) and normalizes results.
func TestSearchByProviderFofaStillWorks(t *testing.T) {
	var gotKey, gotQBase64, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotKey = r.URL.Query().Get("key")
		gotQBase64 = r.URL.Query().Get("qbase64")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":1,"page":1,"total":1,"results":[["https://example.com","1.1.1.1"]]}`))
	}))
	defer srv.Close()
	rt, err := New(config.FofaConfig{BaseURL: srv.URL, APIKey: "fofa-key", Email: "e@x.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.SearchByProvider(context.Background(), "fofa", SearchRequest{
		Query: `domain="example.com"`, Size: 1, Page: 1, Fields: "host,ip",
	})
	if err != nil {
		t.Fatalf("fofa search: %v", err)
	}
	if gotMethod != http.MethodGet || gotKey != "fofa-key" || gotQBase64 == "" {
		t.Fatalf("fofa must keep qbase64+key GET, got method=%q key=%q qbase64=%q", gotMethod, gotKey, gotQBase64)
	}
	if resp.Provider != "fofa" || resp.Total != 1 || len(resp.Results) != 1 {
		t.Fatalf("fofa normalized response wrong: %#v", resp)
	}
	if resp.Results[0]["host"] != "https://example.com" || resp.Results[0]["ip"] != "1.1.1.1" {
		t.Fatalf("fofa field projection wrong: %#v", resp.Results[0])
	}
}

func TestEnsureSearchPathFillsDefaultWhenRoot(t *testing.T) {
	cases := []struct {
		in, path, want string
	}{
		{"https://fofoapi.com", "/api/v1/search/all", "https://fofoapi.com/api/v1/search/all"},
		{"https://fofoapi.com/", "/api/v1/search/all", "https://fofoapi.com/api/v1/search/all"},
		{"https://fofa.info/api/v1/search/all", "/api/v1/search/all", "https://fofa.info/api/v1/search/all"},
		{"http://127.0.0.1:8080", "/shodan/host/search", "http://127.0.0.1:8080/shodan/host/search"},
		{"https://api.shodan.io/shodan/host/search", "/shodan/host/search", "https://api.shodan.io/shodan/host/search"},
		{"", "/api/v1/search/all", ""},
		{"not-a-url", "/api/v1/search/all", "not-a-url"},
	}
	for _, tc := range cases {
		if got := ensureSearchPath(tc.in, tc.path); got != tc.want {
			t.Errorf("ensureSearchPath(%q, %q) = %q, want %q", tc.in, tc.path, got, tc.want)
		}
	}
}

func TestSearchCompletesRootBaseURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":1,"total":1,"results":[["ok"]]}`))
	}))
	defer srv.Close()

	runtime, err := New(config.FofaConfig{BaseURL: srv.URL, APIKey: "k"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Search(context.Background(), SearchRequest{Query: "x", Size: 1, Page: 1, Fields: "host"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/search/all" {
		t.Fatalf("root base_url request path = %q, want /api/v1/search/all", gotPath)
	}
}
