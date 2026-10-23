package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/network"
)

// sourceTestConfig points every native provider at the test fixture with a shared key.
func sourceTestConfig(baseURL string) *config.Config {
	return &config.Config{
		FOFA:    config.FofaConfig{APIKey: "source-key", BaseURL: baseURL},
		Quake:   config.SpaceSearchConfig{APIKey: "source-key", BaseURL: baseURL},
		Shodan:  config.SpaceSearchConfig{APIKey: "source-key", BaseURL: baseURL},
		ZoomEye: config.SpaceSearchConfig{APIKey: "source-key", BaseURL: baseURL},
	}
}

// useHunterFixture redirects the Hunter endpoint at the fixture for the test duration.
func useHunterFixture(t *testing.T, baseURL string) {
	t.Helper()
	t.Setenv("HUNTER_API_KEY", "source-key")
	original := hunterAPIEndpoint
	hunterAPIEndpoint = baseURL
	t.Cleanup(func() { hunterAPIEndpoint = original })
}

func TestNetworkSourceNativeProviders(t *testing.T) {
	for _, tc := range []struct {
		kind, response string
		want           []string
	}{
		{"fofa", `{"error":false,"total":3,"results":[["192.0.2.1",8080,"HTTP"],["192.0.2.2",1080,"socks5"],["192.0.2.3",80,"tcp"]]}`, []string{"http://192.0.2.1:8080", "socks5://192.0.2.2:1080"}},
		{"quake", `{"code":0,"total_count":3,"data":[{"ip":"192.0.2.1","port":8080,"service":{"name":"http"}},{"ip":"2001:db8::1","port":443,"service":{"name":"https"}},{"ip":"192.0.2.3","port":80,"transport":"tcp"}]}`, []string{"http://192.0.2.1:8080", "https://[2001:db8::1]:443"}},
		{"shodan", `{"total":3,"matches":[{"ip_str":"192.0.2.1","port":8080,"_shodan":{"module":"http"},"transport":"tcp"},{"ip_str":"192.0.2.2","port":443,"_shodan":{"module":"https"}},{"ip_str":"192.0.2.3","port":80,"transport":"tcp"}]}`, []string{"http://192.0.2.1:8080", "https://192.0.2.2:443"}},
		{"zoomeye", `{"code":60000,"total":3,"data":[{"ip":"192.0.2.1","port":8080,"service":"http","protocol":"tcp"},{"ip":"192.0.2.2","port":1080,"service":"socks5","protocol":"tcp"},{"ip":"192.0.2.3","port":80,"protocol":"tcp"}]}`, []string{"http://192.0.2.1:8080", "socks5://192.0.2.2:1080"}},
		{"hunter", `{"code":200,"data":{"total":3,"arr":[{"ip":"192.0.2.1","port":8080,"protocol":"http","base_protocol":"tcp"},{"ip":"192.0.2.2","port":443,"protocol":"https"},{"ip":"192.0.2.3","port":80,"base_protocol":"tcp"}]}}`, []string{"http://192.0.2.1:8080", "https://192.0.2.2:443"}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch tc.kind {
				case "fofa":
					if r.Method != "GET" || r.URL.Query().Get("key") != "source-key" || r.URL.Query().Get("qbase64") != base64.StdEncoding.EncodeToString([]byte("owned-query")) {
						t.Errorf("wrong FOFA native request")
					}
				case "quake":
					var body map[string]interface{}
					_ = json.NewDecoder(r.Body).Decode(&body)
					if r.Method != "POST" || r.Header.Get("X-QuakeToken") != "source-key" || body["query"] != "owned-query" || body["start"] != float64(0) {
						t.Errorf("wrong Quake native request")
					}
				case "shodan":
					if r.URL.Path != "/shodan/host/search" || r.URL.Query().Get("key") != "source-key" || r.URL.Query().Get("query") != "owned-query" {
						t.Errorf("wrong Shodan native request")
					}
				case "zoomeye":
					if r.Method != "POST" || r.Header.Get("API-KEY") != "source-key" {
						t.Errorf("wrong ZoomEye native request")
					}
				case "hunter":
					if r.Method != "GET" || r.URL.Path != "/openApi/search" || r.URL.Query().Get("api-key") != "source-key" || r.URL.Query().Get("search") != base64.URLEncoding.EncodeToString([]byte("owned-query")) || r.URL.Query().Get("is_web") != "3" {
						t.Errorf("wrong Hunter native request")
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.response))
			}))
			defer srv.Close()
			if tc.kind == "hunter" {
				useHunterFixture(t, srv.URL+"/openApi/search")
			}
			got, done, err := networkSourceFetcher(sourceTestConfig(srv.URL))(context.Background(), network.Source{Kind: tc.kind, Query: "owned-query", Limit: 100}, 1)
			if err != nil || !done || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, done=%v, err=%v; want %v", got, done, err, tc.want)
			}
		})
	}
}

func TestNetworkSourcePagingAndLimit(t *testing.T) {
	for _, kind := range []string{"fofa", "quake", "shodan", "zoomeye", "hunter"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				page, size := r.URL.Query().Get("page"), r.URL.Query().Get("size")
				if kind == "hunter" {
					size = r.URL.Query().Get("page_size")
				}
				if kind == "quake" || kind == "zoomeye" {
					var body map[string]interface{}
					_ = json.NewDecoder(r.Body).Decode(&body)
					if kind == "quake" {
						size = fmt.Sprint(body["size"])
						page = strconv.Itoa(int(body["start"].(float64))/100 + 1)
					} else {
						size = fmt.Sprint(body["pagesize"])
						page = fmt.Sprint(body["page"])
					}
				}
				if page != strconv.Itoa(calls) || (kind != "shodan" && size != "100") {
					t.Errorf("unexpected pagination page=%s size=%s calls=%d", page, size, calls)
				}
				rows := make([]interface{}, 100)
				for i := range rows {
					if kind == "fofa" {
						rows[i] = []interface{}{"192.0.2.1", 8000 + i, "http"}
					} else {
						rows[i] = map[string]interface{}{"ip": "192.0.2.1", "ip_str": "192.0.2.1", "port": 8000 + i, "protocol": "http", "service": "http", "_shodan": map[string]interface{}{"module": "http"}}
						if kind == "quake" {
							rows[i].(map[string]interface{})["service"] = map[string]interface{}{"name": "http"}
						}
					}
				}
				var result interface{}
				switch kind {
				case "fofa":
					result = map[string]interface{}{"error": false, "total": 151, "results": rows}
				case "quake":
					result = map[string]interface{}{"code": 0, "total_count": 151, "data": rows}
				case "shodan":
					result = map[string]interface{}{"total": 151, "matches": rows}
				case "zoomeye":
					result = map[string]interface{}{"code": 60000, "total": 151, "data": rows}
				case "hunter":
					result = map[string]interface{}{"code": 200, "data": map[string]interface{}{"total": 151, "arr": rows}}
				}
				_ = json.NewEncoder(w).Encode(result)
			}))
			defer srv.Close()
			if kind == "hunter" {
				useHunterFixture(t, srv.URL+"/openApi/search")
			}
			fetch := networkSourceFetcher(sourceTestConfig(srv.URL))
			source := network.Source{Kind: kind, Query: "owned", Limit: 150}
			first, done, err := fetch(context.Background(), source, 1)
			if err != nil || done || len(first) != 100 {
				t.Fatalf("first: len=%d done=%v err=%v", len(first), done, err)
			}
			second, done, err := fetch(context.Background(), source, 2)
			if err != nil || !done || len(second) != 50 {
				t.Fatalf("second: len=%d done=%v err=%v", len(second), done, err)
			}
			_, done, err = fetch(context.Background(), source, 3)
			if err != nil || !done || calls != 2 {
				t.Fatalf("over limit: done=%v err=%v calls=%d", done, err, calls)
			}
		})
	}
}

func TestNetworkSourceErrorsAreRedacted(t *testing.T) {
	for _, kind := range []string{"fofa", "quake", "shodan", "zoomeye", "hunter", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			t.Setenv(strings.ToUpper(kind)+"_API_KEY", "")
			_, _, err := networkSourceFetcher(&config.Config{})(context.Background(), network.Source{Kind: kind, Query: "private-query", Limit: 10}, 1)
			if err == nil {
				t.Fatal("missing credentials must fail")
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"error":true,"code":401,"message":"secret-key private-query https://secret.invalid/?key=secret-key","errmsg":"secret-key private-query"}`))
			}))
			defer srv.Close()
			if kind == "hunter" {
				useHunterFixture(t, srv.URL)
			}
			_, _, err = networkSourceFetcher(sourceTestConfig(srv.URL))(context.Background(), network.Source{Kind: kind, Query: "private-query", Limit: 100}, 1)
			if err == nil || strings.Contains(err.Error(), "secret-key") || strings.Contains(err.Error(), "private-query") || strings.Contains(err.Error(), "http") {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}

func TestNetworkSourceCancellation(t *testing.T) {
	for _, kind := range []string{"fofa", "quake", "shodan", "zoomeye", "hunter"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			defer func() { close(release); srv.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if kind == "hunter" {
				useHunterFixture(t, srv.URL)
			}
			_, _, err := networkSourceFetcher(sourceTestConfig(srv.URL))(ctx, network.Source{Kind: kind, Query: "owned", Limit: 100}, 1)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancellation must remain observable: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls=%d", calls.Load())
			}
		})
	}
}

func TestNetworkSourceGlobalConfigurationAndProviders(t *testing.T) {
	for _, kind := range []string{"FOFA", "QUAKE", "SHODAN", "ZOOMEYE", "HUNTER"} {
		t.Setenv(kind+"_API_KEY", "")
	}
	cfg := &config.Config{}
	providers := networkSourceProviders(cfg)
	if len(providers) != 6 {
		t.Fatalf("providers=%v", providers)
	}
	for _, provider := range providers {
		if provider.Configured != (provider.Kind == "subscription") {
			t.Fatalf("unexpected configuration: %v", provider)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-bearer" {
			t.Errorf("global bearer auth lost")
		}
		_, _ = w.Write([]byte(`{"error":false,"total":1,"results":[["192.0.2.1",8080,"http"]]}`))
	}))
	defer srv.Close()
	cfg.FOFA = config.FofaConfig{BaseURL: srv.URL, BearerToken: "synthetic-bearer"}
	cfg.Quake.APIKey, cfg.Shodan.APIKey, cfg.ZoomEye.APIKey = "q-key", "s-key", "z-key"
	t.Setenv("HUNTER_API_KEY", "h-key")
	for _, provider := range networkSourceProviders(cfg) {
		if !provider.Configured {
			t.Fatalf("configured provider missing: %v", provider)
		}
	}
	got, done, err := networkSourceFetcher(cfg)(context.Background(), network.Source{Kind: "fofa", Query: "owned", Limit: 100}, 1)
	if err != nil || !done || !reflect.DeepEqual(got, []string{"http://192.0.2.1:8080"}) {
		t.Fatalf("global FOFA configuration: %v %v %v", got, done, err)
	}
}

func TestNetworkSourceUsesSystemEndpointConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "global-key" {
			t.Errorf("system-configured endpoint key lost")
		}
		_, _ = w.Write([]byte(`{"error":false,"total":1,"results":[["192.0.2.1",8080,"http"]]}`))
	}))
	defer srv.Close()
	cfg := &config.Config{FOFA: config.FofaConfig{Endpoints: []config.FofaEndpointConfig{{BaseURL: srv.URL, APIKey: "global-key"}}}}
	got, _, err := networkSourceFetcher(cfg)(context.Background(), network.Source{Kind: "fofa", Query: "owned", Limit: 100}, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("system endpoint config not used: %v %v", got, err)
	}
	if cfg.FOFA.Endpoints[0].APIKey != "global-key" {
		t.Fatal("fetch mutated global configuration")
	}
}

func TestNetworkSourceRejectsInvalidEndpointRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":"200","data":{"total":5,"arr":[{"ip":"192.0.2.1","port":0,"protocol":"http"},{"ip":"192.0.2.1","port":65536,"protocol":"http"},{"ip":"example.invalid/path","port":80,"protocol":"http"},{"ip":"192.0.2.1","port":80,"protocol":"socks4"},{"ip":"192.0.2.1","port":80,"protocol":"tcp"}]}}`))
	}))
	defer srv.Close()
	useHunterFixture(t, srv.URL)
	got, done, err := networkSourceFetcher(nil)(context.Background(), network.Source{Kind: "hunter", Query: "owned", Limit: 100}, 1)
	if err != nil || !done || len(got) != 0 {
		t.Fatalf("unsafe records accepted: %v %v %v", got, done, err)
	}
}

func TestNetworkSourceNativeTotalEndsFullPage(t *testing.T) {
	rows := make([]map[string]interface{}, 100)
	for i := range rows {
		rows[i] = map[string]interface{}{"ip": "192.0.2.1", "port": 8000 + i, "protocol": "http"}
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("api-key") != "source-key" || r.URL.Query().Get("page_size") != "100" {
			t.Errorf("environment credential or size missing")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"total": 100, "arr": rows}})
	}))
	defer srv.Close()
	useHunterFixture(t, srv.URL)
	fetch := networkSourceFetcher(nil)
	source := network.Source{Kind: "hunter", Query: "owned", Limit: 100}
	got, done, err := fetch(context.Background(), source, 1)
	if err != nil || !done || len(got) != 100 {
		t.Fatalf("full last page: len=%d done=%v err=%v", len(got), done, err)
	}
	source.Limit = 10001
	got, done, err = fetch(context.Background(), source, 101)
	if err != nil || !done || len(got) != 0 || calls != 1 {
		t.Fatalf("maximum quota ignored: len=%d done=%v err=%v calls=%d", len(got), done, err, calls)
	}
}

func TestNetworkSourceSOCKSAliasCompatibility(t *testing.T) {
	for _, kind := range []string{"fofa", "quake", "shodan", "zoomeye", "hunter"} {
		for _, protocol := range []string{"socks", "SOCKS", "socks5", "socks4", "socks4a", "unknown"} {
			t.Run(kind+"/"+protocol, func(t *testing.T) {
				row := map[string]interface{}{"ip": "192.0.2.1", "ip_str": "192.0.2.1", "port": 1080, "protocol": protocol, "service": map[string]interface{}{"name": protocol}, "_shodan": map[string]interface{}{"module": protocol}}
				if kind == "zoomeye" {
					row["service"] = protocol
				}
				want := ""
				if protocol == "socks" || protocol == "SOCKS" || protocol == "socks5" {
					want = "socks5://192.0.2.1:1080"
				}
				if got := networkSourceEndpoint(kind, row); got != want {
					t.Fatalf("endpoint=%q want=%q", got, want)
				}
			})
		}
	}
}
