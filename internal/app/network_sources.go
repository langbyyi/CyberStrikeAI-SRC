package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/fofaruntime"
	"cyberstrike-ai/internal/network"
)

func networkSourceProviders(cfg *config.Config) []network.SourceProvider {
	if cfg == nil {
		cfg = &config.Config{}
	}
	providers := make([]network.SourceProvider, 0, 6)
	for _, provider := range []struct{ kind, name string }{
		{"fofa", "FOFA"}, {"quake", "Quake"}, {"shodan", "Shodan"}, {"zoomeye", "ZoomEye"}, {"hunter", "Hunter"}, {"subscription", "订阅"},
	} {
		configured := false
		switch provider.kind {
		case "fofa":
			configured = fofaHasAnyCredential(cfg) || strings.TrimSpace(cfg.FOFA.BearerToken) != ""
		case "hunter":
			configured = strings.TrimSpace(os.Getenv("HUNTER_API_KEY")) != ""
		case "subscription":
			configured = true
		default:
			configured = resolveProviderAPIKey(cfg, provider.kind) != ""
		}
		providers = append(providers, network.SourceProvider{Kind: provider.kind, Name: provider.name, Configured: configured})
	}
	return providers
}

func networkSourceFetcher(cfg *config.Config) network.SourceFetch {
	return func(ctx context.Context, source network.Source, page int) ([]string, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, true, err
		}
		if source.Kind == "subscription" {
			return network.FetchSubscription(ctx, source, page)
		}
		fields := map[string]string{
			"fofa": "ip,port,protocol", "quake": "ip,port,service.name", "shodan": "ip_str,port,_shodan.module", "zoomeye": "ip,port,service",
		}
		if _, ok := fields[source.Kind]; !ok && source.Kind != "hunter" {
			return nil, true, fmt.Errorf("unsupported proxy-source provider")
		}
		if page < 1 || source.Limit < 1 {
			return nil, true, fmt.Errorf("proxy-source page and limit must be positive")
		}
		limit := min(source.Limit, 10000)
		size := min(limit, 100)
		// Keep the API page size fixed on the final page so offsets do not change.
		if page > (limit+size-1)/size {
			return nil, true, nil
		}
		offset := (page - 1) * size
		var rows []map[string]interface{}
		var total int
		var err error
		if source.Kind == "hunter" {
			rows, total, err = networkHunterSearch(ctx, source, page, size)
		} else {
			var rt *fofaruntime.Runtime
			rt, err = networkSourceRuntime(cfg, source.Kind)
			if err == nil {
				var response *fofaruntime.SearchResponse
				response, err = rt.SearchByProvider(ctx, source.Kind, fofaruntime.SearchRequest{Query: source.Query, Size: size, Page: page, Fields: fields[source.Kind]})
				if err == nil {
					rows, total = response.Results, response.Total
				}
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, true, ctx.Err()
			}
			// Provider errors can echo credentials, encoded queries, and request URLs.
			return nil, true, fmt.Errorf("%s proxy-source search failed; check credentials, endpoint and quota", source.Kind)
		}
		done := len(rows) < size || offset+size >= limit || (total > 0 && offset+len(rows) >= total)
		rows = rows[:min(len(rows), limit-offset)]
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			if endpoint := networkSourceEndpoint(source.Kind, row); endpoint != "" {
				out = append(out, endpoint)
			}
		}
		return out, done, nil
	}
}

// networkSourceRuntime always resolves provider credentials and endpoints from the
// system configuration; sources no longer carry their own credentials.
func networkSourceRuntime(cfg *config.Config, kind string) (*fofaruntime.Runtime, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if kind == "fofa" && strings.TrimSpace(cfg.FOFA.BearerToken) != "" {
		return fofaruntime.New(cfg.FOFA, strings.TrimSpace(os.Getenv("FOFA_API_KEY")))
	}
	return resolveProviderRuntime(cfg, kind)
}

func networkSourceEndpoint(kind string, row map[string]interface{}) string {
	protocolField, ipField := "protocol", "ip"
	switch kind {
	case "quake":
		protocolField = "service.name"
	case "shodan":
		protocolField, ipField = "_shodan.module", "ip_str"
	case "zoomeye":
		protocolField = "service"
	}
	protocol, _ := networkSourceValue(row, protocolField).(string)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "socks" {
		protocol = "socks5"
	}
	if protocol != "http" && protocol != "https" && protocol != "socks5" {
		return ""
	}
	host, _ := row[ipField].(string)
	if net.ParseIP(host) == nil {
		return ""
	}
	portText := fmt.Sprint(row["port"])
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return ""
	}
	return protocol + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func networkSourceValue(row map[string]interface{}, field string) interface{} {
	if value, ok := row[field]; ok {
		return value
	}
	var value interface{} = row
	for _, part := range strings.Split(field, ".") {
		object, ok := value.(map[string]interface{})
		if !ok {
			return nil
		}
		value = object[part]
	}
	return value
}

// hunterAPIEndpoint is a package variable so integration tests can point the
// fetcher at a controlled fixture without per-source endpoint overrides.
var hunterAPIEndpoint = "https://hunter.qianxin.com/openApi/search"

func networkHunterSearch(ctx context.Context, source network.Source, page, size int) ([]map[string]interface{}, int, error) {
	key := strings.TrimSpace(os.Getenv("HUNTER_API_KEY"))
	if key == "" {
		return nil, 0, fmt.Errorf("Hunter credentials missing; set HUNTER_API_KEY or configure it in system settings")
	}
	u, err := url.Parse(hunterAPIEndpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, 0, fmt.Errorf("invalid Hunter endpoint")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, 0, fmt.Errorf("Hunter endpoint requires TLS")
		}
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/openApi/search"
	}
	params := u.Query()
	params.Set("api-key", key)
	params.Set("search", base64.URLEncoding.EncodeToString([]byte(source.Query)))
	params.Set("page", strconv.Itoa(page))
	params.Set("page_size", strconv.Itoa(size))
	params.Set("is_web", "3")
	params.Set("fields", "ip,port,protocol")
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create Hunter request failed")
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("Hunter request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("Hunter request rejected")
	}
	var result struct {
		Code interface{} `json:"code"`
		Data struct {
			Total int                      `json:"total"`
			Rows  []map[string]interface{} `json:"arr"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("invalid Hunter response")
	}
	if fmt.Sprint(result.Code) != "200" {
		return nil, 0, fmt.Errorf("Hunter search rejected")
	}
	return result.Data.Rows, result.Data.Total, nil
}
