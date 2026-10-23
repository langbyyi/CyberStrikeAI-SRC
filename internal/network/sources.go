package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type SourceFetch func(context.Context, Source, int) ([]string, bool, error)
type SyncResult struct {
	Imported    int            `json:"imported"`
	Skipped     int            `json:"skipped"`
	Pages       int            `json:"pages"`
	Unsupported map[string]int `json:"unsupported,omitempty"`
}

func (s *Service) DeleteSource(id string) error {
	return s.mutate(func() error {
		if _, ok := s.state.Sources[id]; !ok {
			return fmt.Errorf("proxy source not found")
		}
		delete(s.state.Sources, id)
		return nil
	})
}

func (s *Service) SaveSource(src Source) (Source, error) {
	if src.Kind != "fofa" && src.Kind != "subscription" && src.Kind != "quake" && src.Kind != "hunter" && src.Kind != "shodan" && src.Kind != "zoomeye" {
		return src, fmt.Errorf("unsupported proxy source kind")
	}
	if src.Name == "" || len(src.Name) > 200 || len(src.Query) > 8192 {
		return src, fmt.Errorf("invalid source name or query")
	}
	if src.Kind != "subscription" && strings.TrimSpace(src.Query) == "" {
		return src, fmt.Errorf("search source query is required")
	}
	if src.Limit <= 0 {
		src.Limit = 100
	}
	if src.Limit > MaxProxyImport {
		return src, fmt.Errorf("source limit cannot exceed 10000")
	}
	err := s.mutate(func() error {
		if src.ID != "" {
			existing, ok := s.state.Sources[src.ID]
			if !ok {
				return fmt.Errorf("proxy source not found")
			}
			// Listing redacts subscription tokens. An empty edit keeps the stored URL.
			if src.Kind == "subscription" && existing.Kind == src.Kind && src.URL == "" {
				src.URL = existing.URL
			}
		} else {
			src.ID = newID()
		}
		if src.Kind == "subscription" {
			u, e := url.Parse(src.URL)
			if e != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
				return fmt.Errorf("invalid subscription URL")
			}
		}
		s.state.Sources[src.ID] = src
		return nil
	})
	return src, err
}
func (s *Service) Sources() []Source {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Source, 0, len(s.state.Sources))
	for _, src := range s.state.Sources {
		if u, e := url.Parse(src.URL); e == nil {
			// Subscription credentials commonly live in path segments as well as query strings.
			src.URL = (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
		} else {
			src.URL = ""
		}
		out = append(out, src)
	}
	return out
}
func (s *Service) SyncSource(ctx context.Context, id string, fetch SourceFetch) (SyncResult, error) {
	s.mu.RLock()
	src, ok := s.state.Sources[id]
	s.mu.RUnlock()
	result := SyncResult{Unsupported: map[string]int{}}
	if !ok {
		return result, fmt.Errorf("proxy source not found")
	}
	if fetch == nil {
		return result, fmt.Errorf("proxy source fetcher is unavailable")
	}
	count := 0
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if current, exists := s.state.Sources[id]; !exists || current != src {
			return fmt.Errorf("proxy source changed during collection; start collection again with the current configuration")
		}
		return nil
	}
	maxPages := (src.Limit + 99) / 100
	if maxPages < 10 {
		maxPages = 10
	}
	for page := 1; page <= maxPages && count < src.Limit; page++ {
		finish, err := beginJobUnit(ctx)
		if err != nil {
			return result, err
		}
		done, err := func() (bool, error) {
			defer finish()
			s.mu.RLock()
			err := check()
			s.mu.RUnlock()
			if err != nil {
				return false, err
			}
			reportJobProgress(ctx, JobProgress{Kind: "source", Stage: "fetching"})
			pageCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			items, done, err := fetch(pageCtx, src, page)
			timedOut := errors.Is(pageCtx.Err(), context.DeadlineExceeded)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return false, ctx.Err()
				}
				if timedOut {
					return false, fmt.Errorf("%s source page %d timed out after 30 seconds; completed pages are preserved", src.Kind, page)
				}
				return false, fmt.Errorf("%s source page %d failed; check credentials, API endpoint and quota; completed pages are preserved", src.Kind, page)
			}
			if err := ctx.Err(); err != nil {
				return false, err
			}
			result.Pages++
			parsed, err := ParseProxyInput(strings.Join(items, "\n"), src.Limit-count)
			if err != nil {
				return false, fmt.Errorf("invalid proxy source content on page %d", page)
			}
			if err := ctx.Err(); err != nil {
				return false, err
			}
			imported, err := s.importParsedProxiesChecked(parsed, "source:"+id, check)
			if err != nil {
				return false, err
			}
			count += len(imported.Nodes) + imported.Skipped
			result.Imported += imported.Imported
			result.Skipped += imported.Skipped
			for kind, n := range imported.Unsupported {
				result.Unsupported[kind] += n
			}
			reportJobProgress(ctx, JobProgress{Kind: "source", Stage: "collecting", Pages: 1, Imported: imported.Imported, Skipped: imported.Skipped})
			return done, nil
		}()
		if err != nil {
			return result, err
		}
		if done {
			break
		}
	}
	return result, nil
}

// errSubscriptionAddressDenied marks a subscription host whose DNS resolves into
// a reserved or non-public range (fake-ip proxy DNS, intranet, cloud metadata).
var errSubscriptionAddressDenied = errors.New("subscription DNS points to a private or reserved address; the server cannot fetch it")

func FetchSubscription(ctx context.Context, src Source, page int) ([]string, bool, error) {
	if page != 1 {
		return nil, true, nil
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("subscription host %s could not be resolved: %w", host, err)
		}
		for _, ip := range ips {
			if !publicSubscriptionIP(ip) {
				// Wrapped so client.Do cannot mask it: fake-ip proxy DNS and
				// intranet addresses mean the server cannot fetch this URL.
				return nil, fmt.Errorf("%w: %s resolved to %s", errSubscriptionAddressDenied, host, ips[0])
			}
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("subscription host has no address")
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, true, fmt.Errorf("invalid subscription request")
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errSubscriptionAddressDenied) {
			return nil, true, err
		}
		return nil, true, fmt.Errorf("subscription connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, true, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return nil, true, fmt.Errorf("subscription exceeded 2 MiB or could not be read")
	}
	return []string{string(raw)}, true, nil
}
func publicSubscriptionIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4"} {
		if netip.MustParsePrefix(p).Contains(ip) {
			return false
		}
	}
	return true
}
