package network

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSourceEditPreservesSecretURLAndRejectsMissingSource(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	src, err := s.SaveSource(Source{Name: "fixture", Kind: "subscription", URL: "https://provider.test/private-token?key=synthetic", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	listed := s.Sources()[0]
	listed.Name, listed.URL = "renamed", ""
	saved, err := s.SaveSource(listed)
	if err != nil {
		t.Fatal(err)
	}
	if saved.URL != src.URL || saved.Name != "renamed" {
		t.Fatalf("edit lost source configuration: %+v", saved)
	}
	listed.ID = "missing"
	if _, err := s.SaveSource(listed); err == nil {
		t.Fatal("editing a deleted source recreated it")
	}
}

func TestSourceStopsOnFetchFailureOrCancellationBeforeImport(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		s, _ := Open(t.TempDir())
		src, _ := s.SaveSource(Source{Name: "stopping source", Kind: "fofa", Query: "fixture", Limit: 100})
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		result, err := s.SyncSource(ctx, src.ID, func(context.Context, Source, int) ([]string, bool, error) {
			calls++
			if canceled {
				cancel()
				return []string{"http://127.0.0.1:8080"}, false, nil
			}
			return nil, false, fmt.Errorf("synthetic quota or authentication failure")
		})
		cancel()
		nodes := s.Nodes()
		_ = s.Close()
		if err == nil || calls != 1 || result.Imported != 0 || len(nodes) != 0 {
			t.Fatalf("canceled=%v imported after stop: %+v calls=%d nodes=%d err=%v", canceled, result, calls, len(nodes), err)
		}
	}
}

func TestSourceChangeDuringFetchRejectsStaleResults(t *testing.T) {
	for _, change := range []string{"delete", "query", "limit", "url"} {
		t.Run(change, func(t *testing.T) {
			s := validationService(t)
			src, err := s.SaveSource(Source{Name: "changing source", Kind: "fofa", Query: "fixture", Limit: 100})
			if change == "url" {
				src, err = s.SaveSource(Source{Name: "changing subscription", Kind: "subscription", URL: "https://provider.example/old", Limit: 100})
			}
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			result, err := s.SyncSource(context.Background(), src.ID, func(context.Context, Source, int) ([]string, bool, error) {
				calls++
				if change == "delete" {
					if err := s.DeleteSource(src.ID); err != nil {
						t.Fatal(err)
					}
				} else {
					updated := src
					switch change {
					case "query":
						updated.Query = "replacement"
					case "limit":
						updated.Limit = 1
					case "url":
						updated.URL = "https://provider.example/new"
					}
					if _, err := s.SaveSource(updated); err != nil {
						t.Fatal(err)
					}
				}
				return []string{"http://127.0.0.1:18001"}, true, nil
			})
			if err == nil || result.Imported != 0 || len(s.Nodes()) != 0 || calls != 1 {
				t.Fatalf("stale source results were accepted: result=%+v nodes=%d calls=%d err=%v", result, len(s.Nodes()), calls, err)
			}
		})
	}
}

func TestSourcePaginationAndPreserveDisabled(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	src, err := s.SaveSource(Source{Name: "fixture", Kind: "fofa", Query: "fixture", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fetch := func(ctx context.Context, source Source, page int) ([]string, bool, error) {
		calls++
		if page == 1 {
			return []string{"socks5://127.0.0.1:1080", "http://127.0.0.1:8080"}, false, nil
		}
		return []string{"http://127.0.0.1:8081"}, true, nil
	}
	result, err := s.SyncSource(context.Background(), src.ID, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 3 || calls != 2 {
		t.Fatalf("unexpected sync: %+v calls=%d", result, calls)
	}
	n := s.Nodes()[0]
	if err = s.SetNode(n.ID, false); err != nil {
		t.Fatal(err)
	}
	repeated, err := s.SyncSource(context.Background(), src.ID, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Imported != 0 || repeated.Skipped != 0 || repeated.Pages != 2 {
		t.Fatalf("repeated source counted existing nodes as additions or invalid input: %+v", repeated)
	}
	for _, node := range s.Nodes() {
		if node.ID == n.ID && node.Enabled {
			t.Fatal("sync reenabled disabled node")
		}
	}
}

func TestSourceExistingNodesStillConsumeCollectionBudget(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.AddProxy("http://127.0.0.1:18001", "manual"); err != nil {
		t.Fatal(err)
	}
	source, err := s.SaveSource(Source{Name: "bounded repeated source", Kind: "fofa", Query: "fixture", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.SyncSource(context.Background(), source.ID, func(_ context.Context, _ Source, page int) ([]string, bool, error) {
		switch page {
		case 1:
			return []string{"http://127.0.0.1:18001"}, false, nil
		case 2:
			return []string{"http://127.0.0.1:18002"}, false, nil
		default:
			t.Error("source fetched beyond its two-node budget")
			return []string{"http://127.0.0.1:18003"}, true, nil
		}
	})
	if err != nil || result.Imported != 1 || result.Skipped != 0 || result.Pages != 2 || len(s.Nodes()) != 2 {
		t.Fatalf("existing nodes changed collection budget or addition counts: %+v nodes=%d err=%v", result, len(s.Nodes()), err)
	}
}

func TestSourceCandidateAndCancellation(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	src, _ := s.SaveSource(Source{Name: "unconfirmed search", Kind: "fofa", Query: "fixture", Limit: 2})
	fetch := func(context.Context, Source, int) ([]string, bool, error) {
		return []string{"socks5://127.0.0.1:1080", "invalid"}, true, nil
	}
	result, err := s.SyncSource(context.Background(), src.ID, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 1 || !s.Nodes()[0].Enabled {
		t.Fatal("search result was not imported as a usable node")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.SyncSource(ctx, src.ID, fetch); err == nil {
		t.Fatal("canceled sync continued")
	}
}

func TestSourceContinuesAfterFilteredEmptyPage(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	src, _ := s.SaveSource(Source{Name: "filtered pages", Kind: "fofa", Query: "fixture", Limit: 100})
	result, err := s.SyncSource(context.Background(), src.ID, func(_ context.Context, _ Source, page int) ([]string, bool, error) {
		if page == 1 {
			return nil, false, nil
		}
		return []string{"socks5://127.0.0.1:1080"}, true, nil
	})
	if err != nil || result.Pages != 2 || result.Imported != 1 {
		t.Fatalf("filtered page dropped later proxies: %+v %v", result, err)
	}
	result, err = s.SyncSource(context.Background(), src.ID, func(context.Context, Source, int) ([]string, bool, error) { return nil, false, nil })
	if err != nil || result.Pages != 10 {
		t.Fatalf("empty pages exceeded pagination budget: %+v %v", result, err)
	}
}

func TestSourceListingRedactsSubscriptionPathTokens(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	original := "https://provider.example/subscription/synthetic-path-secret?token=synthetic-query-secret#synthetic-fragment-secret"
	source, err := s.SaveSource(Source{Name: "subscription fixture", Kind: "subscription", URL: original, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	listed := s.Sources()
	if len(listed) != 1 || strings.Contains(listed[0].URL, "synthetic-") {
		t.Fatalf("source listing exposes credential material: %#v", listed)
	}
	called := false
	_, err = s.SyncSource(context.Background(), source.ID, func(_ context.Context, src Source, _ int) ([]string, bool, error) {
		called = true
		if src.URL != original {
			t.Error("source synchronization lost its stored URL")
		}
		return []string{"http://127.0.0.1:8080"}, true, nil
	})
	if err != nil || !called {
		t.Fatalf("source synchronization: %v", err)
	}
}

func TestSourceCancellationDuringFetchPreservesCause(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	source, err := s.SaveSource(Source{Name: "canceled source", Kind: "fofa", Query: "fixture", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = s.SyncSource(ctx, source.ID, func(context.Context, Source, int) ([]string, bool, error) {
		cancel()
		return nil, true, ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("source fetch cancellation lost: %v", err)
	}
}

func TestFetchSubscriptionRejectsReservedAddressesWithPreciseError(t *testing.T) {
	src := Source{Name: "literal", Kind: "subscription", URL: "https://198.18.0.191/sub", Limit: 100}
	_, _, err := FetchSubscription(context.Background(), src, 1)
	if !errors.Is(err, errSubscriptionAddressDenied) {
		t.Fatalf("reserved-address guard error was masked or missing: %v", err)
	}
	if !strings.Contains(err.Error(), "198.18.0.191") {
		t.Fatalf("error omits the resolved address: %v", err)
	}
}
