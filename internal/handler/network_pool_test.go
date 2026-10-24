package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/network"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
)

func poolHandler(t *testing.T, admin bool) (*NetworkHandler, *gin.Engine) {
	t.Helper()
	s, err := network.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := NewNetworkHandler(s, nil)
	t.Cleanup(func() { h.Close(); _ = s.Close() })
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "fixture", Scope: database.RBACScopeAll, Permissions: map[string]bool{"config:write": admin}})
	})
	h.Register(r.Group("/api"))
	return h, r
}

func poolRequest(r *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestSourceJobPauseKeepsProgressAndResumesNextPage(t *testing.T) {
	h, r := poolHandler(t, true)
	source, _ := h.Service.SaveSource(network.Source{Name: "fixture", Kind: "fofa", Query: "synthetic", Limit: 3})
	first := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	h.Fetcher = func(ctx context.Context, _ network.Source, page int) ([]string, bool, error) {
		calls.Add(1)
		if page == 1 {
			close(first)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, false, ctx.Err()
			}
		}
		return []string{fmt.Sprintf("http://127.0.0.1:%d", 18000+page)}, page == 3, nil
	}
	accepted := poolRequest(r, "POST", "/api/network/sources/"+source.ID+"/sync", map[string]interface{}{})
	var id struct {
		JobID string `json:"job_id"`
	}
	json.Unmarshal(accepted.Body.Bytes(), &id)
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("collection did not start")
	}
	paused := poolRequest(r, "POST", "/api/network/jobs/"+id.JobID+"/pause", map[string]interface{}{})
	if paused.Code != 200 {
		close(release)
		t.Fatalf("pause failed: %d %s", paused.Code, paused.Body)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		var job struct {
			State    string `json:"state"`
			Progress struct {
				Imported int `json:"imported"`
			} `json:"progress"`
		}
		json.Unmarshal(poolRequest(r, "GET", "/api/network/jobs/"+id.JobID, nil).Body.Bytes(), &job)
		if job.State == "paused" {
			if job.Progress.Imported != 1 || len(h.Service.Nodes()) != 1 || calls.Load() != 1 {
				t.Fatalf("partial results missing: %+v calls=%d", job, calls.Load())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job did not settle paused")
		}
		time.Sleep(time.Millisecond)
	}
	if w := poolRequest(r, "POST", "/api/network/jobs/"+id.JobID+"/resume", map[string]interface{}{}); w.Code != 200 {
		t.Fatal(w.Body)
	}
	job := poolWait(t, r, accepted)
	if job["state"] != "completed" || calls.Load() != 3 || len(h.Service.Nodes()) != 3 {
		t.Fatalf("resume repeated or skipped a page: %+v calls=%d", job, calls.Load())
	}
}

func TestPausedPoolJobOwnershipCancellationAndResumePermission(t *testing.T) {
	h, r := poolHandler(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	control := network.NewJobControl()
	control.Pause()
	job := &networkJob{ID: "owned", Owner: "fixture", State: "running", Pausable: true, Writes: true, Control: control, Cancel: cancel}
	h.mu.Lock()
	h.jobs[job.ID] = job
	h.jobs["other"] = &networkJob{ID: "other", Owner: "someone-else", State: "running", Pausable: true, Control: network.NewJobControl(), Cancel: func() {}}
	h.mu.Unlock()
	for _, action := range []string{"pause", "resume", "cancel"} {
		if w := poolRequest(r, "POST", "/api/network/jobs/other/"+action, map[string]interface{}{}); w.Code != 404 {
			t.Fatalf("non-owner %s: %d", action, w.Code)
		}
	}
	listing := poolRequest(r, "GET", "/api/network/jobs", nil)
	if strings.Contains(listing.Body.String(), "other") || !strings.Contains(listing.Body.String(), `"state":"paused"`) {
		t.Fatalf("unsafe or incomplete listing: %s", listing.Body)
	}
	viewer := gin.New()
	viewer.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "fixture", Scope: database.RBACScopeAll, Permissions: map[string]bool{}})
	})
	h.Register(viewer.Group("/api"))
	if w := poolRequest(viewer, "POST", "/api/network/jobs/owned/resume", map[string]interface{}{}); w.Code != 403 {
		t.Fatalf("revoked write permission resumed job: %d", w.Code)
	}
	if state, _ := control.Snapshot(); state != "paused" {
		t.Fatal("forbidden resume changed state")
	}
	if w := poolRequest(viewer, "POST", "/api/network/jobs/owned/cancel", map[string]interface{}{}); w.Code != 200 {
		t.Fatal(w.Body)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancel did not wake paused job")
	}
	h.mu.Lock()
	job.State = "completed"
	h.mu.Unlock()
	if w := poolRequest(r, "POST", "/api/network/jobs/owned/resume", map[string]interface{}{}); w.Code != 409 {
		t.Fatalf("completed job resumed: %d", w.Code)
	}
}

func poolWait(t *testing.T, r *gin.Engine, response *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	if response.Code != 202 {
		t.Fatalf("job not accepted: %d %s", response.Code, response.Body)
	}
	var accepted struct {
		JobID string `json:"job_id"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &accepted)
	// Managed validation commits every eight nodes; race builds also exercise
	// those encrypted-state writes for the 1001-node coverage fixture.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		w := poolRequest(r, http.MethodGet, "/api/network/jobs/"+accepted.JobID, nil)
		var job map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &job); err != nil {
			t.Fatal(err)
		}
		if job["state"] != "running" {
			return job
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("network job did not finish")
	return nil
}

func TestNetworkPoolRoutesRequireGlobalAdministration(t *testing.T) {
	_, r := poolHandler(t, false)
	for _, route := range []struct{ method, path string }{{"GET", "validation"}, {"PUT", "validation"}, {"POST", "validate"}, {"POST", "proxies/bulk"}, {"POST", "subscriptions/import"}, {"POST", "sources/sync"}} {
		w := poolRequest(r, route.method, "/api/network/"+route.path, map[string]interface{}{})
		if w.Code != 403 {
			t.Errorf("%s %s accepted viewer: %d", route.method, route.path, w.Code)
		}
	}
}

func TestNetworkPoolImportsFormatsWithoutCredentials(t *testing.T) {
	h, r := poolHandler(t, true)
	for _, content := range []string{"http://fixture:synthetic-pass@127.0.0.1:18001", base64.StdEncoding.EncodeToString([]byte("socks5://fixture:synthetic-pass@127.0.0.1:18002")), "proxies:\n  - name: fixture\n    type: http\n    server: 127.0.0.1\n    port: 18003\n    username: fixture\n    password: synthetic-pass\n"} {
		w := poolRequest(r, "POST", "/api/network/proxies", map[string]interface{}{"addresses": content})
		if w.Code != 200 || strings.Contains(w.Body.String(), "synthetic-pass") {
			t.Fatalf("unsafe/failed formatted import: %d %s", w.Code, w.Body)
		}
	}
	if len(h.Service.Nodes()) != 3 {
		t.Fatalf("format imports missing nodes: %d", len(h.Service.Nodes()))
	}
	w := poolRequest(r, "GET", "/api/network/proxies", nil)
	if strings.Contains(w.Body.String(), "synthetic-pass") || !strings.Contains(w.Body.String(), `"pool_observations":{}`) {
		t.Fatalf("unsafe listing: %s", w.Body)
	}
	if w := poolRequest(r, "PUT", "/api/network/validation", map[string]interface{}{"target": ""}); w.Code != 200 {
		t.Fatal("failed to explicitly skip validation")
	}
	job := poolWait(t, r, poolRequest(r, "POST", "/api/network/validate", map[string]interface{}{}))
	if job["state"] != "completed" || job["result"].(map[string]interface{})["checked"] != float64(0) {
		t.Fatalf("empty target marked verified: %+v", job)
	}
}

func TestNetworkSubscriptionImportAndBatchSync(t *testing.T) {
	h, r := poolHandler(t, true)
	h.Fetcher = func(ctx context.Context, source network.Source, page int) ([]string, bool, error) {
		return []string{"http://fixture:subscription-secret@127.0.0.1:18004", "vmess://unsupported"}, true, nil
	}
	h.Providers = func() []network.SourceProvider {
		return []network.SourceProvider{{Kind: "fofa", Name: "FOFA", Configured: true}}
	}
	job := poolWait(t, r, poolRequest(r, "POST", "/api/network/subscriptions/import", map[string]interface{}{"urls": []string{"https://subscription.invalid/synthetic-token"}, "authorized": true}))
	raw, _ := json.Marshal(job)
	if job["state"] != "completed" || strings.Contains(string(raw), "synthetic-token") || strings.Contains(string(raw), "subscription-secret") {
		t.Fatalf("subscription job unsafe: %s", raw)
	}
	if len(h.Service.Sources()) != 1 || len(h.Service.Nodes()) != 1 {
		t.Fatal("subscription not saved/imported")
	}
	job = poolWait(t, r, poolRequest(r, "POST", "/api/network/sources/sync", map[string]interface{}{}))
	if job["state"] != "completed" {
		t.Fatalf("batch sync: %+v", job)
	}
	w := poolRequest(r, "GET", "/api/network/sources", nil)
	if !strings.Contains(w.Body.String(), `"configured":true`) || strings.Contains(w.Body.String(), "synthetic-token") {
		t.Fatalf("provider/source listing unsafe: %s", w.Body)
	}
	for _, body := range []interface{}{map[string]interface{}{"content": "http://127.0.0.1:80", "urls": []string{"https://subscription.invalid"}}, map[string]interface{}{"urls": make([]string, 21)}, map[string]interface{}{}} {
		if w := poolRequest(r, "POST", "/api/network/subscriptions/import", body); w.Code != 400 {
			t.Fatalf("invalid import accepted: %d", w.Code)
		}
	}
}

func TestNetworkPoolValidateAllCoversMultipleBatches(t *testing.T) {
	h, r := poolHandler(t, true)
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	defer proxy.Close()
	var input strings.Builder
	for index := 0; index < 1001; index++ {
		_, _ = fmt.Fprintf(&input, "%s\n", strings.Replace(proxy.URL, "://", fmt.Sprintf("://fixture%d:synthetic@", index), 1))
	}
	if _, err := h.Service.ImportProxyText(input.String(), "manual"); err != nil {
		t.Fatal(err)
	}
	w := poolRequest(r, "PUT", "/api/network/validation", map[string]interface{}{"target": "http://validation.invalid"})
	if w.Code != 200 {
		t.Fatalf("save validation: %d %s", w.Code, w.Body)
	}
	job := poolWait(t, r, poolRequest(r, "POST", "/api/network/validate", map[string]interface{}{}))
	result := job["result"].(map[string]interface{})
	if job["state"] != "completed" || result["checked"] != float64(1001) || result["passed"] != float64(1001) || hits.Load() != 1001 {
		t.Fatalf("all-validation did not cover second batch: state=%v checked=%v passed=%v hits=%d", job["state"], result["checked"], result["passed"], hits.Load())
	}
	progress := job["progress"].(map[string]interface{})
	if progress["total"] != float64(1001) || progress["completed"] != float64(1001) || progress["passed"] != float64(1001) {
		t.Fatalf("validation progress lost committed batches: %+v", progress)
	}
	observations := h.Service.PoolObservations()
	if len(observations) != 1001 {
		t.Fatalf("validation did not retain every committed result: %d", len(observations))
	}
	for id, observation := range observations {
		if observation.NodeID != id || !observation.Reachable || observation.HTTPStatus != http.StatusNoContent {
			t.Fatalf("invalid committed validation result: %+v", observation)
		}
	}
	if w := poolRequest(r, "POST", "/api/network/validate", map[string]interface{}{"node_ids": make([]string, 10001)}); w.Code != 400 {
		t.Fatal("unbounded validation accepted")
	}
}

func TestNetworkSourceBatchCancellationPreservesPartialCounts(t *testing.T) {
	h, r := poolHandler(t, true)
	for _, name := range []string{"first", "second"} {
		if _, err := h.Service.SaveSource(network.Source{Name: name, Kind: "fofa", Query: "synthetic"}); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	blocked := make(chan struct{})
	var longDeadline atomic.Bool
	h.Fetcher = func(ctx context.Context, source network.Source, page int) ([]string, bool, error) {
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= 30*time.Second && time.Until(deadline) > 20*time.Second {
			longDeadline.Store(true)
		}
		if calls.Add(1) == 1 {
			return []string{"http://fixture:synthetic@127.0.0.1:18005"}, true, nil
		}
		close(blocked)
		<-ctx.Done()
		return nil, true, ctx.Err()
	}
	accepted := poolRequest(r, "POST", "/api/network/sources/sync", map[string]interface{}{})
	if accepted.Code != 202 {
		t.Fatalf("batch not accepted: %s", accepted.Body)
	}
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("second source did not start")
	}
	var response struct {
		JobID string `json:"job_id"`
	}
	_ = json.Unmarshal(accepted.Body.Bytes(), &response)
	if w := poolRequest(r, "POST", "/api/network/jobs/"+response.JobID+"/cancel", map[string]interface{}{}); w.Code != 200 {
		t.Fatalf("cancel failed: %s", w.Body)
	}
	job := poolWait(t, r, accepted)
	if job["state"] != "failed" || job["result"].(map[string]interface{})["imported"] != float64(1) || !longDeadline.Load() {
		t.Fatalf("cancel lost counts or per-page timeout was not bounded: %+v", job)
	}
}

func TestNetworkSourceSaveEditAndSyncWithoutPerSourceCredentials(t *testing.T) {
	h, r := poolHandler(t, true)
	w := poolRequest(r, "POST", "/api/network/sources", map[string]interface{}{"name": "synthetic provider", "kind": "quake", "query": "synthetic", "limit": 10000})
	if w.Code != 200 {
		t.Fatalf("provider save failed: %d %s", w.Code, w.Body)
	}
	var saved struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &saved)
	w = poolRequest(r, "POST", "/api/network/sources", map[string]interface{}{"id": saved.ID, "name": "edited provider", "kind": "quake", "query": "synthetic"})
	if w.Code != 200 {
		t.Fatalf("source edit failed: %s", w.Body)
	}
	w = poolRequest(r, "GET", "/api/network/sources", nil)
	if strings.Contains(w.Body.String(), "api_key") || strings.Contains(w.Body.String(), "has_api_key") || strings.Contains(w.Body.String(), "api_url") {
		t.Fatalf("provider listing still advertises per-source credentials: %s", w.Body)
	}
	var retained bool
	h.Fetcher = func(ctx context.Context, source network.Source, page int) ([]string, bool, error) {
		retained = true
		return nil, true, nil
	}
	job := poolWait(t, r, poolRequest(r, "POST", "/api/network/sources/"+saved.ID+"/sync", map[string]interface{}{}))
	if job["state"] != "completed" || !retained {
		t.Fatalf("source sync failed without per-source credentials: %+v", job)
	}
}
