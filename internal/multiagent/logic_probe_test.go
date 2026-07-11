package multiagent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLogicProbe_IdentityDiff(t *testing.T) {
	t.Parallel()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		auth := r.Header.Get("Authorization")
		if strings.Contains(auth, "userA") {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"user":"A","balance":10}`)
			return
		}
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"error":"forbidden"}`)
	}))
	defer srv.Close()

	res := RunLogicProbeDiff(context.Background(), LogicProbeRequest{
		Method: "GET",
		URL:    srv.URL + "/api/me",
		AuthA:  "Bearer userA",
		AuthB:  "Bearer userB",
		Mode:   LogicProbeModeIdentityDiff,
		Client: srv.Client(),
	})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if res.StatusA != 200 || res.StatusB != 403 {
		t.Fatalf("status a/b=%d/%d", res.StatusA, res.StatusB)
	}
	if res.BodyHashA == "" || res.BodyHashA == res.BodyHashB {
		t.Fatalf("expected different hashes a=%s b=%s", res.BodyHashA, res.BodyHashB)
	}
	if !res.DualAuthRecorded {
		t.Fatal("dual auth should be recorded")
	}
	if !strings.Contains(res.SuggestedInvariantBreak, "divergence") &&
		!strings.Contains(res.SuggestedInvariantBreak, "IDOR") {
		t.Fatalf("suggested=%s", res.SuggestedInvariantBreak)
	}
	if atomic.LoadInt32(&hits) < 2 {
		t.Fatalf("hits=%d", hits)
	}
}

func TestLogicProbe_ParamTamper(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"price":0`) || strings.Contains(string(body), `"price": 0`) {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"total":0,"ok":true}`)
			return
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"total":99,"ok":true}`)
	}))
	defer srv.Close()

	res := RunLogicProbeDiff(context.Background(), LogicProbeRequest{
		Method: "POST",
		URL:    srv.URL + "/checkout",
		Body:   `{"price":99,"qty":1}`,
		AuthA:  "Cookie: s=1",
		Mode:   LogicProbeModeParamTamper,
		Mutations: map[string][]string{
			"price": {"0", "0.01"},
		},
		Client: srv.Client(),
	})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if len(res.Variants) < 2 {
		t.Fatalf("variants=%d", len(res.Variants))
	}
	// baseline vs tamper should differ
	base := res.Variants[0]
	var foundDiff bool
	for _, v := range res.Variants[1:] {
		if v.BodyHash != base.BodyHash {
			foundDiff = true
		}
	}
	if !foundDiff {
		t.Fatalf("expected hash divergence, variants=%+v", res.Variants)
	}
}

func TestLogicProbe_Parallel(t *testing.T) {
	t.Parallel()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&n, 1)
		if c%2 == 0 {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"redeemed":true,"id":`+itoa(int(c))+`}`)
			return
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"redeemed":true,"id":same}`)
	}))
	defer srv.Close()

	res := RunLogicProbeDiff(context.Background(), LogicProbeRequest{
		Method:    "POST",
		URL:       srv.URL + "/redeem",
		Body:      `{"coupon":"ONCE"}`,
		Mode:      LogicProbeModeParallel,
		ParallelN: 6,
		Client:    srv.Client(),
	})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if len(res.Variants) != 6 {
		t.Fatalf("variants=%d", len(res.Variants))
	}
	if res.Note == "" {
		t.Fatal("note empty")
	}
}

func TestLogicProbe_Errors(t *testing.T) {
	t.Parallel()
	if msg := ValidateLogicProbeRequest(LogicProbeRequest{}); !strings.Contains(msg, "url") {
		t.Fatalf("want url error, got %q", msg)
	}
	if msg := ValidateLogicProbeRequest(LogicProbeRequest{
		URL: "http://x", Mode: LogicProbeModeParallel, ParallelN: 99,
	}); !strings.Contains(msg, "上限") && !strings.Contains(msg, "parallel") {
		t.Fatalf("want parallel limit error: %q", msg)
	}
	if msg := ValidateLogicProbeRequest(LogicProbeRequest{
		URL: "ftp://x/y", Mode: LogicProbeModeParamTamper,
	}); !strings.Contains(msg, "http") {
		t.Fatalf("want scheme error: %q", msg)
	}
	if msg := ValidateLogicProbeRequest(LogicProbeRequest{
		URL: "https://shop.example/pay", Mode: LogicProbeModeIdentityDiff,
	}); !strings.Contains(msg, "auth") {
		t.Fatalf("identity_diff without auth should error: %q", msg)
	}
	res := RunLogicProbeDiff(context.Background(), LogicProbeRequest{URL: ""})
	if res.Error == "" {
		t.Fatal("empty url must error")
	}
	// no panic on bad mode via Run after validate
	res2 := RunLogicProbeDiff(context.Background(), LogicProbeRequest{URL: "http://127.0.0.1:1", Mode: "nope"})
	if res2.Error == "" {
		t.Fatal("bad mode should error")
	}
}

func TestLogicProbe_ParamTamperQueryString(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		price := r.URL.Query().Get("price")
		if price == "0" || price == "0.01" {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"total":0}`)
			return
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"total":99}`)
	}))
	defer srv.Close()

	res := RunLogicProbeDiff(context.Background(), LogicProbeRequest{
		Method: "GET",
		URL:    srv.URL + "/pay/create?price=99&qty=1",
		Mode:   LogicProbeModeParamTamper,
		Mutations: map[string][]string{
			"price": {"0"},
		},
		Client: srv.Client(),
	})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	base := res.Variants[0]
	var foundDiff bool
	for _, v := range res.Variants[1:] {
		if v.Err == "" && v.BodyHash != base.BodyHash {
			foundDiff = true
		}
	}
	if !foundDiff {
		t.Fatalf("GET query tamper should diverge, variants=%+v", res.Variants)
	}
}

func TestApplyRequestMutation_QueryAndJSON(t *testing.T) {
	t.Parallel()
	u, b := applyRequestMutation("https://t/pay?price=9", "", "GET", "price", "0")
	if !strings.Contains(u, "price=0") {
		t.Fatalf("query not mutated: %s", u)
	}
	u2, b2 := applyRequestMutation("https://t/pay", `{"price":9}`, "POST", "price", "0")
	if !strings.Contains(b2, `"price":0`) && !strings.Contains(b2, `"price": 0`) {
		t.Fatalf("json body not mutated: %s", b2)
	}
	_ = u2
	_ = b
}

func TestLogicProbe_FormatAndSessionDualAuth(t *testing.T) {
	t.Parallel()
	conv := "test-probe-dual-auth"
	ResetConversationExecutionStateForTest(conv)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	st := GetConversationExecutionState(conv)
	st.MarkAuthProbe(true, true)
	if !st.HasDualAuthProbe() {
		t.Fatal("dual auth flag")
	}
	res := RunLogicProbeDiff(context.Background(), LogicProbeRequest{
		URL: srv.URL, Mode: LogicProbeModeIdentityDiff,
		AuthA: "a", AuthB: "b", Client: srv.Client(),
	})
	text := FormatLogicProbeResult(res)
	if !strings.Contains(text, "logic_probe_diff") && !strings.Contains(text, "identity_diff") {
		t.Fatalf("format: %s", text)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [16]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
