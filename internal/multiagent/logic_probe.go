package multiagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Logic probe modes — Business/Backend Logic Track (R5).
// Recommended try order: param_tamper → step_skip → parallel → (optional dual-account) identity_diff.
const (
	LogicProbeModeIdentityDiff = "identity_diff" // optional; cross-account only
	LogicProbeModeParamTamper  = "param_tamper"  // default: payment/amount/price/qty
	LogicProbeModeStepSkip     = "step_skip"     // workflow skip / trust client status
	LogicProbeModeParallel     = "parallel"      // race / double spend / replay
)

// MaxLogicProbeParallel is the hard cap for parallel mode (abuse prevention).
const MaxLogicProbeParallel = 10

// DefaultLogicProbeMode is single-identity payment/business first (not identity_diff).
const DefaultLogicProbeMode = LogicProbeModeParamTamper

// LogicProbeRecommendedOrder documents the product try order for models/tests.
const LogicProbeRecommendedOrder = "param_tamper → step_skip → parallel → (有双号再) identity_diff"

// LogicProbeToolDescription is the canonical product description (MCP + tests).
// Dual-auth is optional; payment/workflow/race are primary.
const LogicProbeToolDescription = "业务/后端缺陷差分探针（Business/Backend Logic Track）：对同一 URL 发基线与变体 HTTP，返回 status/len/body_hash 与业务不变量提示。" +
	"主用途：支付金额/数量/折扣客户端篡改、流程跳步（未支付 confirm）、并行竞态/重复回调、信任前端 status/paid 等状态字段。" +
	"推荐顺序：" + LogicProbeRecommendedOrder + "。" +
	"mode=param_tamper（默认，改 price/amount/total_fee 等）、step_skip（改 step/status）、parallel（并发 n≤10）、" +
	"identity_diff（可选，auth_a/auth_b 双号对比水平越权——非必填、非整轨入场条件）。" +
	"单身份即可推进支付/流程/竞态；无 url / 并行超限返回明确错误。不替代 L2 完整证据。"

// DefaultPaymentMutations suggested fields when param_tamper has empty mutations.
var DefaultPaymentMutations = map[string][]string{
	"price":     {"0", "0.01", "-1"},
	"amount":    {"0", "1", "0.01"},
	"total":     {"0", "0.01"},
	"total_fee": {"1", "0"},
	"quantity":  {"0", "999"},
	"discount":  {"100", "999"},
}

// LogicProbeRequest is the pure input for differential logic probing.
type LogicProbeRequest struct {
	Method     string // default GET
	URL        string
	Headers    map[string]string // shared headers (without auth override)
	Body       string
	AuthA      string // Cookie or Authorization value for identity A
	AuthB      string // Cookie or Authorization value for identity B
	AuthHeader string // header name for auth; default Authorization; use Cookie for session cookies
	Mode       string
	// Mutations for param_tamper / step_skip: JSON field path → values (applied to Body if JSON).
	// Simple form: map key is field name, values are replacement strings.
	Mutations map[string][]string
	ParallelN int // parallel mode only; clamped to [1, MaxLogicProbeParallel]
	// Client optional; tests inject httptest client. If nil, http.DefaultClient is not used —
	// a short-timeout client is created (still no external requirement for unit tests).
	Client *http.Client
	// Timeout per request when building default client.
	Timeout time.Duration
}

// LogicProbeVariant is one HTTP sample in the diff set.
type LogicProbeVariant struct {
	Label      string `json:"label"`
	Status     int    `json:"status"`
	Length     int    `json:"length"`
	BodyHash   string `json:"body_hash"`
	Err        string `json:"error,omitempty"`
	HeadersKey string `json:"headers_sample,omitempty"`
}

// LogicProbeResult is the structured differential output for the model.
type LogicProbeResult struct {
	Mode                    string              `json:"mode"`
	URL                     string              `json:"url"`
	Variants                []LogicProbeVariant `json:"variants"`
	StatusA                 int                 `json:"status_a,omitempty"`
	StatusB                 int                 `json:"status_b,omitempty"`
	LenA                    int                 `json:"len_a,omitempty"`
	LenB                    int                 `json:"len_b,omitempty"`
	BodyHashA               string              `json:"body_hash_a,omitempty"`
	BodyHashB               string              `json:"body_hash_b,omitempty"`
	HeaderDiffKeys          []string            `json:"header_diff_keys,omitempty"`
	Note                    string              `json:"note"`
	SuggestedInvariantBreak string              `json:"suggested_invariant_break,omitempty"`
	DualAuthRecorded        bool                `json:"dual_auth_recorded"`
	Error                   string              `json:"error,omitempty"`
}

// ValidateLogicProbeRequest returns a user-facing error string or "".
// auth_a/auth_b are never required for payment/workflow modes; identity_diff needs at least one identity
// (auth vs anonymous is valid; both empty is useless).
func ValidateLogicProbeRequest(req LogicProbeRequest) string {
	if strings.TrimSpace(req.URL) == "" {
		return "错误: url 必填"
	}
	rawURL := strings.TrimSpace(req.URL)
	if u, err := url.Parse(rawURL); err != nil || u.Scheme == "" || u.Host == "" {
		// Allow relative only if invalid parse — still require http(s) for real probes.
		low := strings.ToLower(rawURL)
		if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
			return "错误: url 须为 http:// 或 https:// 绝对地址"
		}
	} else {
		sch := strings.ToLower(u.Scheme)
		if sch != "http" && sch != "https" {
			return "错误: url 仅支持 http/https scheme"
		}
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = DefaultLogicProbeMode
	}
	switch mode {
	case LogicProbeModeIdentityDiff, LogicProbeModeParamTamper, LogicProbeModeStepSkip, LogicProbeModeParallel:
	default:
		return "错误: mode 非法，支持 param_tamper|step_skip|parallel|identity_diff（推荐先 param_tamper）"
	}
	if mode == LogicProbeModeIdentityDiff {
		if strings.TrimSpace(req.AuthA) == "" && strings.TrimSpace(req.AuthB) == "" {
			return "错误: identity_diff 至少提供 auth_a 或 auth_b（单身份 vs 匿名亦可）；双号对比请两者都填。" +
				"支付/流程请用 param_tamper/step_skip/parallel，不强制双号。"
		}
	}
	if mode == LogicProbeModeParallel && req.ParallelN > MaxLogicProbeParallel {
		return fmt.Sprintf("错误: parallel_n 超过上限 %d", MaxLogicProbeParallel)
	}
	return ""
}

// NormalizeLogicProbeMode returns default business mode when empty.
func NormalizeLogicProbeMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return DefaultLogicProbeMode
	}
	return mode
}

// RunLogicProbeDiff executes baseline/variant HTTP requests and returns structured diffs.
// Never panics on bad input; transport errors are captured per variant.
func RunLogicProbeDiff(ctx context.Context, req LogicProbeRequest) LogicProbeResult {
	if errMsg := ValidateLogicProbeRequest(req); errMsg != "" {
		return LogicProbeResult{Error: errMsg, Mode: req.Mode, URL: req.URL}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	mode := NormalizeLogicProbeMode(req.Mode)
	client := req.Client
	if client == nil {
		to := req.Timeout
		if to <= 0 {
			to = 15 * time.Second
		}
		client = &http.Client{
			Timeout: to,
			// Cap redirects: default client can follow indefinitely until timeout; also
			// reduces accidental cross-host cookie leakage chains during probes.
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return nil
			},
		}
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		// Prefer POST when body present (payment JSON); else GET.
		if strings.TrimSpace(req.Body) != "" {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	authHeader := strings.TrimSpace(req.AuthHeader)
	if authHeader == "" {
		// Prefer Cookie when values look like session cookies
		if strings.Contains(req.AuthA, "=") || strings.Contains(req.AuthB, "=") {
			authHeader = "Cookie"
		} else {
			authHeader = "Authorization"
		}
	}

	out := LogicProbeResult{Mode: mode, URL: req.URL}
	dual := strings.TrimSpace(req.AuthA) != "" && strings.TrimSpace(req.AuthB) != ""

	doOne := func(label, reqURL, body, auth string) LogicProbeVariant {
		v := LogicProbeVariant{Label: label}
		if reqURL == "" {
			reqURL = req.URL
		}
		var bodyReader io.Reader
		if body != "" {
			bodyReader = strings.NewReader(body)
		}
		httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		for k, val := range req.Headers {
			if strings.TrimSpace(k) == "" {
				continue
			}
			httpReq.Header.Set(k, val)
		}
		if auth != "" {
			httpReq.Header.Set(authHeader, auth)
		}
		if body != "" && httpReq.Header.Get("Content-Type") == "" {
			// form body heuristic
			if strings.Contains(body, "=") && !strings.HasPrefix(strings.TrimSpace(body), "{") {
				httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				httpReq.Header.Set("Content-Type", "application/json")
			}
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MiB cap
		v.Status = resp.StatusCode
		v.Length = len(raw)
		sum := sha256.Sum256(raw)
		v.BodyHash = hex.EncodeToString(sum[:8])
		// sample a few header keys
		keys := make([]string, 0, 4)
		for k := range resp.Header {
			keys = append(keys, k)
			if len(keys) >= 6 {
				break
			}
		}
		v.HeadersKey = strings.Join(keys, ",")
		return v
	}

	switch mode {
	case LogicProbeModeIdentityDiff:
		a := doOne("auth_a", req.URL, req.Body, req.AuthA)
		b := doOne("auth_b", req.URL, req.Body, req.AuthB)
		out.Variants = []LogicProbeVariant{a, b}
		out.StatusA, out.StatusB = a.Status, b.Status
		out.LenA, out.LenB = a.Length, b.Length
		out.BodyHashA, out.BodyHashB = a.BodyHash, b.BodyHash
		out.HeaderDiffKeys = headerKeyDiff(a.HeadersKey, b.HeadersKey)
		out.Note = "identity_diff (optional): compare status/len/hash across auth_a vs auth_b — horizontal access only"
		out.DualAuthRecorded = dual && a.Err == "" && b.Err == "" && a.Status > 0 && b.Status > 0
		if a.Err != "" || b.Err != "" {
			out.Error = fmt.Sprintf("identity_diff request failed: auth_a=%s; auth_b=%s", a.Err, b.Err)
			out.SuggestedInvariantBreak = "identity_probe_failed: no comparable dual-auth responses"
		} else if a.Status != b.Status || a.BodyHash != b.BodyHash {
			out.SuggestedInvariantBreak = "identity_response_divergence: cross-account access differs — check IDOR/BOLA (subset of logic track)"
		} else if out.DualAuthRecorded {
			out.SuggestedInvariantBreak = "no_identity_divergence: continue payment/workflow tests with param_tamper/step_skip on same account"
		} else {
			out.SuggestedInvariantBreak = "identity_diff without dual auth: only one identity used — optional for IDOR; payment/param tests do not need auth_b"
		}

	case LogicProbeModeParamTamper, LogicProbeModeStepSkip:
		base := doOne("baseline", req.URL, req.Body, req.AuthA)
		out.Variants = []LogicProbeVariant{base}
		out.StatusA, out.LenA, out.BodyHashA = base.Status, base.Length, base.BodyHash
		muts := req.Mutations
		if len(muts) == 0 && mode == LogicProbeModeStepSkip {
			muts = map[string][]string{
				"step":   {"0", "99", "done"},
				"status": {"paid", "completed", "success"},
				"paid":   {"true", "1"},
			}
		}
		if len(muts) == 0 {
			muts = DefaultPaymentMutations
		}
		// Stable field order so mutation budget is deterministic (map range is random).
		fields := make([]string, 0, len(muts))
		for f := range muts {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		i := 0
	fieldLoop:
		for _, field := range fields {
			vals := muts[field]
			for _, val := range vals {
				i++
				if i > 8 {
					break fieldLoop
				}
				mutURL, mutBody := applyRequestMutation(req.URL, req.Body, method, field, val)
				lab := fmt.Sprintf("tamper.%s=%s", field, truncateRunes(val, 24))
				v := doOne(lab, mutURL, mutBody, req.AuthA)
				out.Variants = append(out.Variants, v)
				if v.Status != base.Status || v.BodyHash != base.BodyHash {
					out.StatusB, out.LenB, out.BodyHashB = v.Status, v.Length, v.BodyHash
					out.SuggestedInvariantBreak = fmt.Sprintf(
						"param_effect: mutating %s changed response — 金额/状态是否以服务端为准？是否可跳过支付？", field)
				}
			}
		}
		if out.SuggestedInvariantBreak == "" {
			if mode == LogicProbeModeStepSkip {
				out.SuggestedInvariantBreak = "no_step_divergence: try status=paid without pay callback; confirm 是否可跳过支付/校验步"
			} else {
				out.SuggestedInvariantBreak = "no_tamper_divergence: try price/amount/total_fee/quantity（含 query/body）; 确认金额是否仅信任客户端"
			}
		}
		out.Note = mode + ": baseline vs business field mutations (body+query; single identity OK)"
		out.HeaderDiffKeys = nil

	case LogicProbeModeParallel:
		n := req.ParallelN
		if n <= 0 {
			n = 5
		}
		if n > MaxLogicProbeParallel {
			n = MaxLogicProbeParallel
		}
		variants := make([]LogicProbeVariant, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				variants[i] = doOne(fmt.Sprintf("p%d", i), req.URL, req.Body, req.AuthA)
			}(i)
		}
		wg.Wait()
		out.Variants = variants
		hashCount := map[string]int{}
		statusSet := map[int]int{}
		for _, v := range variants {
			if v.Err == "" {
				hashCount[v.BodyHash]++
				statusSet[v.Status]++
			}
		}
		if len(variants) > 0 {
			out.StatusA = variants[0].Status
			out.LenA = variants[0].Length
			out.BodyHashA = variants[0].BodyHash
		}
		out.Note = fmt.Sprintf("parallel n=%d concurrent same request (race/double-spend/replay)", n)
		if len(hashCount) > 1 || len(statusSet) > 1 {
			out.SuggestedInvariantBreak = "parallel_divergence: 并发同请求响应不一致 — 可能双花/重复核销/回调竞态"
		} else {
			out.SuggestedInvariantBreak = "parallel_consistent: 尝试优惠券/积分/限购/支付回调重复 notify"
		}
	}

	return out
}

// NextHintForLogicProbe returns business-invariant-oriented next steps (not only user_id swap).
func NextHintForLogicProbe(mode string, hasDualAuth bool) string {
	mode = NormalizeLogicProbeMode(mode)
	switch mode {
	case LogicProbeModeParamTamper:
		return "next_hint: 核对金额/数量/折扣是否以服务端计价；试 price=0/amount=-1/total_fee 篡改；默认 mutation 含 price/amount/total_fee/quantity"
	case LogicProbeModeStepSkip:
		return "next_hint: 试跳过支付直接 confirm；改 step/status/paid 是否被信任；未支付能否推进订单"
	case LogicProbeModeParallel:
		return "next_hint: 并发领券/核销/支付回调；限次资源是否可刷；重复 notify 是否双入账"
	case LogicProbeModeIdentityDiff:
		if hasDualAuth {
			return "next_hint: 对比两账号对象级读/写；此为越权子集。支付/流程请另跑 param_tamper/step_skip"
		}
		return "next_hint: identity_diff 可选；无双号时不要停整轨——继续 param_tamper/step_skip/parallel"
	default:
		return "next_hint: 推荐顺序 " + LogicProbeRecommendedOrder
	}
}

// FormatLogicProbeResult renders a model-facing text block with business next_hint.
func FormatLogicProbeResult(r LogicProbeResult) string {
	if r.Error != "" {
		return r.Error
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Sprintf("mode=%s url=%s note=%s", r.Mode, r.URL, r.Note)
	}
	var sb strings.Builder
	sb.WriteString("## logic_probe_diff result（业务/后端缺陷轨）\n")
	sb.WriteString("recommended_order: ")
	sb.WriteString(LogicProbeRecommendedOrder)
	sb.WriteString("\n")
	sb.Write(b)
	sb.WriteString("\n")
	if r.SuggestedInvariantBreak != "" {
		sb.WriteString("suggested_invariant_break: ")
		sb.WriteString(r.SuggestedInvariantBreak)
		sb.WriteString("\n")
	}
	sb.WriteString(NextHintForLogicProbe(r.Mode, r.DualAuthRecorded))
	sb.WriteString("\n")
	return sb.String()
}

func headerKeyDiff(a, b string) []string {
	setA := map[string]struct{}{}
	for _, k := range strings.Split(a, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			setA[k] = struct{}{}
		}
	}
	var diff []string
	for _, k := range strings.Split(b, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, ok := setA[k]; !ok {
			diff = append(diff, k)
		}
	}
	for k := range setA {
		found := false
		for _, x := range strings.Split(b, ",") {
			if strings.TrimSpace(x) == k {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, k)
		}
	}
	return diff
}

// applyRequestMutation mutates body and/or URL query for business param probes.
// - JSON/form body when present (or method is POST/PUT/PATCH)
// - URL query always updated when the key exists or body is empty / GET-like
// Returns (newURL, newBody).
func applyRequestMutation(rawURL, body, method, field, value string) (string, string) {
	field = strings.TrimSpace(field)
	if field == "" {
		return rawURL, body
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	trimBody := strings.TrimSpace(body)
	hasBodyShape := trimBody != "" && (strings.HasPrefix(trimBody, "{") || strings.Contains(trimBody, "="))
	useBody := hasBodyShape || method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch

	newBody := body
	if useBody {
		newBody = applyJSONFieldMutation(body, field, value)
	}

	newURL := rawURL
	// Mutate query when: GET/HEAD/DELETE, or URL already has the key, or no body to carry fields.
	u, err := url.Parse(rawURL)
	if err == nil && u != nil {
		q := u.Query()
		_, keyExists := q[field]
		if method == http.MethodGet || method == http.MethodHead || method == "" ||
			keyExists || !useBody || trimBody == "" {
			q.Set(field, value)
			u.RawQuery = q.Encode()
			newURL = u.String()
		}
	}

	// If neither body nor URL changed usefully and body was empty, ensure at least query mutation.
	if newBody == body && newURL == rawURL {
		if u2, err2 := url.Parse(rawURL); err2 == nil && u2 != nil {
			q := u2.Query()
			q.Set(field, value)
			u2.RawQuery = q.Encode()
			newURL = u2.String()
		}
	}
	return newURL, newBody
}

// applyJSONFieldMutation replaces a top-level JSON string/number field or form field.
func applyJSONFieldMutation(body, field, value string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return body
	}
	trim := strings.TrimSpace(body)
	if strings.HasPrefix(trim, "{") {
		var m map[string]interface{}
		if json.Unmarshal([]byte(trim), &m) == nil {
			if isNumericLike(value) {
				var num float64
				if _, err := fmt.Sscanf(value, "%f", &num); err == nil {
					m[field] = num
				} else {
					m[field] = value
				}
			} else {
				m[field] = value
			}
			if out, err := json.Marshal(m); err == nil {
				return string(out)
			}
		}
	}
	// form-urlencoded style
	if strings.Contains(body, "=") && !strings.HasPrefix(trim, "{") {
		parts := strings.Split(body, "&")
		found := false
		for i, p := range parts {
			if strings.HasPrefix(p, field+"=") {
				parts[i] = field + "=" + value
				found = true
			}
		}
		if found {
			return strings.Join(parts, "&")
		}
		if body == "" {
			return field + "=" + value
		}
		return body + "&" + field + "=" + value
	}
	if body == "" {
		// Prefer form for empty body when caller only wanted body path; query handled separately.
		return fmt.Sprintf(`{"%s":%s}`, field, jsonStringOrNumber(value))
	}
	return body
}

func isNumericLike(value string) bool {
	if value == "" {
		return false
	}
	if !strings.ContainsAny(value, "0123456789") {
		return false
	}
	return !strings.ContainsAny(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func jsonStringOrNumber(value string) string {
	if isNumericLike(value) {
		return value
	}
	b, _ := json.Marshal(value)
	return string(b)
}
