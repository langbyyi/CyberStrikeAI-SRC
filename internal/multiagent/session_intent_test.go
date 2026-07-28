package multiagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cyberstrike-ai/internal/config"
	openaiclient "cyberstrike-ai/internal/openai"

	"go.uber.org/zap"
)

func TestClassifySessionIntentRules_NoFalsePentest(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		role string
		want SessionIntent
	}{
		{"greeting", "你好", "", SessionIntentChat},
		{"how_to", "这个配置怎么写", "", SessionIntentChat},
		{"recon_fofa", "用 fofa 收集 cdsu.edu.cn 资产", "", SessionIntentRecon},
		{"recon_url_only", "https://www.example.com/", "", SessionIntentRecon},
		{"recon_url_with_record_role", "https://www.example.com/", "role_tools:record_capable", SessionIntentRecon},
		{"recon_info", "信息收集成都体育学院", "role_tools:recon_only", SessionIntentRecon},
		{"pentest_explicit", "对 https://a.example.com 做渗透测试", "", SessionIntentPentest},
		{"pentest_vuln", "验证这个站的 SQL 注入 https://a.example.com", "", SessionIntentPentest},
		{"cancel", "先别测，只是聊天", "", SessionIntentChat},
		{"interrupt_template_chat", "【用户补充 / 中断后继续】\n先别测了，问问配置\n\n【请在本轮落实】\n- 将用户提供的接口路径", "", SessionIntentChat},
		{"interrupt_template_recon", "【用户补充 / 中断后继续】\n只要信息收集\n\n【请在本轮落实】\n- 端口探测", "", SessionIntentRecon},
		{"cas_bare_url", "http://www.cdsu.edu.cn:80/cas/login", "role_tools:record_capable", SessionIntentRecon},
		{"unrelated", "帮我写一段 Python 读 csv 的代码", "", SessionIntentChat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifySessionIntentRules(tc.msg, tc.role)
			if got != tc.want {
				t.Fatalf("msg=%q role=%q got=%s want=%s", tc.msg, tc.role, got, tc.want)
			}
		})
	}
}

func TestRecordObligationsEnabled_RequiresPentestAndTarget(t *testing.T) {
	id := "test-intent-obl-1"
	s := GetConversationExecutionState(id)
	s.SetSessionIntent(SessionIntentChat)
	if RecordObligationsEnabled(id) {
		t.Fatal("chat must not enable obligations")
	}
	s.SetSessionIntent(SessionIntentRecon)
	s.SetPrimaryTarget("https://example.com")
	if RecordObligationsEnabled(id) {
		t.Fatal("recon+target must not enable obligations")
	}

	id2 := "test-intent-obl-2"
	GetConversationExecutionState(id2).SetSessionIntent(SessionIntentPentest)
	if RecordObligationsEnabled(id2) {
		t.Fatal("pentest without target must not enable obligations")
	}
	GetConversationExecutionState(id2).SetPrimaryTarget("10.0.0.1")
	if !RecordObligationsEnabled(id2) {
		t.Fatal("pentest+target must enable obligations")
	}
}

func TestPureGreetingNeverPentestEvenWithRecordRole(t *testing.T) {
	role := RoleHintFromTools([]string{"record_vulnerability", "exec", "nmap"})
	if strings.Contains(role, "渗透") || strings.Contains(role, "漏洞") {
		t.Fatalf("role hint must not contain attack keywords: %q", role)
	}
	if got := ClassifySessionIntentRules("你好", role); got != SessionIntentChat {
		t.Fatalf("got %s want chat", got)
	}
	intent, src := ClassifySessionIntentWithLLMModel(context.Background(), "你好", role, "", "dummy-model", nil, nil)
	if intent != SessionIntentChat {
		t.Fatalf("got %s/%s want chat", intent, src)
	}
	if src != "rules_fast_chat" {
		t.Fatalf("greeting must short-circuit before LLM, got source %s", src)
	}
}

func TestRoleHintBlobMustNotBecomePentest(t *testing.T) {
	// Historical false-positive: classifying "角色提示: 渗透…" as the user message.
	role := RoleHintFromTools([]string{"record_vulnerability", "exec"})
	blob := "role_hint: " + role + "\nprev_intent: none\nuser_message:\n你好"
	// Even if someone feeds the blob, sanitize + rules must not stick on pentest without attack verbs in user text.
	// Rules on the blob: may see nothing; pure user part is 你好 if stripped... blob as whole has no 渗透 now.
	if pentestKeywords.MatchString(role) {
		t.Fatal("role hint must not match pentest keywords")
	}
	got := sanitizeIntent(ClassifySessionIntentRules(blob, role), "你好")
	if got == SessionIntentPentest {
		t.Fatal("must not be pentest")
	}
}

func TestSanitizeIntent_DowngradesFalsePentest(t *testing.T) {
	if got := sanitizeIntent(SessionIntentPentest, "你好"); got != SessionIntentChat {
		t.Fatalf("got %s", got)
	}
	if got := sanitizeIntent(SessionIntentPentest, "https://a.example.com/"); got != SessionIntentRecon {
		t.Fatalf("got %s", got)
	}
	if got := sanitizeIntent(SessionIntentPentest, "对 https://a.example.com/ 做渗透"); got != SessionIntentPentest {
		t.Fatalf("got %s", got)
	}
}

func TestMergeSessionIntent_DowngradeFromPentest(t *testing.T) {
	if got := mergeSessionIntent(SessionIntentPentest, SessionIntentChat, "帮我看看配置怎么写"); got != SessionIntentChat {
		t.Fatalf("got %s want chat", got)
	}
	if got := mergeSessionIntent(SessionIntentPentest, SessionIntentRecon, "改成只做信息收集"); got != SessionIntentRecon {
		t.Fatalf("got %s want recon", got)
	}
	if got := mergeSessionIntent(SessionIntentPentest, SessionIntentPentest, "继续"); got != SessionIntentPentest {
		t.Fatalf("ack should keep pentest, got %s", got)
	}
}

func TestResolveEndToEnd_HelloAndCAS(t *testing.T) {
	// 你好
	id1 := "e2e-hello"
	intent, src := ResolveAndStoreSessionIntent(context.Background(), id1, "你好",
		RoleHintFromTools([]string{"record_vulnerability", "exec"}), "m", nil, nil)
	if intent != SessionIntentChat || RecordObligationsEnabled(id1) {
		t.Fatalf("hello: intent=%s src=%s obl=%v", intent, src, RecordObligationsEnabled(id1))
	}
	// bare CAS URL
	id2 := "e2e-cas"
	if tgt := ExtractTargetFromText("http://www.cdsu.edu.cn:80/cas/login"); tgt != "" {
		GetConversationExecutionState(id2).SetPrimaryTarget(tgt)
	}
	intent, src = ResolveAndStoreSessionIntent(context.Background(), id2, "http://www.cdsu.edu.cn:80/cas/login",
		RoleHintFromTools([]string{"record_vulnerability", "exec"}), "m", nil, nil)
	if intent != SessionIntentRecon {
		t.Fatalf("cas: intent=%s src=%s want recon", intent, src)
	}
	if RecordObligationsEnabled(id2) {
		t.Fatal("cas bare url must not enable obligations")
	}
	// real pentest
	id3 := "e2e-pentest"
	msg := "对 http://www.cdsu.edu.cn:80/cas/login 做渗透测试"
	if tgt := ExtractTargetFromText(msg); tgt != "" {
		GetConversationExecutionState(id3).SetPrimaryTarget(tgt)
	}
	intent, src = ResolveAndStoreSessionIntent(context.Background(), id3, msg,
		RoleHintFromTools([]string{"record_vulnerability", "exec"}), "m", nil, nil)
	if intent != SessionIntentPentest || !RecordObligationsEnabled(id3) {
		t.Fatalf("pentest: intent=%s src=%s obl=%v", intent, src, RecordObligationsEnabled(id3))
	}
}

func TestChatClearsPrimaryTarget(t *testing.T) {
	id := "e2e-clear-target"
	s := GetConversationExecutionState(id)
	s.SetPrimaryTarget("https://example.com")
	s.SetSessionIntent(SessionIntentPentest)
	got := ApplySessionIntentFromUserNote(id, "先别测，只是聊天")
	if got != SessionIntentChat {
		t.Fatalf("got %s", got)
	}
	if s.Controller().PrimaryTarget() != "" {
		t.Fatal("chat should clear primary target")
	}
	if RecordObligationsEnabled(id) {
		t.Fatal("obligations must be off")
	}
}

func TestPocNotMatchEpoch(t *testing.T) {
	// "epoch" must not trigger \bpoc\b
	if pentestKeywords.MatchString("use epoch time for logs") {
		t.Fatal("epoch must not match poc keyword")
	}
}

func TestRulesConfidentSkipsLLM(t *testing.T) {
	// Explicit pentest language must not call the model (nil client would otherwise be rules).
	intent, src := ClassifySessionIntentWithLLMModel(context.Background(),
		"对 https://a.example.com 做渗透测试", "", "", "glm-5.1", nil, nil)
	if intent != SessionIntentPentest || src != "rules_confident" {
		t.Fatalf("got %s/%s want pentest/rules_confident", intent, src)
	}
	intent, src = ClassifySessionIntentWithLLMModel(context.Background(),
		"用 fofa 收集 example.com", "", "", "glm-5.1", nil, nil)
	if intent != SessionIntentRecon || src != "rules_confident" {
		t.Fatalf("got %s/%s want recon/rules_confident", intent, src)
	}
	// Ambiguous free text with nil client → rules (not confident LLM path).
	intent, src = ClassifySessionIntentWithLLMModel(context.Background(),
		"这个目标后续怎么安排比较好", "", "", "glm-5.1", nil, nil)
	if src != "rules" {
		t.Fatalf("ambiguous with nil client: intent=%s src=%s want rules", intent, src)
	}
}

// Confident path must agree with rule classifier (no silent divergence that flips obligations).
func TestRulesConfidentMatchesRulesClassifier(t *testing.T) {
	msgs := []string{
		"你好",
		"对 https://a.example.com 做渗透测试",
		"验证 SQL 注入 https://a.example.com",
		"用 fofa 收集 cdsu.edu.cn 资产",
		"https://www.example.com/",
		"先别测，只是聊天",
		"信息收集成都体育学院",
		"http://www.cdsu.edu.cn:80/cas/login",
		"【用户补充 / 中断后继续】\n只要信息收集\n\n【请在本轮落实】\n- 端口探测",
	}
	role := "role_tools:record_capable"
	for _, msg := range msgs {
		conf, ok := rulesConfidentIntent(msg, role)
		if !ok {
			// Only pure free-text should be non-confident; listed msgs all have signals.
			if ExtractTargetFromText(intentTextForClassification(msg)) != "" ||
				pentestKeywords.MatchString(intentTextForClassification(msg)) ||
				reconKeywords.MatchString(intentTextForClassification(msg)) ||
				chatKeywords.MatchString(intentTextForClassification(msg)) ||
				explicitChatOnly.MatchString(intentTextForClassification(msg)) ||
				isPureGreeting(intentTextForClassification(msg)) {
				t.Fatalf("expected confident for %q", msg)
			}
			continue
		}
		rules := ClassifySessionIntentRules(msg, role)
		// Safety clamp used by ClassifySessionIntentWithLLMModel
		if rules == SessionIntentPentest && !pentestKeywords.MatchString(intentTextForClassification(msg)) {
			if ExtractTargetFromText(intentTextForClassification(msg)) != "" {
				rules = SessionIntentRecon
			} else {
				rules = SessionIntentChat
			}
		}
		if conf != rules {
			t.Fatalf("msg=%q confident=%s rules=%s", msg, conf, rules)
		}
		// Through full entry with nil client must not panic and must preserve intent.
		got, src := ClassifySessionIntentWithLLMModel(context.Background(), msg, role, "", "m", nil, nil)
		if got != conf {
			t.Fatalf("msg=%q full=%s/%s want %s", msg, got, src, conf)
		}
	}
}

func TestResolveNeverPanicsAndObligationsGate(t *testing.T) {
	cases := []struct {
		id, msg    string
		wantIntent SessionIntent
		wantOblig  bool
		setTarget  bool
	}{
		{"rv-hello", "你好", SessionIntentChat, false, false},
		{"rv-url", "https://example.com/app", SessionIntentRecon, false, true},
		{"rv-pentest", "对 https://example.com 做渗透测试", SessionIntentPentest, true, true},
		{"rv-cancel", "先别测，只是聊天", SessionIntentChat, false, false},
		{"rv-code", "帮我写一段 Python 读 csv 的代码", SessionIntentChat, false, false},
	}
	for _, tc := range cases {
		if tc.setTarget {
			if tgt := ExtractTargetFromText(tc.msg); tgt != "" {
				GetConversationExecutionState(tc.id).SetPrimaryTarget(tgt)
			}
		}
		intent, src := ResolveAndStoreSessionIntent(context.Background(), tc.id, tc.msg,
			RoleHintFromTools([]string{"record_vulnerability", "nmap"}), "glm-5.1", nil, nil)
		if intent != tc.wantIntent {
			t.Fatalf("%s: intent=%s src=%s want %s", tc.id, intent, src, tc.wantIntent)
		}
		if obl := RecordObligationsEnabled(tc.id); obl != tc.wantOblig {
			t.Fatalf("%s: obligations=%v want %v (intent=%s src=%s target=%q)",
				tc.id, obl, tc.wantOblig, intent, src,
				GetConversationExecutionState(tc.id).Controller().PrimaryTarget())
		}
	}
}

func TestStripAndExtractIntentJSON(t *testing.T) {
	if got := extractIntentMessageContent("```json\n{\"intent\":\"recon\",\"reason\":\"x\"}\n```", ""); got != `{"intent":"recon","reason":"x"}` {
		t.Fatalf("fence: %q", got)
	}
	if got := extractIntentMessageContent("", "先分析一下\n{\"intent\":\"chat\",\"reason\":\"闲聊\"}\n完毕"); !strings.Contains(got, `"intent":"chat"`) {
		t.Fatalf("reasoning fallback: %q", got)
	}
	if got := extractIntentMessageContent("", ""); got != "" {
		t.Fatalf("empty: %q", got)
	}
}

func TestIntentLLMFailureIsReportedAsRulesFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"message":"unsupported request fields"}}`, http.StatusBadRequest)
	}))
	defer server.Close()

	client := openaiclient.NewClient(&config.OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Model:   "test-model",
	}, server.Client(), zap.NewNop())

	intent, source := ClassifySessionIntentWithLLMModel(
		context.Background(),
		"这个目标后续怎么安排比较好",
		"",
		"",
		"test-model",
		client,
		zap.NewNop(),
	)
	if intent != SessionIntentChat {
		t.Fatalf("intent=%s want chat", intent)
	}
	if source != "rules_fallback" {
		t.Fatalf("source=%s want rules_fallback", source)
	}
}

func TestActivePentestProgressQueryPreservesState(t *testing.T) {
	id := "intent-progress-preserves-pentest"
	state := GetConversationExecutionState(id)
	state.SetSessionIntent(SessionIntentPentest)
	state.SetPrimaryTarget("https://example.com")
	initialTarget := state.Controller().PrimaryTarget()

	intent, _ := ResolveAndStoreSessionIntent(
		context.Background(),
		id,
		"总结一下目前的测试进度",
		"",
		"test-model",
		nil,
		zap.NewNop(),
	)
	if intent != SessionIntentPentest {
		t.Fatalf("intent=%s want pentest", intent)
	}
	if target := state.Controller().PrimaryTarget(); target != initialTarget {
		t.Fatalf("target=%q want preserved target %q", target, initialTarget)
	}
	if !RecordObligationsEnabled(id) {
		t.Fatal("active pentest obligations must remain enabled")
	}
}

func TestActiveTaskProgressQuerySkipsIntentLLM(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := openaiclient.NewClient(&config.OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Model:   "test-model",
	}, server.Client(), zap.NewNop())
	id := "intent-progress-skips-llm"
	state := GetConversationExecutionState(id)
	state.SetSessionIntent(SessionIntentPentest)
	state.SetPrimaryTarget("https://example.com")

	intent, source := ResolveAndStoreSessionIntent(
		context.Background(),
		id,
		"查看一下当前测试进度",
		"",
		"test-model",
		client,
		zap.NewNop(),
	)
	if intent != SessionIntentPentest {
		t.Fatalf("intent=%s want pentest", intent)
	}
	if source != "rules_confident" {
		t.Fatalf("source=%s want rules_confident", source)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests=%d want 0", got)
	}
}

func TestExplicitStopClearsActivePentestState(t *testing.T) {
	id := "intent-explicit-stop-clears-pentest"
	state := GetConversationExecutionState(id)
	state.SetSessionIntent(SessionIntentPentest)
	state.SetPrimaryTarget("https://example.com")

	intent, _ := ResolveAndStoreSessionIntent(
		context.Background(),
		id,
		"先别测了，只是聊天",
		"",
		"test-model",
		nil,
		zap.NewNop(),
	)
	if intent != SessionIntentChat {
		t.Fatalf("intent=%s want chat", intent)
	}
	if target := state.Controller().PrimaryTarget(); target != "" {
		t.Fatalf("target=%q want cleared target", target)
	}
}

func TestUnrelatedNewTaskClearsActivePentestState(t *testing.T) {
	id := "intent-new-task-clears-pentest"
	state := GetConversationExecutionState(id)
	state.SetSessionIntent(SessionIntentPentest)
	state.SetPrimaryTarget("https://example.com")

	intent, _ := ResolveAndStoreSessionIntent(
		context.Background(),
		id,
		"帮我写一段 Python 读取 CSV 的代码",
		"",
		"test-model",
		nil,
		zap.NewNop(),
	)
	if intent != SessionIntentChat {
		t.Fatalf("intent=%s want chat", intent)
	}
	if target := state.Controller().PrimaryTarget(); target != "" {
		t.Fatalf("target=%q want cleared target", target)
	}
}

func TestIntentLLMCompatibilityRetryUsesAlternateTokenField(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := requests.Add(1)
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if _, exists := payload["thinking"]; exists {
			t.Errorf("attempt %d unexpectedly sent thinking", attempt)
		}
		switch attempt {
		case 1:
			if _, exists := payload["max_tokens"]; !exists {
				t.Errorf("first attempt missing max_tokens")
			}
			http.Error(w, `{"error":{"message":"use max_completion_tokens"}}`, http.StatusBadRequest)
		case 2:
			if _, exists := payload["max_completion_tokens"]; !exists {
				t.Errorf("compatibility attempt missing max_completion_tokens")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"intent\":\"recon\",\"reason\":\"外部暴露面\"}"}}]}`))
		default:
			t.Errorf("unexpected attempt %d", attempt)
			http.Error(w, "unexpected retry", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client := openaiclient.NewClient(&config.OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Model:   "test-model",
	}, server.Client(), zap.NewNop())

	intent, source := ClassifySessionIntentWithLLMModel(
		context.Background(),
		"分析这个组织的外部暴露面",
		"",
		"",
		"test-model",
		client,
		zap.NewNop(),
	)
	if intent != SessionIntentRecon || source != "llm" {
		t.Fatalf("got %s/%s want recon/llm", intent, source)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests=%d want 2", got)
	}
}

func TestIntentLLMCompatibilityRetryOnUnprocessableEntity(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			http.Error(w, `{"error":{"message":"unsupported max_tokens"}}`, http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"intent\":\"chat\",\"reason\":\"咨询\"}"}}]}`))
	}))
	defer server.Close()

	client := openaiclient.NewClient(&config.OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Model:   "test-model",
	}, server.Client(), zap.NewNop())

	intent, source := ClassifySessionIntentWithLLMModel(
		context.Background(),
		"这个目标后续怎么安排比较好",
		"",
		"",
		"test-model",
		client,
		zap.NewNop(),
	)
	if intent != SessionIntentChat || source != "llm" {
		t.Fatalf("got %s/%s want chat/llm", intent, source)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests=%d want 2", got)
	}
}

func TestIntentLLMReadsJSONFromReasoningContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"","reasoning_content":"{\"intent\":\"recon\",\"reason\":\"资产分析\"}"}}]}`))
	}))
	defer server.Close()

	client := openaiclient.NewClient(&config.OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Model:   "test-model",
	}, server.Client(), zap.NewNop())

	intent, source := ClassifySessionIntentWithLLMModel(
		context.Background(),
		"分析这个组织的外部暴露面",
		"",
		"",
		"test-model",
		client,
		zap.NewNop(),
	)
	if intent != SessionIntentRecon || source != "llm" {
		t.Fatalf("got %s/%s want recon/llm", intent, source)
	}
}

func TestIntentLLMDoesNotRetryNonCompatibilityHTTPFailures(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusTooManyRequests,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				http.Error(w, `{"error":{"message":"request rejected"}}`, status)
			}))
			defer server.Close()

			client := openaiclient.NewClient(&config.OpenAIConfig{
				APIKey:  "test-key",
				BaseURL: server.URL,
				Model:   "test-model",
			}, server.Client(), zap.NewNop())

			_, source := ClassifySessionIntentWithLLMModel(
				context.Background(),
				"这个目标后续怎么安排比较好",
				"",
				"",
				"test-model",
				client,
				zap.NewNop(),
			)
			if source != "rules_fallback" {
				t.Fatalf("source=%s want rules_fallback", source)
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("requests=%d want 1", got)
			}
		})
	}
}

func TestIntentLLMDoesNotCallGatewayAfterContextCancellation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := openaiclient.NewClient(&config.OpenAIConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Model:   "test-model",
	}, server.Client(), zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, source := ClassifySessionIntentWithLLMModel(
		ctx,
		"这个目标后续怎么安排比较好",
		"",
		"",
		"test-model",
		client,
		zap.NewNop(),
	)
	if source != "rules_fallback" {
		t.Fatalf("source=%s want rules_fallback", source)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests=%d want 0", got)
	}
}
