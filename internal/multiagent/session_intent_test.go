package multiagent

import (
	"context"
	"strings"
	"testing"
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
