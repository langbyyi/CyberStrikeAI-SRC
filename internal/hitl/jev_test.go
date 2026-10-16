package hitl

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/typesafe"
)

func TestDecideJevRejectsDestructive(t *testing.T) {
	dec, comment := DecideJev(&typesafe.Result{Answers: map[string]map[string]any{
		jevQAvailability: {"noul": 0.92},
		jevQDataLoss:     {"noul": 0.1},
		jevQCredentials:  {"noul": 0.05},
		jevQConfig:       {"noul": 0.04},
		jevQPentest:      {"noul": 0.8},
		jevQDecision:     {"choice": "approve", "confidence": 0.4},
	}})
	if dec != "reject" {
		t.Fatalf("decision=%s comment=%s", dec, comment)
	}
	if !strings.Contains(comment, "破坏业务可用性") {
		t.Fatalf("comment=%s", comment)
	}
}

func TestDecideJevApprovesPentestPayload(t *testing.T) {
	dec, _ := DecideJev(&typesafe.Result{Answers: map[string]map[string]any{
		jevQAvailability: {"noul": 0.08},
		jevQDataLoss:     {"noul": 0.06},
		jevQCredentials:  {"noul": 0.04},
		jevQConfig:       {"noul": 0.05},
		jevQPentest:      {"noul": 0.97},
		jevQDecision:     {"choice": "approve", "confidence": 0.9},
	}})
	if dec != "approve" {
		t.Fatalf("decision=%s", dec)
	}
}

func TestDecideJevDestructiveWinsOverPentest(t *testing.T) {
	dec, _ := DecideJev(&typesafe.Result{Answers: map[string]map[string]any{
		jevQAvailability: {"noul": 0.12},
		jevQDataLoss:     {"noul": 0.88},
		jevQCredentials:  {"noul": 0.1},
		jevQConfig:       {"noul": 0.1},
		jevQPentest:      {"noul": 0.95},
		jevQDecision:     {"choice": "approve", "confidence": 0.7},
	}})
	if dec != "reject" {
		t.Fatalf("decision=%s", dec)
	}
}

func TestDecideJevUncertainApproves(t *testing.T) {
	dec, _ := DecideJev(&typesafe.Result{Answers: map[string]map[string]any{
		jevQAvailability: {"noul": 0.4},
		jevQDataLoss:     {"noul": 0.2},
		jevQCredentials:  {"noul": 0.1},
		jevQConfig:       {"noul": 0.1},
		jevQPentest:      {"noul": 0.3},
		jevQDecision:     {"choice": "reject", "confidence": 0.5},
	}})
	if dec != "approve" {
		t.Fatalf("decision=%s", dec)
	}
}

func TestBuildJevStateOmitsCognitionBlobs(t *testing.T) {
	state := BuildJevState("approval", "exec", map[string]interface{}{
		"arguments":      `{"command":"id"}`,
		"userMessage":    "whoami",
		"thinking":       "long chain",
		"reasoningChain": "should not appear",
	}, "")
	if state["toolName"] != "exec" {
		t.Fatalf("toolName=%v", state["toolName"])
	}
	if _, ok := state["thinking"]; ok {
		t.Fatal("thinking should be omitted")
	}
	if _, ok := state["reasoningChain"]; ok {
		t.Fatal("reasoningChain should be omitted")
	}
	if state["arguments"] != `{"command":"id"}` {
		t.Fatalf("arguments=%v", state["arguments"])
	}
}

// 授权基线必须与 openai 后端同口径地进 Jev state：
// 漏掉 userMessage/testingSpecification，Jev 就只能凭命令参数推断授权状态。
func TestBuildJevStateCarriesAuthorizationBaseline(t *testing.T) {
	state := BuildJevState("approval", "http-framework-test", map[string]interface{}{
		"arguments":            `{"method":"POST","url":"http://t/api/resetPassword"}`,
		"userMessage":          "我授权你测试该接口",
		"testingSpecification": "## 任务测试规范\n允许对自建账号做改密验证",
	}, "")
	if state["userMessage"] != "我授权你测试该接口" {
		t.Fatalf("userMessage=%v", state["userMessage"])
	}
	spec, _ := state["testingSpecification"].(string)
	if !strings.Contains(spec, "允许对自建账号做改密验证") {
		t.Fatalf("testingSpecification 必须进 state，实际 %v", state["testingSpecification"])
	}
}

func TestJevAuditQuestionsCoverPolicyAxes(t *testing.T) {
	qs := JevAuditQuestions("")
	for _, id := range []string{
		jevQAvailability, jevQDataLoss, jevQCredentials, jevQConfig, jevQPentest,
		jevQScope, jevQUnjustified, jevQAuthorization, jevQDecision,
	} {
		if _, ok := qs[id]; !ok {
			t.Fatalf("missing question %s", id)
		}
	}
	if _, ok := qs[jevQOperatorPolicy]; ok {
		t.Fatal("default questions should not include operator policy overlay")
	}
}

func TestBuildJevStateIncludesOperatorPolicy(t *testing.T) {
	state := BuildJevState("approval", "exec", map[string]interface{}{"command": "id"}, "拦截所有命令执行")
	if state["operatorPolicy"] != "拦截所有命令执行" {
		t.Fatalf("operatorPolicy=%v", state["operatorPolicy"])
	}
	policy, _ := state["policy"].(string)
	if !strings.Contains(policy, "operatorPolicy") {
		t.Fatalf("policy=%v", state["policy"])
	}
}

func TestJevAuditQuestionsAddsPolicyOverlay(t *testing.T) {
	qs := JevAuditQuestions("拦截所有命令执行")
	if _, ok := qs[jevQOperatorPolicy]; !ok {
		t.Fatal("missing operator policy noul")
	}
}

func TestDecideJevRejectsOperatorPolicy(t *testing.T) {
	dec, comment := DecideJev(&typesafe.Result{Answers: map[string]map[string]any{
		jevQAvailability:   {"noul": 0.08},
		jevQDataLoss:       {"noul": 0.06},
		jevQCredentials:    {"noul": 0.04},
		jevQConfig:         {"noul": 0.05},
		jevQPentest:        {"noul": 0.01},
		jevQOperatorPolicy: {"noul": 0.91},
		jevQDecision:       {"choice": "approve", "confidence": 0.2},
	}})
	if dec != "reject" {
		t.Fatalf("decision=%s comment=%s", dec, comment)
	}
	if !strings.Contains(comment, "组织审批策略") {
		t.Fatalf("comment=%s", comment)
	}
}

func TestDecideJevPolicyChoiceRejectsEvenIfPentest(t *testing.T) {
	dec, comment := DecideJev(&typesafe.Result{Answers: map[string]map[string]any{
		jevQAvailability:   {"noul": 0.1},
		jevQDataLoss:       {"noul": 0.1},
		jevQCredentials:    {"noul": 0.1},
		jevQConfig:         {"noul": 0.1},
		jevQPentest:        {"noul": 0.9},
		jevQOperatorPolicy: {"noul": 0.4},
		jevQDecision:       {"choice": "reject", "confidence": 0.92},
	}})
	if dec != "reject" {
		t.Fatalf("decision=%s comment=%s", dec, comment)
	}
	if !strings.Contains(comment, "组织策略") {
		t.Fatalf("comment=%s", comment)
	}
}

// jevAnswers 用一份"全部低分"的基线覆盖指定轴，避免每个用例重复二十行。
func jevAnswers(overrides map[string]map[string]any) *typesafe.Result {
	answers := map[string]map[string]any{
		jevQAvailability:  {"noul": 0.05},
		jevQDataLoss:      {"noul": 0.05},
		jevQCredentials:   {"noul": 0.05},
		jevQConfig:        {"noul": 0.05},
		jevQPentest:       {"noul": 0.1},
		jevQScope:         {"noul": 0.05},
		jevQUnjustified:   {"noul": 0.05},
		jevQAuthorization: {"choice": "none", "confidence": 0.9},
		jevQDecision:      {"choice": "approve", "confidence": 0.9},
	}
	for k, v := range overrides {
		answers[k] = v
	}
	return &typesafe.Result{Answers: answers}
}

// TypeSafe 通道必须与 openai 提示词给出同向结论：同意可解封、理由可解封、
// 超范围不可解封、无理由试探拦下——否则换个审批后端行为就变了。
func TestDecideJevMirrorsConsentAndReasonRubric(t *testing.T) {
	const (
		selfCreatedID = 0.7  // 自建/不存在对象上的改密，Jev 通常给 0.6~0.8
		realAccountID = 0.95 // 真实账号改密
	)

	cases := []struct {
		name     string
		answers  *typesafe.Result
		want     string
		contains string
	}{
		{
			name: "有理由：自建对象的单次改密 → 放行",
			answers: jevAnswers(map[string]map[string]any{
				jevQCredentials:   {"noul": selfCreatedID},
				jevQAuthorization: {"choice": "justified", "confidence": 0.9},
			}),
			want: "approve",
		},
		{
			name: "有理由但破坏分逼近确定（真实账号）→ 拒绝",
			answers: jevAnswers(map[string]map[string]any{
				jevQCredentials:   {"noul": realAccountID},
				jevQAuthorization: {"choice": "justified", "confidence": 0.9},
			}),
			want: "reject",
		},
		{
			name: "用户明确同意 → 压过破坏轴放行",
			answers: jevAnswers(map[string]map[string]any{
				jevQCredentials:   {"noul": realAccountID},
				jevQAuthorization: {"choice": "consent", "confidence": 0.9},
			}),
			want:     "approve",
			contains: "用户已明确同意",
		},
		{
			name: "超出授权范围 → 同意也不放行",
			answers: jevAnswers(map[string]map[string]any{
				jevQScope:         {"noul": 0.92},
				jevQAuthorization: {"choice": "consent", "confidence": 0.95},
			}),
			want:     "reject",
			contains: "不可覆盖",
		},
		{
			name: "组织策略禁令 → 同意也不放行",
			answers: jevAnswers(map[string]map[string]any{
				jevQOperatorPolicy: {"noul": 0.91},
				jevQAuthorization:  {"choice": "consent", "confidence": 0.95},
			}),
			want:     "reject",
			contains: "组织审批策略",
		},
		{
			name: "无理由试探：凑参数、破坏轴不高 → 拒绝并请求授权",
			answers: jevAnswers(map[string]map[string]any{
				jevQCredentials:   {"noul": 0.4},
				jevQUnjustified:   {"noul": 0.82},
				jevQAuthorization: {"choice": "none", "confidence": 0.9},
			}),
			want:     "reject",
			contains: "请确认是否授权本次操作",
		},
		{
			name: "授权标签不可信（置信 0.5）→ 回落破坏轴拒绝",
			answers: jevAnswers(map[string]map[string]any{
				jevQCredentials:   {"noul": 0.9},
				jevQAuthorization: {"choice": "justified", "confidence": 0.5},
			}),
			want: "reject",
		},
		{
			name: "理由与无理由同时命中（Jev 自相矛盾）→ 保守拒绝",
			answers: jevAnswers(map[string]map[string]any{
				jevQCredentials:   {"noul": 0.5},
				jevQUnjustified:   {"noul": 0.8},
				jevQAuthorization: {"choice": "justified", "confidence": 0.9},
			}),
			want:     "reject",
			contains: "请确认是否授权本次操作",
		},
		{
			name: "普通只读侦察：标签为 none 也不该被拒",
			answers: jevAnswers(map[string]map[string]any{
				jevQPentest:       {"noul": 0.95},
				jevQAuthorization: {"choice": "none", "confidence": 0.95},
			}),
			want: "approve",
		},
	}

	for _, tc := range cases {
		dec, comment := DecideJev(tc.answers)
		if dec != tc.want {
			t.Errorf("%s: decision=%s 期望=%s (comment=%s)", tc.name, dec, tc.want, comment)
		}
		if tc.contains != "" && !strings.Contains(comment, tc.contains) {
			t.Errorf("%s: comment 应含 %q，实际 %s", tc.name, tc.contains, comment)
		}
	}
}
