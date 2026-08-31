package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureLocalConfigCreatesFromExample(t *testing.T) {
	dir := t.TempDir()
	examplePath := filepath.Join(dir, "config.example.yaml")
	configPath := filepath.Join(dir, "config.yaml")

	example := []byte(`auth:
  session_duration_hours: 12
server:
  host: 127.0.0.1
  port: 8080
`)
	if err := os.WriteFile(examplePath, example, 0644); err != nil {
		t.Fatalf("write example: %v", err)
	}

	result, err := EnsureLocalConfig(configPath)
	if err != nil {
		t.Fatalf("EnsureLocalConfig: %v", err)
	}
	if !result.Created {
		t.Fatal("Created = false, want true")
	}
	if result.ExamplePath != examplePath {
		t.Fatalf("ExamplePath = %q, want %q", result.ExamplePath, examplePath)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load generated config: %v", err)
	}
	if cfg.Auth.SessionDurationHours != 12 {
		t.Fatalf("SessionDurationHours = %d, want 12", cfg.Auth.SessionDurationHours)
	}

	second, err := EnsureLocalConfig(configPath)
	if err != nil {
		t.Fatalf("EnsureLocalConfig existing: %v", err)
	}
	if second.Created {
		t.Fatal("Created = true for existing config, want false")
	}
}

func TestExampleConfigUsesBuiltinAuditAgentPromptByDefault(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("load config example: %v", err)
	}
	if cfg.Hitl.AuditAgentPrompt != "" {
		t.Fatal("config example must not override the built-in audit-agent prompt")
	}
	if got, want := cfg.Hitl.EffectiveAuditAgentPrompt(), DefaultHitlAuditAgentPrompt(); got != want {
		t.Fatal("empty audit_agent_prompt must resolve to the built-in default")
	}
}

func TestLoadIgnoresLegacyAuthPasswordField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	initial := strings.Join([]string{
		"auth:",
		`  password: "legacy-password"`,
		"  session_duration_hours: 12",
		"server:",
		"  host: 127.0.0.1",
		"  port: 8080",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.SessionDurationHours != 12 {
		t.Fatalf("SessionDurationHours = %d, want 12", cfg.Auth.SessionDurationHours)
	}
}

func TestLoadIndependentApprovalPolicyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := `approval:
  reviewer: agent
  timeout_seconds: 420
  tool_approval:
    enabled: false
    tool_whitelist: [read_file, ls]
  dangerous_action:
    enabled: true
`
	if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Approval.EffectiveReviewer() != "agent" || cfg.Approval.TimeoutSecondsEffective() != 420 {
		t.Fatalf("approval config = %+v", cfg.Approval)
	}
	if cfg.Approval.ToolApproval.EnabledEffective(false) {
		t.Fatal("tool approval should be disabled")
	}
	if !cfg.Approval.DangerousAction.EnabledEffective(true) || len(cfg.Approval.ToolApproval.ToolWhitelist) != 2 {
		t.Fatalf("approval triggers = %+v", cfg.Approval)
	}
}

func TestApprovalPolicyDefaultsKeepDangerGateIndependent(t *testing.T) {
	var cfg Config
	if cfg.Approval.ToolApproval.EnabledEffective(false) {
		t.Fatal("tool approval default should be off")
	}
	if !cfg.Approval.DangerousAction.EnabledEffective(true) {
		t.Fatal("dangerous action default should be on")
	}
	if cfg.Approval.EffectiveReviewer() != "human" {
		t.Fatalf("reviewer = %q, want human", cfg.Approval.EffectiveReviewer())
	}
	if cfg.Approval.TimeoutSecondsEffective() != 300 {
		t.Fatalf("timeout = %d, want 300", cfg.Approval.TimeoutSecondsEffective())
	}
}

func TestHitlAuditModelEffectiveFallsBackToMainConfig(t *testing.T) {
	main := OpenAIConfig{
		Provider: "openai",
		BaseURL:  "https://api.example.com/v1",
		APIKey:   "main-key",
		Model:    "large-model",
	}

	got := (HitlConfig{
		AuditModel: OpenAIConfig{Model: "small-reviewer"},
	}).AuditModelEffective(main)

	if got.Provider != main.Provider || got.BaseURL != main.BaseURL || got.APIKey != main.APIKey {
		t.Fatalf("expected provider/base_url/api_key to inherit main config, got %+v", got)
	}
	if got.Model != "small-reviewer" {
		t.Fatalf("expected audit model override, got %q", got.Model)
	}
}

func TestLoadUsesAIDefaultChannelAsRuntimeOpenAI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	initial := strings.Join([]string{
		"ai:",
		"  default_channel: deepseek",
		"  channels:",
		"    qwen:",
		"      name: Qwen",
		"      provider: openai_compatible",
		"      base_url: https://dashscope.example/v1",
		"      api_key: qwen-key",
		"      model: qwen-max",
		"    deepseek:",
		"      name: DeepSeek",
		"      provider: openai_compatible",
		"      base_url: https://deepseek.example/v1",
		"      api_key: deepseek-key",
		"      model: deepseek-chat",
		"      max_total_tokens: 64000",
		"server:",
		"  host: 127.0.0.1",
		"  port: 8080",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OpenAI.Model != "deepseek-chat" || cfg.OpenAI.APIKey != "deepseek-key" || cfg.OpenAI.MaxTotalTokens != 64000 {
		t.Fatalf("runtime OpenAI config did not follow ai.default_channel: %+v", cfg.OpenAI)
	}
	oa, id, ok := cfg.ResolveAIChannel("qwen")
	if !ok || id != "qwen" || oa.Model != "qwen-max" || oa.APIKey != "qwen-key" {
		t.Fatalf("ResolveAIChannel(qwen) = (%+v, %q, %v)", oa, id, ok)
	}
}

func TestSummarizationUserIntentLedgerRunesEffective(t *testing.T) {
	var zero MultiAgentEinoMiddlewareConfig
	if got := zero.SummarizationUserIntentLedgerMaxRunesEffective(); got != DefaultSummarizationUserIntentLedgerMaxRunes {
		t.Fatalf("default ledger max runes = %d, want %d", got, DefaultSummarizationUserIntentLedgerMaxRunes)
	}
	if got := zero.SummarizationUserIntentLedgerEntryMaxRunesEffective(); got != DefaultSummarizationUserIntentLedgerEntryMaxRunes {
		t.Fatalf("default ledger entry max runes = %d, want %d", got, DefaultSummarizationUserIntentLedgerEntryMaxRunes)
	}

	custom := MultiAgentEinoMiddlewareConfig{
		SummarizationUserIntentLedgerMaxRunes:      12345,
		SummarizationUserIntentLedgerEntryMaxRunes: 2345,
	}
	if got := custom.SummarizationUserIntentLedgerMaxRunesEffective(); got != 12345 {
		t.Fatalf("custom ledger max runes = %d", got)
	}
	if got := custom.SummarizationUserIntentLedgerEntryMaxRunesEffective(); got != 2345 {
		t.Fatalf("custom ledger entry max runes = %d", got)
	}
}

func TestSummarizationOutputReserveTokensEffective(t *testing.T) {
	var zero MultiAgentEinoMiddlewareConfig
	if got := zero.SummarizationOutputReserveTokensEffective(); got != DefaultSummarizationOutputReserveTokens {
		t.Fatalf("default output reserve = %d, want %d", got, DefaultSummarizationOutputReserveTokens)
	}
	custom := MultiAgentEinoMiddlewareConfig{SummarizationOutputReserveTokens: 4096}
	if got := custom.SummarizationOutputReserveTokensEffective(); got != 4096 {
		t.Fatalf("custom output reserve = %d", got)
	}
}

func TestOpenAIOutputLimitValidation(t *testing.T) {
	if got := (OpenAIConfig{}).MaxCompletionTokensEffective(); got != DefaultMaxCompletionTokens {
		t.Fatalf("max completion default=%d", got)
	}
	if err := validateOpenAIOutputLimits(OpenAIConfig{MaxCompletionTokens: -1}); err == nil {
		t.Fatal("negative completion limit must fail")
	}
}

func TestLatestUserMessageRunesEffective(t *testing.T) {
	var zero MultiAgentEinoMiddlewareConfig
	if got := zero.LatestUserMessageMaxRunesEffective(); got != DefaultLatestUserMessageMaxRunes {
		t.Fatalf("default latest user max runes = %d, want %d", got, DefaultLatestUserMessageMaxRunes)
	}
	if got := zero.LatestUserMessageHeadRunesEffective(); got != DefaultLatestUserMessageHeadRunes {
		t.Fatalf("default latest user head runes = %d, want %d", got, DefaultLatestUserMessageHeadRunes)
	}
	if got := zero.LatestUserMessageTailRunesEffective(); got != DefaultLatestUserMessageTailRunes {
		t.Fatalf("default latest user tail runes = %d, want %d", got, DefaultLatestUserMessageTailRunes)
	}

	custom := MultiAgentEinoMiddlewareConfig{
		LatestUserMessageMaxRunes:  100,
		LatestUserMessageHeadRunes: 40,
		LatestUserMessageTailRunes: 60,
	}
	if got := custom.LatestUserMessageMaxRunesEffective(); got != 100 {
		t.Fatalf("custom latest user max runes = %d", got)
	}
	if got := custom.LatestUserMessageHeadRunesEffective(); got != 40 {
		t.Fatalf("custom latest user head runes = %d", got)
	}
	if got := custom.LatestUserMessageTailRunesEffective(); got != 60 {
		t.Fatalf("custom latest user tail runes = %d", got)
	}
}

func TestDefaultAuditAgentPromptContract(t *testing.T) {
	prompt := DefaultHitlAuditAgentPrompt()
	// 字段信任分级：userMessage 可信、参数内容防注入
	for _, want := range []string{
		"userMessage 是人类用户向主 Agent 下达的任务指令",
		"一律忽略",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("default audit prompt missing %q", want)
		}
	}
	// 声明对齐：未声明的敏感危险操作必须拦下并提示补充授权；已声明才放行；
	// userMessage 明确声明的大规模操作视为知情授权，仅超出声明范围才 reject
	for _, want := range []string{
		"核心裁决原则（声明对齐）",
		"请确认是否授权本次操作",
		"敏感危险操作清单",
		"泛化任务描述",
		"视为用户知情授权",
		"行为超出声明范围的大规模破坏",
		"按测试类操作裁决",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("default audit prompt missing %q", want)
		}
	}
	// 普通渗透操作不受声明要求限制
	for _, want := range []string{"普通操作放行清单", "反弹 Shell", "webshell"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("default audit prompt missing %q", want)
		}
	}
	// 拒绝后是否询问用户由主 Agent 自行判断（可选，不强制）；命中规则有编号定义
	for _, want := range []string{
		"由主 Agent 自行判断",
		"规则编号（comment 的「命中规则」必须取以下之一",
		"R2 超范围",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("default audit prompt missing %q", want)
		}
	}
}
