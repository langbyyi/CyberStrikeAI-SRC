package config

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestHitlEffectiveAuditBackend(t *testing.T) {
	if got := (HitlConfig{}).EffectiveAuditBackend(); got != HitlAuditBackendOpenAI {
		t.Fatalf("empty backend = %q, want openai", got)
	}
	if got := (HitlConfig{AuditBackend: "Jev"}).EffectiveAuditBackend(); got != HitlAuditBackendTypeSafe {
		t.Fatalf("jev alias = %q, want typesafe", got)
	}
	if got := (HitlConfig{AuditBackend: "claude"}).EffectiveAuditBackend(); got != HitlAuditBackendOpenAI {
		t.Fatalf("unknown backend = %q, want openai", got)
	}
}

func TestHitlTypeSafeConfigEffectiveDoesNotInheritMainKey(t *testing.T) {
	gotURL, gotKey, gotModel := (HitlConfig{
		AuditBackend: "typesafe",
		AuditModel:   OpenAIConfig{APIKey: "ts-key"},
	}).TypeSafeConfigEffective()
	if gotURL != TypeSafeDefaultBaseURL {
		t.Fatalf("base url = %q, want default", gotURL)
	}
	if gotKey != "ts-key" {
		t.Fatalf("api key = %q, want ts-key", gotKey)
	}
	if gotModel != TypeSafeDefaultModel {
		t.Fatalf("model = %q, want default", gotModel)
	}
}

func TestJevOperatorPolicySkipsDefaultPrompt(t *testing.T) {
	if got := (HitlConfig{}).JevOperatorPolicy(); got != "" {
		t.Fatalf("empty config should not send default prompt to Jev, got %q", got)
	}
	if got := (HitlConfig{AuditAgentPrompt: DefaultHitlAuditAgentPrompt()}).JevOperatorPolicy(); got != "" {
		t.Fatalf("default prompt should not be sent to Jev, got %q", got)
	}
	if got := (HitlConfig{AuditAgentPrompt: "拦截所有命令执行"}).JevOperatorPolicy(); got != "拦截所有命令执行" {
		t.Fatalf("custom prompt=%q", got)
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

func TestNormalizeAIProviderProfilesForOfficialDeepSeekEndpoint(t *testing.T) {
	cfg := &Config{
		OpenAI: OpenAIConfig{
			BaseURL: "https://api.deepseek.com/v1",
			Model:   "deepseek-chat",
			Reasoning: OpenAIReasoningConfig{
				Profile: "openai_compat",
			},
		},
		AI: AIConfig{
			Channels: map[string]AIChannelConfig{
				"official": {
					BaseURL: "api.deepseek.com/v1",
					Model:   "deepseek-chat",
					Reasoning: OpenAIReasoningConfig{
						Profile: "auto",
					},
				},
				"gateway": {
					BaseURL: "https://compatible.example.com/v1",
					Model:   "deepseek-chat",
					Reasoning: OpenAIReasoningConfig{
						Profile: "openai_compat",
					},
				},
			},
		},
	}

	cfg.NormalizeAIProviderProfiles()

	if cfg.OpenAI.Reasoning.Profile != "deepseek" {
		t.Fatalf("openai profile = %q, want deepseek", cfg.OpenAI.Reasoning.Profile)
	}
	if got := cfg.AI.Channels["official"].Reasoning.Profile; got != "deepseek" {
		t.Fatalf("official channel profile = %q, want deepseek", got)
	}
	if got := cfg.AI.Channels["gateway"].Reasoning.Profile; got != "openai_compat" {
		t.Fatalf("gateway profile should be preserved, got %q", got)
	}
}

func TestLoadNormalizesDefaultChannelForOfficialDeepSeekEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	initial := strings.Join([]string{
		"ai:",
		"  default_channel: deepseek",
		"  channels:",
		"    deepseek:",
		"      name: DeepSeek",
		"      provider: openai_compatible",
		"      base_url: https://api.deepseek.com/v1",
		"      api_key: deepseek-key",
		"      model: deepseek-chat",
		"      reasoning:",
		"        profile: openai_compat",
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
	if cfg.OpenAI.Reasoning.Profile != "deepseek" {
		t.Fatalf("runtime OpenAI profile = %q, want deepseek", cfg.OpenAI.Reasoning.Profile)
	}
	if got := cfg.AI.Channels["deepseek"].Reasoning.Profile; got != "deepseek" {
		t.Fatalf("channel profile = %q, want deepseek", got)
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
	// 判据口径：同意与理由优先，未声明且无理由才拦下并提示补充授权；
	// 用户明确同意的大规模操作视为知情授权，仅超出声明范围才 reject
	for _, want := range []string{
		"核心裁决原则（同意与理由）",
		"是否请求授权、何时请求由主 Agent 判断",
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
	// 自主闭环：用户同意必须压过"未声明"，理由可核验的验证必须放行，
	// 且不得再出现"最小化验证也算敏感危险操作"这类把正解判死的措辞。
	for _, want := range []string{
		"唯一不可被同意覆盖",
		"A2 有可检验的理由",
		"长期有效",
		"testingSpecification",
		"最小化本身不构成拒绝理由",
		// 同意不得外推：对 A 接口的同意不能变成"所有写操作都同意"，
		// 否则一次授权会把整类操作永久打开，且没有 R1 逃生话术可以补救。
		"同意的范围",
		"同意不得外推",
		"不构成新的同意",
		// 声明窗口有界（最近若干条 + 截断）：不能对审计 Agent 谎称"你看到的是全部"，
		// 否则它会因窗口外的同意不可见而确信"用户从未同意"。
		"只保留最近若干条",
		// 无声明不构成超范围：R2 是唯一不可被同意覆盖的档位，允许凭印象判 R2
		// 等于把刚修好的死锁换条路重新打开。判 R2 必须指得出冲突的声明。
		"无声明不构成超范围",
		// A2 的三条理由是累加而非任一：写成"任一满足"会让一次有界就替真实账号背书。
		"三项同时满足",
		// 两张清单交叉（DROP/TRUNCATE、写计划任务、数据库命令执行同名）必须有取舍规则，
		// 否则同一形态两侧同时命中，裁决随模型心情。
		"两张清单交叉时按",
		// 看不到同意不等于定案：继续走 A2，避免窗口外的同意不可见就把 A2 好的调用一并判死。
		"看不到明确同意时不要就此定案",
		// 授权提问归执行 Agent：被拒后"还要不要做"由主 Agent 自行拍板，
		// 定不了才留到收尾交给用户。
		"收尾时与其他结论一并提出是否授权",
		"自行拍板继续",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("default audit prompt missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"最小化验证（删除不存在的 ID、使用自建测试数据）同样属于敏感危险操作",
		"userMessage 必须明确提及该类操作本身",
		// 审计侧不再强制索要授权：那句提问由执行 Agent 决定何时发出，
		// 强制它出现会逼模型在主线中途停下来等授权。
		"comment 必须以问题形式请求授权",
	} {
		if strings.Contains(prompt, forbidden) {
			t.Errorf("default audit prompt must not keep %q", forbidden)
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
		"由主 Agent 决定",
		"规则编号（comment 的「命中规则」必须取以下之一",
		"R2 超范围",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("default audit prompt missing %q", want)
		}
	}
}
func TestLoadUpdateRepoReadsOnlyTheSourceField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// The rest of the file may be broken or unvalidatable; the CLI only asks for the
	// update source, and a full config load must not be a precondition for updating.
	if err := os.WriteFile(path, []byte("update:\n  repo: https://github.com/Sycun/CyberStrikeAI.git\nserver:\n  port: 8088\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo, err := LoadUpdateRepo(path)
	if err != nil {
		t.Fatal(err)
	}
	if repo != "https://github.com/Sycun/CyberStrikeAI.git" {
		t.Fatalf("repo = %q, want the configured address", repo)
	}

	// Unset and missing files both mean "the official repository is the default".
	if err := os.WriteFile(path, []byte("server:\n  port: 8088\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if repo, err := LoadUpdateRepo(path); err != nil || repo != "" {
		t.Fatalf("repo = %q err = %v, want empty with no error", repo, err)
	}
	if repo, err := LoadUpdateRepo(filepath.Join(dir, "missing.yaml")); err != nil || repo != "" {
		t.Fatalf("a missing config is not an error: repo = %q err = %v", repo, err)
	}

	// A file that is not YAML at all must fail loudly rather than silently fall back to
	// the official repository (that would be an update from the wrong place).
	if err := os.WriteFile(path, []byte("update: [not: a: map\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUpdateRepo(path); err == nil {
		t.Fatal("a malformed config must be an error, not a silent default")
	}
}

func TestFileVersionAndWriteVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Missing file reads as "unknown", not an error.
	if v, err := FileVersion(filepath.Join(dir, "missing.yaml")); err != nil || v != "" {
		t.Fatalf("missing file: %q %v", v, err)
	}

	original := "version: \"v1.0.0\"\nserver:\n  port: 8088\n  # a nested word: version: should stay put\nnotes:\n  version: nested-untouched\n"
	if err := os.WriteFile(path, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := FileVersion(path); err != nil || v != "v1.0.0" {
		t.Fatalf("version = %q err = %v", v, err)
	}

	changed, err := WriteVersion(path, "v1.1.0")
	if err != nil || !changed {
		t.Fatalf("write: changed=%v err=%v", changed, err)
	}
	got := readTestFile(t, path)
	want := "version: \"v1.1.0\"\nserver:\n  port: 8088\n  # a nested word: version: should stay put\nnotes:\n  version: nested-untouched\n"
	if got != want {
		t.Fatalf("file after write:\n%q\nwant:\n%q", got, want)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != originalInfo.Mode().Perm() {
		t.Fatalf("mode = %v err = %v, want 0640 preserved", info.Mode(), err)
	}

	// Idempotent: the same value is not rewritten.
	if changed, err := WriteVersion(path, "v1.1.0"); err != nil || changed {
		t.Fatalf("rewriting the same value: changed=%v err=%v", changed, err)
	}

	// No top-level field: insert at the top, nested keys stay untouched.
	if err := os.WriteFile(path, []byte("server:\n  port: 8088\nnotes:\n  version: nested\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err := WriteVersion(path, "v1.2.0"); err != nil || !changed {
		t.Fatalf("insert: changed=%v err=%v", changed, err)
	}
	got = readTestFile(t, path)
	if !strings.HasPrefix(got, "version: \"v1.2.0\"\n") || !strings.Contains(got, "  version: nested") {
		t.Fatalf("file after insert:\n%q", got)
	}

	// A value that would write malformed YAML is refused rather than written.
	if _, err := WriteVersion(path, "v1.0.0\"\nserver: hijacked"); err == nil {
		t.Fatal("a version containing a quote/newline must be refused")
	}
}

func TestWriteVersionPreservesYAMLDocumentStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := "---\nserver:\n  port: 8088\n"
	const originalMode = os.FileMode(0o600)
	if err := os.WriteFile(path, []byte(original), originalMode); err != nil {
		t.Fatal(err)
	}

	originalInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	changed, err := WriteVersion(path, "v1.2.3")
	if err != nil || !changed {
		t.Fatalf("WriteVersion: changed=%v err=%v", changed, err)
	}
	got := readTestFile(t, path)
	want := "---\nversion: \"v1.2.3\"\nserver:\n  port: 8088\n"
	if got != want {
		t.Fatalf("file after write:\n%q\nwant:\n%q", got, want)
	}
	if !strings.HasPrefix(got, "---\n") {
		t.Fatalf("YAML document start must remain first: %q", got)
	}
	if version, err := FileVersion(path); err != nil || version != "v1.2.3" {
		t.Fatalf("FileVersion = %q, %v; want v1.2.3", version, err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load after WriteVersion: %v", err)
	}
	if cfg.Server.Port != 8088 {
		t.Fatalf("server.port = %d, want 8088", cfg.Server.Port)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != originalInfo.Mode().Perm() {
		t.Fatalf("mode = %v, want %v preserved", info.Mode().Perm(), originalMode)
	}
}

// FileVersion 用 YAML 解析（引号键认得出），WriteVersion 若只认顶格裸键，合法配置就会被追加
// 出第二个 version 键、整个文件随后 Load 失败。这条测试钉死两者口径一致，以及"改不了就拒绝写"。
func TestWriteVersionRewritesQuotedKeysAndRefusesWhatItCannot(t *testing.T) {
	dir := t.TempDir()

	// Legal spellings of the same top-level key: replaced in place, exactly one key left.
	for _, original := range []string{
		"\"version\": \"v1.0.0\"\nserver:\n  port: 8088\n",
		"'version': v1.0.0\nserver:\n  port: 8088\n",
		"\"version\":   v1.0.0\nserver:\n  port: 8088\n",
	} {
		path := filepath.Join(dir, "quoted.yaml")
		if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
			t.Fatal(err)
		}
		if v, err := FileVersion(path); err != nil || v != "v1.0.0" {
			t.Fatalf("FileVersion(%q) = %q, %v", original, v, err)
		}
		changed, err := WriteVersion(path, "v1.7.22")
		if err != nil || !changed {
			t.Fatalf("WriteVersion(%q): changed=%v err=%v", original, changed, err)
		}
		got := readTestFile(t, path)
		if strings.Count(got, "version") != 1 {
			t.Fatalf("writing %q left %d version keys:\n%q", original, strings.Count(got, "version"), got)
		}
		if v, err := FileVersion(path); err != nil || v != "v1.7.22" {
			t.Fatalf("after writing %q: FileVersion = %q, %v (file %q)", original, v, err, got)
		}
		if !strings.Contains(got, "port: 8088") {
			t.Fatalf("the rest of the file must stay: %q", got)
		}
	}

	// Forms a line-based replacement cannot rewrite: refused with the file untouched. A
	// stale version number is a display artifact; a config that no longer loads is an
	// installation that no longer starts.
	for _, original := range []string{
		"{\"version\": \"v1.0.0\", \"server\": {\"port\": 8088}}\n",
		"version: >-\n  v1.0.0\nserver:\n  port: 8088\n",
		"\"version\": \"v9.9.9\"\n\"version\": \"v1.0.0\"\n",
	} {
		path := filepath.Join(dir, "unwritable.yaml")
		if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
			t.Fatal(err)
		}
		changed, err := WriteVersion(path, "v1.7.22")
		if err == nil {
			t.Fatalf("WriteVersion(%q) must refuse instead of writing: changed=%v file=%q", original, changed, readTestFile(t, path))
		}
		if got := readTestFile(t, path); got != original {
			t.Fatalf("a refused write must not touch the file:\nbefore %q\nafter  %q", original, got)
		}
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestWriteVersionAfterCommentedDocumentStart(t *testing.T) {
	for _, prefix := range []string{"# local settings\n---\n", "\n# local settings\n--- # config\n", "%YAML 1.1\n---\n"} {
		t.Run(prefix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			original := prefix + "server:\n  port: 8088\n"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			if changed, err := WriteVersion(path, "v1.2.3"); err != nil || !changed {
				t.Fatalf("write: %v %v", changed, err)
			}
			cfg, err := Load(path)
			if err != nil || cfg.Server.Port != 8088 {
				t.Fatalf("settings lost after version write: cfg=%+v err=%v", cfg, err)
			}
			if got := readTestFile(t, path); got != prefix+"version: \"v1.2.3\"\nserver:\n  port: 8088\n" {
				t.Fatalf("unexpected rewrite: %q", got)
			}
		})
	}
}

func TestWriteVersionRefusesToHideAnInlineYAMLDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := "--- {server: {port: 8088}}\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := WriteVersion(path, "v1.2.3"); err == nil || changed {
		t.Fatalf("must refuse document loss: changed=%v err=%v", changed, err)
	}
	if got := readTestFile(t, path); got != original {
		t.Fatal("refusal modified config")
	}
}

func TestVersionWritePreservesConfigSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "actual.yaml")
	link := filepath.Join(dir, "config.yaml")
	original := "server:\n  port: 8088\n"
	if err := os.WriteFile(target, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteVersion(link, "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("version write replaced config symlink")
	}
	if version, err := FileVersion(target); err != nil || version != "v1.2.3" {
		t.Fatal("version did not reach symlink target")
	}
	if _, err := RemoveVersion(link); err != nil {
		t.Fatal(err)
	}
	if got := readTestFile(t, target); got != original {
		t.Fatal("version removal changed original settings")
	}
}
