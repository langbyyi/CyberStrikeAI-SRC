package multiagent

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBuildStructuredToolSummary_SqlmapFakeOutput(t *testing.T) {
	t.Parallel()
	args := `{"url":"http://target.example/item?id=1","param":"id","payload":"1' AND SLEEP(5)--"}`
	output := `sqlmap identified the following injection point(s):
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: id=1' AND SLEEP(5)--

[INFO] the back-end DBMS is MySQL
HTTP/1.1 500 Internal Server Error
response time: 5120 ms
vulnerable to SQL injection
`
	sum := BuildStructuredToolSummary("sqlmap", args, output)
	if sum.StatusHint == "" {
		t.Fatal("status_hint required")
	}
	if sum.StatusHint != "interesting" {
		t.Fatalf("status_hint=%q want interesting", sum.StatusHint)
	}
	if sum.Length != len(output) {
		t.Fatalf("length=%d want %d", sum.Length, len(output))
	}
	if sum.HTTPStatus != "500" {
		t.Fatalf("http_status=%q want 500", sum.HTTPStatus)
	}
	if sum.TimeMs <= 0 {
		t.Fatalf("time_ms should be parsed, got %d", sum.TimeMs)
	}
	if sum.MatchedPayload == "" && sum.InterestingParams == "" {
		t.Fatal("expected matched_payload or interesting_params")
	}
	if sum.NextHint == "" {
		t.Fatal("next_hint required")
	}

	block := FormatStructuredSummaryBlock(sum, DefaultStructuredSummaryMaxRunes)
	for _, field := range []string{
		"status_hint", "http_status", "length", "time_ms",
		"error_sig", "interesting_params", "matched_payload", "next_hint",
	} {
		if !strings.Contains(block, field+":") {
			t.Fatalf("block missing field %s:\n%s", field, block)
		}
	}
	if len([]rune(block)) > DefaultStructuredSummaryMaxRunes {
		t.Fatalf("block exceeds budget: %d", len([]rune(block)))
	}

	out, ok := PrependStructuredToolSummary("sqlmap", args, output, 1200)
	if !ok {
		t.Fatal("expected prepend")
	}
	if !strings.HasPrefix(out, "## [tool_structured_summary]") {
		t.Fatalf("summary not prepended: %s", out[:min(80, len(out))])
	}
	if !strings.Contains(out, "vulnerable to SQL injection") {
		t.Fatal("original body must remain")
	}
}

func TestBuildStructuredToolSummary_NucleiFfufHTTP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tool   string
		output string
		wantInteresting bool
	}{
		{
			tool: "nuclei",
			output: `[critical] CVE-2021-41773 matched on http://t/cgi-bin
[INFO] Templates loaded
HTTP/1.1 200 OK
`,
			wantInteresting: true,
		},
		{
			tool: "ffuf",
			output: `:: Progress: [100/100]
admin                  [Status: 200, Size: 1234, Words: 10, Duration: 45ms]
api/v1                 [Status: 403, Size: 19]
`,
			wantInteresting: false,
		},
		{
			tool: "http-framework-test",
			output: `Framework: Spring Boot 2.5
HTTP/1.1 200 OK
status code: 200
response time: 120 ms
`,
			wantInteresting: false,
		},
	}
	for _, tc := range cases {
		sum := BuildStructuredToolSummary(tc.tool, `{"url":"http://t"}`, tc.output)
		block := FormatStructuredSummaryBlock(sum, 1200)
		for _, field := range []string{"status_hint:", "http_status:", "length:", "next_hint:"} {
			if !strings.Contains(block, field) {
				t.Fatalf("%s missing %s in %s", tc.tool, field, block)
			}
		}
		if tc.wantInteresting && sum.StatusHint != "interesting" {
			t.Fatalf("%s status_hint=%q", tc.tool, sum.StatusHint)
		}
		if sum.NextHint == "" {
			t.Fatalf("%s next_hint empty", tc.tool)
		}
	}
}

func TestFormatStructuredSummaryBlock_BudgetTruncate(t *testing.T) {
	t.Parallel()
	sum := StructuredToolSummary{
		StatusHint:        "interesting",
		HTTPStatus:        "500",
		Length:            99999,
		TimeMs:            5000,
		ErrorSig:          strings.Repeat("E", 400),
		InterestingParams: strings.Repeat("P", 400),
		MatchedPayload:    strings.Repeat("X", 400),
		NextHint:          strings.Repeat("N", 400),
	}
	block := FormatStructuredSummaryBlock(sum, 200)
	if len([]rune(block)) > 200 {
		t.Fatalf("budget 200 exceeded: %d", len([]rune(block)))
	}
}

func TestPrependStructuredToolSummary_SkipsNonScanner(t *testing.T) {
	t.Parallel()
	out, ok := PrependStructuredToolSummary("list_vulnerabilities", "{}", "ok", 1200)
	if ok {
		t.Fatal("should skip non-scanner")
	}
	if out != "ok" {
		t.Fatalf("got %q", out)
	}
}

func TestPrependStructuredToolSummary_NoPanicHugeAndBinary(t *testing.T) {
	t.Parallel()
	// invalid utf8 + huge
	huge := strings.Repeat("A", 10000) + string([]byte{0xff, 0xfe, 0xfd}) + strings.Repeat("B", 10000)
	out, ok := PrependStructuredToolSummary("sqlmap", "{}", huge, 300)
	if !ok {
		t.Fatal("sqlmap should structure")
	}
	if !strings.Contains(out, "## [tool_structured_summary]") {
		t.Fatal("missing summary header")
	}
	// must not panic; output is valid enough for rune count
	_ = utf8.ValidString(out) // may be false if body has invalid; still no panic
}

func TestShouldStructureToolResult_AlignedWithScanners(t *testing.T) {
	t.Parallel()
	// Core scanners in always_visible hunting set that produce bulky output.
	for _, n := range []string{"sqlmap", "nuclei", "ffuf", "http-framework-test", "dalfox", "execute-python-script", "katana", "arjun", "jwt-analyzer", "exec"} {
		if !ShouldStructureToolResult(n) {
			t.Fatalf("%s should be in StructuredSummaryTools", n)
		}
	}
	if ShouldStructureToolResult("skill") {
		t.Fatal("skill should not structure")
	}
	if !ShouldStructureToolResult("ext__nuclei") {
		t.Fatal("prefix strip")
	}
}

func TestComposeToolResultWithBoostOrder(t *testing.T) {
	t.Parallel()
	// Order: summary → body → skill
	out := ComposeToolResultWithBoostOrder(
		"## [tool_structured_summary]\nstatus_hint: ok\n---\n",
		"RAW_BODY_LINE\n",
		"\n## [SkillRouter]\nskill=sqli\n",
	)
	si := strings.Index(out, "tool_structured_summary")
	bi := strings.Index(out, "RAW_BODY_LINE")
	ki := strings.Index(out, "SkillRouter")
	if si < 0 || bi < 0 || ki < 0 {
		t.Fatalf("missing parts: %s", out)
	}
	if !(si < bi && bi < ki) {
		t.Fatalf("order wrong: summary@%d body@%d skill@%d", si, bi, ki)
	}
}

func TestApplyExecutionBoostPostProcess_Order(t *testing.T) {
	t.Parallel()
	// Direct unit of Compose already covers order; also exercise post-process via exported helpers.
	body := "You have an error in your SQL syntax; Parameter id\nvulnerable"
	sum, ok := PrependStructuredToolSummary("sqlmap", `{"param":"id"}`, body, 800)
	if !ok {
		t.Fatal("expected summary")
	}
	// Simulate skill block after
	composed := ComposeToolResultWithBoostOrder(
		sum[:strings.Index(sum, "---\n")+4],
		body,
		"\n## SkillRouter tips\nsqli-sql-injection\n",
	)
	if !strings.HasPrefix(composed, "## [tool_structured_summary]") {
		t.Fatal("summary must lead")
	}
	if !strings.Contains(composed, "SkillRouter") {
		t.Fatalf("skill must trail: %s", composed[len(composed)-80:])
	}
	idxSum := strings.Index(composed, "tool_structured_summary")
	idxBody := strings.Index(composed, "vulnerable")
	idxSkill := strings.Index(composed, "SkillRouter")
	if !(idxSum < idxBody && idxBody < idxSkill) {
		t.Fatalf("order sum=%d body=%d skill=%d", idxSum, idxBody, idxSkill)
	}
}

func TestClassifyToolError_Patterns(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		output   string
		wantCode string
		wantRe   bool
	}{
		{"nuclei 模板缺失", "INF [FTL] could not find templates in", "templates_missing", false},
		{"连接被拒", "curl: (7) Failed to connect to host: Connection refused", "target_unreachable", false},
		{"DNS 解析失败", "nmap: Failed to resolve \"x\". could not resolve host", "target_unreachable", false},
		{"ctx 超时", "context deadline exceeded (120s)", "timeout", true},
		{"inactivity 中文", "命令已终止：超过 300 秒没有新的输出", "timeout", true},
		{"preflight 配置缺失", "[preflight] ffuf 字典路径不存在: /a/b", "config_error", false},
		{"正常无错误", "scan complete, 0 findings", "", false},
	}
	for _, c := range cases {
		code, re := classifyToolError(c.output)
		if code != c.wantCode || re != c.wantRe {
			t.Fatalf("%s: got code=%q retryable=%v, want code=%q retryable=%v", c.name, code, re, c.wantCode, c.wantRe)
		}
	}
}

func TestNextHintForTool_DynamicByErrorCode(t *testing.T) {
	t.Parallel()
	// error_code 优先于工具名静态提示。
	if h := nextHintForTool("nuclei", StructuredToolSummary{ErrorCode: "templates_missing"}); !strings.Contains(h, "模板库缺失") && !strings.Contains(h, "update-templates") {
		t.Fatalf("templates_missing hint: %q", h)
	}
	if h := nextHintForTool("ffuf", StructuredToolSummary{ErrorCode: "timeout"}); !strings.Contains(h, "可重试") {
		t.Fatalf("timeout hint should mention retryable: %q", h)
	}
	// 无 error_code 时回退到工具名语义。
	if h := nextHintForTool("nuclei", StructuredToolSummary{StatusHint: "interesting"}); !strings.Contains(h, "matched template") {
		t.Fatalf("fallback nuclei hint: %q", h)
	}
}

func TestBuildStructuredToolSummary_ErrorCodeEndToEnd(t *testing.T) {
	t.Parallel()
	sum := BuildStructuredToolSummary("nuclei", `{}`, "INF nuclei started\n[FTL] could not find templates in\n")
	if sum.ErrorCode != "templates_missing" || sum.Retryable {
		t.Fatalf("end-to-end classify: code=%q retryable=%v", sum.ErrorCode, sum.Retryable)
	}
	if !strings.Contains(sum.NextHint, "模板库缺失") && !strings.Contains(sum.NextHint, "update-templates") {
		t.Fatalf("next_hint should reflect templates_missing: %q", sum.NextHint)
	}
	block := FormatStructuredSummaryBlock(sum, 1200)
	if !strings.Contains(block, "error_code: templates_missing") {
		t.Fatalf("block missing error_code: %s", block)
	}
	if !strings.Contains(block, "retryable: false") {
		t.Fatalf("block missing retryable: %s", block)
	}
	// 正常输出不应出现 retryable 行。
	ok := BuildStructuredToolSummary("nuclei", `{}`, "scan complete, 0 findings")
	if ok.ErrorCode != "" {
		t.Fatalf("clean output should have empty error_code, got %q", ok.ErrorCode)
	}
	okBlock := FormatStructuredSummaryBlock(ok, 1200)
	if strings.Contains(okBlock, "retryable:") {
		t.Fatalf("clean output should not emit retryable line: %s", okBlock)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
