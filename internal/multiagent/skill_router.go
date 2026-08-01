package multiagent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// SkillSignalRule maps fingerprint/error/param signals to a skills/*/ directory name.
type SkillSignalRule struct {
	Skill    string   // directory under skills/, e.g. sqli-sql-injection
	Patterns []string // case-insensitive substrings matched against tool name+args+output
	Weight   int      // higher wins when ranking
}

// DefaultSkillSignalRules production mapping for common hunting signals.
var DefaultSkillSignalRules = []SkillSignalRule{
	{Skill: "sqli-sql-injection", Weight: 10, Patterns: []string{
		"sql syntax", "you have an error in your sql", "mysql_fetch", "mysql_num_rows",
		"sqlstate", "ora-", "pg::", "postgresql", "sqlite3.operationalerror",
		"unclosed quotation mark", "odbc sql server", "jdbc", "sqlmap",
		"sleep(", "waitfor delay", "information_schema", "union select",
	}},
	{Skill: "xss-cross-site-scripting", Weight: 9, Patterns: []string{
		"<script", "onerror=", "onload=", "javascript:", "dalfox", "alert(",
		"document.cookie", "xss", "cross-site scripting",
	}},
	{Skill: "ssrf-server-side-request-forgery", Weight: 9, Patterns: []string{
		"169.254.169.254", "metadata.google", "ssrf", "file://", "gopher://",
		"dict://", "internal network", "aws metadata",
	}},
	{Skill: "cmdi-command-injection", Weight: 9, Patterns: []string{
		"uid=", "gid=", "/bin/sh", "cmd.exe", "whoami", "command injection",
		"os.system", "runtime.exec", "shell_exec",
	}},
	{Skill: "path-traversal-lfi", Weight: 8, Patterns: []string{
		"../", "..\\", "/etc/passwd", "boot.ini", "path traversal", "lfi",
		"file inclusion", "php://filter",
	}},
	{Skill: "jwt-oauth-token-attacks", Weight: 8, Patterns: []string{
		"eyj", "jwt", "alg:none", "rs256", "hs256", "oauth", "bearer ",
		"invalid signature", "jwt-analyzer",
	}},
	// IDOR: mid-low weight; only explicit object/cross-user access (not bare order_id on pay create).
	{Skill: "idor-broken-object-authorization", Weight: 5, Patterns: []string{
		"idor", "object id", "user_id=", "account_id=", "unauthorized access to other",
		"horizontal privilege", "broken object", "水平越权", "越权访问", "bola",
	}},
	// Business/Backend Logic Track (R5): payment/workflow/race — weight above idor.
	{Skill: "business-logic-vulnerabilities", Weight: 11, Patterns: []string{
		"price=", "amount=", "quantity=", "coupon", "discount", "balance", "credit",
		"checkout", "payment", "refund", "transfer", "withdraw", "redeem",
		"gift_card", "giftcard", "invite_code", "refer", "workflow", "business logic",
		"param_tamper", "workflow_skip", "coupon_abuse", "state_tamper",
		"/cart", "/checkout", "/order", "/pay", "/payment", "/refund", "/trade",
		"pay/create", "api/pay", "out_trade_no", "total_fee", "trade_status",
		"\"price\"", "\"amount\"", "\"coupon\"", "\"discount\"", "\"total_fee\"",
		"\"balance\"", "\"paid\"", "wallet", "notify", "callback",
		"购物车", "结账", "优惠券", "支付", "退款", "提现", "信任客户端",
	}},
	{Skill: "race-condition", Weight: 8, Patterns: []string{
		"race condition", "race-condition", "toctou", "double spend", "double-spend",
		"parallel request", "concurrent request", "单包", "竞态", "并发请求",
		"turbo intruder", "last-byte sync", "限购", "领券", "重复回调", "notify",
	}},
	{Skill: "ssti-server-side-template-injection", Weight: 8, Patterns: []string{
		"{{7*7}}", "${7*7}", "freemarker", "jinja2", "twig", "ssti", "template injection",
	}},
	{Skill: "xxe-xml-external-entity", Weight: 8, Patterns: []string{
		"<!entity", "xxe", "xml external", "system \"file:", "doctype",
	}},
	{Skill: "upload-insecure-files", Weight: 7, Patterns: []string{
		"multipart/form-data", "file upload", ".php", "content-type: image",
		"webshell", "upload path",
	}},
	{Skill: "cors-cross-origin-misconfiguration", Weight: 6, Patterns: []string{
		"access-control-allow-origin", "access-control-allow-credentials", "cors",
	}},
	// CVE / scanner track: keep high enough that pure nuclei CVE lists do not top business-logic.
	{Skill: "unauthorized-access-common-services", Weight: 9, Patterns: []string{
		"cve-20", "[cve-", "cve_id", "known cve", "nuclei-templates",
	}},
	{Skill: "recon-and-methodology", Weight: 3, Patterns: []string{
		"subdomain", "open ports", "tech stack", "fingerprint", "katana", "ffuf", "nuclei",
	}},
	{Skill: "bug-bounty", Weight: 2, Patterns: []string{
		"bug bounty", "src ", "赏金", "资产范围", "in-scope",
	}},
}

// ParamNameSkillHints maps query/body parameter name fragments → skill (round-2/4 heuristics).
// Matched against tool arguments JSON / output as whole-word-ish substrings.
var ParamNameSkillHints = []struct {
	ParamFrag string
	Skill     string
	Weight    int
}{
	// IDOR: only clear cross-user object keys (lower weight than payment business-logic).
	{"user_id", "idor-broken-object-authorization", 5},
	{"account_id", "idor-broken-object-authorization", 5},
	// order_id alone is payment lifecycle → business-logic (not idor); idor needs user/victim context in rules.
	{"\"id\"", "idor-broken-object-authorization", 3},
	{"\"id\":", "idor-broken-object-authorization", 3},
	{"id=", "idor-broken-object-authorization", 3},
	{`param":"id`, "sqli-sql-injection", 5},
	{"file=", "path-traversal-lfi", 7},
	{"filepath", "path-traversal-lfi", 7},
	{"filename", "path-traversal-lfi", 5},
	{"path=", "path-traversal-lfi", 5},
	{"\"path\"", "path-traversal-lfi", 5},
	{"url=", "ssrf-server-side-request-forgery", 7},
	{"\"url\"", "ssrf-server-side-request-forgery", 6},
	{"redirect", "open-redirect", 6},
	{"return_url", "open-redirect", 6},
	{"next=", "open-redirect", 5},
	{"\"q\"", "xss-cross-site-scripting", 4},
	{"q=", "xss-cross-site-scripting", 3},
	{"search", "xss-cross-site-scripting", 3},
	{"keyword", "xss-cross-site-scripting", 3},
	{"token", "jwt-oauth-token-attacks", 5},
	{"jwt", "jwt-oauth-token-attacks", 7},
	{"access_token", "jwt-oauth-token-attacks", 6},
	// payment callback/notify → business-logic (not bare SSRF); keep generic callback lower for SSRF elsewhere
	{"callback", "business-logic-vulnerabilities", 7},
	{"notify", "business-logic-vulnerabilities", 7},
	{"template", "ssti-server-side-template-injection", 6},
	// Business/Backend Logic Track — high weight payment & workflow params
	{"price", "business-logic-vulnerabilities", 10},
	{"amount", "business-logic-vulnerabilities", 10},
	{"total_fee", "business-logic-vulnerabilities", 10},
	{"out_trade_no", "business-logic-vulnerabilities", 9},
	{"trade_status", "business-logic-vulnerabilities", 9},
	{"quantity", "business-logic-vulnerabilities", 8},
	{"coupon", "business-logic-vulnerabilities", 10},
	{"discount", "business-logic-vulnerabilities", 9},
	{"balance", "business-logic-vulnerabilities", 8},
	{"credit", "business-logic-vulnerabilities", 7},
	{"wallet", "business-logic-vulnerabilities", 8},
	{"checkout", "business-logic-vulnerabilities", 10},
	{"payment", "business-logic-vulnerabilities", 10},
	{"refund", "business-logic-vulnerabilities", 9},
	{"transfer", "business-logic-vulnerabilities", 8},
	{"withdraw", "business-logic-vulnerabilities", 8},
	{"redeem", "business-logic-vulnerabilities", 8},
	{"invite", "business-logic-vulnerabilities", 6},
	{"refer", "business-logic-vulnerabilities", 6},
	{"gift", "business-logic-vulnerabilities", 6},
	{"cart", "business-logic-vulnerabilities", 8},
	{"order_id", "business-logic-vulnerabilities", 7},
	{"order_status", "business-logic-vulnerabilities", 8},
	{"confirm_step", "business-logic-vulnerabilities", 7},
	{"step=", "business-logic-vulnerabilities", 6},
	{"\"step\"", "business-logic-vulnerabilities", 6},
	{"\"paid\"", "business-logic-vulnerabilities", 8},
	{"point", "business-logic-vulnerabilities", 6},
}

// webEntryTools weakly suggest recon/bug-bounty when no strong skill signal.
var webEntryTools = map[string]struct{}{
	"http-framework-test": {},
	"katana":              {},
	"ffuf":                {},
	"nuclei":              {},
	"arjun":               {},
	"sqlmap":              {},
	"dalfox":              {},
	"exec":                {},
	"execute-python-script": {},
	"waybackurls":         {},
	"gau":                 {},
	"logic_probe_diff":    {},
}

// logicAwareTools may receive weak/medium business-logic injection when output looks like business JSON
// and lacks strong SQL/RCE scanner signals (Logic Track M1).
var logicAwareTools = map[string]struct{}{
	"http-framework-test":   {},
	"execute-python-script": {},
	"logic_probe_diff":      {},
	"exec":                  {},
}

// strongInjectionSignal reports SQL/RCE-like fingerprints that should dominate over logic track.
func strongInjectionSignal(hay string) bool {
	needles := []string{
		"sql syntax", "you have an error in your sql", "sqlstate", "union select",
		"information_schema", "mysql_fetch", "sleep(", "waitfor delay",
		"uid=", "gid=", "/bin/sh", "command injection", "runtime.exec",
		"cve-20", "[cve-", "nuclei-templates",
	}
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// looksLikeBusinessJSON detects order/price/coupon-style API JSON without requiring full parse.
func looksLikeBusinessJSON(s string) bool {
	low := strings.ToLower(s)
	if !strings.Contains(low, "{") || !strings.Contains(low, "}") {
		return false
	}
	keys := []string{
		"\"price\"", "\"amount\"", "\"quantity\"", "\"coupon\"", "\"discount\"",
		"\"balance\"", "\"order_id\"", "\"orderid\"", "\"cart\"", "\"checkout\"",
		"\"payment\"", "\"refund\"", "\"total\"", "\"sku\"", "\"inventory\"",
	}
	hits := 0
	for _, k := range keys {
		if strings.Contains(low, k) {
			hits++
		}
	}
	return hits >= 1
}

// SkillRouterInput is the pure-function input for routing.
type SkillRouterInput struct {
	ToolName   string
	Arguments  string
	Output     string
	Rules      []SkillSignalRule // nil → DefaultSkillSignalRules
	TopK       int               // default 3
	MaxRunes   int               // total budget for tips block
	SkillsRoot string            // absolute path to skills/
	// AlreadyInjected skill directory names already shown this conversation (dedupe).
	AlreadyInjected map[string]struct{}
	// SkillTipsLoader optional; tests inject fixed tips. Default reads SKILL.md.
	SkillTipsLoader func(skillsRoot, skillDir string, maxRunes int) string
}

// SkillRouterResult is the routing outcome.
type SkillRouterResult struct {
	Skills   []string // skill directory names selected
	Block    string   // text to append to tool result (may be empty)
	Injected []string // skills actually included in Block
}

// RouteSkills matches signals and builds an injection block for the model's next turn.
func RouteSkills(in SkillRouterInput) SkillRouterResult {
	rules := in.Rules
	if len(rules) == 0 {
		rules = DefaultSkillSignalRules
	}
	topK := in.TopK
	if topK <= 0 {
		topK = 3
	}
	maxRunes := in.MaxRunes
	if maxRunes <= 0 {
		maxRunes = 3500
	}
	loader := in.SkillTipsLoader
	if loader == nil {
		loader = loadSkillTipsFromDisk
	}

	hay := strings.ToLower(in.ToolName + "\n" + in.Arguments + "\n" + in.Output)
	type scored struct {
		skill string
		score int
	}
	var hits []scored
	seenHit := map[string]struct{}{}
	addHit := func(skill string, score int) {
		skill = strings.TrimSpace(skill)
		if skill == "" || score <= 0 {
			return
		}
		if in.AlreadyInjected != nil {
			if _, done := in.AlreadyInjected[skill]; done {
				return
			}
		}
		if _, ok := seenHit[skill]; ok {
			// upgrade score if higher
			for i := range hits {
				if hits[i].skill == skill && score > hits[i].score {
					hits[i].score = score
				}
			}
			return
		}
		hits = append(hits, scored{skill: skill, score: score})
		seenHit[skill] = struct{}{}
	}
	for _, r := range rules {
		skill := strings.TrimSpace(r.Skill)
		if skill == "" {
			continue
		}
		score := 0
		for _, p := range r.Patterns {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if strings.Contains(hay, p) {
				score += r.Weight
			}
		}
		if score > 0 {
			addHit(skill, score)
		}
	}
	// Param-name heuristics (id/file/url/path/redirect/q/search/token/jwt/price/coupon …)
	argHay := strings.ToLower(in.Arguments + "\n" + in.ToolName)
	for _, h := range ParamNameSkillHints {
		frag := strings.ToLower(h.ParamFrag)
		if frag == "" {
			continue
		}
		if strings.Contains(argHay, frag) || strings.Contains(hay, frag) {
			addHit(h.Skill, h.Weight)
		}
	}
	// Weak～medium business-logic for logic-aware tools with business JSON and no strong inject/CVE.
	tn := normalizeToolBaseName(in.ToolName)
	if _, ok := logicAwareTools[tn]; ok && !strongInjectionSignal(hay) && looksLikeBusinessJSON(in.Output+"\n"+in.Arguments) {
		addHit("business-logic-vulnerabilities", 6)
	}
	// Strong SQL/RCE/CVE fingerprints dominate the business track (scanner vs business split).
	// Prevent incidental "price" in the same blob from topping over real injection signals.
	if strongInjectionSignal(hay) {
		for i := range hits {
			switch hits[i].skill {
			case "sqli-sql-injection", "cmdi-command-injection", "unauthorized-access-common-services":
				hits[i].score += 25
			case "business-logic-vulnerabilities":
				if hits[i].score > 4 {
					hits[i].score = 4 // demote: inject wins Top1
				}
			}
		}
	}
	// Weak recon/bug-bounty for web-entry tools when no strong signal
	if len(hits) == 0 {
		if _, ok := webEntryTools[tn]; ok {
			addHit("recon-and-methodology", 2)
			addHit("bug-bounty", 1)
		}
	}
	// sort by score desc (stable simple selection)
	for i := 0; i < len(hits); i++ {
		for j := i + 1; j < len(hits); j++ {
			if hits[j].score > hits[i].score {
				hits[i], hits[j] = hits[j], hits[i]
			}
		}
	}
	if len(hits) > topK {
		hits = hits[:topK]
	}

	out := SkillRouterResult{Skills: make([]string, 0, len(hits))}
	for _, h := range hits {
		out.Skills = append(out.Skills, h.skill)
	}
	if len(hits) == 0 {
		return out
	}

	var b strings.Builder
	b.WriteString("\n\n## [SkillRouter] 自动触达要点（框架注入，非用户消息）\n")
	b.WriteString("根据本轮工具输出信号匹配到下列 skill；优先按要点继续验证，勿忽略差分/报错特征。\n")
	remaining := maxRunes - len([]rune(b.String()))
	for _, h := range hits {
		if remaining <= 80 {
			break
		}
		perBudget := remaining / (len(hits) - len(out.Injected))
		// Per-skill budget cap. When only one skill matches (common for the
		// DecisionController topK=1 path) the previous hard cap of 1200 left
		// most of the 4000-rune total budget unused and truncated core
		// methodology buried later in the skill file (e.g. SQLi boolean-blind
		// pairing). Raise the single-skill cap so the full methodology is
		// visible; keep a tighter cap when several skills share the budget.
		singleSkill := len(hits) == 1
		perSkillCap := 2400
		if singleSkill {
			perSkillCap = remaining // use all remaining budget for the lone skill
		}
		if perBudget > perSkillCap {
			perBudget = perSkillCap
		}
		if perBudget < 120 {
			perBudget = 120
		}
		tips := strings.TrimSpace(loader(in.SkillsRoot, h.skill, perBudget))
		if tips == "" {
			continue
		}
		section := "### skill: " + h.skill + "\n" + tips + "\n"
		secRunes := len([]rune(section))
		if secRunes > remaining {
			section = truncateRunes(section, remaining-20) + "…\n"
			secRunes = len([]rune(section))
		}
		b.WriteString(section)
		remaining -= secRunes
		out.Injected = append(out.Injected, h.skill)
	}
	if len(out.Injected) == 0 {
		return SkillRouterResult{Skills: out.Skills}
	}
	out.Block = b.String()
	return out
}

var (
	skillTipsCacheMu sync.Mutex
	skillTipsCache   = map[string]string{}
)

func loadSkillTipsFromDisk(skillsRoot, skillDir string, maxRunes int) string {
	root := strings.TrimSpace(skillsRoot)
	if root == "" || skillDir == "" {
		return ""
	}
	// prevent path escape
	if strings.Contains(skillDir, "..") || strings.ContainsAny(skillDir, `/\`) {
		return ""
	}
	path := filepath.Join(root, skillDir, "SKILL.md")
	skillTipsCacheMu.Lock()
	if cached, ok := skillTipsCache[path]; ok {
		skillTipsCacheMu.Unlock()
		return truncateRunes(cached, maxRunes)
	}
	skillTipsCacheMu.Unlock()

	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	tips := extractSkillTips(string(raw), 3000)
	skillTipsCacheMu.Lock()
	skillTipsCache[path] = tips
	skillTipsCacheMu.Unlock()
	return truncateRunes(tips, maxRunes)
}

// extractSkillTips strips YAML frontmatter and keeps the first actionable sections.
// For business-logic skill content, prefer payment/workflow/race first-pass over pure IDOR sections.
func extractSkillTips(md string, maxRunes int) string {
	s := strings.TrimSpace(md)
	if strings.HasPrefix(s, "---") {
		if end := strings.Index(s[3:], "\n---"); end >= 0 {
			s = strings.TrimSpace(s[3+end+4:])
		}
	}
	// Business/Backend Logic Track: bias toward payment/price/workflow/race paragraphs.
	if prefer := preferBusinessLogicFirstPass(s, maxRunes); prefer != "" {
		return prefer
	}
	// Drop very long code fences beyond first few by taking early lines preferentially.
	lines := strings.Split(s, "\n")
	var kept []string
	codeBlocks := 0
	inCode := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "```") {
			if !inCode {
				codeBlocks++
				if codeBlocks > 3 {
					inCode = true
					continue
				}
			}
			inCode = !inCode
			if codeBlocks > 3 && inCode {
				continue
			}
		}
		if codeBlocks > 3 && inCode {
			continue
		}
		kept = append(kept, line)
		if len([]rune(strings.Join(kept, "\n"))) >= maxRunes {
			break
		}
	}
	out := strings.TrimSpace(strings.Join(kept, "\n"))
	if idx := regexp.MustCompile(`(?m)^##\s+[5-9]\.`).FindStringIndex(out); idx != nil && idx[0] > 200 {
		out = strings.TrimSpace(out[:idx[0]])
	}
	out = truncateRunes(out, maxRunes)
	// Snap a hard cut to the last complete `## ` heading boundary so we don't
	// leave a methodology sentence dangling mid-way. If the truncated tail is
	// long enough to matter, drop the partial final section.
	if len([]rune(out)) >= maxRunes {
		lastHeading := strings.LastIndex(out, "\n## ")
		if lastHeading > maxRunes/2 {
			out = strings.TrimSpace(out[:lastHeading])
		}
	}
	return out
}

// preferBusinessLogicFirstPass extracts payment/workflow/race checklist lines when present.
func preferBusinessLogicFirstPass(md string, maxRunes int) string {
	low := strings.ToLower(md)
	// Only apply bias when document is clearly the business-logic playbook.
	if !strings.Contains(low, "price") && !strings.Contains(low, "coupon") &&
		!strings.Contains(low, "workflow") && !strings.Contains(low, "race") &&
		!strings.Contains(low, "payment") && !strings.Contains(low, "业务") {
		return ""
	}
	keywords := []string{
		"price", "amount", "payment", "checkout", "coupon", "discount", "race",
		"workflow", "skip", "parallel", "status", "paid", "refund", "quantity",
		"支付", "金额", "优惠券", "流程", "竞态", "跳步", "信任客户端", "回调",
	}
	lines := strings.Split(md, "\n")
	var scored []string
	var head []string
	for i, line := range lines {
		if i < 40 {
			head = append(head, line)
		}
		ll := strings.ToLower(line)
		for _, k := range keywords {
			if strings.Contains(ll, k) {
				scored = append(scored, line)
				break
			}
		}
		if len(scored) >= 35 {
			break
		}
	}
	if len(scored) < 5 {
		return ""
	}
	// Prefixed orientation line for the model (R5 product copy).
	var b strings.Builder
	b.WriteString("【Business/Backend Logic Track first-pass】优先：金额/数量篡改 → 流程跳步 → 券/积分滥用 → 竞态/重复回调 → 信任客户端 status/paid；")
	b.WriteString("双号 identity_diff 仅用于跨账号越权（可选，非入场条件）。\n")
	b.WriteString(strings.Join(head[:minInt(12, len(head))], "\n"))
	b.WriteString("\n")
	b.WriteString(strings.Join(scored, "\n"))
	return truncateRunes(strings.TrimSpace(b.String()), maxRunes)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
