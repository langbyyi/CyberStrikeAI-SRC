package security

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// SensitiveHTTPGate classifies irreversible or high-impact HTTP writes. The
// Executor only lets a classified call pass when Context carries an internal,
// exact-argument approval Grant; no model-visible argument can unlock it.

var (
	reHTTPURL = regexp.MustCompile(`(?i)https?://[^\s"'<>\\]+`)
	// Path segments / actions that look like data destruction or critical control-plane ops.
	// Allow camelCase/suffixes (delOne, delBatchOnes, execPowerOff).
	reDestructivePath = regexp.MustCompile(`(?i)(^|/)(` +
		`delete[a-z0-9_]*|del[_-]?one[a-z0-9_]*|delones?|del[_-]?batch[a-z0-9_]*|` +
		`remove[a-z0-9_]*|purge[a-z0-9_]*|destroy[a-z0-9_]*|unlink|rmdir|` +
		`drop(?:_?table|_?database|_?db)?|truncate|` +
		`shutdown|reboot|poweroff|halt|` +
		// Avoid bare "restart" (matches /restart-job); only host/OS style names.
		`restart(?:server|host|system|service|os)[a-z0-9_]*|` +
		`execpoweroff|execreboot|execcontainerpoweroff|execcontainerreboot|execpower[a-z0-9_]*|execreboot[a-z0-9_]*|` +
		`format|wipe|factory.?reset|` +
		`resetpassword|changepassword|resetpwd|changepwd|` +
		`deleteuser|disableuser|lockuser|` +
		`kill(?:proc|process)?` +
		`)([/?#._-]|$)`)
	reWriteMethodHint = regexp.MustCompile(`(?i)(` +
		`-X\s*(DELETE|PUT|PATCH|POST)|` +
		`--request\s*(DELETE|PUT|PATCH|POST)|` +
		`method\s*[=:]\s*['"]?(DELETE|PUT|PATCH|POST)|` +
		`requests\.(delete|put|patch|post)\s*\(|` +
		`httpx\.(delete|put|patch|post)\s*\(|` +
		`\.(delete|put|patch|post)\s*\(\s*['"]https?://` +
		`)`)
	reReadMethodHint = regexp.MustCompile(`(?i)(` +
		`-X\s*(GET|HEAD|OPTIONS)|` +
		`--request\s*(GET|HEAD|OPTIONS)|` +
		`method\s*[=:]\s*['"]?(GET|HEAD|OPTIONS)|` +
		`requests\.(get|head|options)\s*\(|` +
		`httpx\.(get|head|options)\s*\(` +
		`)`)
)

// SensitiveHTTPAssessment is the gate decision payload.
type SensitiveHTTPAssessment struct {
	Blocked  bool
	ToolName string
	Method   string
	Target   string
	Reason   string
	Message  string
}

// CheckSensitiveHTTPGate inspects a tool invocation before real execution.
// Returns (blocked, user-visible message). Message is empty when not blocked.
func CheckSensitiveHTTPGate(toolName string, args map[string]interface{}) (bool, string) {
	a := AssessSensitiveHTTP(toolName, args)
	if !a.Blocked {
		return false, ""
	}
	return true, a.Message
}

// AssessSensitiveHTTP classifies the call and builds a block message when needed.
func AssessSensitiveHTTP(toolName string, args map[string]interface{}) SensitiveHTTPAssessment {
	toolName = strings.TrimSpace(toolName)
	if args == nil {
		args = map[string]interface{}{}
	}

	method, target, reason := extractSensitiveHTTPRisk(toolName, args)
	out := SensitiveHTTPAssessment{
		ToolName: toolName,
		Method:   method,
		Target:   target,
		Reason:   reason,
	}
	if reason == "" || target == "" {
		return out
	}

	// Explicit read-only HTTP method on a sensitive path is allowed (recon of the endpoint).
	if isReadHTTPMethod(method) && !isCriticalEvenOnGET(reason) {
		return out
	}

	out.Blocked = true
	out.Message = formatSensitiveHTTPBlockMessage(out)
	return out
}

func extractSensitiveHTTPRisk(toolName string, args map[string]interface{}) (method, target, reason string) {
	switch normalizeToolKey(toolName) {
	case "http-framework-test", "http_framework_test":
		method = strings.ToUpper(strings.TrimSpace(strFromArgs(args, "method")))
		if method == "" {
			method = "GET"
		}
		target = strings.TrimSpace(strFromArgs(args, "url"))
		if target == "" {
			return method, "", ""
		}
		if hit := matchDestructivePath(target); hit != "" {
			// Write methods always block. GET only for critical control-plane paths.
			if isWriteHTTPMethod(method) || isCriticalPathHit(hit) {
				return method, target, "path:" + hit
			}
			return method, target, ""
		}
		// Any DELETE is treated as high-impact even without a keyworded path.
		if method == "DELETE" {
			return method, target, "method:DELETE"
		}
		return method, target, ""
	}

	// exec / execute-python-script / free-form command or script bodies
	blob := collectToolTextBlob(args)
	if blob == "" {
		return "", "", ""
	}
	if !looksLikeHTTPTransport(blob) {
		return "", "", ""
	}

	method = inferHTTPMethodFromText(blob)
	targets := collectHTTPTargets(blob)
	for _, t := range targets {
		if hit := matchDestructivePath(t); hit != "" {
			// Prefer write method if present; destructive path + any non-read also blocks.
			if isWriteHTTPMethod(method) || method == "" || !isReadHTTPMethod(method) {
				if method == "" {
					method = "WRITE?"
				}
				return method, t, "path:" + hit
			}
		}
	}
	// Free-form DELETE to any URL (curl -X DELETE …)
	if method == "DELETE" && len(targets) > 0 {
		return method, targets[0], "method:DELETE"
	}
	return method, "", ""
}

func collectToolTextBlob(args map[string]interface{}) string {
	keys := []string{"command", "script", "script_content", "code", "body", "data", "url", "raw", "payload"}
	parts := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		if v := strFromArgs(args, k); v != "" {
			parts = append(parts, v)
		}
	}
	// Fallback: whole args JSON (covers unusual param names).
	if b, err := json.Marshal(args); err == nil {
		parts = append(parts, string(b))
	}
	return strings.Join(parts, "\n")
}

func looksLikeHTTPTransport(s string) bool {
	lower := strings.ToLower(s)
	indicators := []string{
		"curl ", "wget ", "httpx", "requests.", "urllib", "http.client",
		"aiohttp", "httpx.", "fetch(", "https://", "http://",
		"application/json", "content-type",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func collectHTTPTargets(blob string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(t string) {
		t = strings.TrimSpace(t)
		t = strings.TrimRight(t, `"'>,);`)
		if t == "" {
			return
		}
		key := strings.ToLower(t)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, t)
	}
	for _, m := range reHTTPURL.FindAllString(blob, 32) {
		add(m)
	}
	// Also scan bare paths that include destructive keywords.
	for _, line := range strings.Split(blob, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/") && matchDestructivePath(line) != "" {
			add(line)
		}
	}
	return out
}

func inferHTTPMethodFromText(blob string) string {
	lower := strings.ToLower(blob)
	// Explicit write hints first.
	if reWriteMethodHint.FindStringSubmatch(blob) != nil {
		m := reWriteMethodHint.FindStringSubmatch(blob)
		for i := len(m) - 1; i >= 1; i-- {
			if m[i] != "" {
				return strings.ToUpper(m[i])
			}
		}
	}
	if reReadMethodHint.MatchString(blob) {
		return "GET"
	}
	// curl without -X defaults to GET unless body flags present.
	if strings.Contains(lower, "curl ") {
		if strings.Contains(lower, " -d ") || strings.Contains(lower, "--data") ||
			strings.Contains(lower, "--json") || strings.Contains(lower, "-t ") {
			return "POST"
		}
		return "GET"
	}
	if strings.Contains(lower, "requests.post") || strings.Contains(lower, "httpx.post") {
		return "POST"
	}
	return ""
}

func matchDestructivePath(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// Prefer URL path when present.
	if u, err := url.Parse(s); err == nil && u.Path != "" {
		s = u.Path
		if u.RawQuery != "" {
			s = s + "?" + u.RawQuery
		}
	}
	m := reDestructivePath.FindStringSubmatch(s)
	if m == nil {
		// Also try full string (relative paths embedded in scripts).
		m = reDestructivePath.FindStringSubmatch(raw)
	}
	if m == nil {
		return ""
	}
	for i := 1; i < len(m); i++ {
		if m[i] != "" && !strings.HasPrefix(m[i], "/") && m[i] != "?" {
			return strings.ToLower(m[i])
		}
	}
	return "destructive_path"
}

func isWriteHTTPMethod(m string) bool {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func isReadHTTPMethod(m string) bool {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

// Critical control-plane paths are blocked even on GET (e.g. GET /execPowerOff).
func isCriticalEvenOnGET(reason string) bool {
	return isCriticalPathHit(strings.TrimPrefix(strings.ToLower(reason), "path:"))
}

func isCriticalPathHit(hit string) bool {
	r := strings.ToLower(hit)
	for _, k := range []string{
		"shutdown", "reboot", "poweroff", "halt", "execpower", "execreboot",
		"execcontainer", "format", "wipe", "factory", "drop", "truncate",
	} {
		if strings.Contains(r, k) {
			return true
		}
	}
	return false
}

func formatSensitiveHTTPBlockMessage(a SensitiveHTTPAssessment) string {
	return fmt.Sprintf(
		"[sensitive_http_gate] blocked\n"+
			"检测到可能不可逆或高影响的 HTTP 写操作，当前执行上下文没有与该工具及参数完全匹配的内部审批授权，已阻止真实发送。\n\n"+
			"tool: %s\nmethod: %s\ntarget: %s\nreason: %s",
		a.ToolName, a.Method, a.Target, a.Reason,
	)
}

func strFromArgs(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		// numbers etc.
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func normalizeToolKey(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	}
	if i := strings.LastIndex(name, "::"); i >= 0 {
		name = name[i+2:]
	}
	return name
}
