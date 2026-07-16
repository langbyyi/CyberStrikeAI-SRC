package multiagent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SurfaceSignal is a high-value attack-surface clue extracted from tool output.
// Designed for multi-scenario pentest (Web/API/cloud/config/info-leak), not a single product.
// Used by execution_boost to open coverage and force dig+record decisions without relying on the LLM alone.
type SurfaceSignal struct {
	Kind     string   // stable taxonomy — see SurfaceKind* constants
	Label    string   // short human label (locale-neutral description)
	Paths    []string // concrete paths/resources when extractable
	Priority string   // P0 | P1 | P2
}

// Surface kind taxonomy (scenario-agnostic).
const (
	SurfaceKindAPIInventory   = "api_inventory"   // service lists, OpenAPI, GraphQL schema, WSDL
	SurfaceKindDebugEntry     = "debug_entry"     // actuator, phpinfo, server-status, debug consoles
	SurfaceKindInfoDisclosure = "info_disclosure" // stack traces, verbose errors, version banners
	SurfaceKindVCSExposure    = "vcs_exposure"    // .git / source maps / backup dumps
	SurfaceKindDirListing     = "dir_listing"     // open directory indexes
	SurfaceKindCloudMeta      = "cloud_meta"      // cloud metadata / IAM material hints
	SurfaceKindSecretLeak     = "secret_leak"     // keys/tokens in tool output
	SurfaceKindEndpointList   = "endpoint_list"   // explicit endpoint lines without full inventory banner
)

var (
	// --- API / service inventory (framework-agnostic fingerprints) ---
	// No product-specific brand hardcoding: match generic inventory/schema/list patterns only.
	reAPIInventory = regexp.MustCompile(`(?i)` + strings.Join([]string{
		`swagger[-_ ]?ui`,
		`openapi\.json`,
		`/v[23]/api-docs`,
		`"openapi"\s*:\s*"3\.`,
		`swagger\s*:\s*['"]?2\.`,
		`__schema`,
		`graphql\s*introspection|introspectionquery|__typename`,
		`"data"\s*:\s*\{\s*"__schema"`,
		`<definitions[^>]+xmlns[^=]*=.*wsdl`,
		`wsdl:definitions`,
		`list of operations`,
		`available\s+services`,
		`service\s+list`,
		`services?\s+list`,
		`exposed\s+services?`,
		`api\s+catalog`,
		`api\s+inventory`,
	}, "|"))

	// Explicit endpoint labels only — bare "path=/foo" from scanner dumps is NOT an exposure.
	reEndpointLine = regexp.MustCompile(`(?i)(?:endpoint|服务端点|rest\s*endpoint|operation)\s*[:：=]\s*(/[^\s"'<>]{1,120})`)
	// Paths commonly emitted by inventories (not only /api/). Used only after a strong inventory banner.
	reInventoryPath = regexp.MustCompile(`(?i)(/(?:api|v[0-9]+|rest|graphql|services?|actuator)[a-z0-9_./-]{0,80})`)

	// --- Debug / management entries (body-oriented; path-only scans filtered separately) ---
	reDebugEntry = regexp.MustCompile(`(?i)` + strings.Join([]string{
		`phpinfo\s*\(`,
		`<title>phpinfo`,
		`server-status`,
		`server-info`,
		`wp-json/wp/v2`,
		`drupal\.settings`,
		`console\.log\s*\(\s*['"]DEBUG`,
		`debug\s*=\s*true`,
		`django\.debug`,
		`werkzeug debugger`,
		`spring boot admin`,
		// Real Actuator JSON/body — not mere "/actuator" in a path list.
		`"_links"\s*:\s*\{[^}]{0,200}actuator`,
		`"status"\s*:\s*"UP"`,
		`/actuator/env`,
		`/actuator/health`,
	}, "|"))

	// --- Info disclosure ---
	reInfoDisclosure = regexp.MustCompile(`(?i)` + strings.Join([]string{
		`exception report`,
		`stack trace`,
		`traceback \(most recent`,
		`java\.[a-z0-9_.]+exception`,
		`org\.apache\.catalina`,
		`microsoft ole db`,
		`odbc driver`,
		`mysql_fetch`,
		`pg_query`,
		`sqlite3\.operationalerror`,
		`fatal error:`,
		`warning:.*on line`,
		`apache tomcat/[0-9]`,
		`nginx/[0-9]`,
		`iis/[0-9]`,
		`x-powered-by:`,
		`server:.*tomcat`,
	}, "|"))

	// --- VCS / backup / source (content fingerprints, not "path=/.git/HEAD" probe lists) ---
	reVCS = regexp.MustCompile(`(?i)` + strings.Join([]string{
		`\[core\]`, // .git/config body
		`ref: refs/heads`,
		`Index of /\.git`,
		`repositoryformatversion\s*=`,
		`APP_KEY=`,
		`DB_PASSWORD=`,
	}, "|"))

	// --- Directory listing ---
	reDirListing = regexp.MustCompile(`(?i)index of /|directory listing for |\[to parent directory\]|<title>index of`)

	// --- Cloud / secret material (strong, multi-scenario) ---
	reCloudMeta  = regexp.MustCompile(`(?i)169\.254\.169\.254|latest/meta-data|iam/security-credentials|metadata\.google\.internal|computemetadata`)
	reSecretLeak = regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.|xox[baprs]-[0-9a-zA-Z-]{10,}`)
)

// prepareSurfaceDetectionText strips scanner bookkeeping that mentions sensitive paths
// without proving exposure (interesting_params dumps, 412 WAF probe rows).
func prepareSurfaceDetectionText(output string) string {
	out := strings.TrimSpace(output)
	if out == "" {
		return ""
	}
	lines := strings.Split(out, "\n")
	keep := make([]string, 0, len(lines))
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		low := strings.ToLower(trim)
		// Structured summary path dumps from probes (not response bodies).
		if strings.HasPrefix(low, "interesting_params:") {
			continue
		}
		// Bulk path-probe rows that are clearly blocked (WAF 412 / has_waf), not real content.
		if surfaceLineIsBlockedProbe(low) {
			continue
		}
		keep = append(keep, line)
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}

func surfaceLineIsBlockedProbe(low string) bool {
	if low == "" {
		return false
	}
	blocked := strings.Contains(low, "412") ||
		strings.Contains(low, "访问被阻断") ||
		strings.Contains(low, "precondition failed") ||
		strings.Contains(low, "has_waf true") ||
		strings.Contains(low, "has_git false") ||
		strings.Contains(low, "waf412")
	if !blocked {
		return false
	}
	// Only drop lines that look like path probe records, not full HTML responses with mixed content.
	return strings.Contains(low, "path=") ||
		strings.Contains(low, "/.git") ||
		strings.Contains(low, "/actuator") ||
		strings.Contains(low, "==== /") ||
		strings.HasPrefix(low, "get /") ||
		strings.Contains(low, "status 412") ||
		strings.Contains(low, "status=412")
}

// isDeniedScanInventory reports bulk path-scan dumps dominated by WAF denials,
// which must not mint record obligations (real hunting still works via confirmed bodies).
func isDeniedScanInventory(out string) bool {
	low := strings.ToLower(out)
	denyMarks := 0
	for _, m := range []string{"412", "访问被阻断", "precondition failed", "has_waf true", "waf412", "securityfs"} {
		if strings.Contains(low, m) {
			denyMarks++
		}
	}
	pathMarks := strings.Count(low, "path=") + strings.Count(low, "/.git") + strings.Count(low, "/actuator") +
		strings.Count(low, "==== /")
	if denyMarks >= 2 && pathMarks >= 2 {
		return true
	}
	if strings.Contains(low, "has_git false") && strings.Contains(low, "has_waf true") {
		return true
	}
	return false
}

// hasConfirmedExposureBody keeps high-value true positives inside otherwise noisy dumps
// (real .git body, real OpenAPI/schema inventory body, secrets, cloud metadata).
func hasConfirmedExposureBody(out string) bool {
	low := strings.ToLower(out)
	if strings.Contains(out, "ref: refs/heads") || strings.Contains(out, "[core]") ||
		strings.Contains(low, "repositoryformatversion") {
		return true
	}
	if strings.Contains(out, `"openapi"`) && (strings.Contains(out, `"paths"`) || strings.Contains(out, `"3.`)) {
		return true
	}
	if reAPIInventory.MatchString(out) && !strings.Contains(low, "访问被阻断") {
		return true
	}
	if reSecretLeak.MatchString(out) || reCloudMeta.MatchString(out) {
		return true
	}
	if strings.Contains(low, "phpinfo()") || strings.Contains(low, "werkzeug debugger") {
		return true
	}
	return false
}

// DetectSurfaceSignals extracts scenario-agnostic high-value surface signals from tool output.
func DetectSurfaceSignals(output string) []SurfaceSignal {
	out := prepareSurfaceDetectionText(output)
	if out == "" {
		return nil
	}
	// Pure WAF/path-inventory dumps: only keep confirmed body exposures.
	if isDeniedScanInventory(out) && !hasConfirmedExposureBody(out) {
		return nil
	}
	var sigs []SurfaceSignal
	seenKind := map[string]bool{}
	seenPath := map[string]bool{}

	addPath := func(p string) {
		p = strings.TrimSpace(p)
		p = strings.TrimRight(p, ".,;)]}>\"'")
		if p == "" || !strings.HasPrefix(p, "/") {
			return
		}
		low := strings.ToLower(p)
		if strings.HasSuffix(low, ".css") || strings.HasSuffix(low, ".js") ||
			strings.HasSuffix(low, ".png") || strings.HasSuffix(low, ".jpg") ||
			strings.HasSuffix(low, ".ico") || strings.HasSuffix(low, ".woff") {
			return
		}
		if seenPath[low] {
			return
		}
		// Cap path noise
		if len(seenPath) >= 40 {
			return
		}
		seenPath[low] = true
	}

	collectPaths := func() []string {
		for _, m := range reEndpointLine.FindAllStringSubmatch(out, 30) {
			if len(m) > 1 {
				addPath(m[1])
			}
		}
		for _, m := range reInventoryPath.FindAllStringSubmatch(out, 40) {
			if len(m) > 1 {
				addPath(m[1])
			}
		}
		var paths []string
		for p := range seenPath {
			paths = append(paths, p)
		}
		return paths
	}

	// Priority order: stronger / more specific kinds first.
	if reAPIInventory.MatchString(out) && !seenKind[SurfaceKindAPIInventory] {
		// Ignore inventory keywords that only appear inside WAF block pages.
		low := strings.ToLower(out)
		if !strings.Contains(low, "访问被阻断") || hasConfirmedExposureBody(out) {
			paths := collectPaths()
			sigs = append(sigs, SurfaceSignal{
				Kind:     SurfaceKindAPIInventory,
				Label:    "API/服务清单或 schema 暴露",
				Paths:    paths,
				Priority: "P1",
			})
			seenKind[SurfaceKindAPIInventory] = true
		}
	}
	if !seenKind[SurfaceKindAPIInventory] && !seenKind[SurfaceKindEndpointList] {
		// Explicit "Endpoint: /api/..." lines only (not scanner path= dumps).
		for _, m := range reEndpointLine.FindAllStringSubmatch(out, 20) {
			if len(m) > 1 {
				addPath(m[1])
			}
		}
		if len(seenPath) > 0 {
			var paths []string
			for p := range seenPath {
				paths = append(paths, p)
			}
			sigs = append(sigs, SurfaceSignal{
				Kind:     SurfaceKindEndpointList,
				Label:    "显式 Endpoint/路径清单",
				Paths:    paths,
				Priority: "P1",
			})
			seenKind[SurfaceKindEndpointList] = true
		}
	}

	if reDebugEntry.MatchString(out) && !seenKind[SurfaceKindDebugEntry] {
		low := strings.ToLower(out)
		// Require body-level evidence; skip pure path catalogs.
		strong := strings.Contains(low, "phpinfo") || strings.Contains(low, "werkzeug") ||
			strings.Contains(low, "server-status") || strings.Contains(low, "debug=true") ||
			strings.Contains(low, `"status":"up"`) || strings.Contains(low, `"_links"`) ||
			strings.Contains(low, "spring boot admin") || strings.Contains(low, "wp-json/wp/v2")
		if strong {
			sigs = append(sigs, SurfaceSignal{
				Kind:     SurfaceKindDebugEntry,
				Label:    "调试/管理入口信号",
				Priority: "P1",
			})
			seenKind[SurfaceKindDebugEntry] = true
		}
	}

	if reVCS.MatchString(out) && !seenKind[SurfaceKindVCSExposure] {
		sigs = append(sigs, SurfaceSignal{
			Kind:     SurfaceKindVCSExposure,
			Label:    "源码/配置/VCS 暴露信号",
			Priority: "P0",
		})
		seenKind[SurfaceKindVCSExposure] = true
	}

	if reDirListing.MatchString(out) && !seenKind[SurfaceKindDirListing] {
		sigs = append(sigs, SurfaceSignal{
			Kind:     SurfaceKindDirListing,
			Label:    "目录列表暴露",
			Priority: "P1",
		})
		seenKind[SurfaceKindDirListing] = true
	}

	if reCloudMeta.MatchString(out) && !seenKind[SurfaceKindCloudMeta] {
		low := strings.ToLower(out)
		// Ignore SSRF probe argument echoes (url=http://169.254...) without metadata body.
		echoOnly := (strings.Contains(low, "url=http://169.254") || strings.Contains(low, "url=http://metadata.google")) &&
			!strings.Contains(low, "ami-") && !strings.Contains(low, "instance-id") &&
			!strings.Contains(low, "security-credentials") && !strings.Contains(low, "computemetadata")
		if !echoOnly {
			sigs = append(sigs, SurfaceSignal{
				Kind:     SurfaceKindCloudMeta,
				Label:    "云元数据/实例凭证面信号",
				Priority: "P0",
			})
			seenKind[SurfaceKindCloudMeta] = true
		}
	}

	if reSecretLeak.MatchString(out) && !seenKind[SurfaceKindSecretLeak] {
		sigs = append(sigs, SurfaceSignal{
			Kind:     SurfaceKindSecretLeak,
			Label:    "密钥/令牌泄露信号",
			Priority: "P0",
		})
		seenKind[SurfaceKindSecretLeak] = true
	}

	if reInfoDisclosure.MatchString(out) && !seenKind[SurfaceKindInfoDisclosure] {
		// Avoid marking every soft 400; require exception/stack/version fingerprint strength.
		low := strings.ToLower(out)
		strongInfo := strings.Contains(low, "exception") || strings.Contains(low, "traceback") ||
			strings.Contains(low, "stack trace") || strings.Contains(low, "tomcat/") ||
			strings.Contains(low, "fatal error") || strings.Contains(low, "mysql_") ||
			strings.Contains(low, "odbc")
		if strongInfo {
			sigs = append(sigs, SurfaceSignal{
				Kind:     SurfaceKindInfoDisclosure,
				Label:    "敏感信息/错误页/版本指纹泄露",
				Priority: "P2",
			})
			seenKind[SurfaceKindInfoDisclosure] = true
		}
	}

	return sigs
}

// HasHighValueSurfaceSignal reports whether output contains reportable surface inventory/disclosure.
func HasHighValueSurfaceSignal(output string) bool {
	return len(DetectSurfaceSignals(output)) > 0
}

// SignalsFromSurfaceOutput adapts scenario-specific extraction into the generic
// execution-controller contract. Detection itself remains independent of scheduling.
func SignalsFromSurfaceOutput(target, output string) []ExecutionSignal {
	target = NormalizePrimaryTarget(target)
	surfaceSignals := DetectSurfaceSignals(output)
	if target == "" || len(surfaceSignals) == 0 {
		return nil
	}
	out := make([]ExecutionSignal, 0, len(surfaceSignals))
	for _, signal := range surfaceSignals {
		out = append(out, ExecutionSignal{
			Class:      signal.Kind,
			Target:     target,
			Resources:  append([]string(nil), signal.Paths...),
			Reportable: reportableSurfaceKind(signal.Kind),
			Confidence: "confirmed",
			Priority:   signal.Priority,
			Summary:    signal.Label,
		})
	}
	return out
}

// reportableSurfaceKind: P2-only soft disclosures still mark seen, but finalize force-record
// applies to any seen surface (info leaks are valid L1 across scenarios).
func reportableSurfaceKind(kind string) bool {
	switch kind {
	case SurfaceKindAPIInventory, SurfaceKindDebugEntry, SurfaceKindVCSExposure,
		SurfaceKindDirListing, SurfaceKindCloudMeta, SurfaceKindSecretLeak,
		SurfaceKindEndpointList, SurfaceKindInfoDisclosure:
		return true
	default:
		return false
	}
}

// surfaceDetectionEligibleTool excludes meta/docs tools whose bodies mention vuln patterns
// as examples (skill markdown, tool_search catalogs) and must not create record obligations.
func surfaceDetectionEligibleTool(toolName string) bool {
	switch normalizedExecutionToolName(toolName) {
	case "", "skill", "tool_search", "task", "transfer_to_agent",
		"record_vulnerability", "record_vulnerability_candidate",
		"list_vulnerabilities", "get_vulnerability",
		"update_vulnerability", "delete_vulnerability",
		"upsert_execution_coverage", "get_execution_coverage", "should_continue_execution",
		"upsert_project_fact", "list_project_facts", "get_project_fact",
		"read_file", "write", "edit", "glob", "grep", "list_dir":
		return false
	default:
		return true
	}
}

// AutoUpsertSurfaceCoverageFromTool opens coverage items for discovered surfaces/resources.
// Scenario-agnostic: works for Web/API/cloud/config exposures.
func AutoUpsertSurfaceCoverageFromTool(conversationID, toolName, arguments, output string) []CoverageItem {
	if !surfaceDetectionEligibleTool(toolName) {
		return nil
	}
	// Chat / non-ops sessions: never invent record obligations from tool noise.
	if !RecordObligationsEnabled(conversationID) {
		return nil
	}
	sigs := DetectSurfaceSignals(output)
	if len(sigs) == 0 {
		return nil
	}
	state := GetConversationExecutionState(conversationID)
	// Any reportable surface requires L1/L2 before report-style finalize.
	for _, sig := range sigs {
		if reportableSurfaceKind(sig.Kind) {
			state.MarkSurfaceSignalSeen()
			break
		}
	}
	target := extractTargetFromToolArgs(arguments)
	if target != "" {
		state.SetPrimaryTarget(target)
	}
	if target == "" {
		target = state.Controller().PrimaryTarget()
	}
	var written []CoverageItem
	now := time.Now()

	for _, sig := range sigs {
		parentPath := "surface." + sanitizeCoverageSeg(sig.Kind)
		if target != "" {
			parentPath += ".t:" + sanitizeCoverageSeg(truncateRunes(NormalizeCoverageTarget(target), 48))
		}
		note := sig.Label
		if len(sig.Paths) > 0 {
			note = note + "; paths=" + strings.Join(sig.Paths, ",")
		}
		pr := sig.Priority
		if pr == "" {
			pr = "P1"
		}
		item := CoverageItem{
			Path:      parentPath,
			Status:    "open",
			Priority:  pr,
			Note:      truncateRunes(note, 200),
			UpdatedAt: now,
		}
		state.UpsertAutomaticCoverage(item)
		written = append(written, item)

		// Child resources (paths) — keep probe checklist multi-scenario.
		for _, p := range sig.Paths {
			ep := "surface.resource:" + sanitizeCoverageSeg(p)
			if target != "" {
				ep += ".t:" + sanitizeCoverageSeg(truncateRunes(NormalizeCoverageTarget(target), 40))
			}
			child := CoverageItem{
				Path:      ep,
				Status:    "open",
				Priority:  "P1",
				Note:      fmt.Sprintf("from %s via %s", sig.Kind, strings.TrimSpace(toolName)),
				UpdatedAt: now,
			}
			state.UpsertAutomaticCoverage(child)
			written = append(written, child)
		}
	}
	linked := make([]string, 0, len(written))
	for _, item := range written {
		linked = append(linked, item.Path)
	}
	state.Controller().ObserveSignals(SignalsFromSurfaceOutput(target, output), linked)
	return written
}

func extractTargetFromToolArgs(arguments string) string {
	arguments = strings.TrimSpace(arguments)
	if arguments == "" {
		return ""
	}
	var raw map[string]interface{}
	if json.Unmarshal([]byte(arguments), &raw) != nil {
		if t := ExtractTargetFromText(arguments); t != "" {
			return t
		}
		return ""
	}
	for _, k := range []string{"url", "target", "host", "base_url", "uri", "endpoint"} {
		if v, ok := raw[k]; ok {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" {
				if t := ExtractTargetFromText(s); t != "" {
					return t
				}
				return s
			}
		}
	}
	return ""
}

// MarkInterestingIfSurface upgrades status_hint when surface signals present.
func MarkInterestingIfSurface(statusHint, output string) string {
	if IsInterestingStatusHint(statusHint) {
		return statusHint
	}
	if HasHighValueSurfaceSignal(output) {
		return "interesting"
	}
	return statusHint
}
