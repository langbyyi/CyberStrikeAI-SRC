package multiagent

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// NormalizeCoverageTarget normalizes a URL/host for coverage path keys:
// host lowercased, default ports (:80/:443) stripped, trailing slash trimmed.
// Non-URL targets are lowercased and trimmed.
func NormalizeCoverageTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	// Try parse as URL (add scheme if bare host/path looks like host).
	raw := target
	if !strings.Contains(raw, "://") && (strings.Contains(raw, ".") || strings.Contains(raw, "/")) {
		// Prefer https for host-like; keep path-only as-is.
		if strings.HasPrefix(raw, "/") {
			return strings.ToLower(strings.TrimRight(raw, "/"))
		}
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(target))
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	if port != "" {
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			port = ""
		}
	}
	if port != "" {
		host = host + ":" + port
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	out := host + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return strings.TrimRight(out, "/")
}

// CoveragePathFromCandidate builds a stable coverage path key from L1 candidate fields.
// path ≈ target + param/type (truncated for map key sanity).
func CoveragePathFromCandidate(target, param, vulnType, category string) string {
	target = NormalizeCoverageTarget(target)
	param = strings.TrimSpace(param)
	vulnType = strings.TrimSpace(vulnType)
	category = strings.TrimSpace(category)
	kind := vulnType
	if kind == "" {
		kind = category
	}
	if kind == "" {
		kind = "candidate"
	}
	kind = sanitizeCoverageSeg(kind)
	if param != "" {
		seg := "cand." + kind + ".param:" + sanitizeCoverageSeg(param)
		if target != "" {
			seg += ".t:" + sanitizeCoverageSeg(truncateRunes(target, 48))
		}
		return seg
	}
	if target != "" {
		return fmt.Sprintf("cand.%s.target:%s", kind, sanitizeCoverageSeg(truncateRunes(target, 80)))
	}
	return "cand." + kind
}

func sanitizeCoverageSeg(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, "\n", "_")
	s = strings.ReplaceAll(s, ":", "_")
	if s == "" {
		return "unknown"
	}
	return truncateRunes(s, 64)
}

// EstimateCoveragePriorityFromVuln maps type/severity to P0/P1/P2/P3.
// Rules (testable table):
//   - sqli/rce/ssrf/auth/upload/xxe/ssti + critical|high → P0
//   - idor/xss/csrf/jwt/cors/lfi → P1 (or P0 if critical/high severity)
//   - logic classes (workflow_skip/coupon_abuse/…) → P2 via EstimateLogicCoveragePriority
//     (severity must NOT bypass this; promote to P0/P1 only after real testing)
//   - info / low generic disclosure → P2/P3
func EstimateCoveragePriorityFromVuln(vulnType, severity string) string {
	sev := strings.ToLower(strings.TrimSpace(severity))
	vt := strings.ToLower(strings.TrimSpace(vulnType))

	// Logic track classes are ALWAYS P2 when sourced from heuristics/candidates.
	// Severity must not bypass this; LLM promotes to P0/P1 only after real testing.
	if IsLogicCoverageClass(vt) {
		return EstimateLogicCoveragePriority(vt)
	}

	highSev := sev == "critical" || sev == "high"
	p0types := []string{"sqli", "sql", "rce", "command", "ssrf", "auth", "unauth", "deserial", "upload", "xxe", "ssti", "jndi"}
	for _, k := range p0types {
		if strings.Contains(vt, k) {
			if sev == "low" || sev == "info" {
				return "P1"
			}
			return "P0"
		}
	}
	p1types := []string{"xss", "csrf", "jwt", "cors", "lfi", "path", "open redirect", "redirect"}
	for _, k := range p1types {
		if strings.Contains(vt, k) {
			if highSev {
				return "P0"
			}
			return "P1"
		}
	}
	switch sev {
	case "critical", "high":
		return "P0"
	case "medium":
		return "P1"
	case "info":
		return "P3"
	case "low":
		return "P2"
	}
	return "P1"
}

// AutoUpsertCoverageFromCandidate writes open coverage for an L1 candidate (pure state helper).
// Logic-class vulnerability_type/category land on logic.* paths so finalize gate treats them as logic track.
func AutoUpsertCoverageFromCandidate(conversationID, target, param, vulnType, category, severity, note string) CoverageItem {
	kind := strings.TrimSpace(vulnType)
	if kind == "" {
		kind = strings.TrimSpace(category)
	}
	var path string
	var priority string
	if IsLogicCoverageClass(kind) {
		// Normalize free-text to a known class when possible
		cls := kind
		for _, c := range AllLogicCoverageClasses {
			if strings.Contains(strings.ToLower(kind), c) {
				cls = c
				break
			}
		}
		// aliases
		low := strings.ToLower(kind)
		switch {
		case strings.Contains(low, "coupon"):
			cls = LogicClassCouponAbuse
		case strings.Contains(low, "race"):
			cls = LogicClassRace
		case strings.Contains(low, "idor") || strings.Contains(low, "horizontal"):
			cls = LogicClassIDORHoriz
		case strings.Contains(low, "workflow") || strings.Contains(low, "skip"):
			cls = LogicClassWorkflowSkip
		case strings.Contains(low, "state"):
			cls = LogicClassStateTamper
		case strings.Contains(low, "param") || strings.Contains(low, "price") || strings.Contains(low, "tamper"):
			cls = LogicClassParamTamper
		case strings.Contains(low, "auth") && strings.Contains(low, "step"):
			cls = LogicClassAuthStepSkip
		case strings.Contains(low, "business") || strings.Contains(low, "logic"):
			cls = LogicClassParamTamper
		}
		path = CoveragePathFromLogic(target, cls, param)
		priority = EstimateCoveragePriorityFromVuln(cls, severity)
	} else {
		path = CoveragePathFromCandidate(target, param, vulnType, category)
		priority = EstimateCoveragePriorityFromVuln(vulnType, severity)
	}
	item := CoverageItem{
		Path:      path,
		Status:    "open",
		Priority:  priority,
		Note:      truncateRunes(note, 200),
		UpdatedAt: time.Now(),
	}
	GetConversationExecutionState(conversationID).UpsertCoverage(item)
	return item
}

// MarkCoverageDoneForVuln best-effort marks matching open coverage as done when L2 succeeds.
// Match by normalized target substring or title keywords against path/note.
func MarkCoverageDoneForVuln(conversationID, title, target string) []string {
	state := GetConversationExecutionState(conversationID)
	items := state.ListCoverage()
	if len(items) == 0 {
		return nil
	}
	titleL := strings.ToLower(strings.TrimSpace(title))
	targetL := strings.ToLower(strings.TrimSpace(target))
	normTarget := NormalizeCoverageTarget(target)
	normSeg := sanitizeCoverageSeg(truncateRunes(normTarget, 48))
	var marked []string
	for _, it := range items {
		st := strings.ToLower(strings.TrimSpace(it.Status))
		if st == "done" || st == "blocked" {
			continue
		}
		pathL := strings.ToLower(it.Path)
		noteL := strings.ToLower(it.Note)
		match := false
		if normSeg != "" && normSeg != "unknown" && strings.Contains(pathL, normSeg) {
			match = true
		}
		if !match && targetL != "" && (strings.Contains(noteL, targetL) || strings.Contains(pathL, sanitizeCoverageSeg(targetL))) {
			match = true
		}
		if !match && titleL != "" {
			// keyword overlap: sqli/xss etc.
			for _, kw := range []string{"sql", "xss", "ssrf", "rce", "idor", "upload", "jwt", "lfi", "ssti", "xxe", "auth"} {
				if strings.Contains(titleL, kw) && (strings.Contains(pathL, kw) || strings.Contains(noteL, kw)) {
					match = true
					break
				}
			}
		}
		if !match && strings.HasPrefix(pathL, "cand.") && targetL != "" && strings.Contains(noteL, targetL) {
			match = true
		}
		if match {
			it.Status = "done"
			it.Note = strings.TrimSpace(it.Note + " | L2 recorded: " + truncateRunes(title, 80))
			it.UpdatedAt = time.Now()
			state.UpsertCoverage(it)
			marked = append(marked, it.Path)
		}
	}
	return marked
}

// ResolveConversationObligation resolves only the obligation bound to callID and
// closes its discovery coverage. Candidate coverage created by L1 is intentionally
// not linked and therefore remains open for L2 verification.
func ResolveConversationObligation(conversationID, callID, vulnerabilityID string) []string {
	state := GetConversationExecutionState(conversationID)
	resolved := state.Controller().ResolveBoundObligation(callID, vulnerabilityID)
	if resolved == nil {
		return nil
	}
	items := state.ListCoverage()
	byPath := make(map[string]CoverageItem, len(items))
	for _, item := range items {
		byPath[item.Path] = item
	}
	closed := make([]string, 0, len(resolved.LinkedCoverage))
	for _, path := range resolved.LinkedCoverage {
		item, ok := byPath[path]
		if !ok {
			continue
		}
		item.Status = "done"
		item.Note = "resolved by L1/L2: " + strings.TrimSpace(vulnerabilityID)
		item.UpdatedAt = time.Now()
		state.UpsertCoverage(item)
		closed = append(closed, path)
	}
	state.MarkVulnerabilityRecorded()
	return closed
}
