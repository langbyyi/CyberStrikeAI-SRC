package multiagent

import (
	"fmt"
	"strings"
	"time"
)

// Business/Backend Logic Track (业务与后端缺陷轨) coverage class constants.
// Center of gravity: payment/workflow/race/client-trust — NOT horizontal privilege.
// idor_horizontal is optional (only when clear object-id / cross-user signals).
const (
	LogicClassWorkflowSkip = "workflow_skip"
	LogicClassParamTamper  = "param_tamper"
	LogicClassRace         = "race"
	LogicClassIDORHoriz    = "idor_horizontal"
	LogicClassStateTamper  = "state_tamper"
	LogicClassCouponAbuse  = "coupon_abuse"
	LogicClassAuthStepSkip = "auth_step_skip"
)

// AllLogicCoverageClasses is the canonical set for tests and docs.
// Business classes are listed first intentionally (docs + iteration order).
var AllLogicCoverageClasses = []string{
	LogicClassParamTamper,
	LogicClassWorkflowSkip,
	LogicClassCouponAbuse,
	LogicClassRace,
	LogicClassStateTamper,
	LogicClassAuthStepSkip,
	LogicClassIDORHoriz, // subset — access control only
}

// BusinessLogicCoverageClasses are single-identity-testable backend/business defects.
var BusinessLogicCoverageClasses = []string{
	LogicClassParamTamper,
	LogicClassWorkflowSkip,
	LogicClassCouponAbuse,
	LogicClassRace,
	LogicClassStateTamper,
	LogicClassAuthStepSkip,
}

// IsLogicCoverageClass reports whether s is (or contains) a known logic class token.
func IsLogicCoverageClass(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	if low == "" {
		return false
	}
	for _, c := range AllLogicCoverageClasses {
		if low == c || strings.Contains(low, c) {
			return true
		}
	}
	aliases := []string{
		"business_logic", "business-logic", "logic_vuln", "workflow", "price_tamper",
		"coupon", "horizontal", "idor", "race_condition", "race-condition",
		"payment", "checkout", "param_tamper",
	}
	for _, a := range aliases {
		if strings.Contains(low, a) {
			return true
		}
	}
	return false
}

// IsBusinessLogicClass is true for payment/workflow/race/state classes (not pure idor).
func IsBusinessLogicClass(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	for _, c := range BusinessLogicCoverageClasses {
		if low == c || strings.Contains(low, c) {
			return true
		}
	}
	for _, a := range []string{"payment", "checkout", "price", "amount", "coupon", "workflow", "race", "state_tamper"} {
		if strings.Contains(low, a) && !strings.Contains(low, "idor") {
			return true
		}
	}
	return false
}

// EstimateLogicCoveragePriority maps logic class → P2.
// Heuristic-only signals (no confirmed PoC) are always P2 — they are clues, not
// blockers. Only when a heuristic item is confirmed via real testing should the
// LLM upsert it to P0/P1.
func EstimateLogicCoveragePriority(logicClass string) string {
	_ = strings.ToLower(strings.TrimSpace(logicClass))
	return "P2"
}

// CoveragePathFromLogic builds a stable path key for logic-class coverage (R3 path norms on target).
func CoveragePathFromLogic(target, logicClass, param string) string {
	cls := sanitizeCoverageSeg(logicClass)
	if cls == "unknown" {
		cls = "logic"
	}
	target = NormalizeCoverageTarget(target)
	param = strings.TrimSpace(param)
	if param != "" {
		seg := "logic." + cls + ".param:" + sanitizeCoverageSeg(param)
		if target != "" {
			seg += ".t:" + sanitizeCoverageSeg(truncateRunes(target, 48))
		}
		return seg
	}
	if target != "" {
		return fmt.Sprintf("logic.%s.target:%s", cls, sanitizeCoverageSeg(truncateRunes(target, 80)))
	}
	return "logic." + cls
}

// LogicSignal is one heuristic hit from URL / params / tool summary.
type LogicSignal struct {
	Class    string
	Priority string
	Param    string
	Note     string
	Target   string
}

// paymentDomainHay is true when hay looks like pay/order/checkout/trade domain.
func paymentDomainHay(hay string) bool {
	needles := []string{
		"/pay", "/payment", "/checkout", "/order", "/trade", "/refund",
		"payment", "checkout", "out_trade_no", "total_fee", "trade_status",
		"amount=", "price=", "\"amount\"", "\"price\"", "wallet", "notify",
		"callback", "create_order", "pay/create", "api/pay",
	}
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// crossUserIDORContext is true only for explicit horizontal-access signals
// (not bare order_id on a payment create path).
func crossUserIDORContext(hay string) bool {
	strong := []string{
		"idor", "水平越权", "越权访问", "broken object", "horizontal privilege",
		"other user", "another user", "other_account", "victim", "bolA", "bola",
		"unauthorized access to other", "access other", "swap user", "user_id=",
		"account_id=", "object_id=",
	}
	for _, n := range strong {
		if strings.Contains(hay, n) {
			return true
		}
	}
	// order_id alone in payment domain is NOT idor — it's order lifecycle.
	// Only when comparing users / "my order vs other order" phrasing.
	if strings.Contains(hay, "order_id") || strings.Contains(hay, "\"order_id\"") {
		if strings.Contains(hay, "user") || strings.Contains(hay, "account") ||
			strings.Contains(hay, "other") || strings.Contains(hay, "victim") ||
			strings.Contains(hay, "idor") || strings.Contains(hay, "越权") {
			return true
		}
	}
	return false
}

// HeuristicLogicSignals extracts business/backend defect signals (pure, no I/O).
// Priority: param_tamper / workflow_skip / coupon_abuse / race / state_tamper / auth_step_skip;
// idor_horizontal only when crossUserIDORContext.
func HeuristicLogicSignals(urlOrTarget, paramsOrArgs, toolSummary string) []LogicSignal {
	hay := strings.ToLower(urlOrTarget + "\n" + paramsOrArgs + "\n" + toolSummary)
	target := strings.TrimSpace(urlOrTarget)
	if target == "" {
		for _, part := range strings.Fields(paramsOrArgs + " " + toolSummary) {
			if strings.Contains(part, "http://") || strings.Contains(part, "https://") || strings.Contains(part, ".") {
				target = strings.Trim(part, `"',`)
				break
			}
		}
	}

	type rule struct {
		class   string
		needles []string
		param   string
	}
	// Business-first rule order (emitted order prefers payment/workflow).
	rules := []rule{
		{LogicClassCouponAbuse, []string{
			"coupon", "discount", "promo", "voucher", "redeem", "优惠券", "积分",
			"invite_code", "point=", "\"points\"", "gift_card",
		}, "coupon"},
		{LogicClassParamTamper, []string{
			"price", "amount", "quantity", "total", "qty", "fee", "total_fee",
			"\"price\"", "\"amount\"", "price=", "amount=", "total_fee",
			"currency", "wallet", "balance", "credit",
		}, "amount"},
		{LogicClassWorkflowSkip, []string{
			"/checkout", "checkout", "workflow_skip", "skip step", "step=", "\"step\"",
			"confirm_step", "/pay/create", "pay/create", "create_order", "confirm",
			"未支付", "skip pay", "skip payment",
		}, "step"},
		{LogicClassStateTamper, []string{
			"order_status", "status=paid", "status=complete", "state_tamper",
			"\"status\"", "trade_status", "\"paid\"", "paid=true", "\"paid\":",
			"refund_status", "after_sale",
		}, "status"},
		{LogicClassRace, []string{
			"race", "parallel", "concurrent", "toctou", "竞态", "double spend",
			"notify", "callback", "webhook", "限购", "领券",
		}, ""},
		{LogicClassAuthStepSkip, []string{
			"auth_step", "skip verify", "bypass otp", "skip mfa", "password_reset",
			"reset_token", "验证码跳过", "skip otp",
		}, ""},
	}

	var out []LogicSignal
	seen := map[string]struct{}{}
	add := func(class, param, note string) {
		if _, ok := seen[class]; ok {
			return
		}
		seen[class] = struct{}{}
		out = append(out, LogicSignal{
			Class:    class,
			Priority: EstimateLogicCoveragePriority(class),
			Param:    param,
			Note:     note,
			Target:   target,
		})
	}

	for _, r := range rules {
		hit := false
		for _, n := range r.needles {
			if strings.Contains(hay, n) {
				hit = true
				break
			}
		}
		if hit {
			add(r.class, r.param, "business/backend heuristic: "+r.class)
		}
	}

	// Payment-domain entry paths: always open business classes, never force idor.
	if paymentDomainHay(hay) {
		if _, ok := seen[LogicClassParamTamper]; !ok {
			add(LogicClassParamTamper, "amount", "payment domain entry → param_tamper (client amount/price)")
		}
		if _, ok := seen[LogicClassWorkflowSkip]; !ok {
			// checkout/pay/create/confirm style
			if strings.Contains(hay, "checkout") || strings.Contains(hay, "/pay") ||
				strings.Contains(hay, "payment") || strings.Contains(hay, "confirm") ||
				strings.Contains(hay, "create") {
				add(LogicClassWorkflowSkip, "step", "payment domain entry → workflow_skip (skip pay/confirm)")
			}
		}
		// notify/callback → race (repeat notify)
		if strings.Contains(hay, "notify") || strings.Contains(hay, "callback") {
			add(LogicClassRace, "", "payment callback/notify → race/replay")
		}
	}

	// Generic order/cart/pay path without finer hits
	if len(out) == 0 {
		entryNeedles := []string{"/order", "/cart", "/pay", "/payment", "/checkout", "/refund", "/transfer", "/withdraw", "/trade", "/wallet"}
		for _, n := range entryNeedles {
			if strings.Contains(hay, n) {
				add(LogicClassParamTamper, "amount", "logic entry path: "+n)
				add(LogicClassWorkflowSkip, "step", "logic entry path workflow: "+n)
				break
			}
		}
	}

	// idor_horizontal: OPTIONAL — only clear cross-user / object-access signals.
	// Bare order_id on /api/pay/create must NOT force idor as the only open item.
	if crossUserIDORContext(hay) {
		add(LogicClassIDORHoriz, "id", "optional idor: cross-user/object-id context")
	}

	return out
}

// HeuristicLogicCoverageItems converts signals to open CoverageItems (does not write state).
func HeuristicLogicCoverageItems(urlOrTarget, paramsOrArgs, toolSummary string) []CoverageItem {
	sigs := HeuristicLogicSignals(urlOrTarget, paramsOrArgs, toolSummary)
	items := make([]CoverageItem, 0, len(sigs))
	now := time.Now()
	for _, s := range sigs {
		items = append(items, CoverageItem{
			Path:      CoveragePathFromLogic(s.Target, s.Class, s.Param),
			Status:    "open",
			Priority:  s.Priority,
			Note:      truncateRunes(s.Note, 200),
			UpdatedAt: now,
		})
	}
	return items
}

// HasBusinessLogicOpen reports open|in_progress P0/P1 business-class coverage (not only idor).
func HasBusinessLogicOpen(state *ConversationExecutionState) bool {
	if state == nil {
		return false
	}
	for _, it := range state.ListCoverage() {
		st := strings.ToLower(strings.TrimSpace(it.Status))
		if st != "open" && st != "in_progress" && st != "" {
			continue
		}
		pr := strings.ToUpper(strings.TrimSpace(it.Priority))
		if pr != "P0" && pr != "P1" {
			continue
		}
		path := strings.ToLower(it.Path + " " + it.Note)
		if IsBusinessLogicClass(path) {
			return true
		}
		for _, c := range BusinessLogicCoverageClasses {
			if strings.Contains(path, c) {
				return true
			}
		}
	}
	return false
}

// AutoUpsertLogicCoverageFromToolSignals writes open business/backend coverage from tool I/O.
func AutoUpsertLogicCoverageFromToolSignals(conversationID, toolName, args, output string) []CoverageItem {
	tn := normalizeToolBaseName(toolName)
	switch tn {
	case "tool_search", "skill", "task", "transfer_to_agent", "exit",
		builtinToolNameLower("upsert_execution_coverage"),
		builtinToolNameLower("get_execution_coverage"),
		builtinToolNameLower("should_continue_execution"),
		builtinToolNameLower("record_vulnerability"),
		builtinToolNameLower("record_vulnerability_candidate"):
		return nil
	}
	interesting := map[string]struct{}{
		"http-framework-test": {}, "execute-python-script": {}, "logic_probe_diff": {},
		"exec": {}, "execute": {}, "ffuf": {}, "katana": {}, "arjun": {},
		"nuclei": {}, "sqlmap": {},
	}
	if _, ok := interesting[tn]; !ok && !strings.Contains(tn, "http") && !strings.Contains(tn, "probe") {
		lowArgs := strings.ToLower(args)
		if !paymentDomainHay(lowArgs) && !strings.Contains(lowArgs, "price") &&
			!strings.Contains(lowArgs, "coupon") && !strings.Contains(lowArgs, "checkout") {
			return nil
		}
	}
	hay := strings.ToLower(args + "\n" + output)
	if tn == "nuclei" && (strings.Contains(hay, "cve-20") || strings.Contains(hay, "[cve-")) {
		if !paymentDomainHay(hay) && !strings.Contains(hay, "price") && !strings.Contains(hay, "coupon") {
			return nil
		}
	}

	items := HeuristicLogicCoverageItems(extractURLFromArgs(args), args, output)
	if len(items) == 0 {
		return nil
	}
	state := GetConversationExecutionState(conversationID)
	upserted := make([]CoverageItem, 0, len(items))
	for _, it := range items {
		existing := state.ListCoverage()
		skip := false
		for _, e := range existing {
			if e.Path == it.Path {
				st := strings.ToLower(e.Status)
				if st == "done" || st == "blocked" {
					skip = true
				}
				break
			}
		}
		if skip {
			continue
		}
		state.UpsertCoverage(it)
		upserted = append(upserted, it)
	}
	return upserted
}

func builtinToolNameLower(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func extractURLFromArgs(args string) string {
	args = strings.TrimSpace(args)
	if args == "" {
		return ""
	}
	low := strings.ToLower(args)
	for _, key := range []string{`"url"`, `"target"`, `"endpoint"`} {
		idx := strings.Index(low, key)
		if idx < 0 {
			continue
		}
		rest := args[idx+len(key):]
		for _, scheme := range []string{"https://", "http://"} {
			if j := strings.Index(strings.ToLower(rest), scheme); j >= 0 {
				frag := rest[j:]
				end := len(frag)
				for i, r := range frag {
					if r == '"' || r == '\'' || r == ' ' || r == '\n' || r == ',' || r == '}' {
						end = i
						break
					}
				}
				return frag[:end]
			}
		}
	}
	for _, scheme := range []string{"https://", "http://"} {
		if j := strings.Index(low, scheme); j >= 0 {
			frag := args[j:]
			end := len(frag)
			for i, r := range frag {
				if r == '"' || r == '\'' || r == ' ' || r == '\n' || r == ',' || r == '}' {
					end = i
					break
				}
			}
			return frag[:end]
		}
	}
	return ""
}
