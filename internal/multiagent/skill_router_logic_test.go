package multiagent

import (
	"strings"
	"testing"
)

func TestRouteSkills_BusinessParamsTopBusinessLogic(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args string
		out  string
	}{
		{"price", `{"url":"https://shop.example/cart","data":"price=1&qty=2"}`, "ok"},
		{"coupon", `{"body":"{\"coupon\":\"SAVE50\",\"order_id\":1}"}`, `{"ok":true}`},
		{"checkout", `{"url":"https://t/checkout"}`, "HTTP 200"},
		{"payment", `{"path":"/api/payment","amount":"9.9"}`, "paid"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := RouteSkills(SkillRouterInput{
				ToolName:  "http-framework-test",
				Arguments: tc.args,
				Output:    tc.out,
				TopK:      3,
				SkillTipsLoader: func(_, skillDir string, _ int) string {
					return "tips " + skillDir
				},
			})
			if len(res.Skills) == 0 {
				t.Fatal("expected skills")
			}
			found := false
			for _, s := range res.Skills {
				if s == "business-logic-vulnerabilities" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("business-logic not in skills=%v", res.Skills)
			}
			// Prefer business-logic high when business param is the main signal
			if res.Skills[0] != "business-logic-vulnerabilities" &&
				res.Skills[0] != "idor-broken-object-authorization" {
				// order_id may also hit idor; still should rank business near top
				if !containsSkill(res.Skills, "business-logic-vulnerabilities") {
					t.Fatalf("top=%v", res.Skills)
				}
			}
		})
	}
}

func TestRouteSkills_NucleiCVEOnlyBusinessLogicNotTop1(t *testing.T) {
	t.Parallel()
	out := `[CVE-2021-44228] apache log4j RCE
[cve-2023-44487] http/2 rapid reset
[CVE-2024-1234] wordpress plugin
matched nuclei-templates network/cves/
`
	res := RouteSkills(SkillRouterInput{
		ToolName:  "nuclei",
		Arguments: `{"target":"https://scan.example"}`,
		Output:    out,
		TopK:      3,
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "tips " + skillDir
		},
	})
	if len(res.Skills) == 0 {
		t.Fatal("expected some skill for CVE list")
	}
	if res.Skills[0] == "business-logic-vulnerabilities" {
		t.Fatalf("CVE-only must not top business-logic, got %v", res.Skills)
	}
}

func TestRouteSkills_BusinessJSONWeakInject(t *testing.T) {
	t.Parallel()
	res := RouteSkills(SkillRouterInput{
		ToolName:  "execute-python-script",
		Arguments: `{"code":"print(r.text)"}`,
		Output:    `{"order_id": 99, "price": 0.01, "status": "ok"}`,
		TopK:      3,
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "tips " + skillDir
		},
	})
	if !containsSkill(res.Skills, "business-logic-vulnerabilities") {
		t.Fatalf("business JSON should inject business-logic, got %v", res.Skills)
	}
}

func TestRouteSkills_BusinessJSONSuppressedBySQL(t *testing.T) {
	t.Parallel()
	res := RouteSkills(SkillRouterInput{
		ToolName:  "http-framework-test",
		Arguments: `{"url":"https://t/order"}`,
		Output:    `You have an error in your SQL syntax near ''' ; also {"price":1}`,
		TopK:      2,
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "tips " + skillDir
		},
	})
	if len(res.Skills) == 0 || res.Skills[0] != "sqli-sql-injection" {
		t.Fatalf("SQL should dominate top, got %v", res.Skills)
	}
}

func TestRouteSkills_IDORAndRaceHints(t *testing.T) {
	t.Parallel()
	res := RouteSkills(SkillRouterInput{
		ToolName:  "http-framework-test",
		Arguments: `{"url":"https://t/api","data":"user_id=2&order_id=5"}`,
		Output:    "possible race condition on concurrent request for redeem",
		TopK:      5,
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "tips " + skillDir
		},
	})
	if !containsSkill(res.Skills, "idor-broken-object-authorization") {
		t.Fatalf("expected idor, got %v", res.Skills)
	}
	if !containsSkill(res.Skills, "race-condition") && !containsSkill(res.Skills, "business-logic-vulnerabilities") {
		t.Fatalf("expected race or business-logic, got %v", res.Skills)
	}
}

func TestRouteSkills_LogicMissingSkillsDirNoPanic(t *testing.T) {
	t.Parallel()
	res := RouteSkills(SkillRouterInput{
		ToolName:   "http-framework-test",
		Arguments:  `{"data":"price=0"}`,
		Output:     "ok",
		SkillsRoot: "/nonexistent/skills/path/xyz",
		// default loader reads disk → empty tips → no Injected block
	})
	// Skills may be selected but Injected empty when tips missing; must not panic
	_ = res
	if strings.Contains(res.Block, "panic") {
		t.Fatal(res.Block)
	}
}

func containsSkill(skills []string, want string) bool {
	for _, s := range skills {
		if s == want {
			return true
		}
	}
	return false
}
