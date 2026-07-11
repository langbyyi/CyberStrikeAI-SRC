package multiagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRouteSkills_SQLErrorInjectsSQLiTips(t *testing.T) {
	t.Parallel()
	out := RouteSkills(SkillRouterInput{
		ToolName:  "http-framework-test",
		Arguments: `{"url":"http://t/login","param":"id"}`,
		Output:    "You have an error in your SQL syntax; check the manual near ''' at line 1\nSQLSTATE[42000]",
		TopK:      3,
		MaxRunes:  2000,
		SkillTipsLoader: func(skillsRoot, skillDir string, maxRunes int) string {
			if skillDir == "sqli-sql-injection" {
				return "SQLi first-pass: try ' OR 1=1-- and SLEEP(5); preserve error_sig."
			}
			return "other skill tips for " + skillDir
		},
	})
	if len(out.Skills) == 0 {
		t.Fatal("expected skill matches")
	}
	if out.Skills[0] != "sqli-sql-injection" {
		t.Fatalf("top skill = %q want sqli-sql-injection (skills=%v)", out.Skills[0], out.Skills)
	}
	if !strings.Contains(out.Block, "sqli-sql-injection") {
		t.Fatalf("block missing skill name: %s", out.Block)
	}
	if !strings.Contains(out.Block, "SQLi first-pass") {
		t.Fatalf("block missing tips: %s", out.Block)
	}
	if len(out.Injected) == 0 || out.Injected[0] != "sqli-sql-injection" {
		t.Fatalf("injected=%v", out.Injected)
	}
}

func TestRouteSkills_DedupeAndBudget(t *testing.T) {
	t.Parallel()
	already := map[string]struct{}{"sqli-sql-injection": {}}
	out := RouteSkills(SkillRouterInput{
		Output:          "You have an error in your SQL syntax and also <script>alert(1)</script>",
		TopK:            2,
		MaxRunes:        500,
		AlreadyInjected: already,
		SkillTipsLoader: func(_, skillDir string, maxRunes int) string {
			return strings.Repeat("T", 400) + " skill=" + skillDir
		},
	})
	for _, s := range out.Skills {
		if s == "sqli-sql-injection" {
			t.Fatal("already injected skill should be skipped")
		}
	}
	if len([]rune(out.Block)) > 600 {
		t.Fatalf("budget exceeded: runes=%d", len([]rune(out.Block)))
	}
}

func TestRouteSkills_NoSignal(t *testing.T) {
	t.Parallel()
	out := RouteSkills(SkillRouterInput{
		ToolName: "unknown-meta-tool",
		Output:   "ping ok 200",
		SkillTipsLoader: func(string, string, int) string {
			t.Fatal("loader should not run")
			return ""
		},
	})
	if out.Block != "" || len(out.Skills) != 0 {
		t.Fatalf("expected empty, got %+v", out)
	}
}

func TestRouteSkills_ParamNameHeuristics(t *testing.T) {
	t.Parallel()
	out := RouteSkills(SkillRouterInput{
		ToolName:  "http-framework-test",
		Arguments: `{"url":"http://t/api","param":"file","data":"file=../../etc/passwd"}`,
		Output:    "HTTP/1.1 200 OK\nroot:x:0:0:",
		TopK:      3,
		MaxRunes:  1500,
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "tips for " + skillDir
		},
	})
	found := false
	for _, s := range out.Skills {
		if s == "path-traversal-lfi" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected path-traversal-lfi from param heuristic, got %v", out.Skills)
	}
}

func TestRouteSkills_JWTParamHint(t *testing.T) {
	t.Parallel()
	out := RouteSkills(SkillRouterInput{
		ToolName:  "jwt-analyzer",
		Arguments: `{"token":"eyJhbGciOiJub25lIn0.e30."}`,
		Output:    "alg:none accepted",
		TopK:      2,
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "jwt tips " + skillDir
		},
	})
	if len(out.Skills) == 0 || out.Skills[0] != "jwt-oauth-token-attacks" {
		t.Fatalf("skills=%v", out.Skills)
	}
}

func TestRouteSkills_WeakReconOnWebEntry(t *testing.T) {
	t.Parallel()
	out := RouteSkills(SkillRouterInput{
		ToolName:  "katana",
		Arguments: `{"url":"http://t"}`,
		Output:    "crawled 12 urls",
		TopK:      2,
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "recon tips " + skillDir
		},
	})
	if len(out.Skills) == 0 {
		t.Fatal("expected weak recon/bug-bounty suggestion")
	}
	ok := false
	for _, s := range out.Skills {
		if s == "recon-and-methodology" || s == "bug-bounty" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("expected recon or bug-bounty, got %v", out.Skills)
	}
}

func TestRouteSkills_MissingSkillsDirSilent(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(os.TempDir(), "cyberstrike-skills-missing-dir-xyz-noexist")
	out := RouteSkills(SkillRouterInput{
		ToolName:   "sqlmap",
		Output:     "sqlmap identified injection point SQL syntax error",
		TopK:       1,
		SkillsRoot: missing,
	})
	// Selected skills may be non-empty; disk miss → empty inject, no panic
	if out.Block != "" && !strings.Contains(out.Block, "SkillRouter") {
		t.Fatalf("unexpected block: %s", out.Block)
	}
}

func TestRouteSkills_ParamIDHeuristic(t *testing.T) {
	t.Parallel()
	out := RouteSkills(SkillRouterInput{
		ToolName:  "http-framework-test",
		Arguments: `{"url":"http://t/item","param":"id","data":"id=1"}`,
		Output:    "HTTP/1.1 200 OK\nbody length 1200",
		TopK:      3,
		MaxRunes:  1500,
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "tips " + skillDir
		},
	})
	found := false
	for _, s := range out.Skills {
		if s == "sqli-sql-injection" || s == "idor-broken-object-authorization" ||
			s == "recon-and-methodology" || s == "bug-bounty" {
			found = true
		}
	}
	if !found {
		t.Fatalf("id= / param id should route idor/sqli/recon, got %v", out.Skills)
	}
	// Empty skills_dir string silent (loader still supplies tips)
	out2 := RouteSkills(SkillRouterInput{
		ToolName:   "sqlmap",
		Output:     "SQL syntax error near",
		SkillsRoot: "",
		SkillTipsLoader: func(_, skillDir string, _ int) string {
			return "inline " + skillDir
		},
		TopK: 1,
	})
	if len(out2.Skills) == 0 {
		t.Fatal("SQL error should still select skill even if SkillsRoot empty when loader provided")
	}
}
