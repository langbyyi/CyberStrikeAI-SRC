package approval

import "testing"

// TestDangerRuleQueueEntryMatchesRealApprovalHistory 用真实审计记录
// （099ce374 / 650479e6 / 26e41de5，2026-10-15~16）的调用形状，锁定
// "哪些调用该进审批队列"：
//   - 写方法到改密类路径 → 必须进队（审计 Agent 才有机会按同意/理由放行）
//   - 只读探测到同一路径 → 不进队（之前仅凭 URL 含 resetPassword 就把大量 GET 送审）
//
// 注意：脚本通道（exec / execute-python-script / execute）的只读探测仍会进队——
// 判只读要把方法推断下沉到规则层，而推断实现目前在 internal/security，
// approval 反向依赖它会形成 import cycle。这条列为后续项，不在此处假装覆盖。
func TestDangerRuleQueueEntryMatchesRealApprovalHistory(t *testing.T) {
	rules, err := LoadBundledDangerRules()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := compileRuleSnapshot(rules)
	if err != nil {
		t.Fatal(err)
	}
	enqueued := func(tool string, args map[string]any) bool {
		for i := range snapshot.rules {
			if matched, _ := snapshot.rules[i].matches(Invocation{ToolName: tool, Arguments: args}); matched {
				return true
			}
		}
		return false
	}

	const seeyonReset = "http://117.40.190.110:8888/seeyon/rest/phoneLogin/phoneCode/resetPassword"
	const staffReset = "https://sewy.jxs163.com/api/1.0/pm/org/staff/resetPassword"

	cases := []struct {
		name  string
		tool  string
		args  map[string]any
		want  bool
		notes string
	}{
		{
			name: "写验证：不带 password 的最小化 POST",
			tool: "http-framework-test",
			args: map[string]any{"method": "POST", "url": seeyonReset, "data": `{"loginName":"zzz_nonexist_9f3a2b"}`},
			want: true,
		},
		{
			name: "写验证：带 password 的 POST",
			tool: "http-framework-test",
			args: map[string]any{"method": "POST", "url": seeyonReset, "data": `{"loginName":"zzz_nonexist_9f3a2b","password":"Xx123456!"}`},
			want: true,
		},
		{
			name: "写验证：自造账号 + 伪造来源头",
			tool: "http-framework-test",
			args: map[string]any{"method": "POST", "url": staffReset, "data": `{"username":"nonexistent_zzz_2026","mobile":"10000000000","code":"000000","password":"Aa123456!"}`},
			want: true,
		},
		{
			name:  "只读探测：GET 同一路径不进队",
			tool:  "http-framework-test",
			args:  map[string]any{"method": "GET", "url": seeyonReset},
			want:  false,
			notes: "这正是 15 条记录里 7 条纯 GET 噪音的来源",
		},
		{
			name: "命令行写验证：POST resetPwd 占位 userId",
			tool: "exec",
			args: map[string]any{"command": `cd /opt/ws && curl -sk -X POST -H "X-Forwarded-For: 127.0.0.1" -d '{"userId":999999999999}' "https://sewy.jxs163.com/guard/user/resetPwd"`},
			want: true,
		},
		{
			name: "命令行写验证：getResetCode + resetPassword 整套字段",
			tool: "exec",
			args: map[string]any{"command": `curl -sk -X POST -d '{"staffId":99999999,"userId":99999999,"mobile":"10000000000","code":"123456","password":"x"}' "https://sewy.jxs163.com/api/1.0/pm/org/staff/resetPassword"`},
			want: true,
		},
		{
			name: "方法变量化：for 列表扫写方法",
			tool: "exec",
			args: map[string]any{"command": `for m in PUT put pUt DELETE delete PATCH TRACE; do curl -s -m 5 -X "$m" -o /dev/null "http://117.21.249.204:8090/"; done`},
			want: true,
		},
		{
			name:  "已知噪音：脚本通道 GET 探测仍进队",
			tool:  "execute-python-script",
			args:  map[string]any{"script": "import requests\nr=requests.get('http://117.40.190.110:8888/seeyon/rest/phoneLogin/phoneCode/resetPassword')\nprint(r.status_code)"},
			want:  true,
			notes: "待方法推断下沉规则层后收敛",
		},
		{
			name: "只读扫描：与本类路径无关的枚举不进队",
			tool: "exec",
			args: map[string]any{"command": `for p in /status /health /metrics; do curl -s -o /dev/null -w "%{http_code}\n" "http://117.21.249.204:8090$p"; done`},
			want: false,
		},
	}

	for _, tc := range cases {
		if got := enqueued(tc.tool, tc.args); got != tc.want {
			suffix := ""
			if tc.notes != "" {
				suffix = " (" + tc.notes + ")"
			}
			t.Errorf("%s: 入队=%v 期望=%v%s", tc.name, got, tc.want, suffix)
		}
	}
}
