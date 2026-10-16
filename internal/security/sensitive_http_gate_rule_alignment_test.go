package security

import (
	"context"
	"testing"

	"cyberstrike-ai/internal/approval"
)

// 硬闸拦下的调用必须同时也能进审批队列。
//
// 硬闸命中时 Executor 直接 IsError 返回、不产生审批单——规则层若不拦，
// 这条调用就成了"无记录、无出口"的死路：用户看不到审批意见，也没法授权。
// 这正是线上死锁（会话 099ce374 等）的一种形态，所以把它固化成不变量：
//
//	CheckSensitiveHTTPGate 拦下  ⇒  DangerousActionPolicy 必须入队
//
// security 包已因 executor 取 Grant 而 import approval，跨层断言放在这里不会成环。
func TestSensitiveHTTPGateBlockedImpliesApprovalEnqueued(t *testing.T) {
	rules, err := approval.LoadBundledDangerRules()
	if err != nil {
		t.Fatal(err)
	}
	loader, err := approval.NewRuleLoader(rules)
	if err != nil {
		t.Fatal(err)
	}
	policy := approval.NewDangerousActionPolicy(true, loader)

	cases := []struct {
		name string
		tool string
		cmd  string
	}{
		{"写方法藏在引号变量里", "exec", `for m in PUT put DELETE delete PATCH TRACE; do curl -s -m 5 -X "$m" -o /dev/null "http://t/"; done`},
		{"写方法藏在裸变量里", "exec", `for m in OPTIONS TRACE PUT DELETE HEAD POST; do curl -s -X $m "http://t/"; done`},
		{"只枚举 POST 的循环", "exec", `for m in GET POST; do curl -s -X $m "http://t/"; done`},
		{"单变量间接引用 PUT", "exec", `M=PUT; curl -s -X $M "http://t/api/item/1"`},
		{"单变量间接引用 POST", "exec", `M=POST; curl -s -X $M "http://t/api/item/1"`},
		{"长选项间接引用方法", "exec", `M=PUT; curl -s --request $M "http://t/api/item/1"`},
		{"长选项带引号间接引用方法", "exec", `for m in PUT DELETE; do curl -s --request "$m" "http://t/api/item/1"; done`},
		{"字面量 DELETE", "exec", `curl -s -X DELETE "http://t/api/v1/panels/1"`},
		{"敏感路径写验证", "exec", `curl -s -X POST -d '{"loginName":"x"}' "http://t/seeyon/rest/phoneLogin/phoneCode/resetPassword"`},
		{"硬闸独有路径 truncate", "exec", `curl -s -X POST "http://t/api/truncateTable"`},
		{"硬闸独有路径 factory reset", "exec", `curl -s "http://t/api/factory-reset"`},
		{"HTTP 工具 DELETE 方法", "http-framework-test", `{"method":"DELETE","url":"http://t/api/v1/panels/1"}`},
		{"HTTP 工具改密路径", "http-framework-test", `{"method":"POST","url":"http://t/api/resetPassword"}`},
		// 硬闸的路径词表比 HTTP 规则宽，差集内硬闸直接 IsError 且不产生审批单。
		// 这三条此前正是死路，补规则后必须保持两侧同宽。
		{"硬闸独有路径 format（HTTP 工具）", "http-framework-test", `{"method":"POST","url":"http://t/api/format"}`},
		{"硬闸独有路径 wipe（HTTP 工具）", "http-framework-test", `{"method":"POST","url":"http://t/api/wipe"}`},
		{"硬闸独有路径 unlink（HTTP 工具）", "http-framework-test", `{"method":"POST","url":"http://t/api/unlink"}`},
		{"eino 通道写接口", "execute", `curl -s -X DELETE "http://t/api/v1/panels/1"`},
	}

	for _, tc := range cases {
		args := map[string]any{"command": tc.cmd}
		if tc.tool == "http-framework-test" {
			args = map[string]any{"method": "DELETE", "url": "http://t/api/v1/panels/1"}
			switch tc.name {
			case "HTTP 工具改密路径":
				args = map[string]any{"method": "POST", "url": "http://t/api/resetPassword"}
			case "硬闸独有路径 format（HTTP 工具）":
				args = map[string]any{"method": "POST", "url": "http://t/api/format"}
			case "硬闸独有路径 wipe（HTTP 工具）":
				args = map[string]any{"method": "POST", "url": "http://t/api/wipe"}
			case "硬闸独有路径 unlink（HTTP 工具）":
				args = map[string]any{"method": "POST", "url": "http://t/api/unlink"}
			}
		}
		blocked, message := CheckSensitiveHTTPGate(tc.tool, args)
		if !blocked {
			// 放行不需要对齐，跳过。
			continue
		}
		result, err := policy.Evaluate(context.Background(), approval.Invocation{ToolName: tc.tool, Arguments: args})
		if err != nil {
			t.Fatalf("%s: 规则评估失败: %v", tc.name, err)
		}
		if !result.Matched {
			t.Errorf("%s: 硬闸拦下（%s）但规则层未入队 → 该调用无审批单、无解封路径", tc.name, message)
		}
	}
}
