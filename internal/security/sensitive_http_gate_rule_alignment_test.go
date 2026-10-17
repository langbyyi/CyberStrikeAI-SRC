package security

import (
	"context"
	"testing"

	"cyberstrike-ai/internal/approval"
)

// 不变量：敏感 HTTP 判定命中 ⇒ 统一审批必须入队。
//
// 硬闸曾直接在执行器 IsError 拒绝且不产生审批单——"无记录、无出口"的死路：
// 用户看不到审批意见，也没法授权（线上会话 099ce374、shfft 验证码探测均属此形态）。
// 判定现在是审批触发器链的一环，命中即 RequiresApproval，由审计 Agent/人工裁决，
// 不存在硬编码拒绝。
func TestSensitiveHTTPGateBlockedImpliesApprovalRequired(t *testing.T) {
	rules, err := approval.LoadBundledDangerRules()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := approval.NewGlobalRuntime(approval.Config{
		Reviewer:        approval.ReviewerHuman,
		DangerousAction: approval.TriggerConfig{Enabled: true},
	}, rules, NewSensitiveHTTPGateTrigger())
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		tool string
		cmd  string
	}{
		{"写方法藏在引号变量里", "exec", `for m in PUT put DELETE delete PATCH TRACE; do curl -s -m 5 -X "$m" -o /dev/null "http://t/"; done`},
		{"只枚举 POST 的循环", "exec", `for m in GET POST; do curl -s -X $m "http://t/"; done`},
		{"单变量间接引用 PUT", "exec", `M=PUT; curl -s -X $M "http://t/api/item/1"`},
		{"字面量 DELETE", "exec", `curl -s -X DELETE "http://t/api/v1/panels/1"`},
		{"敏感路径写验证", "exec", `curl -s -X POST -d '{"loginName":"x"}' "http://t/seeyon/rest/phoneLogin/phoneCode/resetPassword"`},
		{"硬闸独有路径 truncate", "exec", `curl -s -X POST "http://t/api/truncateTable"`},
		{"硬闸独有路径 factory reset", "exec", `curl -s "http://t/api/factory-reset"`},
		{"HTTP 工具 DELETE 方法", "http-framework-test", `{"method":"DELETE","url":"http://t/api/v1/panels/1"}`},
		{"HTTP 工具改密路径", "http-framework-test", `{"method":"POST","url":"http://t/api/resetPassword"}`},
		{"硬闸独有路径 format（HTTP 工具）", "http-framework-test", `{"method":"POST","url":"http://t/api/format"}`},
		{"硬闸独有路径 wipe（HTTP 工具）", "http-framework-test", `{"method":"POST","url":"http://t/api/wipe"}`},
		{"硬闸独有路径 unlink（HTTP 工具）", "http-framework-test", `{"method":"POST","url":"http://t/api/unlink"}`},
		{"eino 通道写接口", "execute", `curl -s -X DELETE "http://t/api/v1/panels/1"`},
	}

	for _, tc := range cases {
		args := map[string]any{"command": tc.cmd}
		if tc.tool == "http-framework-test" {
			switch tc.name {
			case "HTTP 工具 DELETE 方法":
				args = map[string]any{"method": "DELETE", "url": "http://t/api/v1/panels/1"}
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
		assessment, err := runtime.Evaluate(context.Background(), approval.Invocation{
			ID: "inv_alignment", Source: "test", RequesterUserID: "tester",
			ToolName: tc.tool, Arguments: args,
		})
		if err != nil {
			t.Fatalf("%s: 触发器评估失败: %v", tc.name, err)
		}
		if !assessment.RequiresApproval {
			t.Errorf("%s: 判定命中（%s）但统一审批未入队 → 该调用无审批单、无解封路径", tc.name, message)
			continue
		}
		hasGateSource := false
		for _, source := range assessment.TriggerSources {
			if source == "sensitive_http_gate" {
				hasGateSource = true
				break
			}
		}
		if !hasGateSource {
			t.Errorf("%s: 触发来源应含 sensitive_http_gate，实际: %v", tc.name, assessment.TriggerSources)
		}
	}
}

// 只读探测不得进入强制审批。
func TestSensitiveHTTPGateTriggerAllowsReadOnlyProbes(t *testing.T) {
	trigger := NewSensitiveHTTPGateTrigger()
	commands := []string{
		`curl -s -m 8 "http://target/status"`,
		`for p in /a /b /c; do curl -s -m 5 -o /dev/null -w "%{http_code}" "http://target$p"; done`,
		`curl -s -X GET "http://target/api/list"`,
	}
	for _, command := range commands {
		result, err := trigger.Evaluate(context.Background(), approval.Invocation{
			ToolName: "exec", Arguments: map[string]any{"command": command},
		})
		if err != nil {
			t.Fatalf("评估失败: %v", err)
		}
		if result.Matched {
			t.Errorf("只读探测不应触发强制审批: %s", command)
		}
	}
}
