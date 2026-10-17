package security

import (
	"strings"
	"testing"
)

// 写方法被藏进 shell 变量或 for 列表时，字面量提示（-X DELETE）会失明。
// 这类写法唯一的目的就是把写方法扫一遍，必须按写方法拦下。
func TestCheckSensitiveHTTPGateCatchesVariableIndirectedWriteMethods(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{
			name: "循环枚举写方法（无引号）",
			cmd:  `for m in OPTIONS TRACE PUT DELETE HEAD POST; do curl -s -m 8 -X $m -o /dev/null -w "%{http_code}" "http://117.21.249.204:8090/"; done`,
		},
		{
			name: "循环枚举写方法（带引号）",
			cmd:  `for m in PUT put pUt DELETE delete PATCH TRACE; do r=$(curl -s -m 5 -X "$m" -o /dev/null -w "%{http_code}" "http://target/"); echo "$r [$m]"; done`,
		},
		{
			name: "变量间接引用方法",
			cmd:  `M=DELETE; curl -s -X $M "http://target/api/item/1"`,
		},
	}
	for _, tc := range cases {
		blocked, message := CheckSensitiveHTTPGate("exec", map[string]interface{}{"command": tc.cmd})
		if !blocked {
			t.Errorf("%s: 应被硬闸拦下，命令: %s", tc.name, tc.cmd)
			continue
		}
		if !strings.Contains(message, "method:sweep") {
			t.Errorf("%s: 拦截理由应标注方法枚举，实际: %s", tc.name, message)
		}
	}
}

// 补漏不能把只读探测一起误伤。
func TestCheckSensitiveHTTPGateKeepsReadOnlyProbesAllowed(t *testing.T) {
	commands := []string{
		`curl -s -m 8 "http://target/status"`,
		`for p in /a /b /c; do curl -s -m 5 -o /dev/null -w "%{http_code}" "http://target$p"; done`,
		`curl -s -X GET "http://target/api/list"`,
		`curl -s -I "http://target/"`,
	}
	for _, command := range commands {
		if blocked, message := CheckSensitiveHTTPGate("exec", map[string]interface{}{"command": command}); blocked {
			t.Errorf("只读探测不应被拦: %s -> %s", command, message)
		}
	}
}

// 回归（线上真实误拦）：Python 脚本用 for 循环枚举验证码字段名、helper 恰好叫
// post。旧实现把整个 args JSON 兜底拼接进扫描文本，字面量 \n 让 for-列表捕获
// 跨行吞进 post,cj=newsess()，函数名 post 被当成"写方法枚举"→ method:sweep 误拦。
// sweep 判定只允许作用于原始命令文本。
func TestCheckSensitiveHTTPGateAllowsPythonFieldLoopWithPostHelper(t *testing.T) {
	cmd := "python3 - <<'PY'\nimport json,base64,urllib.request,ssl,http.cookiejar,ddddocr,time\nBASE=\"https://www.example.com/api-gateway/oileus/\"\ndef newsess():\n    op=urllib.request.build_opener()\n    def post(p,o):\n        req=urllib.request.Request(BASE+p,data=json.dumps(o).encode(),headers={\"Content-Type\":\"application/json\"})\n        return json.loads(op.open(req,timeout=20).read().decode())\n    return post,cj\nfor fld in [\"captcha\",\"captchaCode\",\"imgCode\",\"checkCode\",\"code\"]:\n    post,cj=newsess()\n    resp=post(\"register/getImgCaptcha\",{}); res=resp.get(\"result\") or resp\n    body={\"mobile\":\"13000000000\",fld:\"abcd\"}\n    out=post(\"register/registerValidateImgCaptcha\",body)\n    print(\"%-12s -> %s\"%(fld,json.dumps(out,ensure_ascii=False)[:150]))\nPY"
	if blocked, message := CheckSensitiveHTTPGate("exec", map[string]interface{}{"command": cmd}); blocked {
		t.Errorf("Python 字段名循环 + post helper 不应被判为 method:sweep，实际: %s", message)
	}
}
