package security

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestMaybeInjectCmdTimeout(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // 期望子串；空表示期望与输入相同（不注入）
	}{
		{"curl 无超时注入", "curl http://example.com/", "--max-time 60 --connect-timeout 10"},
		{"curl 已含 max-time 不覆盖", "curl --max-time 5 http://example.com/", ""},
		{"curl 已含简写 -m 仍注入（保守只看 --max-time）", "curl -m 5 http://x", "--max-time 60"},
		{"wget 无超时注入", "wget http://example.com/file", "--timeout=60 --tries=2"},
		{"wget 已含 --timeout 不覆盖", "wget --timeout=5 http://x", ""},
		{"wget 已含 -T 不覆盖", "wget -T 5 http://x", ""},
		{"无关命令不变", "nmap -sV 10.0.0.1", ""},
		{"空串不变", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := maybeInjectCmdTimeout(c.in)
			if c.want == "" {
				if got != c.in {
					t.Fatalf("不应注入：in=%q got=%q", c.in, got)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Fatalf("期望注入后含 %q，实际 %q", c.want, got)
			}
		})
	}
}

func TestExtractFlagValue(t *testing.T) {
	if v := extractFlagValue("-w /a/b.txt -mc 200", "-w", "--wordlist"); v != "/a/b.txt" {
		t.Fatalf("-w 提取错误: %q", v)
	}
	if v := extractFlagValue("--wordlist /c/d.txt", "-w", "--wordlist"); v != "/c/d.txt" {
		t.Fatalf("--wordlist 提取错误: %q", v)
	}
	if v := extractFlagValue("-u http://x", "-w", "--wordlist"); v != "" {
		t.Fatalf("无匹配应返回空: %q", v)
	}
}

func TestResolveFfufWordlist(t *testing.T) {
	tc := &config.ToolConfig{
		Parameters: []config.ParameterConfig{
			{Name: "wordlist", Default: "/default/common.txt"},
		},
	}
	// 显式参数优先
	if v := resolveFfufWordlist(map[string]interface{}{"wordlist": "/explicit.txt"}, tc); v != "/explicit.txt" {
		t.Fatalf("显式 wordlist 优先级错误: %q", v)
	}
	// additional_args 中的 -w 次之
	if v := resolveFfufWordlist(map[string]interface{}{"additional_args": "-u http://x -w /from/args"}, tc); v != "/from/args" {
		t.Fatalf("additional_args -w 解析错误: %q", v)
	}
	// 兜底取 yaml 默认值
	if v := resolveFfufWordlist(map[string]interface{}{}, tc); v != "/default/common.txt" {
		t.Fatalf("默认 wordlist 解析错误: %q", v)
	}
}

func TestPreflightToolPaths(t *testing.T) {
	e := &Executor{}

	// nuclei 显式指定 template 时跳过内置目录校验（返回空）。
	if msg := e.preflightToolPaths("nuclei", &config.ToolConfig{}, map[string]interface{}{"template": "/tmp/x.yaml"}); msg != "" {
		t.Fatalf("nuclei 显式 template 应跳过预检，实际: %q", msg)
	}
	// nuclei 显式 additional_args 含 -t 时同样跳过。
	if msg := e.preflightToolPaths("nuclei", &config.ToolConfig{}, map[string]interface{}{"additional_args": "-t /tmp/t/"}); msg != "" {
		t.Fatalf("nuclei additional_args -t 应跳过预检，实际: %q", msg)
	}

	// nuclei 无模板：仅当本机默认模板目录确实不存在时验证 soft error 触发（存在则跳过）。
	if dir := defaultNucleiTemplatesDir(); dir != "" && !pathExists(dir) {
		if msg := e.preflightToolPaths("nuclei", &config.ToolConfig{}, map[string]interface{}{}); msg == "" {
			t.Fatalf("nuclei 模板目录缺失时应返回 soft error")
		}
	}

	// ffuf 字典不存在时返回 soft error。
	msg := e.preflightToolPaths("ffuf", &config.ToolConfig{}, map[string]interface{}{"wordlist": "/definitely/not/here/xyz.txt"})
	if msg == "" || !strings.Contains(msg, "ffuf 字典路径不存在") {
		t.Fatalf("ffuf 字典缺失应返回结构化错误，实际: %q", msg)
	}

	// 未知工具不做预检。
	if msg := e.preflightToolPaths("nmap", &config.ToolConfig{}, map[string]interface{}{}); msg != "" {
		t.Fatalf("nmap 不应触发预检，实际: %q", msg)
	}
}
