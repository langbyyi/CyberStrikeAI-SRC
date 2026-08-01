package mcp

import "testing"

func TestClassifyToolExecutionSemanticOutcome(t *testing.T) {
	tests := []struct {
		name string
		exec *ToolExecution
		want string
	}{
		{
			name: "transport success with stable negative target result",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "completed",
				Result:   &ToolResult{Content: []Content{{Type: "text", Text: "HTTP/1.1 404 Not Found"}}},
			},
			want: SemanticOutcomeTargetNegative,
		},
		{
			name: "schema failure",
			exec: &ToolExecution{
				ToolName: "upsert_project_fact",
				Status:   "failed",
				Error:    "invalid arguments: links 须为数组",
			},
			want: SemanticOutcomeInvocationError,
		},
		{
			name: "policy rejection",
			exec: &ToolExecution{
				ToolName: "record_vulnerability",
				Status:   "completed",
				Result:   &ToolResult{IsError: true, Content: []Content{{Type: "text", Text: "【硬拒绝·禁止换分类重试】CORS 不收录"}}},
			},
			want: SemanticOutcomePolicyRejected,
		},
		{
			name: "transient reset",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "failed",
				Error:    "connection reset by peer",
			},
			want: SemanticOutcomeExternalTransient,
		},
		{
			name: "normal completion",
			exec: &ToolExecution{
				ToolName: "execute",
				Status:   "completed",
				Result:   &ToolResult{Content: []Content{{Type: "text", Text: "done"}}},
			},
			want: SemanticOutcomeCompleted,
		},
		{
			name: "transport success with SPA shell",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "completed",
				Result: &ToolResult{Content: []Content{{Type: "text", Text: `Content-Type: text/html
<html><body><div id="app"></div><script src="/assets/app.abcdef12.js"></script></body></html>`}}},
			},
			want: SemanticOutcomeTargetNegative,
		},
		{
			name: "target DNS failure",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "failed",
				Error:    "dial tcp: lookup target.test: name resolution failed",
			},
			want: SemanticOutcomeTargetNegative,
		},
		{
			name: "HTTP2 stream reset",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "failed",
				Error:    "http/2 stream 1 was not closed cleanly: INTERNAL_ERROR",
			},
			want: SemanticOutcomeExternalTransient,
		},
		{
			name: "HTTP2 stable negative status",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "completed",
				Result:   &ToolResult{Content: []Content{{Type: "text", Text: "HTTP/2 404 Not Found"}}},
			},
			want: SemanticOutcomeTargetNegative,
		},
		{
			name: "HTTP2 server failure status",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "completed",
				Result:   &ToolResult{Content: []Content{{Type: "text", Text: "HTTP/2 503 Service Unavailable"}}},
			},
			want: SemanticOutcomeExternalTransient,
		},
		{
			name: "HTTP 401 is auth rejected",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "completed",
				Result:   &ToolResult{Content: []Content{{Type: "text", Text: "HTTP/1.1 401 Unauthorized"}}},
			},
			want: SemanticOutcomeAuthRejected,
		},
		{
			name: "HTTP 403 is auth rejected",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "completed",
				Result:   &ToolResult{Content: []Content{{Type: "text", Text: "HTTP/1.1 403 Forbidden"}}},
			},
			want: SemanticOutcomeAuthRejected,
		},
		{
			name: "login failed body is auth rejected",
			exec: &ToolExecution{
				ToolName: "http-framework-test",
				Status:   "completed",
				Result:   &ToolResult{Content: []Content{{Type: "text", Text: "密码错误，剩余 4 次尝试机会"}}},
			},
			want: SemanticOutcomeAuthRejected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyToolExecutionSemanticOutcome(tt.exec); got != tt.want {
				t.Fatalf("outcome=%q want=%q", got, tt.want)
			}
		})
	}
}

func TestTargetSQLErrorIsNotInvocationError(t *testing.T) {
	exec := &ToolExecution{Status: "completed", Result: &ToolResult{Content: []Content{{Type: "text", Text: "HTTP/1.1 500 Internal Server Error\nSQL syntax error near quote"}}}}
	if got := ClassifyToolExecutionSemanticOutcome(exec); got == SemanticOutcomeInvocationError {
		t.Fatal("target SQL error must not be classified as invocation error")
	}
}

func TestToolInvocationSQLErrorRemainsInvocationError(t *testing.T) {
	exec := &ToolExecution{Status: "failed", Error: "SQL syntax error in tool query"}
	if got := ClassifyToolExecutionSemanticOutcome(exec); got != SemanticOutcomeInvocationError {
		t.Fatalf("tool-side SQL error must remain invocation error, got %q", got)
	}
}
