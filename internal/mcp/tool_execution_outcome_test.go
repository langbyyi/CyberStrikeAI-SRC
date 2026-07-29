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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyToolExecutionSemanticOutcome(tt.exec); got != tt.want {
				t.Fatalf("outcome=%q want=%q", got, tt.want)
			}
		})
	}
}
