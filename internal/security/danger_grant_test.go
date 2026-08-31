package security

import (
	"context"
	"strings"
	"testing"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/config"
	"go.uber.org/zap"
)

func TestDangerousInvocationRequiresMatchingInternalGrant(t *testing.T) {
	args := map[string]interface{}{"command": "curl -X DELETE https://target.example/api/users/1"}
	if DangerousInvocationGranted(context.Background(), "exec", args) {
		t.Fatal("dangerous call passed without grant")
	}
	grant := approval.NewGrantForTesting(approval.GrantSpec{ApprovalID: "apr-1", InvocationID: "inv-1", ToolName: "exec", Arguments: args})
	ctx := approval.WithGrant(context.Background(), grant)
	if !DangerousInvocationGranted(ctx, "exec", args) {
		t.Fatal("exact frozen call did not match grant")
	}
	if DangerousInvocationGranted(ctx, "exec", map[string]interface{}{"command": "curl -X DELETE https://target.example/api/users/2"}) {
		t.Fatal("grant was reused for different arguments")
	}
	if DangerousInvocationGranted(ctx, "other", args) {
		t.Fatal("grant was reused for different tool")
	}
}

func TestExecutorDangerBlockDoesNotExposeModelUnlockProtocol(t *testing.T) {
	executor := NewExecutor(&config.SecurityConfig{}, nil, zap.NewNop())
	result, err := executor.ExecuteTool(context.Background(), "exec", map[string]interface{}{
		"command": "curl -X DELETE https://target.example/api/users/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.IsError || len(result.Content) == 0 {
		t.Fatalf("result = %+v", result)
	}
	text := result.Content[0].Text
	for _, forbidden := range []string{"confirm_token", "confirm_destructive", "用相同参数重试"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("danger block exposed %q: %s", forbidden, text)
		}
	}
}
