package approval

import "testing"

func TestCanonicalArgumentsStableAcrossMapOrder(t *testing.T) {
	left := map[string]any{
		"b":      2,
		"a":      1,
		"nested": map[string]any{"z": nil, "x": true},
	}
	right := map[string]any{
		"nested": map[string]any{"x": true, "z": nil},
		"a":      1,
		"b":      2,
	}

	const want = `{"a":1,"b":2,"nested":{"x":true,"z":null}}`
	if got := CanonicalArguments(left); got != want {
		t.Fatalf("CanonicalArguments(left) = %q, want %q", got, want)
	}
	if got := CanonicalArguments(right); got != want {
		t.Fatalf("CanonicalArguments(right) = %q, want %q", got, want)
	}
}

func TestInvocationHashStableAcrossMapAndPolicyOrder(t *testing.T) {
	left := Invocation{
		ID:              "inv-1",
		RequesterUserID: "user-1",
		ConversationID:  "conversation-1",
		ProjectID:       "project-1",
		ToolName:        "exec",
		Arguments:       map[string]any{"b": 2, "a": 1},
	}
	right := left
	right.Arguments = map[string]any{"a": 1, "b": 2}

	leftHash := InvocationHash(left, []string{"danger.delete", "tool_approval"})
	rightHash := InvocationHash(right, []string{"tool_approval", "danger.delete"})
	if leftHash != rightHash {
		t.Fatalf("stable invocation hashes differ: %q != %q", leftHash, rightHash)
	}
}

func TestInvocationHashBindsExecutionIdentityAndMatchedPolicy(t *testing.T) {
	base := Invocation{
		ID:              "inv-1",
		RequesterUserID: "user-1",
		ConversationID:  "conversation-1",
		ProjectID:       "project-1",
		ToolName:        "exec",
		Arguments:       map[string]any{"command": "id"},
	}

	variants := []struct {
		name      string
		inv       Invocation
		policyIDs []string
	}{
		{name: "base", inv: base, policyIDs: []string{"danger.exec"}},
		{name: "invocation", inv: invocationWith(base, func(v *Invocation) { v.ID = "inv-2" }), policyIDs: []string{"danger.exec"}},
		{name: "requester", inv: invocationWith(base, func(v *Invocation) { v.RequesterUserID = "user-2" }), policyIDs: []string{"danger.exec"}},
		{name: "conversation", inv: invocationWith(base, func(v *Invocation) { v.ConversationID = "conversation-2" }), policyIDs: []string{"danger.exec"}},
		{name: "project", inv: invocationWith(base, func(v *Invocation) { v.ProjectID = "project-2" }), policyIDs: []string{"danger.exec"}},
		{name: "tool", inv: invocationWith(base, func(v *Invocation) { v.ToolName = "execute-python-script" }), policyIDs: []string{"danger.exec"}},
		{name: "arguments", inv: invocationWith(base, func(v *Invocation) { v.Arguments = map[string]any{"command": "whoami"} }), policyIDs: []string{"danger.exec"}},
		{name: "policy", inv: base, policyIDs: []string{"danger.http-delete"}},
	}

	seen := make(map[string]string, len(variants))
	for _, variant := range variants {
		hash := InvocationHash(variant.inv, variant.policyIDs)
		if previous, exists := seen[hash]; exists {
			t.Fatalf("%s and %s produced the same hash %q", previous, variant.name, hash)
		}
		seen[hash] = variant.name
	}
}

func invocationWith(base Invocation, change func(*Invocation)) Invocation {
	copy := base
	change(&copy)
	return copy
}
