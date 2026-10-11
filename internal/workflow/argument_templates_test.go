package workflow

import (
	"testing"
)

func TestToolArgumentTemplatesResolveAfterJSONParsing(t *testing.T) {
	state := newWorkflowLocalState(map[string]interface{}{"target": "https://example.test/a?x=\"quoted\"\nnext"}, "run")
	cfg := map[string]any{"arguments": `{"target":"{{inputs.target}}","headers":{"label":"probe {{inputs.target}}"},"items":["{{inputs.target}}",{"count":2}],"empty":"","enabled":true}`}
	args, err := resolveToolArguments(cfg, state)
	if err != nil {
		t.Fatal(err)
	}
	if args["target"] != state.Inputs["target"] {
		t.Fatalf("unexpanded target: %#v", args)
	}
	if args["headers"].(map[string]interface{})["label"] != "probe "+state.Inputs["target"].(string) {
		t.Fatal("nested template did not resolve")
	}
	if args["items"].([]interface{})[0] != state.Inputs["target"] {
		t.Fatal("array template did not resolve")
	}
	if args["empty"] != "" || args["enabled"] != true {
		t.Fatal("non-template values changed")
	}
}

func TestExplicitToolArgumentBindingsRemainAuthoritative(t *testing.T) {
	state := newWorkflowLocalState(map[string]interface{}{"port": 8080}, "run")
	cfg := map[string]any{"arguments": `{"port":"wrong"}`, "argument_bindings": map[string]any{"port": map[string]any{"from": "inputs", "field": "port"}}}
	args, err := resolveToolArguments(cfg, state)
	if err != nil || args["port"] != 8080 {
		t.Fatalf("binding changed: %#v %v", args, err)
	}
}
