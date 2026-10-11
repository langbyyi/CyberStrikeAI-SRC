//go:build !windows

package security

import (
	"cyberstrike-ai/internal/config"
	"gopkg.in/yaml.v3"
	"os"
	"reflect"
	"testing"
)

func TestNmapScanTypeDoesNotSplitScriptOptionAndValue(t *testing.T) {
	data, err := os.ReadFile("../../tools/nmap.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var tool config.ToolConfig
	if err := yaml.Unmarshal(data, &tool); err != nil {
		t.Fatal(err)
	}
	executor, _ := setupTestExecutor(t)
	for _, tc := range []struct {
		additional, script string
		expected           []string
	}{
		{"-Pn --script http-headers,http-title,http-server-header", "", []string{"-sT", "-sV", "-sC", "-p", "18081", "192.0.2.1", "-Pn", "--script", "http-headers,http-title,http-server-header"}},
		{"-Pn --max-retries 3", "http-title", []string{"-sT", "-sV", "-sC", "-p", "18081", "--script", "http-title", "192.0.2.1", "-Pn", "--max-retries", "3"}},
	} {
		args := map[string]interface{}{"target": "192.0.2.1", "ports": "18081", "scan_type": "-sT -sV -sC", "additional_args": tc.additional, "nse_scripts": tc.script}
		actual := executor.buildCommandArgs("nmap", &tool, args)
		if !reflect.DeepEqual(actual, tc.expected) {
			t.Fatalf("argument ordering: got %v want %v", actual, tc.expected)
		}
	}
}
