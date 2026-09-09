package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadToolGuardDefaultsAndValidation(t *testing.T) {
	for _, tc := range []struct {
		name, yaml       string
		enabled, wantErr bool
	}{
		{"legacy config", "server: {port: 8080}\n", true, false},
		{"null section", "tool_guard: null\n", true, false},
		{"implicit null section", "tool_guard:\n", true, false},
		{"explicit off", "tool_guard: {enabled: false, rules: []}\n", false, false},
		{"explicit empty", "tool_guard: {enabled: true, rules: []}\n", true, false},
		{"merged explicit config", "guard_defaults: &guard_defaults {enabled: false, rules: []}\ntool_guard: {<<: *guard_defaults}\n", false, false},
		{"empty section", "tool_guard: {}\n", false, true},
		{"missing enabled", "tool_guard: {rules: []}\n", false, true},
		{"null enabled", "tool_guard: {enabled: null, rules: []}\n", false, true},
		{"missing rules while off", "tool_guard: {enabled: false}\n", false, true},
		{"missing rules while on", "tool_guard: {enabled: true}\n", false, true},
		{"null rules", "tool_guard: {enabled: false, rules: null}\n", false, true},
		{"mistyped enabled field", "tool_guard: {enable: false, rules: []}\n", false, true},
		{"malformed rules while off", "tool_guard: {enabled: false, rules: disabled}\n", false, true},
		{"malformed rule while off", "tool_guard: {enabled: false, rules: [invalid]}\n", false, true},
		{"invalid pattern", "tool_guard:\n  enabled: false\n  rules:\n    - {id: invalid, name: invalid, enabled: false, pattern: '['}\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("load error: %v", err)
			}
			if err == nil && cfg.EffectiveToolGuard().Enabled != tc.enabled {
				t.Fatal("wrong effective enabled state")
			}
		})
	}
}
