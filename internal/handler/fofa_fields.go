package handler

import "strings"

// normalizeFofaFields accepts the legacy province return-field alias from saved
// forms and API clients. FOFA exports this value as region. Query syntax and
// other search providers do not pass through this conversion.
func normalizeFofaFields(raw string) string {
	fields := splitAndCleanCSV(raw)
	seen := make(map[string]bool, len(fields))
	normalized := make([]string, 0, len(fields))
	for _, field := range fields {
		if field == "province" {
			field = "region"
		}
		if !seen[field] {
			normalized = append(normalized, field)
			seen[field] = true
		}
	}
	return strings.Join(normalized, ",")
}

// splitAndCleanCSV 拆分逗号分隔字段并去重（去空白、丢弃空项）。
func splitAndCleanCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
