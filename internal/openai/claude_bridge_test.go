package openai

import "testing"

func TestConvertOpenAIToClaudeMapsTokenLimitFields(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]interface{}
		want    int
	}{
		{
			name:    "max_tokens",
			payload: map[string]interface{}{"max_tokens": 321},
			want:    321,
		},
		{
			name:    "max_completion_tokens",
			payload: map[string]interface{}{"max_completion_tokens": 654},
			want:    654,
		},
		{
			name:    "max_tokens takes precedence",
			payload: map[string]interface{}{"max_tokens": 111, "max_completion_tokens": 222},
			want:    111,
		},
		{
			name:    "default",
			payload: map[string]interface{}{},
			want:    8192,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := convertOpenAIToClaude(tc.payload)
			if err != nil {
				t.Fatalf("convertOpenAIToClaude: %v", err)
			}
			if got.MaxTokens != tc.want {
				t.Fatalf("MaxTokens=%d want %d", got.MaxTokens, tc.want)
			}
		})
	}
}
