package multiagent

import (
	"github.com/bytedance/sonic"
)

// stripReasoningFromSummarizationPayload removes thinking / reasoning fields from a
// chat-completions JSON body. Applied only to summarization Generate calls via
// model.ModelOptions on the shared ChatModel — main-agent requests are unchanged.
func stripReasoningFromSummarizationPayload(rawBody []byte) ([]byte, error) {
	var payload map[string]any
	if err := sonic.Unmarshal(rawBody, &payload); err != nil {
		return rawBody, nil
	}
	changed := false
	for _, key := range []string{
		"thinking",
		"reasoning_effort",
		"output_config",
		"reasoning",
	} {
		if _, ok := payload[key]; ok {
			delete(payload, key)
			changed = true
		}
	}
	if !changed {
		return rawBody, nil
	}
	out, err := sonic.Marshal(payload)
	if err != nil {
		return rawBody, err
	}
	return out, nil
}
