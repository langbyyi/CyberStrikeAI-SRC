package multiagent

import (
	"regexp"
	"strings"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

var (
	summarizationAnalysisBlockRegex = regexp.MustCompile(`(?is)<analysis>\s*.*?\s*</analysis>`)
	summarizationSummaryBlockRegex  = regexp.MustCompile(`(?is)<summary>\s*(.*?)\s*</summary>`)
)

// stripAnalysisFromSummarizationMessage removes the <analysis> block from a post-processed
// Eino summary user message. Analysis helps one-shot generation quality but should not
// occupy continuation context after compaction.
func stripAnalysisFromSummarizationMessage(msg adk.Message) adk.Message {
	if msg == nil {
		return msg
	}
	cloned := *msg
	if cloned.Content != "" {
		cloned.Content = stripAnalysisFromSummarizationText(cloned.Content)
	}
	if len(cloned.UserInputMultiContent) > 0 {
		parts := make([]schema.MessageInputPart, len(cloned.UserInputMultiContent))
		copy(parts, cloned.UserInputMultiContent)
		// Only the first text part carries model output plus Eino preamble/transcript path.
		for i := range parts {
			if parts[i].Type != schema.ChatMessagePartTypeText || parts[i].Text == "" {
				continue
			}
			if i == 0 {
				parts[i].Text = stripAnalysisFromSummarizationText(parts[i].Text)
			}
			break
		}
		cloned.UserInputMultiContent = parts
	}
	return &cloned
}

func stripAnalysisFromSummarizationText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return text
	}
	stripped := strings.TrimSpace(summarizationAnalysisBlockRegex.ReplaceAllString(text, ""))
	if stripped == "" {
		return text
	}
	return stripped
}

// extractSummarizationSummaryBody returns the inner text of the last <summary> block when present.
// Used by tests and optional strict compaction paths.
func extractSummarizationSummaryBody(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", false
	}
	all := summarizationSummaryBlockRegex.FindAllStringSubmatch(text, -1)
	if len(all) == 0 || len(all[len(all)-1]) < 2 {
		return "", false
	}
	body := strings.TrimSpace(all[len(all)-1][1])
	if body == "" {
		return "", false
	}
	return body, true
}
