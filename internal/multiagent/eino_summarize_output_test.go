package multiagent

import (
	"strings"
	"testing"

	"github.com/cloudwego/eino/schema"
)

func TestStripAnalysisFromSummarizationText(t *testing.T) {
	in := "<analysis>internal notes</analysis>\n\n<summary>\n## 1. 授权\n- example.com\n</summary>"
	got := stripAnalysisFromSummarizationText(in)
	if strings.Contains(got, "<analysis>") {
		t.Fatalf("analysis block should be removed: %q", got)
	}
	if !strings.Contains(got, "## 1. 授权") {
		t.Fatalf("summary body should remain: %q", got)
	}
}

func TestStripAnalysisFromSummarizationMessage_UserInputMultiContent(t *testing.T) {
	msg := &schema.Message{
		Role: schema.User,
		UserInputMultiContent: []schema.MessageInputPart{
			{
				Type: schema.ChatMessagePartTypeText,
				Text: "此会话延续自此前一段因上下文耗尽而终止的对话。\n\n<analysis>draft</analysis>\n<summary>body</summary>\n\n完整记录位于：/tmp/transcript.txt",
			},
			{
				Type: schema.ChatMessagePartTypeText,
				Text: "请从我们中断的地方继续对话，无需向用户提出任何进一步的问题。",
			},
		},
	}
	out := stripAnalysisFromSummarizationMessage(msg)
	if len(out.UserInputMultiContent) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(out.UserInputMultiContent))
	}
	if strings.Contains(out.UserInputMultiContent[0].Text, "<analysis>") {
		t.Fatalf("part 0 should drop analysis: %q", out.UserInputMultiContent[0].Text)
	}
	if !strings.Contains(out.UserInputMultiContent[0].Text, "<summary>body</summary>") {
		t.Fatalf("part 0 should keep summary: %q", out.UserInputMultiContent[0].Text)
	}
	if out.UserInputMultiContent[1].Text != "请从我们中断的地方继续对话，无需向用户提出任何进一步的问题。" {
		t.Fatalf("continue instruction part should be unchanged: %q", out.UserInputMultiContent[1].Text)
	}
}

func TestExtractSummarizationSummaryBody(t *testing.T) {
	body, ok := extractSummarizationSummaryBody("<analysis>x</analysis><summary>  kept  </summary>")
	if !ok || body != "kept" {
		t.Fatalf("extract summary body: ok=%v body=%q", ok, body)
	}
	_, ok = extractSummarizationSummaryBody("plain text only")
	if ok {
		t.Fatal("expected false for plain text")
	}
}

func TestStripAnalysisFromSummarizationText_NoAnalysisUnchanged(t *testing.T) {
	in := "<summary>only summary</summary>"
	got := stripAnalysisFromSummarizationText(in)
	if got != in {
		t.Fatalf("expected unchanged text, got %q", got)
	}
}
