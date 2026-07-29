package multiagent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type blockingSummaryModel struct{}

func (blockingSummaryModel) Generate(ctx context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingSummaryModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	panic("summarization deadline test does not use Stream")
}

func TestSummarizationDeadlineFallsBackDeterministically(t *testing.T) {
	input := []*schema.Message{
		schema.UserMessage("测试 https://target.test，禁止越出授权范围"),
		schema.AssistantMessage("", []schema.ToolCall{{
			ID: "call-1",
			Function: schema.FunctionCall{
				Name:      "http-framework-test",
				Arguments: `{"url":"https://target.test/api"}`,
			},
		}}),
		schema.ToolMessage("HTTP/1.1 404 Not Found", "call-1"),
	}
	wrapped := newSummarizationDeadlineModel(blockingSummaryModel{}, 20*time.Millisecond, nil, "conv-1")

	start := time.Now()
	got, err := wrapped.Generate(context.Background(), input)
	if err != nil {
		t.Fatalf("deadline fallback must be returned as a valid summary: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("summary call exceeded bounded deadline: %s", elapsed)
	}
	if got == nil || !strings.Contains(got.Content, "https://target.test") || !strings.Contains(got.Content, "404 Not Found") {
		t.Fatalf("fallback must retain recent user goal and tool fact, got %#v", got)
	}
	if !strings.Contains(got.Content, "摘要模型超时") {
		t.Fatalf("fallback must identify deterministic degradation, got %q", got.Content)
	}
}

func TestDeterministicSummaryBoundsLargeToolOutput(t *testing.T) {
	large := strings.Repeat("A", 20_000)
	got := deterministicSummarizationFallback([]*schema.Message{
		schema.UserMessage("继续验证目标"),
		schema.ToolMessage(large, "call-large"),
	})
	if len(got) > 8_000 {
		t.Fatalf("fallback must remain bounded, length=%d", len(got))
	}
	if !strings.Contains(got, "继续验证目标") {
		t.Fatal("fallback must retain the user goal")
	}
}
