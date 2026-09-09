package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestBlockedExecutionIsTerminalAndNotFailed(t *testing.T) {
	for _, blocked := range []bool{true, false} {
		name := "error"
		want := ToolExecutionStatusFailed
		if blocked {
			name, want = "blocked", ToolExecutionStatusBlocked
		}
		t.Run(name, func(t *testing.T) {
			service := NewExecutionService(nil, nil)
			handle, err := service.Submit(context.Background(), ExecutionRequest{
				ToolName: "test",
				Run: func(context.Context) (*ToolResult, error) {
					// Identical text must not turn ordinary failures into policy blocks.
					return &ToolResult{Content: []Content{{Type: "text", Text: toolGuardBlockedPrefix}}, IsError: true, Blocked: blocked}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			snap, err := service.Wait(context.Background(), handle.ID, time.Second)
			if err != nil || snap.Execution.Status != want || snap.Execution.Result.Blocked != blocked || snap.Execution.Error == "" {
				t.Fatalf("incorrect classification: snapshot=%#v err=%v", snap, err)
			}
			if !isExecutionTerminal(want) || executionStatusCountsAsFailed(want) == blocked {
				t.Fatalf("incorrect terminal/failure classification for %s", want)
			}
			if service.Cancel(handle.ID, "cancel after completion") {
				t.Fatal("terminal execution must not be cancellable")
			}
			after, _ := service.Get(handle.ID)
			if after.Execution.Status != want {
				t.Fatalf("cancel reclassified terminal execution: %s", after.Execution.Status)
			}
		})
	}
}

func TestBlockedMarkerSurvivesNormalizationAndMCPProtocol(t *testing.T) {
	original := &ToolResult{Content: []Content{{Type: "text", Text: strings.Repeat("refused ", 2000)}}, IsError: true, Blocked: true}
	bounded := NormalizeToolResultForStorageWithSpill(original, 1000, ToolResultSpillConfig{RootDir: t.TempDir(), ExecutionID: "blocked"})
	if !bounded.Blocked || !bounded.IsError || ToolResultPlainText(bounded) == ToolResultPlainText(original) {
		t.Fatal("normalization must retain classification while bounding long output")
	}
	wire, err := json.Marshal(CallToolResponse{Content: bounded.Content, IsError: bounded.IsError, Blocked: bounded.Blocked, Meta: toolResultProtocolMeta(bounded)})
	if err != nil {
		t.Fatal(err)
	}
	var decoded ToolResult
	if err := json.Unmarshal(wire, &decoded); err != nil || !decoded.Blocked || !decoded.IsError {
		t.Fatalf("application protocol lost block marker: %#v err=%v", decoded, err)
	}
	var sdkResult sdkmcp.CallToolResult
	if err := json.Unmarshal(wire, &sdkResult); err != nil {
		t.Fatal(err)
	}
	converted := sdkCallToolResultToOurs(&sdkResult)
	if !converted.Blocked || !converted.IsError {
		t.Fatalf("SDK round trip lost block marker: %#v", converted)
	}
}

func TestToolStatsSeparateBlockedFromFailures(t *testing.T) {
	server := NewServer(nil)
	manager := NewExternalMCPManager(nil)
	for _, status := range []string{ToolExecutionStatusCompleted, ToolExecutionStatusFailed, ToolExecutionStatusBlocked, ToolExecutionStatusCancelled} {
		server.updateStats("test", status)
		manager.updateStats("test", status)
	}
	for name, stat := range map[string]*ToolStats{"internal": server.stats["test"], "external": manager.stats["test"]} {
		if stat.TotalCalls != 4 || stat.SuccessCalls != 1 || stat.FailedCalls != 1 || stat.BlockedCalls != 1 {
			t.Fatalf("%s stats = %#v", name, stat)
		}
	}
}
