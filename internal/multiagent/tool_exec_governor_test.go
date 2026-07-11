package multiagent

import (
	"context"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/einomcp"

	"github.com/cloudwego/eino/compose"
)

func TestResolveMCPToolTimeout(t *testing.T) {
	cases := []struct {
		name       string
		tool       string
		defaultSec int
		perTool    map[string]int
		want       time.Duration
	}{
		{"scanner 分档", "nuclei", 600, nil, 900 * time.Second},
		{"exploit 分档", "sqlmap", 600, nil, 1800 * time.Second},
		{"recon 走默认", "nmap", 600, nil, 600 * time.Second},
		{"per-tool 覆盖分档", "nuclei", 600, map[string]int{"nuclei": 120}, 120 * time.Second},
		{"per-tool 负数=不限", "nuclei", 600, map[string]int{"nuclei": -1}, 0},
		{"默认 0=不限", "nmap", 0, nil, 0},
		{"剥离前缀 ext__", "ext__nuclei", 600, nil, 900 * time.Second},
		{"未知工具走默认", "fancy-tool", 600, nil, 600 * time.Second},
		{"execute 跳过（已有 shell 超时体系）", "execute", 600, nil, 0},
		{"exec 跳过", "exec", 600, nil, 0},
	}
	for _, c := range cases {
		if got := resolveMCPToolTimeout(c.tool, c.defaultSec, c.perTool); got != c.want {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestAcquire_CancelAndSuccess(t *testing.T) {
	// 占满的 semaphore 在 ctx 取消时 acquire 返回 false。
	sem := make(chan struct{}, 1)
	sem <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	if _, ok := acquire(ctx, sem); ok {
		t.Fatal("占满的 semaphore 不应 acquire 成功")
	}

	// 有空位时 acquire 成功并归还。
	sem2 := make(chan struct{}, 2)
	release, ok := acquire(context.Background(), sem2)
	if !ok {
		t.Fatal("有空位应 acquire 成功")
	}
	release()
	if len(sem2) != 0 {
		t.Fatalf("release 后槽位应清空，剩 %d", len(sem2))
	}
}

func TestConcurrencyLimit_BlocksBeyondCap(t *testing.T) {
	cfg := executionToolMiddlewareConfig{ConversationID: "test-block-cap"}
	mgr := &sessionSemaphores{}
	mw := concurrencyLimitInvokable(cfg, mgr, 1) // 容量 1

	proceed := make(chan struct{})
	occupied := make(chan struct{})
	hold := compose.InvokableToolEndpoint(func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
		close(occupied)
		<-proceed
		return &compose.ToolOutput{Result: "ok"}, nil
	})
	wrapped := mw(hold)

	go func() { _, _ = wrapped(context.Background(), &compose.ToolInput{Name: "a"}) }()
	<-occupied // 第一个已占住唯一槽位

	// 第二个应被阻塞：用短 ctx 取消验证它没立即拿到槽位。
	ctx2, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := wrapped(ctx2, &compose.ToolInput{Name: "b"})
		done <- e
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("第二个调用在被占满时应因 ctx 取消返回错误，不应成功")
		}
	case <-time.After(time.Second):
		t.Fatal("第二个调用应被阻塞，但不应等待超过 1s")
	}
	close(proceed) // 释放第一个
}

func TestConcurrencyLimit_ZeroIsUnlimited(t *testing.T) {
	cfg := executionToolMiddlewareConfig{ConversationID: "test-unlimited"}
	mgr := &sessionSemaphores{}
	mw := concurrencyLimitInvokable(cfg, mgr, 0) // 0 = 不限
	called := make(chan struct{}, 5)
	next := compose.InvokableToolEndpoint(func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
		called <- struct{}{}
		return &compose.ToolOutput{Result: "ok"}, nil
	})
	wrapped := mw(next)
	for i := 0; i < 5; i++ {
		if _, err := wrapped(context.Background(), &compose.ToolInput{Name: "x"}); err != nil {
			t.Fatalf("unlimited 不应阻塞: %v", err)
		}
	}
	if len(called) != 5 {
		t.Fatalf("0=不限应放行全部，got %d", len(called))
	}
}

func TestPerCallTimeout_InvokableSoftError(t *testing.T) {
	cfg := executionToolMiddlewareConfig{ConversationID: "test-pcall"}
	// sqlmap 分档 1800s 太长，用 per-tool 覆盖为 1s 加速测试。
	mw := perCallTimeoutInvokable(cfg, 600, map[string]int{"slowtool": 1})

	slow := compose.InvokableToolEndpoint(func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
		select {
		case <-time.After(3 * time.Second):
			return &compose.ToolOutput{Result: "done"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	wrapped := mw(slow)
	start := time.Now()
	out, err := wrapped(context.Background(), &compose.ToolInput{Name: "slowtool"})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("超时应返回 nil error 让图继续，got err=%v", err)
	}
	if out == nil || !strings.HasPrefix(out.Result, einomcp.ToolErrorPrefix) {
		t.Fatalf("超时应返回 soft error 前缀，got %q", ternaryOut(out))
	}
	if !strings.Contains(out.Result, "timeout") || !strings.Contains(out.Result, "retryable: true") {
		t.Fatalf("超时文案应含 timeout 与 retryable: %q", out.Result)
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("应在 ~1s 超时，实际 %v", elapsed)
	}
}

func ternaryOut(o *compose.ToolOutput) string {
	if o == nil {
		return "<nil>"
	}
	return o.Result
}
