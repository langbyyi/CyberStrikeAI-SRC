package multiagent

import (
	"context"
	"errors"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

const (
	defaultEinoRunRetryMaxAttempts = 10
	defaultEinoRunRetryMaxBackoff  = 30 * time.Second
)

// isEinoTransientRunError 判断 ADK 运行期错误是否适合指数退避续跑（429、5xx、网络抖动等）。
// 用户取消、超时、迭代上限等由 run loop 单独处理，不在此列。
func isEinoTransientRunError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if isEinoIterationLimitError(err) {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	transientMarkers := []string{
		"406",
		"429",
		"too many requests",
		"rate limit",
		"rate_limit",
		"ratelimit",
		"quota exceeded",
		"overloaded",
		"capacity",
		"temporarily unavailable",
		"service unavailable",
		"bad gateway",
		"gateway timeout",
		"internal server error",
		"connection reset",
		"connection refused",
		"connection closed",
		"i/o timeout",
		"no such host",
		"network is unreachable",
		"broken pipe",
		"read tcp",
		"write tcp",
		"dial tcp",
		"tls handshake timeout",
		"stream error",
		"unexpected eof",
		`": eof`, // net/http: Post "url": EOF (often wraps io.EOF)
		"unexpected end of json",
		"status code: 406",
		"status code: 502",
		"502",
		"503",
		"504",
		"500",
	}
	for _, m := range transientMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

func einoRunRetryMaxAttempts(args *einoADKRunLoopArgs) int {
	if args != nil && args.RunRetryMaxAttempts > 0 {
		return args.RunRetryMaxAttempts
	}
	return defaultEinoRunRetryMaxAttempts
}

// RunRetryMaxAttemptsFromConfig 供 handler 分段续跑计数（与 eino_middleware.run_retry_max_attempts 一致）。
func RunRetryMaxAttemptsFromConfig(mw *config.MultiAgentEinoMiddlewareConfig) int {
	if mw != nil && mw.RunRetryMaxAttempts > 0 {
		return mw.RunRetryMaxAttempts
	}
	return defaultEinoRunRetryMaxAttempts
}

// TransientRetryBackoff 供 handler 在分段续跑前退避。
func TransientRetryBackoff(attempt int, maxBackoffSec int) time.Duration {
	max := defaultEinoRunRetryMaxBackoff
	if maxBackoffSec > 0 {
		max = time.Duration(maxBackoffSec) * time.Second
	}
	return einoTransientRetryBackoff(attempt, max)
}

func einoRunRetryMaxBackoff(args *einoADKRunLoopArgs) time.Duration {
	if args != nil && args.RunRetryMaxBackoffSec > 0 {
		return time.Duration(args.RunRetryMaxBackoffSec) * time.Second
	}
	return defaultEinoRunRetryMaxBackoff
}

// einoRunRestartContextSource 描述无 checkpoint Resume 时 Run 使用的消息来源（日志/SSE）。
type einoRunRestartContextSource string

const (
	einoRestartContextInitial     einoRunRestartContextSource = "initial"
	einoRestartContextAccumulated einoRunRestartContextSource = "accumulated"
	einoRestartContextModelTrace  einoRunRestartContextSource = "model_trace"
)

// einoMessagesForRunRestart 在退避后重新 Run 时选用最完整的上下文：
// 1) ModelFacingTrace（与模型实际入参一致） 2) 事件流累积的 runAccumulatedMsgs 3) 初始 msgs。
func einoMessagesForRunRestart(args *einoADKRunLoopArgs, baseMsgs, accumulated []adk.Message, baseCount int) ([]adk.Message, einoRunRestartContextSource) {
	if trace := persistTraceSource(args, nil); len(trace) > 0 {
		return append([]adk.Message(nil), trace...), einoRestartContextModelTrace
	}
	if len(accumulated) > baseCount {
		return append([]adk.Message(nil), accumulated...), einoRestartContextAccumulated
	}
	return append([]adk.Message(nil), baseMsgs...), einoRestartContextInitial
}

// adkMessagesHasUserContent 从尾部向前查找，是否已有与 want 相同的 user 消息（避免重复 append）。
func adkMessagesHasUserContent(msgs []adk.Message, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return true
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		if m == nil {
			continue
		}
		if m.Role == schema.User {
			return strings.TrimSpace(m.Content) == want
		}
		if m.Role == schema.Assistant || m.Role == schema.Tool {
			continue
		}
		break
	}
	return false
}

// appendUserMessageIfNeeded 在 history 轨迹之后追加本轮 user 消息（仅当轨迹中尚未包含该句）。
func appendUserMessageIfNeeded(msgs []adk.Message, userMessage string) []adk.Message {
	if strings.TrimSpace(userMessage) == "" || adkMessagesHasUserContent(msgs, userMessage) {
		return msgs
	}
	return append(msgs, schema.UserMessage(userMessage))
}

// einoTransientRetryBackoff 指数退避：2s, 4s, 8s… capped by maxBackoff。
func einoTransientRetryBackoff(attempt int, maxBackoff time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	backoff := time.Duration(1<<uint(attempt+1)) * time.Second
	if maxBackoff > 0 && backoff > maxBackoff {
		backoff = maxBackoff
	}
	return backoff
}
