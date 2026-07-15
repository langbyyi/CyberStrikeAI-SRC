package multiagent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/einomcp"

	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// 工具执行治理（Execution Plane）：并发上限（P2-b）+ MCP per-call 超时（P2-a）。
// 两项均通过 compose.ToolMiddleware 叠加，覆盖 execute 与 MCP 两条路径（同经 parallelRunToolCall）。
// 默认开启 + 保守值，可经 tool_exec_governor.enable=false 一键回滚。

// MCP 工具 per-call 超时分档（秒）。可被 cfg.ToolExecGovernor.PerToolTimeoutSec 覆盖。
var mcpToolTimeoutBuckets = map[string]int{
	// scanner：模板/字典型扫描器，默认 900s。
	"nuclei": 900, "ffuf": 900, "nikto": 900, "dalfox": 900, "katana": 900,
	"dirsearch": 900, "gobuster": 900, "arjun": 900,
	// http-framework-test is a lightweight request/probe, not a dictionary scan.
	"http-framework-test": 120,
	// exploit：利用类工具，默认 1800s。
	"sqlmap": 1800, "hydra": 1800, "metasploit": 1800,
	// 其余（nmap/masscan/subfinder/rustscan 等侦察类）默认走 defaultDur。
}

// perCallTimeoutSkip 这些工具跳过 per-call 超时：它们是 filesystem/shell 执行类，
// 已有 executor 的 toolTimeoutMinutes（总超时）+ inactivity（无输出兜底）完整体系，
// 再套 per-call 超时会缩短其长任务，故排除（与计划 P2-a「MCP 工具」口径一致）。
var perCallTimeoutSkip = map[string]bool{
	"execute":               true,
	"exec":                  true,
	"execute-python-script": true,
}

// resolveMCPToolTimeout 解析某工具的 per-call 超时：skip 工具 → 0；per-tool 覆盖 > 分档表 > 配置默认值。返回 0 表示不限。
func resolveMCPToolTimeout(toolName string, defaultSec int, perTool map[string]int) time.Duration {
	tn := normalizeToolBaseName(toolName)
	if tn != "" && perCallTimeoutSkip[tn] {
		return 0
	}
	if tn != "" && perTool != nil {
		if v, ok := perTool[strings.ToLower(tn)]; ok && v != 0 {
			return time.Duration(absTimeoutSec(v)) * time.Second
		}
	}
	if tn != "" {
		if v, ok := mcpToolTimeoutBuckets[tn]; ok && v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	if defaultSec <= 0 {
		return 0
	}
	return time.Duration(defaultSec) * time.Second
}

func absTimeoutSec(v int) int {
	if v < 0 {
		return 0 // 负数 = 不限
	}
	return v
}

// sessionSemaphores 按会话隔离并发信号量，避免跨会话相互饿死。
type sessionSemaphores struct {
	mu   sync.Mutex
	sems map[string]chan struct{}
}

func (s *sessionSemaphores) get(sessionKey string, cap int) chan struct{} {
	if cap <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sems == nil {
		s.sems = make(map[string]chan struct{})
	}
	if c, ok := s.sems[sessionKey]; ok {
		return c
	}
	c := make(chan struct{}, cap)
	s.sems[sessionKey] = c
	return c
}

// acquire 阻塞获取一个槽位，ctx 取消时返回 false（调用方应返回 ctx.Err()）。
// 返回 release 必须在成功获取后调用以归还槽位。
func acquire(ctx context.Context, sem chan struct{}) (release func(), ok bool) {
	select {
	case sem <- struct{}{}:
		return func() {
			select {
			case <-sem:
			default:
			}
		}, true
	case <-ctx.Done():
		return func() {}, false
	}
}

// toolExecGovernorMiddlewares 构造治理中间件：并发上限 → per-call 超时（顺序：先限流再超时）。
// 挂载顺序（buildExecutionToolMiddlewares）：hitl → softRecovery → [并发→超时] → executionBoost。
func toolExecGovernorMiddlewares(cfg executionToolMiddlewareConfig) []compose.ToolMiddleware {
	if cfg.MW == nil || !cfg.MW.ToolExecGovernorEffective() {
		return nil
	}
	maxConcurrent := cfg.MW.ToolExecGovernorMaxConcurrentEffective()
	defaultSec := cfg.MW.ToolExecGovernorMCPPerCallTimeoutEffective()
	perTool := cfg.MW.ToolExecGovernor.PerToolTimeoutSec
	return []compose.ToolMiddleware{
		concurrencyLimitMiddleware(cfg, maxConcurrent),
		perCallTimeoutMiddleware(cfg, defaultSec, perTool),
	}
}

// concurrencyLimitMiddleware P2-b：按会话信号量限制并行工具数（默认 5；0=不限）。
func concurrencyLimitMiddleware(cfg executionToolMiddlewareConfig, maxConcurrent int) compose.ToolMiddleware {
	mgr := globalSessionSemaphores
	return compose.ToolMiddleware{
		Invokable:  concurrencyLimitInvokable(cfg, mgr, maxConcurrent),
		Streamable: concurrencyLimitStreamable(cfg, mgr, maxConcurrent),
	}
}

// globalSessionSemaphores 进程级会话信号量表（会话量可控，不主动回收；YAGNI）。
var globalSessionSemaphores = &sessionSemaphores{}

func concurrencyLimitInvokable(cfg executionToolMiddlewareConfig, mgr *sessionSemaphores, maxConcurrent int) compose.InvokableToolMiddleware {
	return func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
			if maxConcurrent <= 0 {
				return next(ctx, input)
			}
			sem := mgr.get(cfg.ConversationID, maxConcurrent)
			if sem == nil {
				return next(ctx, input)
			}
			start := time.Now()
			release, ok := acquire(ctx, sem)
			if !ok {
				return nil, ctx.Err()
			}
			defer release()
			logAcquireWait(cfg, input, time.Since(start))
			return next(ctx, input)
		}
	}
}

func concurrencyLimitStreamable(cfg executionToolMiddlewareConfig, mgr *sessionSemaphores, maxConcurrent int) compose.StreamableToolMiddleware {
	return func(next compose.StreamableToolEndpoint) compose.StreamableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.StreamToolOutput, error) {
			if maxConcurrent <= 0 {
				return next(ctx, input)
			}
			sem := mgr.get(cfg.ConversationID, maxConcurrent)
			if sem == nil {
				return next(ctx, input)
			}
			start := time.Now()
			release, ok := acquire(ctx, sem)
			if !ok {
				return nil, ctx.Err()
			}
			defer release()
			logAcquireWait(cfg, input, time.Since(start))
			return next(ctx, input)
		}
	}
}

func logAcquireWait(cfg executionToolMiddlewareConfig, input *compose.ToolInput, waited time.Duration) {
	if cfg.Logger == nil || waited <= 0 {
		return
	}
	toolName := ""
	if input != nil {
		toolName = input.Name
	}
	cfg.Logger.Info("tool_concurrency_acquire_waited",
		zap.String("tool", toolName),
		zap.String("conversation_id", cfg.ConversationID),
		zap.Duration("waited", waited),
	)
}

// perCallTimeoutMiddleware P2-a：对每个工具调用注入 per-call 超时（按工具分档），超时转 soft error 让图继续。
func perCallTimeoutMiddleware(cfg executionToolMiddlewareConfig, defaultSec int, perTool map[string]int) compose.ToolMiddleware {
	return compose.ToolMiddleware{
		Invokable:  perCallTimeoutInvokable(cfg, defaultSec, perTool),
		Streamable: perCallTimeoutStreamable(cfg, defaultSec, perTool),
	}
}

func perCallTimeoutInvokable(cfg executionToolMiddlewareConfig, defaultSec int, perTool map[string]int) compose.InvokableToolMiddleware {
	return func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
			toolName := ""
			if input != nil {
				toolName = input.Name
			}
			d := resolveMCPToolTimeout(toolName, defaultSec, perTool)
			started := time.Now()
			layer := timeoutLayerFor(ctx, d)
			if d > 0 {
				var cancel context.CancelFunc
				var effective time.Duration
				ctx, cancel, effective = EffectiveChildTimeout(ctx, d)
				d = effective
				defer cancel()
			}
			output, err := next(ctx, input)
			if d > 0 && ctx.Err() != nil {
				if output == nil {
					output = &compose.ToolOutput{}
				}
				code := "cancelled"
				if ctx.Err() == context.DeadlineExceeded {
					code = "timeout"
					logPerCallTimeout(cfg, toolName, d)
					GetConversationExecutionState(cfg.ConversationID).Controller().RecordTimeout()
					if cfg.Progress != nil {
						cfg.Progress("tool_timeout", "工具调用超过执行预算", map[string]interface{}{"tool": toolName, "timeoutLayer": layer})
					}
				}
				outcome := ToolOutcome{Code: code, TimeoutLayer: layer, Retryable: false, RetryLeft: 0, PartialOutput: output.Result, Duration: time.Since(started)}
				output.Result = einomcp.ToolErrorPrefix + RenderToolOutcome(outcome)
				return output, nil
			}
			return output, err
		}
	}
}

func perCallTimeoutStreamable(cfg executionToolMiddlewareConfig, defaultSec int, perTool map[string]int) compose.StreamableToolMiddleware {
	return func(next compose.StreamableToolEndpoint) compose.StreamableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.StreamToolOutput, error) {
			toolName := ""
			if input != nil {
				toolName = input.Name
			}
			d := resolveMCPToolTimeout(toolName, defaultSec, perTool)
			started := time.Now()
			layer := timeoutLayerFor(ctx, d)
			if d > 0 {
				var cancel context.CancelFunc
				var effective time.Duration
				ctx, cancel, effective = EffectiveChildTimeout(ctx, d)
				d = effective
				defer cancel()
			}
			out, err := next(ctx, input)
			if err != nil || out == nil || out.Result == nil {
				return out, err
			}
			// 缓冲整流后判定是否超时（与 executionBoostStreamable 一致的收集语义）。
			var chunks []string
			for {
				chunk, rerr := out.Result.Recv()
				if rerr != nil {
					break
				}
				chunks = append(chunks, chunk)
			}
			out.Result.Close()
			if d > 0 && ctx.Err() != nil {
				code := "cancelled"
				if ctx.Err() == context.DeadlineExceeded {
					code = "timeout"
					logPerCallTimeout(cfg, toolName, d)
					GetConversationExecutionState(cfg.ConversationID).Controller().RecordTimeout()
					if cfg.Progress != nil {
						cfg.Progress("tool_timeout", "流式工具调用超过执行预算", map[string]interface{}{"tool": toolName, "timeoutLayer": layer})
					}
				}
				outcome := ToolOutcome{Code: code, TimeoutLayer: layer, Retryable: false, RetryLeft: 0, PartialOutput: strings.Join(chunks, ""), Duration: time.Since(started)}
				return &compose.StreamToolOutput{
					Result: schema.StreamReaderFromArray([]string{einomcp.ToolErrorPrefix + RenderToolOutcome(outcome)}),
				}, nil
			}
			return &compose.StreamToolOutput{Result: schema.StreamReaderFromArray(chunks)}, nil
		}
	}
}

func logPerCallTimeout(cfg executionToolMiddlewareConfig, toolName string, d time.Duration) {
	if cfg.Logger == nil {
		return
	}
	cfg.Logger.Info("mcp_tool_per_call_timeout",
		zap.String("tool", toolName),
		zap.String("conversation_id", cfg.ConversationID),
		zap.Duration("timeout", d),
	)
}

// mcpPerCallTimeoutMessage 构造 per-call 超时 soft error 文案（含 error_code=timeout / retryable，与 P1-a 一致）。
func mcpPerCallTimeoutMessage(toolName string, d time.Duration) string {
	sec := int(d.Seconds())
	tn := normalizeToolBaseName(toolName)
	if tn == "" {
		tn = toolName
	}
	return fmt.Sprintf(`工具 %q 超过 %ds 被执行治理终止（per-call timeout）。

可能是目标响应慢或任务范围过大。建议：
- 收窄扫描范围（severity/tags、字典大小、目标列表、线程数）
- 换更轻量的工具或侦察路径
- 确需长跑的任务请改后台运行后查结果

Tool %q exceeded per-call timeout (%ds). Narrow scope, switch tool, or run in background.

[error_code: timeout, retryable: true]`, tn, sec, tn, sec)
}
