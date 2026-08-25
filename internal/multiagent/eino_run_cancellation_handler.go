package multiagent

import "context"

type einoRunCancellationHandler struct {
	ctx              context.Context
	conversationID   string
	progress         func(eventType, message string, data interface{})
	pending          *einoPendingToolCalls
	takePartial      einoPartialResultFunc
	reconcilePending func()
}

type einoRunCancellationHandlerConfig struct {
	Context        context.Context
	ConversationID string
	Progress       func(eventType, message string, data interface{})
	Pending        *einoPendingToolCalls
	TakePartial    einoPartialResultFunc
	// ReconcilePending 在 FlushAsFailed 前对账「结果已送达模型」的 pending（如未知工具路径），
	// 避免把事件观测缺口误报为工具失败。
	ReconcilePending func()
}

func newEinoRunCancellationHandler(cfg einoRunCancellationHandlerConfig) *einoRunCancellationHandler {
	return &einoRunCancellationHandler{
		ctx:              cfg.Context,
		conversationID:   cfg.ConversationID,
		progress:         cfg.Progress,
		pending:          cfg.Pending,
		takePartial:      cfg.TakePartial,
		reconcilePending: cfg.ReconcilePending,
	}
}

func (h *einoRunCancellationHandler) Handle(runErr error) (*RunResult, error) {
	if h == nil {
		return nil, runErr
	}
	if h.pending != nil {
		if h.reconcilePending != nil {
			h.reconcilePending()
		}
		h.pending.FlushAsFailed(runErr)
	}
	if h.progress != nil {
		if isInterruptContinue(h.ctx) {
			h.progress("progress", "已暂停当前输出，正在合并用户补充并继续…", map[string]interface{}{
				"conversationId": h.conversationID,
				"source":         "eino",
				"kind":           "interrupt_continue",
			})
		} else if runErr != nil {
			h.progress("error", runErr.Error(), map[string]interface{}{
				"conversationId": h.conversationID,
				"source":         "eino",
			})
		}
	}
	if h.takePartial == nil {
		return nil, runErr
	}
	return h.takePartial(runErr)
}
