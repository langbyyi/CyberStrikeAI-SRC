package multiagent

import (
	"github.com/cloudwego/eino/adk"
	"go.uber.org/zap"
)

// einoChatModelTailConfig configures middleware appended after reduction/skill/plantask
// and immediately before each ChatModel invocation pipeline completes.
//
// Order (best practice):
//  1. system merge — accurate token count for summarization
//  2. continuation user dedup — drop stale session-resume injections
//  3. summarization
//  4. orphan tool prune
//  5. telemetry
//  6. model-facing trace snapshot
type einoChatModelTailConfig struct {
	logger           *zap.Logger
	phase            string
	summarization    adk.ChatModelAgentMiddleware
	modelName        string
	conversationID   string
	trace            *modelFacingTraceHolder
	skipOrphanPruner bool
	skipTelemetry    bool
	skipTrace        bool
}

func appendEinoChatModelTailMiddlewares(handlers []adk.ChatModelAgentMiddleware, cfg einoChatModelTailConfig) []adk.ChatModelAgentMiddleware {
	handlers = append(handlers, newSystemMessageNormalizerMiddleware(cfg.logger, cfg.phase))
	handlers = append(handlers, newContinuationUserDedupMiddleware(cfg.logger, cfg.phase))
	if cfg.summarization != nil {
		handlers = append(handlers, cfg.summarization)
	}
	if !cfg.skipOrphanPruner {
		handlers = append(handlers, newOrphanToolPrunerMiddleware(cfg.logger, cfg.phase))
	}
	if !cfg.skipTelemetry {
		if teleMw := newEinoModelInputTelemetryMiddleware(cfg.logger, cfg.modelName, cfg.conversationID, cfg.phase); teleMw != nil {
			handlers = append(handlers, teleMw)
		}
	}
	if !cfg.skipTrace && cfg.trace != nil {
		if capMw := newModelFacingTraceMiddleware(cfg.trace); capMw != nil {
			handlers = append(handlers, capMw)
		}
	}
	return handlers
}
