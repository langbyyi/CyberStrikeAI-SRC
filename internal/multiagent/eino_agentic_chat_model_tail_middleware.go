package multiagent

import (
	"context"
	"strings"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// appendEinoAgenticChatModelTailMiddlewares appends protocol-neutral handlers for
// TypedChatModelAgent[*schema.AgenticMessage]. History repair operates
// directly on native function-call/result blocks without converting protocols.
func appendEinoAgenticChatModelTailMiddlewares(
	handlers []adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage],
	cfg einoChatModelTailConfig,
) []adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage] {
	handlers = append(handlers, newAgenticSystemMessageNormalizerMiddleware(cfg.logger, cfg.phase))
	handlers = append(handlers, newAgenticContinuationUserDedupMiddleware(cfg.logger, cfg.phase))
	handlers = append(handlers, newAgenticToolCallArgumentsSanitizerMiddleware(cfg.logger, cfg.phase+"_pre_summarization"))
	if cfg.agenticSummarization != nil {
		handlers = append(handlers, newAgenticToolPairReconcilerMiddleware(cfg.logger, cfg.phase+"_pre_summarization"))
		handlers = append(handlers, cfg.agenticSummarization)
	}
	handlers = append(handlers, newAgenticToolCallArgumentsSanitizerMiddleware(cfg.logger, cfg.phase))
	handlers = append(handlers, newAgenticToolPairReconcilerMiddleware(cfg.logger, cfg.phase))
	if !cfg.skipOrphanPruner {
		handlers = append(handlers, newAgenticOrphanToolPrunerMiddleware(cfg.logger, cfg.phase))
	}
	handlers = append(handlers, newAgenticEmptyMediaPartSanitizerMiddleware(cfg.logger, cfg.phase))
	if !cfg.skipTrace && cfg.trace != nil {
		if capMw := newAgenticModelFacingTraceMiddleware(cfg.trace); capMw != nil {
			handlers = append(handlers, capMw)
		}
	}
	return handlers
}

type agenticSystemMessageNormalizerMiddleware struct {
	*adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]
	logger *zap.Logger
	phase  string
}

func newAgenticSystemMessageNormalizerMiddleware(logger *zap.Logger, phase string) adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage] {
	return &agenticSystemMessageNormalizerMiddleware{
		TypedBaseChatModelAgentMiddleware: &adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]{},
		logger:                            logger,
		phase:                             phase,
	}
}

func (m *agenticSystemMessageNormalizerMiddleware) BeforeModelRewriteState(
	ctx context.Context,
	state *adk.TypedChatModelAgentState[*schema.AgenticMessage],
	mc *adk.TypedModelContext[*schema.AgenticMessage],
) (context.Context, *adk.TypedChatModelAgentState[*schema.AgenticMessage], error) {
	_ = mc
	if m == nil || state == nil || len(state.Messages) == 0 {
		return ctx, state, nil
	}
	before := countAgenticSystemMessages(state.Messages)
	if before <= 1 {
		return ctx, state, nil
	}
	normalized := normalizeSingleLeadingAgenticSystemMessage(state.Messages)
	if len(normalized) == len(state.Messages) && countAgenticSystemMessages(normalized) >= before {
		return ctx, state, nil
	}
	if m.logger != nil {
		m.logger.Info("eino agentic system messages merged",
			zap.String("phase", m.phase),
			zap.Int("system_before", before),
			zap.Int("system_after", countAgenticSystemMessages(normalized)),
			zap.Int("messages_before", len(state.Messages)),
			zap.Int("messages_after", len(normalized)),
		)
	}
	out := *state
	out.Messages = normalized
	return ctx, &out, nil
}

type agenticContinuationUserDedupMiddleware struct {
	*adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]
	logger *zap.Logger
	phase  string
}

func newAgenticContinuationUserDedupMiddleware(logger *zap.Logger, phase string) adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage] {
	return &agenticContinuationUserDedupMiddleware{
		TypedBaseChatModelAgentMiddleware: &adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]{},
		logger:                            logger,
		phase:                             phase,
	}
}

func (m *agenticContinuationUserDedupMiddleware) BeforeModelRewriteState(
	ctx context.Context,
	state *adk.TypedChatModelAgentState[*schema.AgenticMessage],
	mc *adk.TypedModelContext[*schema.AgenticMessage],
) (context.Context, *adk.TypedChatModelAgentState[*schema.AgenticMessage], error) {
	_ = mc
	if m == nil || state == nil || len(state.Messages) == 0 {
		return ctx, state, nil
	}
	deduped, dropped := dedupAgenticContinuationUserMessages(state.Messages)
	if dropped == 0 {
		return ctx, state, nil
	}
	if m.logger != nil {
		m.logger.Info("eino agentic continuation user messages deduplicated",
			zap.String("phase", m.phase),
			zap.Int("dropped", dropped),
			zap.Int("messages_before", len(state.Messages)),
			zap.Int("messages_after", len(deduped)),
		)
	}
	out := *state
	out.Messages = deduped
	return ctx, &out, nil
}

func countAgenticSystemMessages(msgs []*schema.AgenticMessage) int {
	n := 0
	for _, msg := range msgs {
		if msg != nil && msg.Role == schema.AgenticRoleTypeSystem {
			n++
		}
	}
	return n
}

func normalizeSingleLeadingAgenticSystemMessage(msgs []*schema.AgenticMessage) []*schema.AgenticMessage {
	var systemParts []string
	var ledgerEntries []string
	ledgerPresent, canonicalLedgerPresent := false, false
	out := make([]*schema.AgenticMessage, 0, len(msgs))
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		if msg.Role == schema.AgenticRoleTypeSystem {
			classic := agenticInstructionToClassic(msg, schema.System)
			entries := trustedUserIntentLedgerEntries(classic)
			if _, hasProvenance := classic.Extra[userIntentLedgerExtraKey]; hasProvenance {
				ledgerEntries, ledgerPresent, canonicalLedgerPresent = entries, true, true
			} else if !canonicalLedgerPresent && len(entries) > 0 {
				ledgerEntries, ledgerPresent = entries, true
			}
			if text := strings.TrimSpace(agenticMessageText(msg)); text != "" {
				systemParts = append(systemParts, text)
			}
			continue
		}
		out = append(out, msg)
	}
	if len(systemParts) == 0 {
		return out
	}
	merged := schema.SystemAgenticMessage(strings.Join(systemParts, "\n\n"))
	if ledgerPresent {
		merged.Extra = map[string]interface{}{userIntentLedgerExtraKey: append([]string(nil), ledgerEntries...)}
	}
	return append([]*schema.AgenticMessage{merged}, out...)
}

func dedupAgenticContinuationUserMessages(msgs []*schema.AgenticMessage) ([]*schema.AgenticMessage, int) {
	lastIdx := -1
	contCount := 0
	for i, msg := range msgs {
		if !isAgenticContinuationUserMessage(msg) {
			continue
		}
		contCount++
		lastIdx = i
	}
	if contCount <= 1 {
		return msgs, 0
	}
	out := make([]*schema.AgenticMessage, 0, len(msgs)-(contCount-1))
	dropped := 0
	for i, msg := range msgs {
		if isAgenticContinuationUserMessage(msg) && i != lastIdx {
			dropped++
			continue
		}
		out = append(out, msg)
	}
	return out, dropped
}

func isAgenticContinuationUserMessage(msg *schema.AgenticMessage) bool {
	if msg == nil || msg.Role != schema.AgenticRoleTypeUser {
		return false
	}
	return strings.Contains(agenticMessageText(msg), continuationSessionMarker)
}

// 空媒体块的占位文案：清理只降级载荷，工具结果的文本与调用关系保持不变。
const (
	emptyImagePlaceholder = "[图片内容已被清理]"
	emptyAudioPlaceholder = "[音频内容已被清理]"
	emptyVideoPlaceholder = "[视频内容已被清理]"
	emptyFilePlaceholder  = "[文件内容已被清理]"
)

// agenticEmptyMediaPartSanitizerMiddleware 把无载荷的媒体块降级为文本占位。
//
// 上下文清理会在 agentic 路径上重建工具结果：eino 的 toolResultToOutputParts 只保留
// 媒体块的 URL，而本仓库的图片一律以 base64 输入（URL 为空），于是清理后留下 URL 与
// 载荷都为空的图片空壳。下一次 ChatModel 会因空壳直接以
// "image message part must have url or base64 data" 终止整个会话。
// 这里在送入模型前把空壳降级为占位文本：清理语义（旧工具结果出上下文）不变，
// 但不会再让一整轮对话失败。
type agenticEmptyMediaPartSanitizerMiddleware struct {
	*adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]
	logger *zap.Logger
	phase  string
}

func newAgenticEmptyMediaPartSanitizerMiddleware(logger *zap.Logger, phase string) adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage] {
	return &agenticEmptyMediaPartSanitizerMiddleware{
		TypedBaseChatModelAgentMiddleware: &adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]{},
		logger:                            logger,
		phase:                             phase,
	}
}

func (m *agenticEmptyMediaPartSanitizerMiddleware) BeforeModelRewriteState(
	ctx context.Context,
	state *adk.TypedChatModelAgentState[*schema.AgenticMessage],
	mc *adk.TypedModelContext[*schema.AgenticMessage],
) (context.Context, *adk.TypedChatModelAgentState[*schema.AgenticMessage], error) {
	_ = mc
	if m == nil || state == nil || len(state.Messages) == 0 {
		return ctx, state, nil
	}
	cleaned, replaced := sanitizeAgenticEmptyMediaParts(state.Messages)
	if replaced == 0 {
		return ctx, state, nil
	}
	if m.logger != nil {
		m.logger.Info("eino agentic empty media parts degraded to text",
			zap.String("phase", m.phase),
			zap.Int("replaced_parts", replaced),
		)
	}
	out := *state
	out.Messages = cleaned
	return ctx, &out, nil
}

// sanitizeAgenticEmptyMediaParts 就地返回替换后的消息切片；无替换时原样返回入参。
func sanitizeAgenticEmptyMediaParts(msgs []*schema.AgenticMessage) ([]*schema.AgenticMessage, int) {
	out := msgs
	cloned := false
	replaced := 0
	for i, msg := range msgs {
		if msg == nil {
			continue
		}
		blocks, n := sanitizeAgenticEmptyMediaBlocks(msg.ContentBlocks)
		if n == 0 {
			continue
		}
		if !cloned {
			out = append([]*schema.AgenticMessage(nil), msgs...)
			cloned = true
		}
		cp := *msg
		cp.ContentBlocks = blocks
		out[i] = &cp
		replaced += n
	}
	return out, replaced
}

func sanitizeAgenticEmptyMediaBlocks(blocks []*schema.ContentBlock) ([]*schema.ContentBlock, int) {
	out := blocks
	cloned := false
	replaced := 0
	for i, block := range blocks {
		if block == nil {
			continue
		}
		var substitute *schema.ContentBlock
		switch {
		case block.UserInputImage != nil && mediaPayloadEmpty(block.UserInputImage.URL, block.UserInputImage.Base64Data):
			substitute = schema.NewContentBlock(&schema.UserInputText{Text: emptyImagePlaceholder})
		case block.UserInputAudio != nil && mediaPayloadEmpty(block.UserInputAudio.URL, block.UserInputAudio.Base64Data):
			substitute = schema.NewContentBlock(&schema.UserInputText{Text: emptyAudioPlaceholder})
		case block.UserInputVideo != nil && mediaPayloadEmpty(block.UserInputVideo.URL, block.UserInputVideo.Base64Data):
			substitute = schema.NewContentBlock(&schema.UserInputText{Text: emptyVideoPlaceholder})
		case block.UserInputFile != nil && mediaPayloadEmpty(block.UserInputFile.URL, block.UserInputFile.Base64Data):
			substitute = schema.NewContentBlock(&schema.UserInputText{Text: emptyFilePlaceholder})
		case block.FunctionToolResult != nil:
			result, n := sanitizeAgenticToolResultEmptyMedia(block.FunctionToolResult)
			if n == 0 {
				continue
			}
			substitute = schema.NewContentBlock(result)
			replaced += n
		default:
			continue
		}
		if !cloned {
			out = append([]*schema.ContentBlock(nil), blocks...)
			cloned = true
		}
		if substitute.Extra == nil {
			substitute.Extra = block.Extra
		}
		out[i] = substitute
		// 工具结果分支已在内部累计被替换的媒体块数，此处只补记整块降级的输入块。
		if substitute.UserInputText != nil {
			replaced++
		}
	}
	return out, replaced
}

// sanitizeAgenticToolResultEmptyMedia 处理工具结果内部的空媒体块，返回新结果与替换数。
func sanitizeAgenticToolResultEmptyMedia(result *schema.FunctionToolResult) (*schema.FunctionToolResult, int) {
	if result == nil || len(result.Content) == 0 {
		return result, 0
	}
	content := result.Content
	cloned := false
	replaced := 0
	for i, block := range content {
		if block == nil {
			continue
		}
		placeholder := ""
		switch {
		case block.Type == schema.FunctionToolResultContentBlockTypeImage && (block.Image == nil || mediaPayloadEmpty(block.Image.URL, block.Image.Base64Data)):
			placeholder = emptyImagePlaceholder
		case block.Type == schema.FunctionToolResultContentBlockTypeAudio && (block.Audio == nil || mediaPayloadEmpty(block.Audio.URL, block.Audio.Base64Data)):
			placeholder = emptyAudioPlaceholder
		case block.Type == schema.FunctionToolResultContentBlockTypeVideo && (block.Video == nil || mediaPayloadEmpty(block.Video.URL, block.Video.Base64Data)):
			placeholder = emptyVideoPlaceholder
		case block.Type == schema.FunctionToolResultContentBlockTypeFile && (block.File == nil || mediaPayloadEmpty(block.File.URL, block.File.Base64Data)):
			placeholder = emptyFilePlaceholder
		default:
			continue
		}
		if !cloned {
			content = append([]*schema.FunctionToolResultContentBlock(nil), result.Content...)
			cloned = true
		}
		content[i] = &schema.FunctionToolResultContentBlock{
			Type:  schema.FunctionToolResultContentBlockTypeText,
			Text:  &schema.UserInputText{Text: placeholder},
			Extra: block.Extra,
		}
		replaced++
	}
	if replaced == 0 {
		return result, 0
	}
	cp := *result
	cp.Content = content
	return &cp, replaced
}

// mediaPayloadEmpty 判断媒体块是否既没有 URL 也没有 base64 载荷。
func mediaPayloadEmpty(url, base64Data string) bool {
	return strings.TrimSpace(url) == "" && strings.TrimSpace(base64Data) == ""
}


func agenticMessageText(msg *schema.AgenticMessage) string {
	if msg == nil {
		return ""
	}
	var b strings.Builder
	for _, block := range msg.ContentBlocks {
		if block == nil {
			continue
		}
		switch {
		case block.UserInputText != nil:
			if s := strings.TrimSpace(block.UserInputText.Text); s != "" {
				if b.Len() > 0 {
					b.WriteByte('\n')
				}
				b.WriteString(s)
			}
		case block.AssistantGenText != nil:
			if s := strings.TrimSpace(block.AssistantGenText.Text); s != "" {
				if b.Len() > 0 {
					b.WriteByte('\n')
				}
				b.WriteString(s)
			}
		}
	}
	return b.String()
}
