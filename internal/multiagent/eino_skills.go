package multiagent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/einomcp"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/filesystem"
	"github.com/cloudwego/eino/adk/middlewares/skill"
	"go.uber.org/zap"
)

// prepareEinoSkills builds Eino official skill backend + middleware, and a shared local disk backend
// for skill discovery and (optionally) filesystem/execute tools. Returns nils when disabled or dir missing.
// skillsRoot is the absolute skills directory (empty when skills are not active).
func prepareEinoSkills(
	ctx context.Context,
	skillsDir string,
	ma *config.MultiAgentConfig,
	logger *zap.Logger,
) (loc *localbk.Local, skillMW adk.ChatModelAgentMiddleware, fsTools bool, skillsRoot string, err error) {
	if ma == nil || ma.EinoSkills.Disable {
		return nil, nil, false, "", nil
	}
	root := strings.TrimSpace(skillsDir)
	if root == "" {
		if logger != nil {
			logger.Warn("eino skills: skills_dir empty, skip")
		}
		return nil, nil, false, "", nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("skills_dir abs: %w", err)
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		if logger != nil {
			logger.Warn("eino skills: directory missing, skip", zap.String("dir", abs), zap.Error(err))
		}
		return nil, nil, false, "", nil
	}

	loc, err = localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("eino local backend: %w", err)
	}

	skillBE, err := skill.NewBackendFromFilesystem(ctx, &skill.BackendFromFilesystemConfig{
		Backend: loc,
		BaseDir: abs,
	})
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("eino skill filesystem backend: %w", err)
	}

	sc := &skill.Config{Backend: skillBE}
	if name := strings.TrimSpace(ma.EinoSkills.SkillToolName); name != "" {
		sc.SkillToolName = &name
	}
	skillMW, err = skill.NewMiddleware(ctx, sc)
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("eino skill middleware: %w", err)
	}

	fsTools = ma.EinoSkills.EinoSkillFilesystemToolsEffective()
	return loc, skillMW, fsTools, abs, nil
}

// subAgentFilesystemMiddleware returns filesystem middleware for a sub-agent when Deep itself
// does not set Backend (fsTools false on orchestrator) but we still want tools on subs — not used;
// when orchestrator has Backend, builtin FS is only on outer agent; subs need explicit FS for parity.
func subAgentFilesystemMiddleware(
	ctx context.Context,
	loc *localbk.Local,
	invokeNotify *einomcp.ToolInvokeNotifyHolder,
	einoAgentName string,
	recordMonitor func(command, stdout string, success bool, invokeErr error),
	toolTimeoutMinutes int,
	outputChunk func(toolName, toolCallID, chunk string),
) (adk.ChatModelAgentMiddleware, error) {
	if loc == nil {
		return nil, nil
	}
	return filesystem.New(ctx, &filesystem.MiddlewareConfig{
		Backend: loc,
		StreamingShell: &einoStreamingShellWrap{
			inner:              loc,
			invokeNotify:       invokeNotify,
			einoAgentName:      strings.TrimSpace(einoAgentName),
			outputChunk:        outputChunk,
			recordMonitor:      recordMonitor,
			toolTimeoutMinutes: toolTimeoutMinutes,
		},
	})
}

// agentToolTimeoutMinutes 返回 agent.tool_timeout_minutes（与 executeToolViaMCP 一致）；cfg 为 nil 时 0。
func agentToolTimeoutMinutes(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return cfg.Agent.ToolTimeoutMinutes
}
