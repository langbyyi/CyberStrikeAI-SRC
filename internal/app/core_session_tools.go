package app

import (
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

// registerCoreSessionTools registers vulnerability, execution coverage, logic probe,
// project fact, and vision MCP tools. Used by both New() startup and ApplyConfig
// re-registration after ClearTools so coverage/logic tools never disappear on hot reload.
func registerCoreSessionTools(mcpServer *mcp.Server, db *database.DB, cfg *config.Config, logger *zap.Logger) {
	registerVulnerabilityTools(mcpServer, db, logger)
	registerExecutionCoverageTools(mcpServer, logger)
	registerLogicProbeTools(mcpServer, logger)
	registerProjectFactTools(mcpServer, db, cfg, logger)
	registerVisionTools(mcpServer, cfg, logger)
}
