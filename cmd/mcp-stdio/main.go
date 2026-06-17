package main

import (
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/logger"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/storage"
	"flag"
	"fmt"
	"os"

	"go.uber.org/zap"
)

func main() {
	var configPath = flag.String("config", "config.yaml", "配置文件路径")
	flag.Parse()

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志（stdio 模式下使用 stderr 输出日志，避免干扰 JSON-RPC 通信）
	log := logger.New(cfg.Log.Level, "stderr")

	// 创建MCP服务器
	mcpServer := mcp.NewServer(log.Logger)

	// 创建安全工具执行器
	executor := security.NewExecutor(&cfg.Security, mcpServer, log.Logger)

	// 初始化结果存储（与 internal/app/app.go 同样的逻辑）。
	// stdio 模式下原本不初始化，导致 'exec' 等查询型工具报"结果存储未初始化"。
	resultStorageDir := "tmp"
	if cfg.Agent.ResultStorageDir != "" {
		resultStorageDir = cfg.Agent.ResultStorageDir
	}
	if err := os.MkdirAll(resultStorageDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "创建结果存储目录失败: %v\n", err)
		os.Exit(1)
	}
	resultStorage, err := storage.NewFileResultStorage(resultStorageDir, log.Logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化结果存储失败: %v\n", err)
		os.Exit(1)
	}
	executor.SetResultStorage(resultStorage)

	// 注册工具
	executor.RegisterTools(mcpServer)

	log.Logger.Info("MCP服务器（stdio模式）已启动，等待消息...")

	// 运行 stdio 循环
	if err := mcpServer.HandleStdio(); err != nil {
		log.Logger.Error("MCP服务器运行失败", zap.Error(err))
		os.Exit(1)
	}
}

