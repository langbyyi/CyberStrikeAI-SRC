package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/logger"
	"cyberstrike-ai/internal/mcp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/test-external-mcp/main.go <config.yaml>")
		os.Exit(1)
	}

	configPath := os.Args[1]
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	if cfg.ExternalMCP.Servers == nil || len(cfg.ExternalMCP.Servers) == 0 {
		fmt.Println("No external MCP servers configured")
		os.Exit(0)
	}

	fmt.Printf("Found %d external MCP server(s)\n\n", len(cfg.ExternalMCP.Servers))

	// 创建日志
	log := logger.New("info", "stdout")

	// 创建外部MCP管理器
	manager := mcp.NewExternalMCPManager(log.Logger)
	manager.LoadConfigs(&cfg.ExternalMCP)

	// 显示配置
	fmt.Println("=== 配置信息 ===")
	for name, srv := range cfg.ExternalMCP.Servers {
		fmt.Printf("\n%s:\n", name)
		fmt.Printf("  Transport: %s\n", getTransport(srv))
		if srv.Command != "" {
			fmt.Printf("  Command: %s\n", srv.Command)
			fmt.Printf("  Args: %v\n", srv.Args)
		}
		if srv.URL != "" {
			fmt.Printf("  URL: %s\n", srv.URL)
		}
		fmt.Printf("  Description: %s\n", srv.Description)
		fmt.Printf("  Timeout: %d seconds\n", srv.Timeout)
		fmt.Printf("  ExternalMCPEnable: %v\n", srv.ExternalMCPEnable)
	}

	// 获取统计信息
	fmt.Println("\n=== 统计信息 ===")
	stats := manager.GetStats()
	fmt.Printf("总数: %d\n", stats["total"])
	fmt.Printf("已启用: %d\n", stats["enabled"])
	fmt.Printf("已停用: %d\n", stats["disabled"])
	fmt.Printf("已连接: %d\n", stats["connected"])

	// 测试启动（仅测试启用的）
	fmt.Println("\n=== 测试启动 ===")
	for name, srv := range cfg.ExternalMCP.Servers {
		if srv.ExternalMCPEnable {
			fmt.Printf("\n尝试启动 %s...\n", name)
			// 注意：实际启动可能会失败，因为需要真实的MCP服务器
			err := manager.StartClient(name)
			if err != nil {
				fmt.Printf("  启动失败（这是正常的，如果没有真实的MCP服务器）: %v\n", err)
			} else {
				fmt.Printf("  启动成功\n")
				// 获取客户端状态
				if client, exists := manager.GetClient(name); exists {
					fmt.Printf("  状态: %s\n", client.GetStatus())
					fmt.Printf("  已连接: %v\n", client.IsConnected())
				}
			}
		}
	}

	// 等待一下
	time.Sleep(2 * time.Second)

	// 测试获取工具列表
	fmt.Println("\n=== 测试获取工具列表 ===")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools, err := manager.GetAllTools(ctx)
	if err != nil {
		fmt.Printf("获取工具列表失败: %v\n", err)
	} else {
		fmt.Printf("获取到 %d 个工具\n", len(tools))
		for i, tool := range tools {
			if i < 5 { // 只显示前5个
				fmt.Printf("  - %s: %s\n", tool.Name, tool.Description)
			}
		}
		if len(tools) > 5 {
			fmt.Printf("  ... 还有 %d 个工具\n", len(tools)-5)
		}
	}

	// 测试停止
	fmt.Println("\n=== 测试停止 ===")
	for name := range cfg.ExternalMCP.Servers {
		fmt.Printf("\n停止 %s...\n", name)
		err := manager.StopClient(name)
		if err != nil {
			fmt.Printf("  停止失败: %v\n", err)
		} else {
			fmt.Printf("  停止成功\n")
		}
	}

	// 最终统计
	fmt.Println("\n=== 最终统计 ===")
	stats = manager.GetStats()
	fmt.Printf("总数: %d\n", stats["total"])
	fmt.Printf("已启用: %d\n", stats["enabled"])
	fmt.Printf("已停用: %d\n", stats["disabled"])
	fmt.Printf("已连接: %d\n", stats["connected"])

	fmt.Println("\n=== 测试完成 ===")
}

func getTransport(srv config.ExternalMCPServerConfig) string {
	t := srv.GetTransportType()
	if t == "" {
		return "unknown"
	}
	return t
}

