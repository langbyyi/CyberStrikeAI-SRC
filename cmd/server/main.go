package main

import (
	"context"
	"cyberstrike-ai/internal/app"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/logger"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	var configPath = flag.String("config", "config.yaml", "配置文件路径")
	var httpsBootstrap = flag.Bool("https", false, "启用主站 HTTPS：未配置 tls_cert_path/tls_key_path 时使用内存自签证书（本地测试）；与 run.sh 默认行为一致")
	flag.Parse()

	// 环境变量兼容（便于 systemd/docker 等不传参场景）
	if !*httpsBootstrap {
		v := strings.TrimSpace(os.Getenv("CYBERSTRIKE_HTTPS"))
		if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
			*httpsBootstrap = true
		}
	}

	// 加载配置
	cp := strings.TrimSpace(*configPath)
	if cp == "" {
		cp = "config.yaml"
	}
	if strings.HasPrefix(cp, "-") {
		fmt.Fprintf(os.Stderr, "无效的 -config 路径 %q。\n若同时需要 HTTPS，请写成: ./cyberstrike-ai --https -config config.yaml（-config 后必须是 yaml 文件路径）。\n", cp)
		os.Exit(2)
	}
	cfg, err := config.Load(cp)
	if err != nil {
		fmt.Printf("加载配置失败: %v\n", err)
		return
	}

	if *httpsBootstrap {
		config.ApplyDevHTTPSBootstrap(cfg)
	}

	port := cfg.Server.Port
	if port <= 0 {
		port = 8080
	}
	scheme := "http"
	if config.MainWebUIUsesHTTPS(&cfg.Server) {
		scheme = "https"
	}
	fmt.Println()
	fmt.Printf("→ Web 界面: %s://127.0.0.1:%d/\n", scheme, port)
	if scheme == "https" && cfg.Server.TLSAutoSelfSign {
		fmt.Println("  （内存自签证书：浏览器首次需确认「继续访问」）")
	}
	if scheme == "https" && config.ServerHTTPRedirectEnabled(&cfg.Server) {
		fmt.Printf("  （http://127.0.0.1:%d/ 将自动跳转到 HTTPS）\n", port)
	}
	fmt.Println()

	// MCP 启用且 auth_header_value 为空时，自动生成随机密钥并写回配置
	if err := config.EnsureMCPAuth(cp, cfg); err != nil {
		fmt.Printf("MCP 鉴权配置失败: %v\n", err)
		return
	}
	if cfg.MCP.Enabled {
		config.PrintMCPConfigJSON(cfg.MCP)
	}

	// 初始化日志
	log := logger.New(cfg.Log.Level, cfg.Log.Output)

	// 创建可取消的根 context，用于优雅关闭
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 监听系统信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 创建应用
	application, err := app.New(cfg, log, cp)
	if err != nil {
		log.Fatal("应用初始化失败", "error", err)
	}

	// 在后台监听信号
	go func() {
		sig := <-sigCh
		log.Info("收到系统信号，开始优雅关闭: " + sig.String())
		application.Shutdown()
		cancel()
	}()

	// 启动服务器（传入 context 以支持优雅关闭）
	if err := application.RunWithContext(ctx); err != nil {
		// context 取消导致的关闭不视为错误
		if ctx.Err() != nil {
			log.Info("服务器已优雅关闭")
		} else {
			log.Fatal("服务器启动失败", "error", err)
		}
	}
}
