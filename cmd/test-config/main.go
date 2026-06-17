package main

import (
	"fmt"
	"os"

	"cyberstrike-ai/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/test-config/main.go <config.yaml>")
		os.Exit(1)
	}

	configPath := os.Args[1]
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	if cfg.ExternalMCP.Servers == nil {
		fmt.Println("No external MCP servers configured")
		os.Exit(0)
	}

	fmt.Printf("Found %d external MCP server(s):\n\n", len(cfg.ExternalMCP.Servers))

	for name, srv := range cfg.ExternalMCP.Servers {
		fmt.Printf("Name: %s\n", name)
		fmt.Printf("  Transport: %s\n", getTransport(srv))
		fmt.Printf("  Command: %s\n", srv.Command)
		if len(srv.Args) > 0 {
			fmt.Printf("  Args: %v\n", srv.Args)
		}
		fmt.Printf("  URL: %s\n", srv.URL)
		fmt.Printf("  Description: %s\n", srv.Description)
		fmt.Printf("  Timeout: %d seconds\n", srv.Timeout)
		fmt.Printf("  ExternalMCPEnable: %v\n", srv.ExternalMCPEnable)
		fmt.Println()
	}
}

func getTransport(srv config.ExternalMCPServerConfig) string {
	t := srv.GetTransportType()
	if t == "" {
		return "unknown"
	}
	return t
}
