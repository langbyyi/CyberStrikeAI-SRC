package c2

import (
	"fmt"
	"net"
	"strings"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

// ResolveBeaconDialHost 决定植入端应连接的主机名（不含端口）。
// 优先级：explicitOverride > 监听器 config_json 中的 callback_host > bind_host（0.0.0.0/::/空 时 detectExternalIP，失败则 127.0.0.1）。
func ResolveBeaconDialHost(listener *database.C2Listener, explicitOverride string, logger *zap.Logger, listenerID string) string {
	if h := strings.TrimSpace(explicitOverride); h != "" {
		return h
	}
	cfg := &ListenerConfig{}
	if listener != nil && listener.ConfigJSON != "" {
		_ = parseJSON(listener.ConfigJSON, cfg)
	}
	if h := strings.TrimSpace(cfg.CallbackHost); h != "" {
		return h
	}
	if listener == nil {
		return "127.0.0.1"
	}
	host := strings.TrimSpace(listener.BindHost)
	if host == "0.0.0.0" || host == "" || host == "::" {
		host = detectExternalIP()
		if host == "" {
			if logger != nil {
				logger.Warn("listener binds 0.0.0.0 but no external IP detected, falling back to 127.0.0.1; set callback_host or pass explicit host",
					zap.String("listener_id", listenerID))
			}
			return "127.0.0.1"
		}
	}
	return host
}

// ValidateBeaconDialHost accepts a host only, never a URL, port or command fragment.
func ValidateBeaconDialHost(host string) error {
	if host == "" || len(host) > 253 {
		return fmt.Errorf("callback host must be an IP address or hostname without a scheme, path or port")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	name := strings.TrimSuffix(host, ".")
	numeric := true
	for _, c := range name {
		if c != '.' && (c < '0' || c > '9') {
			numeric = false
		}
	}
	if numeric {
		return fmt.Errorf("callback host contains an invalid IP address")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("callback hostname has an invalid label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("callback host must be an IP address or hostname without a scheme, path or port")
			}
		}
	}
	return nil
}
