package termout

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// StartupWebUIOptions configures the startup Web UI banner.
type StartupWebUIOptions struct {
	Scheme       string
	Port         int
	Host         string
	SelfSigned   bool
	HTTPRedirect bool
}

// PrintConfigCreated prints a short notice when config.yaml is bootstrapped.
func PrintConfigCreated() {
	s := New(os.Stdout)
	s.Println("")
	s.Println(s.Green("✔ ") + s.Bold("已创建 config.yaml") + s.Dim("（来自 config.example.yaml）"))
	s.BlankLine()
}

// PrintStartupWebUI prints a colored startup banner for the Web UI.
func PrintStartupWebUI(opts StartupWebUIOptions) {
	s := New(os.Stdout)
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "http"
	}
	port := opts.Port
	if port <= 0 {
		port = 8080
	}
	hosts := bannerHosts(opts.Host)

	s.BlankLine()
	s.Println(s.Bold(s.Cyan("CYBERSTRIKE AI")) + s.Dim("  /  secure workspace"))
	s.Println(s.Dim(strings.Repeat("─", 60)))
	s.Println(s.Green("● ONLINE") + "   " + s.Bold(s.White(fmt.Sprintf("%s://%s:%d/", scheme, hostForURL(hosts[0]), port))))
	for _, host := range hosts[1:] {
		s.Println("           " + s.Dim(fmt.Sprintf("%s://%s:%d/", scheme, hostForURL(host), port)))
	}
	if opts.SelfSigned {
		s.Println(s.Dim("  TLS      ") + s.Yellow("self-signed") + s.Dim(" · accept the browser warning once"))
	}
	if opts.HTTPRedirect {
		s.Println(s.Dim("  Redirect ") + fmt.Sprintf("http://%s:%d/ → HTTPS", hostForURL(hosts[0]), port))
	}
	s.BlankLine()
}

// bannerHosts 返回 banner 应展示的访问地址列表：绑定全接口（空 / 0.0.0.0 / ::）时
// 列出本机全部非环回 IPv4（默认出网口优先）+ 127.0.0.1，绑定具体 host 时仅该地址。
func bannerHosts(host string) []string {
	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0", "::", "[::]":
	default:
		return []string{host}
	}

	var hosts []string
	if preferred := preferredIPv4(); preferred != "" {
		hosts = append(hosts, preferred)
	}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipNet.IP.To4()
				if ip4 == nil || ip4.IsLoopback() {
					continue
				}
				if !containsString(hosts, ip4.String()) {
					hosts = append(hosts, ip4.String())
				}
			}
		}
	}
	if len(hosts) == 0 {
		hosts = append(hosts, "127.0.0.1")
	}
	if !containsString(hosts, "127.0.0.1") {
		hosts = append(hosts, "127.0.0.1")
	}
	return hosts
}

// preferredIPv4 返回默认出网口的 IPv4（UDP 拨号取源地址，不实际发包），
// 失败时返回空串——多网卡时把最可能可用的地址排在 banner 首位。
func preferredIPv4() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP.To4() != nil && !addr.IP.IsLoopback() {
		return addr.IP.String()
	}
	return ""
}

// hostForURL 把裸 IPv6 地址（含 : 且未带方括号）包上 []，IPv4 与域名原样返回。
func hostForURL(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

// PrintBootstrapAdminCredentials prints the initial admin password banner.
func PrintBootstrapAdminCredentials(password string) {
	password = strings.TrimSpace(password)
	if password == "" {
		return
	}

	s := New(os.Stdout)
	s.Println(s.Bold(s.Yellow("ADMIN SETUP REQUIRED")))
	s.Println(s.Dim(strings.Repeat("─", 60)))
	s.Println(s.Dim("  Username  ") + s.Bold(s.White("admin")))
	s.Println(s.Dim("  Password  ") + s.Bold(s.Yellow(password)))
	s.BlankLine()
	s.Println(s.Yellow("  ! ") + s.White("Store this password securely. It is shown only once."))
	s.Println(s.Dim("    Change it in Settings immediately after signing in."))
	s.BlankLine()
}
