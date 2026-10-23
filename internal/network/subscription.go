package network

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	maxProxyInputBytes = 2 << 20
	maxProxyInputNodes = 100000
	maxProxyInputDepth = 32
	maxProxyInputItems = 10000
	maxProxyInputLine  = 16 << 10
)

// ProxyInput contains private import addresses and safe aggregate diagnostics.
// Addresses may contain credentials and must never be returned by an API or logged.
type ProxyInput struct {
	Addresses   []string
	Unsupported map[string]int
	Invalid     int
}

// ParseProxyInput accepts URI lists, base64 subscriptions, Clash YAML and V2Ray JSON.
// Unsupported tunnel protocols are counted without invoking any tunnel runtime.
func ParseProxyInput(raw string, limit int) (ProxyInput, error) {
	if len(raw) > maxProxyInputBytes || !utf8.ValidString(raw) {
		return ProxyInput{}, fmt.Errorf("proxy input exceeds size limits or is not UTF-8")
	}
	if limit <= 0 || limit > maxProxyInputItems {
		limit = maxProxyInputItems
	}
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if decoded, ok := decodeProxyList(raw); ok {
		raw = strings.TrimSpace(decoded)
	}
	p := proxyInputParser{result: ProxyInput{Addresses: []string{}, Unsupported: map[string]int{}}, limit: limit, seen: map[string]bool{}}
	if isProxyDocument(raw) {
		if err := p.document(raw); err != nil {
			// Decoder errors can contain scalar values, including credentials.
			return ProxyInput{}, fmt.Errorf("invalid or overly complex proxy subscription document")
		}
	} else {
		p.lines(raw)
	}
	return p.result, nil
}

type proxyInputParser struct {
	result ProxyInput
	limit  int
	seen   map[string]bool
}

func decodeProxyList(raw string) (string, bool) {
	var compact strings.Builder
	for _, c := range raw {
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("+/=_-", c)) {
			return "", false
		}
		compact.WriteRune(c)
	}
	if compact.Len() == 0 {
		return "", false
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(compact.String())
		if err == nil && utf8.Valid(decoded) && !strings.ContainsRune(string(decoded), '\x00') {
			return string(decoded), true
		}
	}
	return "", false
}

func isProxyDocument(raw string) bool {
	if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "---") {
		return true
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "proxies:") || strings.HasPrefix(line, "outbounds:") {
			return true
		}
	}
	return false
}

func (p *proxyInputParser) lines(raw string) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), maxProxyInputBytes+1)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if len(line) > maxProxyInputLine {
			p.result.Invalid++
			continue
		}
		separator := strings.Index(line, "://")
		if separator > 0 {
			protocol := strings.ToLower(line[:separator])
			if key := unsupportedProxyProtocol(protocol); key != "unknown" {
				p.result.Unsupported[key]++
				continue
			}
		}
		p.address(line)
	}
}

func (p *proxyInputParser) address(raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		p.result.Invalid++
		return
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Fragment, u.RawFragment = "", ""
	node, credentials, err := NormalizeProxy(u.String())
	if err != nil {
		p.result.Invalid++
		return
	}
	canonical, err := url.Parse(node.Address)
	if err != nil {
		p.result.Invalid++
		return
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			canonical.User = url.UserPassword(credentials.Username, credentials.Password)
		} else {
			canonical.User = url.User(credentials.Username)
		}
	}
	address := canonical.String()
	// Username-only and explicit empty passwords have the same proxy auth semantics.
	key := address
	if canonical.User != nil {
		canonical.User = url.UserPassword(credentials.Username, credentials.Password)
		key = canonical.String()
	}
	if !p.seen[key] && len(p.result.Addresses) < p.limit {
		p.seen[key] = true
		p.result.Addresses = append(p.result.Addresses, address)
	}
}

func (p *proxyInputParser) document(raw string) error {
	if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
		if !json.Valid([]byte(raw)) {
			return fmt.Errorf("invalid JSON")
		}
	}
	decoder := yaml.NewDecoder(strings.NewReader(raw))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		return err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("multiple or malformed documents")
	}
	visited := 0
	if err := validateProxyDocument(&doc, 0, &visited); err != nil {
		return err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("expected configuration mapping")
	}
	root := proxyFields(doc.Content[0])
	proxies, hasProxies := root["proxies"]
	outbounds, hasOutbounds := root["outbounds"]
	if !hasProxies && !hasOutbounds {
		return fmt.Errorf("no proxy configuration")
	}
	if hasProxies {
		if proxies.Kind != yaml.SequenceNode {
			return fmt.Errorf("invalid proxies collection")
		}
		for _, node := range proxies.Content {
			p.clash(node)
		}
	}
	if hasOutbounds {
		if outbounds.Kind != yaml.SequenceNode {
			return fmt.Errorf("invalid outbounds collection")
		}
		for _, node := range outbounds.Content {
			p.outbound(node)
		}
	}
	return nil
}

func validateProxyDocument(node *yaml.Node, depth int, visited *int) error {
	*visited = *visited + 1
	if depth > maxProxyInputDepth || *visited > maxProxyInputNodes || node.Kind == yaml.AliasNode {
		return fmt.Errorf("document exceeds parsing limits")
	}
	if node.Kind == yaml.MappingNode {
		keys := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || keys[key.Value] {
				return fmt.Errorf("invalid or duplicate configuration key")
			}
			keys[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateProxyDocument(child, depth+1, visited); err != nil {
			return err
		}
	}
	return nil
}

func proxyFields(node *yaml.Node) map[string]*yaml.Node {
	fields := map[string]*yaml.Node{}
	if node == nil || node.Kind != yaml.MappingNode {
		return fields
	}
	for i := 0; i < len(node.Content); i += 2 {
		fields[node.Content[i].Value] = node.Content[i+1]
	}
	return fields
}

func proxyScalar(node *yaml.Node) (string, bool) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return "", false
	}
	return node.Value, true
}

func (p *proxyInputParser) clash(node *yaml.Node) {
	fields := proxyFields(node)
	protocol, ok := proxyScalar(fields["type"])
	if !ok {
		p.result.Invalid++
		return
	}
	protocol = strings.ToLower(protocol)
	if protocol != "http" && protocol != "socks5" {
		p.result.Unsupported[unsupportedProxyProtocol(protocol)]++
		return
	}
	if tls := fields["tls"]; tls != nil {
		value, valid := proxyScalar(tls)
		if !valid || value != "true" && value != "false" {
			p.result.Invalid++
			return
		}
		if protocol == "http" && value == "true" {
			protocol = "https"
		} else if value == "true" {
			p.result.Unsupported["unknown"]++
			return
		}
	}
	p.endpoint(protocol, fields["server"], fields["port"], fields["username"], fields["password"])
}

func (p *proxyInputParser) outbound(node *yaml.Node) {
	fields := proxyFields(node)
	protocol, ok := proxyScalar(fields["protocol"])
	if !ok {
		p.result.Invalid++
		return
	}
	protocol = strings.ToLower(protocol)
	if protocol != "http" && protocol != "socks" {
		p.result.Unsupported[unsupportedProxyProtocol(protocol)]++
		return
	}
	if protocol == "socks" {
		protocol = "socks5"
	}
	if stream := fields["streamSettings"]; stream != nil {
		if stream.Kind != yaml.MappingNode {
			p.result.Invalid++
			return
		}
		transport := proxyFields(stream)
		for _, field := range []string{"network", "security"} {
			if value := transport[field]; value != nil && value.Kind != yaml.ScalarNode {
				p.result.Invalid++
				return
			}
		}
		wire, _ := proxyScalar(transport["network"])
		security, _ := proxyScalar(transport["security"])
		if wire != "" && wire != "tcp" && wire != "raw" || security != "" && security != "none" && security != "tls" || transport["tlsSettings"] != nil || transport["tcpSettings"] != nil || transport["rawSettings"] != nil {
			p.result.Unsupported["unknown"]++
			return
		}
		if security == "tls" {
			if protocol != "http" {
				p.result.Unsupported["unknown"]++
				return
			}
			protocol = "https"
		}
	}
	servers := proxyFields(fields["settings"])["servers"]
	if servers == nil || servers.Kind != yaml.SequenceNode || len(servers.Content) == 0 {
		p.result.Invalid++
		return
	}
	for _, server := range servers.Content {
		fields := proxyFields(server)
		users := fields["users"]
		if users == nil || users.Kind == yaml.SequenceNode && len(users.Content) == 0 {
			p.endpoint(protocol, fields["address"], fields["port"], nil, nil)
			continue
		}
		if users.Kind != yaml.SequenceNode {
			p.result.Invalid++
			continue
		}
		for _, user := range users.Content {
			credentials := proxyFields(user)
			if credentials["user"] == nil {
				p.result.Invalid++
				continue
			}
			p.endpoint(protocol, fields["address"], fields["port"], credentials["user"], credentials["pass"])
		}
	}
}

func (p *proxyInputParser) endpoint(protocol string, serverNode, portNode, userNode, passwordNode *yaml.Node) {
	server, serverOK := proxyScalar(serverNode)
	port, portOK := proxyScalar(portNode)
	portNumber, err := strconv.Atoi(port)
	if !serverOK || !portOK || server == "" || err != nil || portNumber < 1 || portNumber > 65535 || strings.ContainsAny(server, "/@?#\r\n\x00[]") {
		p.result.Invalid++
		return
	}
	u := &url.URL{Scheme: protocol, Host: net.JoinHostPort(server, strconv.Itoa(portNumber))}
	if userNode != nil || passwordNode != nil {
		user, userOK := proxyScalar(userNode)
		password, passwordOK := proxyScalar(passwordNode)
		if !userOK || passwordNode != nil && !passwordOK {
			p.result.Invalid++
			return
		}
		if passwordNode != nil {
			u.User = url.UserPassword(user, password)
		} else {
			u.User = url.User(user)
		}
	}
	p.address(u.String())
}

func unsupportedProxyProtocol(protocol string) string {
	// Only fixed keys reach aggregate diagnostics; arbitrary protocol values may be private.
	switch protocol {
	case "shadowsocks":
		return "ss"
	case "shadowsocksr":
		return "ssr"
	case "hy2":
		return "hysteria2"
	case "vmess", "vless", "ss", "ssr", "trojan", "hysteria", "hysteria2", "tuic", "wireguard", "snell", "ssh", "anytls", "socks4", "socks4a", "direct", "reject", "freedom", "blackhole", "dns":
		return protocol
	default:
		return "unknown"
	}
}
