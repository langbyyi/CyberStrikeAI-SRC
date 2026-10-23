package network

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func NormalizeProxy(raw string) (Node, Credential, error) {
	if strings.ContainsAny(raw, "\r\n\x00") {
		return Node{}, Credential{}, fmt.Errorf("invalid proxy address")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return Node{}, Credential{}, fmt.Errorf("proxy must be an explicit HTTP(S) or SOCKS5 URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return Node{}, Credential{}, fmt.Errorf("unsupported proxy protocol")
	}
	port := u.Port()
	if port == "" {
		return Node{}, Credential{}, fmt.Errorf("proxy port is required")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return Node{}, Credential{}, fmt.Errorf("invalid proxy port")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return Node{}, Credential{}, fmt.Errorf("proxy address cannot contain path, query or fragment")
	}
	t, err := ParseTarget("tcp://" + u.Host)
	if err != nil {
		return Node{}, Credential{}, err
	}
	c := Credential{}
	if u.User != nil {
		c.Username = u.User.Username()
		c.Password, _ = u.User.Password()
		if len(c.Username) > 255 || len(c.Password) > 255 {
			return Node{}, Credential{}, fmt.Errorf("proxy credentials are too long")
		}
	}
	address := u.Scheme + "://" + net.JoinHostPort(t.Host, strconv.Itoa(p))
	return Node{Address: address, Scheme: u.Scheme, Host: t.Host, Port: strconv.Itoa(p), HasAuth: u.User != nil}, c, nil
}
