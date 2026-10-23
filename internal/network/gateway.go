package network

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type Gateway struct {
	nodeID   string
	owner    string
	allowed  func(Target) bool
	server   *http.Server
	listener net.Listener
	token    string
	scope    Scope
	selected *http.Transport
	baseline *http.Transport
	routing  *TargetTransport
	upstream *url.URL
	dial     func(context.Context, string) (net.Conn, error)
	mu       sync.Mutex
	tunnels  map[net.Conn]bool
}

func (s *Service) NewGateway(nodeID string, scope Scope, bind string) (*Gateway, error) {
	u, savedNode, err := s.proxyURL(nodeID)
	if err != nil {
		return nil, err
	}
	if !savedNode.Enabled {
		return nil, fmt.Errorf("proxy node is disabled")
	}
	if bind == "" {
		bind = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("listen project forwarding gateway: %w", err)
	}
	g := &Gateway{listener: listener, token: newID(), scope: scope, upstream: u, tunnels: map[net.Conn]bool{}}
	g.nodeID = nodeID
	g.selected = &http.Transport{Proxy: http.ProxyURL(u), TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	g.baseline = http.DefaultTransport.(*http.Transport).Clone()
	g.server = &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	go func() { _ = g.server.Serve(listener) }()
	return g, nil
}
func newVPNGateway(scope Scope, bind string, dial func(context.Context, string) (net.Conn, error)) (*Gateway, error) {
	l, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, err
	}
	g := &Gateway{listener: l, token: newID(), scope: scope, dial: dial, tunnels: map[net.Conn]bool{}}
	g.selected = &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) { return dial(ctx, address) }, TLSHandshakeTimeout: 10 * time.Second}
	g.baseline = http.DefaultTransport.(*http.Transport).Clone()
	g.server = &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	go func() { _ = g.server.Serve(l) }()
	return g, nil
}
func (g *Gateway) URL() string {
	u := &url.URL{Scheme: "http", Host: g.listener.Addr().String(), User: url.UserPassword("lease", g.token)}
	return u.String()
}
func (g *Gateway) Close() error {
	// Close tracked listeners through Server first; closing them twice can make
	// Server.Close report net.ErrClosed while Serve is still unregistering them.
	err := g.server.Close()
	// Serve may not have registered its listener with http.Server yet.
	_ = g.listener.Close()
	if g.routing != nil {
		g.routing.CloseIdleConnections()
	}
	g.selected.CloseIdleConnections()
	g.baseline.CloseIdleConnections()
	g.mu.Lock()
	defer g.mu.Unlock()
	for conn := range g.tunnels {
		_ = conn.Close()
	}
	return err
}
func stripHop(h http.Header) {
	for _, token := range strings.Split(h.Get("Connection"), ",") {
		h.Del(strings.TrimSpace(token))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(name)
	}
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wanted := "Basic " + base64.StdEncoding.EncodeToString([]byte("lease:"+g.token))
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(wanted)) != 1 {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"project-network\"")
		http.Error(w, "proxy authentication required", 407)
		return
	}
	if r.Method == http.MethodConnect {
		g.connect(w, r)
		return
	}
	if !r.URL.IsAbs() || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
		http.Error(w, "absolute HTTP(S) target required", 400)
		return
	}
	t, err := ParseTarget(r.URL.String())
	if err != nil {
		http.Error(w, "invalid target", 400)
		return
	}
	if !g.permitted(t) {
		http.Error(w, "network lease or asset binding is no longer active", 403)
		return
	}
	request := r.Clone(r.Context())
	request.RequestURI = ""
	request.Header = request.Header.Clone()
	stripHop(request.Header)
	transport := g.baseline
	if g.scope.Contains(t) {
		transport = g.selected
	}
	var response *http.Response
	if g.routing != nil {
		response, err = g.routing.RoundTrip(request)
	} else {
		response, err = transport.RoundTrip(request)
	}
	if err != nil {
		http.Error(w, "selected network path could not reach target", 502)
		return
	}
	defer response.Body.Close()
	stripHop(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}
func (g *Gateway) connect(w http.ResponseWriter, r *http.Request) {
	t, err := ParseTarget("https://" + r.Host)
	if err != nil {
		http.Error(w, "invalid CONNECT target", 400)
		return
	}
	if !g.permitted(t) {
		http.Error(w, "network lease or asset binding is no longer active", 403)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var upstream net.Conn
	if g.routing != nil {
		upstream, err = g.routing.Dial(ctx, t)
	} else if g.scope.Contains(t) {
		if g.dial != nil {
			upstream, err = g.dial(ctx, t.Address())
		} else {
			upstream, err = dialProxy(ctx, g.upstream, t.Address())
		}
	} else {
		u, e := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: t.Address()}})
		if e != nil {
			err = e
		} else {
			upstream, err = dialProxy(ctx, u, t.Address())
		}
	}
	if err != nil {
		http.Error(w, "selected network path could not reach tunnel target", 502)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "tunnel unsupported", 500)
		return
	}
	client, buffer, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	g.mu.Lock()
	g.tunnels[client] = true
	g.tunnels[upstream] = true
	g.mu.Unlock()
	defer func() {
		client.Close()
		upstream.Close()
		g.mu.Lock()
		delete(g.tunnels, client)
		delete(g.tunnels, upstream)
		g.mu.Unlock()
	}()
	_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err = buffer.Flush(); err != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); close(done) }()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	<-done
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (g *Gateway) permitted(t Target) bool {
	g.mu.Lock()
	allowed := g.allowed
	g.mu.Unlock()
	return allowed == nil || allowed(t)
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func dialProxy(ctx context.Context, u *url.URL, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if u == nil {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	}
	if u.Scheme == "socks5" || u.Scheme == "socks5h" {
		var auth *proxy.Auth
		if u.User != nil {
			pass, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pass}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("SOCKS dialer lacks cancellation")
		}
		return cd.DialContext(ctx, "tcp", address)
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if u.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
	if u.User != nil {
		password, _ := u.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+password)))
	}
	if err = req.Write(conn); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("proxy CONNECT returned HTTP %d", response.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
	success = true
	return &bufferedConn{conn, reader}, nil
}
