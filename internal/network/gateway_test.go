package network

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestGatewayCloseAfterServingIsIdempotentAndReleasesListener(t *testing.T) {

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	allowServeExit := make(chan struct{})
	defer close(allowServeExit)
	held := &gatewayExitListener{Listener: listener, allowServeExit: allowServeExit}
	gateway := &Gateway{listener: held, selected: &http.Transport{}, baseline: &http.Transport{}, tunnels: map[net.Conn]bool{}, server: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })}}
	go gateway.server.Serve(held)
	defer gateway.Close()
	address := gateway.listener.Addr().String()
	response, err := http.Get("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if err := gateway.Close(); err != nil {
			t.Fatalf("close %d failed: %v", attempt, err)
		}
	}
	connection, err := net.Dial("tcp", address)
	if err == nil {
		connection.Close()
		t.Fatal("closed gateway still accepts connections")
	}
}

// Hold Serve's deregistration to reproduce close racing with its accept loop.
type gatewayExitListener struct {
	net.Listener
	allowServeExit <-chan struct{}
}

func (l *gatewayExitListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		select {
		case <-l.allowServeExit:
		case <-time.After(50 * time.Millisecond):
		}
	}
	return connection, err
}

func TestGatewayTargetOnlyAndAuthentication(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Selected-Proxy", "yes")
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	baseline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "baseline") }))
	defer baseline.Close()
	n, _ := s.AddProxy(upstream.URL, "manual")
	g, err := s.NewGateway(n.ID, Scope{Targets: []string{"target.test"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	u, _ := url.Parse(g.URL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	r, err := client.Get("http://target.test/")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.Header.Get("X-Selected-Proxy") != "yes" {
		t.Fatal("target bypassed chosen proxy")
	}
	r, err = client.Get(baseline.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(body) != "baseline" {
		t.Fatal("unrelated address did not preserve baseline")
	}
	u.User = nil
	anonymous := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	r, err = anonymous.Get("http://target.test/")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 407 {
		t.Fatal("gateway accepted unauthenticated use")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = dialProxy(ctx, u, "127.0.0.1:1"); err == nil {
		t.Fatal("canceled tunnel connected")
	}
}
