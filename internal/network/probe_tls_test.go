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

func TestProbeTargetTLSFailureAfterSuccessfulCONNECT(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != targetURL.Host {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		upstream, err := net.DialTimeout("tcp", targetURL.Host, time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		_ = upstream.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err = buffer.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(connection, upstream)
		_ = connection.Close()
		<-done
	}))
	defer proxy.Close()
	s := validationService(t)
	node, err := s.AddProxy(proxy.URL, "manual")
	if err != nil {
		t.Fatal(err)
	}
	results, err := s.Diagnose(context.Background(), Identity{}, Scope{}, target.URL, []string{node.ID})
	if err != nil || len(results) != 1 {
		t.Fatalf("diagnose target TLS failure: %v, %v", results, err)
	}
	if o := results[0]; o.Reachable || o.HTTPStatus != 0 || o.Stage != "tls_failed" {
		t.Fatalf("successful CONNECT concealed target TLS failure: %+v", o)
	}
}
