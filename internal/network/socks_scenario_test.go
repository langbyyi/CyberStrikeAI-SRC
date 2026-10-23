package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthenticatedSOCKSProxySelectionAndCommandGateway(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "through-socks") }))
			defer target.Close()
			u, _ := url.Parse(target.URL)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var authenticated atomic.Int32
			go func() {
				for {
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(3 * time.Second))
						read := func(n int) []byte {
							data := make([]byte, n)
							if _, err := io.ReadFull(c, data); err != nil {
								return nil
							}
							return data
						}
						header := read(2)
						if len(header) != 2 || header[0] != 5 || len(read(int(header[1]))) == 0 {
							return
						}
						if _, err := c.Write([]byte{5, 2}); err != nil {
							return
						}
						header = read(2)
						if len(header) != 2 || header[0] != 1 || string(read(int(header[1]))) != "fixture" {
							return
						}
						size := read(1)
						if len(size) == 0 || string(read(int(size[0]))) != "synthetic-secret" {
							_, _ = c.Write([]byte{1, 1})
							return
						}
						if _, err := c.Write([]byte{1, 0}); err != nil {
							return
						}
						header = read(5)
						if len(header) != 5 || header[1] != 1 || header[3] != 3 || string(read(int(header[4]))) != "socks-target.test" {
							return
						}
						port := read(2)
						if len(port) != 2 || fmt.Sprint(binary.BigEndian.Uint16(port)) != u.Port() {
							return
						}
						upstream, err := net.DialTimeout("tcp", u.Host, time.Second)
						if err != nil {
							return
						}
						defer upstream.Close()
						if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
							return
						}
						authenticated.Add(1)
						go func() { _, _ = io.Copy(upstream, c); _ = upstream.Close() }()
						_, _ = io.Copy(c, upstream)
					}(connection)
				}
			}()
			service, _ := Open(t.TempDir())
			defer service.Close()
			service.factory = func(context.Context, string, Policy, Scope, Profile) (Environment, error) {
				return &fixtureEnvironment{}, nil
			}
			node, err := service.AddProxy(scheme+"://fixture:synthetic-secret@"+listener.Addr().String(), "manual")
			if err != nil {
				t.Fatal(err)
			}
			identity := Identity{ConversationID: "socks-task", UserID: "fixture"}
			targetURL := "http://" + net.JoinHostPort("socks-target.test", u.Port())
			if _, err = service.Acquire(context.Background(), identity, Scope{}, AcquireRequest{Target: targetURL, NodeID: node.ID}); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("unused")
			if err = service.PrepareCommand(context.Background(), identity, Scope{}, command); err != nil {
				t.Fatal(err)
			}
			var gateway *url.URL
			for _, item := range command.Env {
				if strings.HasPrefix(item, "HTTP_PROXY=") {
					gateway, _ = url.Parse(strings.TrimPrefix(item, "HTTP_PROXY="))
				}
			}
			transport := &http.Transport{Proxy: http.ProxyURL(gateway)}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(targetURL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || string(body) != "through-socks" || authenticated.Load() != 2 {
				t.Fatalf("SOCKS authentication or gateway failed: %q connections=%d err=%v", body, authenticated.Load(), err)
			}
		})
	}
}
