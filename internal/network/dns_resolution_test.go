package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"reflect"
	"testing"
)

func TestProjectDNSRetriesOnlyConfiguredServersAndHandlesTCP(t *testing.T) {
	name := dnsmessage.MustNewName("api.example.test.")
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 123}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	raw, _ := query.Pack()
	for _, scenario := range []struct {
		name string
		want []string
	}{
		{"unavailable", []string{"udp/192.0.2.1:53", "udp/192.0.2.2:53"}},
		{"truncated", []string{"udp/192.0.2.1:53", "tcp/192.0.2.1:53"}},
		{"mismatched", []string{"udp/192.0.2.1:53", "udp/192.0.2.2:53"}},
		{"servfail", []string{"udp/192.0.2.1:53", "udp/192.0.2.2:53"}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var calls []string
			reply, err := exchangeProjectDNS(context.Background(), raw, []string{"192.0.2.1", "192.0.2.2"}, func(_ context.Context, network, address string) (net.Conn, error) {
				calls = append(calls, network+"/"+address)
				if scenario.name == "unavailable" && len(calls) == 1 {
					return nil, fmt.Errorf("synthetic resolver unavailable")
				}
				response := query
				response.Header.Response = true
				if len(calls) == 1 {
					switch scenario.name {
					case "truncated":
						response.Header.Truncated = true
					case "mismatched":
						response.Header.ID++
					case "servfail":
						response.Header.RCode = dnsmessage.RCodeServerFailure
					}
				}
				response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{10, 20, 30, 40}}}}
				encoded, _ := response.Pack()
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					if network == "tcp" {
						frame := make([]byte, len(raw)+2)
						if _, err := io.ReadFull(server, frame); err != nil {
							return
						}
						encoded = append(binary.BigEndian.AppendUint16(nil, uint16(len(encoded))), encoded...)
					} else {
						if _, err := io.ReadFull(server, make([]byte, len(raw))); err != nil {
							return
						}
					}
					_, _ = server.Write(encoded)
				}()
				return client, nil
			})
			var decoded dnsmessage.Message
			if err != nil || decoded.Unpack(reply) != nil || decoded.Header.Truncated || decoded.Header.ID != query.Header.ID || decoded.Header.RCode != dnsmessage.RCodeSuccess || !reflect.DeepEqual(calls, scenario.want) {
				t.Fatalf("DNS recovery failed: calls=%v response=%+v err=%v", calls, decoded.Header, err)
			}
		})
	}
}

func TestProjectDNSAllFailuresAndCancellationNeverUseOtherResolvers(t *testing.T) {
	name := dnsmessage.MustNewName("private.example.test.")
	raw, _ := (&dnsmessage.Message{Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		calls := 0
		_, err := exchangeProjectDNS(ctx, raw, []string{"192.0.2.1", "192.0.2.2"}, func(_ context.Context, _, address string) (net.Conn, error) {
			calls++
			if address != "192.0.2.1:53" && address != "192.0.2.2:53" {
				t.Fatalf("private DNS leaked to %s", address)
			}
			return nil, fmt.Errorf("synthetic failure")
		})
		cancel()
		want := 2
		if canceled {
			want = 0
		}
		if err == nil || calls != want {
			t.Fatalf("DNS failure calls=%d want=%d err=%v", calls, want, err)
		}
	}
}

func TestProjectResolverSupportsAAAAOnly(t *testing.T) {
	var queries []dnsmessage.Type
	addresses, err := resolveProjectAddresses(context.Background(), "ipv6.test", func(_ context.Context, raw []byte, _ string) ([]byte, error) {
		var query dnsmessage.Message
		if e := query.Unpack(raw); e != nil {
			return nil, e
		}
		queries = append(queries, query.Questions[0].Type)
		query.Header.Response = true
		if query.Questions[0].Type == dnsmessage.TypeAAAA {
			query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}}}
		}
		return query.Pack()
	})
	if err != nil || len(addresses) != 1 || !addresses[0].Is6() || len(queries) != 2 {
		t.Fatalf("AAAA-only target unsupported: %v %v", addresses, err)
	}
}
