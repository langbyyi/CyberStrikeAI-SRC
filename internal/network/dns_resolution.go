package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func exchangeProjectDNS(ctx context.Context, raw []byte, servers []string, dial func(context.Context, string, string) (net.Conn, error)) ([]byte, error) {
	var query dnsmessage.Message
	if query.Unpack(raw) != nil || len(query.Questions) != 1 || query.Header.Response {
		return nil, fmt.Errorf("invalid project DNS query")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, server := range servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		address := net.JoinHostPort(server, "53")
		for _, protocol := range []string{"udp", "tcp"} {
			reply, err := exchangeDNSPacket(ctx, raw, protocol, address, dial)
			if err != nil {
				break
			}
			var response dnsmessage.Message
			if response.Unpack(reply) != nil || !response.Header.Response || response.Header.ID != query.Header.ID || response.Header.OpCode != query.Header.OpCode || len(response.Questions) != 1 || !strings.EqualFold(response.Questions[0].Name.String(), query.Questions[0].Name.String()) || response.Questions[0].Type != query.Questions[0].Type || response.Questions[0].Class != query.Questions[0].Class {
				break
			}
			if response.Header.Truncated {
				continue
			}
			if response.Header.RCode == dnsmessage.RCodeServerFailure || response.Header.RCode == dnsmessage.RCodeRefused {
				break
			}
			return reply, nil
		}
	}
	return nil, fmt.Errorf("all configured project DNS servers failed")
}

func exchangeDNSPacket(ctx context.Context, raw []byte, protocol, address string, dial func(context.Context, string, string) (net.Conn, error)) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := dial(ctx, protocol, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	packet := raw
	if protocol == "tcp" {
		packet = append(binary.BigEndian.AppendUint16(nil, uint16(len(raw))), raw...)
	}
	if _, err = io.Copy(conn, bytes.NewReader(packet)); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	if protocol == "tcp" {
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		response = response[:binary.BigEndian.Uint16(size[:])]
		_, err = io.ReadFull(conn, response)
		return response, err
	}
	n, err := conn.Read(response)
	return response[:n], err
}

func validateDNSServers(servers []string) error {
	if len(servers) > 8 {
		return fmt.Errorf("project DNS accepts at most 8 servers")
	}
	for _, server := range servers {
		ip, err := netip.ParseAddr(server)
		if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return fmt.Errorf("invalid project DNS server address")
		}
	}
	return nil
}

func resolveProjectAddresses(ctx context.Context, host string, exchange func(context.Context, []byte, string) ([]byte, error)) ([]netip.Addr, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, fmt.Errorf("resolve project target: invalid DNS name")
	}
	addresses := []netip.Addr{}
	seen := map[netip.Addr]bool{}
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}
		raw, err := query.Pack()
		if err != nil {
			return nil, err
		}
		reply, err := exchange(ctx, raw, host)
		if err != nil {
			continue
		}
		var decoded dnsmessage.Message
		if decoded.Unpack(reply) != nil || !decoded.Header.Response || decoded.Header.ID != query.Header.ID || decoded.Header.RCode != dnsmessage.RCodeSuccess {
			continue
		}
		for _, answer := range decoded.Answers {
			var ip netip.Addr
			switch body := answer.Body.(type) {
			case *dnsmessage.AResource:
				ip = netip.AddrFrom4(body.A)
			case *dnsmessage.AAAAResource:
				ip = netip.AddrFrom16(body.AAAA).Unmap()
			}
			if ip.IsValid() && !seen[ip] && len(addresses) < 16 {
				seen[ip] = true
				addresses = append(addresses, ip)
			}
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("project DNS returned no usable address for %s", host)
	}
	return addresses, nil
}
