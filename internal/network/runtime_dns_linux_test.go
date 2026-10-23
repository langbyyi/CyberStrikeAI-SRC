//go:build linux

package network

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPushedProjectDNSHonorsOverrideAndIPv6(t *testing.T) {
	line := "PUSH_REPLY,dhcp-option DNS 10.20.0.53,dhcp-option DNS6 fd00::53,dhcp-option DNS 10.20.0.53"
	environment := &linuxEnvironment{}
	environment.acceptPushedDNS(line)
	if !reflect.DeepEqual(environment.dnsServers, []string{"10.20.0.53", "fd00::53"}) {
		t.Fatalf("pushed DNS addresses or deduplication lost: %v", environment.dnsServers)
	}
	override := &linuxEnvironment{dnsOverride: true, dnsServers: []string{"10.21.0.53"}}
	override.acceptPushedDNS(line)
	if !reflect.DeepEqual(override.dnsServers, []string{"10.21.0.53"}) {
		t.Fatalf("server push changed explicit project DNS: %v", override.dnsServers)
	}
	for index := 1; index <= 20; index++ {
		environment.acceptPushedDNS(fmt.Sprintf("dhcp-option DNS 192.0.2.%d", index))
	}
	if len(environment.dnsServers) != 8 {
		t.Fatalf("server push exceeded project DNS budget: %v", environment.dnsServers)
	}
}
