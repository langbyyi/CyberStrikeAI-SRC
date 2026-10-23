package network

import (
	"fmt"
	"net/netip"
)

const gatewaySocketMark = 0x43534149

func namespaceFirewall(host string) string {
	if _, err := netip.ParseAddr(host); err != nil {
		return ""
	}
	return fmt.Sprintf(`add table inet csai
add set inet csai protected4 { type ipv4_addr; flags interval; }
add set inet csai protected6 { type ipv6_addr; flags interval; }
add set inet csai baseline4 { type ipv4_addr; flags interval; }
add set inet csai baseline6 { type ipv6_addr; flags interval; }
add set inet csai infrastructure4 { type ipv4_addr; }
add set inet csai ambiguous4 { type ipv4_addr; }
add set inet csai ambiguous6 { type ipv6_addr; }
add set inet csai excluded4 { type ipv4_addr; flags interval; auto-merge; }
add set inet csai excluded6 { type ipv6_addr; flags interval; auto-merge; }
add chain inet csai output { type filter hook output priority -10; policy drop; }
add rule inet csai output oifname "lo" accept
add rule inet csai output ip daddr %s accept
add rule inet csai output ip daddr @infrastructure4 meta skuid 0 accept
add rule inet csai output ip daddr @infrastructure4 reject
add rule inet csai output ip daddr @excluded4 oifname "csaitun" reject
add rule inet csai output ip daddr @excluded4 oifname != "csaitun" accept
add rule inet csai output ip6 daddr @excluded6 reject
add rule inet csai output meta mark %d ip daddr @protected4 oifname "csaitun" accept
add rule inet csai output meta mark %d ip6 daddr @protected6 oifname "csaitun" accept
add rule inet csai output ip daddr @ambiguous4 reject
add rule inet csai output ip6 daddr @ambiguous6 reject
add rule inet csai output ip daddr @protected4 oifname != "csaitun" reject
add rule inet csai output ip6 daddr @protected6 oifname != "csaitun" reject
add rule inet csai output ct state established,related accept
add rule inet csai output ip daddr @protected4 oifname "csaitun" accept
add rule inet csai output ip6 daddr @protected6 oifname "csaitun" accept
add rule inet csai output ip daddr @baseline4 accept
add rule inet csai output ip6 daddr @baseline6 accept
`, host, gatewaySocketMark, gatewaySocketMark)
}
