package network

import (
	"strings"
	"testing"
)

func TestNamespaceFirewallFailsClosed(t *testing.T) {
	rules := namespaceFirewall("169.254.1.1")
	if !strings.Contains(rules, "policy drop") || !strings.Contains(rules, "baseline4") || !strings.Contains(rules, "infrastructure4") {
		t.Fatal("missing classified output policy")
	}
	reject := strings.Index(rules, "oifname != \"csaitun\" reject")
	established := strings.Index(rules, "ct state established")
	if reject < 0 || established < reject {
		t.Fatal("established connections could fall back after VPN loss")
	}
}

func TestRawExclusionPrecedesProtectedNetwork(t *testing.T) {
	rules := namespaceFirewall("169.254.1.1")
	excluded := strings.Index(rules, "ip daddr @excluded4 oifname != \"csaitun\" accept")
	protected := strings.Index(rules, "ip daddr @protected4")
	if excluded < 0 || excluded > protected {
		t.Fatal("raw exclusions do not precede protected targets")
	}
}
