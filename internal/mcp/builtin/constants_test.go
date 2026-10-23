package builtin

import (
	"strings"
	"testing"
)

func TestNetworkToolsAreWhitelistPinnedNotHardcoded(t *testing.T) {
	for _, name := range GetAllBuiltinTools() {
		if strings.HasPrefix(name, "network_") {
			t.Fatalf("network tool %s must follow the user whitelist, not the hardcoded pin list", name)
		}
	}
}
