package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOpenVPNProfileDNSIsAutomaticAndCanBeOverridden(t *testing.T) {
	profile := Profile{Config: "dhcp-option DNS 10.20.0.53\n<ca>\ndhcp-option DNS 192.0.2.1\n</ca>\n--dhcp-option DNS6 fd00::53\ndhcp-option DNS 10.20.0.53\n"}
	servers, err := configuredDNSServers(Policy{}, profile)
	if err != nil || !reflect.DeepEqual(servers, []string{"10.20.0.53", "fd00::53"}) {
		t.Fatalf("profile DNS not imported: %v %v", servers, err)
	}
	servers, err = configuredDNSServers(Policy{DNSServers: []string{"10.21.0.53"}}, profile)
	if err != nil || !reflect.DeepEqual(servers, []string{"10.21.0.53"}) {
		t.Fatalf("explicit DNS override ignored: %v %v", servers, err)
	}
	if _, err = configuredDNSServers(Policy{}, Profile{Config: "dhcp-option DNS invalid-address"}); err == nil {
		t.Fatal("malformed profile DNS accepted")
	}
}

func certificateFixture(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}

func TestOpenVPNProfileManagedAndOriginalPreserved(t *testing.T) {
	cert, key := certificateFixture(t)
	raw := "client\ndev tun\nproto udp\nremote vpn.example.test 1194\nca ca.crt\ncert client.crt\nkey client.key\nredirect-gateway def1\nroute 0.0.0.0 0.0.0.0\n"
	profile, err := ValidateProfile("project", raw, map[string]string{"ca.crt": cert, "client.crt": cert, "client.key": key})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Config != raw {
		t.Fatal("original profile changed")
	}
	managed, err := RuntimeProfile(profile, "/managed")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(managed, "redirect-gateway") || strings.Contains(managed, "route 0.0.0.0") {
		t.Fatal("profile took default route")
	}
	if !strings.Contains(managed, "route-nopull") || !strings.Contains(managed, "remote-cert-tls server") {
		t.Fatal("missing managed network or TLS control")
	}
	inline := "client\ndev tun\nremote vpn.example.test 1194\n<ca>\n" + cert + "</ca>\n<cert>\n" + cert + "</cert>\n<key>\n" + key + "</key>\n"
	if _, err = ValidateProfile("p", inline, nil); err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{"up /tmp/script", "plugin /tmp/plugin.so", "config extra.ovpn", "ca ../secret", "management 0.0.0.0 1234", "script-security 2", "dhcp-option DNS invalid-address"} {
		if _, err = ValidateProfile("p", raw+directive+"\n", map[string]string{"ca.crt": cert, "client.crt": cert, "client.key": key}); err == nil {
			t.Fatalf("unsafe directive accepted: %s", directive)
		}
	}
}

func TestOpenVPNRuntimeDisablesOffloadForNamespaceFirewall(t *testing.T) {
	cert, key := certificateFixture(t)
	for _, option := range []string{"", "disable-dco\n"} {
		t.Run(fmt.Sprint(option != ""), func(t *testing.T) {
			raw := "client\ndev tun\nremote vpn.example.test 1194\nca ca.crt\ncert client.crt\nkey client.key\n" + option
			profile, err := ValidateProfile("project", raw, map[string]string{"ca.crt": cert, "client.crt": cert, "client.key": key})
			if err != nil {
				t.Fatal(err)
			}
			managed, err := RuntimeProfile(profile, "/managed")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(managed, "disable-dco\n") != 1 {
				t.Fatal("managed tunnel must use userspace sockets compatible with namespace owner rules")
			}
			if profile.Config != raw {
				t.Fatal("runtime offload policy changed the uploaded profile")
			}
		})
	}
}
