package network

import (
	"encoding/base64"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestParseProxyInputLines(t *testing.T) {
	input := "# labels are not imported\nhttp://user:p%40ss@EXAMPLE.COM:8080/#office\nhttp://user:p%40ss@example.com:8080\nsocks5h://[2001:db8::1]:1080#ipv6\nvmess://opaque-secret\nvless://opaque-secret\nss://opaque-secret\nssr://opaque-secret\ntrojan://opaque-secret\nhysteria://opaque-secret\nhysteria2://opaque-secret\ntuic://opaque-secret\nhttp://user:secret@invalid:99999\nnot-a-proxy\n"
	got, err := ParseProxyInput(input, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://user:p%40ss@example.com:8080", "socks5h://[2001:db8::1]:1080"}
	if !reflect.DeepEqual(got.Addresses, want) || got.Invalid != 2 {
		t.Fatalf("unexpected supported addresses/count: %#v, invalid=%d", got.Addresses, got.Invalid)
	}
	for _, protocol := range []string{"vmess", "vless", "ss", "ssr", "trojan", "hysteria", "hysteria2", "tuic"} {
		if got.Unsupported[protocol] != 1 {
			t.Errorf("unsupported %s count=%d", protocol, got.Unsupported[protocol])
		}
	}
}

func TestParseProxyInputBase64Lists(t *testing.T) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		encoded := encoding.EncodeToString([]byte("https://user:p%3F@example.com:443#label\nsocks5://127.0.0.1:1080\n"))
		got, err := ParseProxyInput(encoded[:12]+"\n"+encoded[12:], 100)
		if err != nil || !reflect.DeepEqual(got.Addresses, []string{"https://user:p%3F@example.com:443", "socks5://127.0.0.1:1080"}) {
			t.Fatalf("base64 list was not decoded: addresses=%v err=%v", got.Addresses, err)
		}
	}
}

func TestParseProxyInputClash(t *testing.T) {
	input := `proxies:
  - name: discarded-label
    type: http
    server: "2001:db8::1"
    port: 8443
    tls: true
    username: "user@name"
    password: "p:/?#%"
  - {type: socks5, server: proxy.example, port: "1080"}
  - {type: ss, server: encrypted.example, port: 443, password: hidden}
  - {type: vmess, uuid: hidden}
  - {type: http, server: invalid.example, port: 0}
  - {type: "unknown-secret-protocol", password: hidden}
`
	got, err := ParseProxyInput(input, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://user%40name:p%3A%2F%3F%23%25@[2001:db8::1]:8443", "socks5://proxy.example:1080"}
	if !reflect.DeepEqual(got.Addresses, want) || got.Invalid != 1 || got.Unsupported["ss"] != 1 || got.Unsupported["vmess"] != 1 || got.Unsupported["unknown"] != 1 {
		t.Fatalf("unexpected Clash result: %#v", got)
	}
}

func TestParseProxyInputV2Ray(t *testing.T) {
	input := `{"outbounds":[
 {"protocol":"http","settings":{"servers":[{"address":"proxy.example","port":8080,"users":[{"user":"name@host","pass":"p:ss"}]}]}},
 {"protocol":"socks","settings":{"servers":[{"address":"2001:db8::2","port":1080},{"address":"proxy.example","port":1080,"users":[{"user":"a","pass":"b"},{"user":"c","pass":"d"}]}]}},
 {"protocol":"shadowsocks","settings":{"servers":[{"address":"encrypted.example","port":443,"password":"hidden"}]}},
 {"protocol":"vless","settings":{}},
 {"protocol":"http","settings":{"servers":[{"address":"bad.example","port":"not-port"}]}}
 ]}`
	got, err := ParseProxyInput(input, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://name%40host:p%3Ass@proxy.example:8080", "socks5://[2001:db8::2]:1080", "socks5://a:b@proxy.example:1080", "socks5://c:d@proxy.example:1080"}
	if !reflect.DeepEqual(got.Addresses, want) || got.Invalid != 1 || got.Unsupported["ss"] != 1 || got.Unsupported["vless"] != 1 {
		t.Fatalf("unexpected V2Ray result: %#v", got)
	}
}

func TestParseProxyInputPreservesNativeTransportSemantics(t *testing.T) {
	for name, input := range map[string]string{
		"clash-tls-socks": "proxies: [{type: socks5, server: proxy.example, port: 1080, tls: true}]",
		"v2ray-tls-socks": `{"outbounds":[{"protocol":"socks","streamSettings":{"security":"tls"},"settings":{"servers":[{"address":"proxy.example","port":1080}]}}]}`,
		"v2ray-websocket": `{"outbounds":[{"protocol":"http","streamSettings":{"network":"ws"},"settings":{"servers":[{"address":"proxy.example","port":8080}]}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseProxyInput(input, 100)
			if err != nil || len(got.Addresses) != 0 || got.Unsupported["unknown"] != 1 {
				t.Fatalf("unsupported transport silently changed: %#v err=%v", got, err)
			}
		})
	}
	input := `{"outbounds":[{"protocol":"http","streamSettings":{"network":"tcp","security":"tls"},"settings":{"servers":[{"address":"proxy.example","port":443}]}}]}`
	got, err := ParseProxyInput(input, 100)
	if err != nil || !reflect.DeepEqual(got.Addresses, []string{"https://proxy.example:443"}) {
		t.Fatalf("native HTTP TLS transport lost: %#v err=%v", got, err)
	}
}

func TestParseProxyInputBoundsAndSanitizedErrors(t *testing.T) {
	for name, input := range map[string]string{
		"oversize":           strings.Repeat("secret", (2<<20)/6+1),
		"malformed-json":     `{"outbounds":[{"password":"secret"}`,
		"malformed-yaml":     "proxies: [secret",
		"alias":              "proxies: &secret [{type: http, server: example.com, port: 80}]\ncopy: *secret",
		"deep":               `{"outbounds":` + strings.Repeat("[", 100) + `"secret"` + strings.Repeat("]", 100) + `}`,
		"multiple-documents": "proxies: []\n---\nsecret: true",
		"duplicate-key":      "proxies: []\nproxies: []",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseProxyInput(input, 100)
			if err == nil || strings.Contains(err.Error(), "secret") || len(got.Addresses) != 0 {
				t.Fatalf("expected sanitized rejection, addresses=%d err=%v", len(got.Addresses), err)
			}
		})
	}
	got, err := ParseProxyInput("http://name:"+strings.Repeat("x", 256)+"@example.com:80\nhttp://example.com:80", 100)
	if err != nil || got.Invalid != 1 || len(got.Addresses) != 1 {
		t.Fatalf("oversize credentials must be invalid: addresses=%d invalid=%d err=%v", len(got.Addresses), got.Invalid, err)
	}
}

func TestParseProxyInputLimitAndAuthDeduplication(t *testing.T) {
	input := "http://a:one@example.com:80\nhttp://a:one@example.com:80/#label\nhttp://a:two@example.com:80\nhttp://example.com:80\nvless://secret\ninvalid"
	got, err := ParseProxyInput(input, 2)
	if err != nil || !reflect.DeepEqual(got.Addresses, []string{"http://a:one@example.com:80", "http://a:two@example.com:80"}) || got.Unsupported["vless"] != 1 || got.Invalid != 1 {
		t.Fatalf("unexpected limited result: %#v err=%v", got, err)
	}
	var many strings.Builder
	for i := 0; i < 10001; i++ {
		many.WriteString("http://example.com:")
		many.WriteString(strconv.Itoa(i + 1))
		many.WriteByte('\n')
	}
	for _, limit := range []int{0, 20000} {
		got, err := ParseProxyInput(many.String(), limit)
		if err != nil || len(got.Addresses) != 10000 {
			t.Fatalf("hard endpoint cap failed: addresses=%d err=%v", len(got.Addresses), err)
		}
	}
}

func TestParseProxyInputEquivalentAuthentication(t *testing.T) {
	got, err := ParseProxyInput("http://user@example.com:80\nhttp://user:@example.com:80\nhttp://%75ser@example.com:080\nhttp://example.com:80", 100)
	if err != nil || !reflect.DeepEqual(got.Addresses, []string{"http://user@example.com:80", "http://example.com:80"}) {
		t.Fatalf("equivalent authentication was not deduplicated: addresses=%v err=%v", got.Addresses, err)
	}
}

func TestParseProxyInputMalformedNodesRemainPrivate(t *testing.T) {
	for _, input := range []string{
		"mixed-port: 7890\nproxies:\n - {type: http, server: good.example, port: 80}\n - {type: http, server: bad.example, port: 80, username: {token: hidden}}\n - {type: http, server: bad.example, port: 80, password: hidden}",
		`{"outbounds":[{"protocol":"http","settings":{"servers":[{"address":"good.example","port":80},{"address":"bad.example","port":80,"users":"hidden"},{"address":"bad.example","port":80,"users":[{"pass":"hidden"}]}]}}]}`,
	} {
		got, err := ParseProxyInput(input, 100)
		if err != nil || !reflect.DeepEqual(got.Addresses, []string{"http://good.example:80"}) || got.Invalid != 2 {
			t.Fatalf("malformed nodes were not isolated: addresses=%v invalid=%d err=%v", got.Addresses, got.Invalid, err)
		}
	}
	for _, raw := range []string{"", "\n# synthetic comment\n// comment\n"} {
		got, err := ParseProxyInput(raw, 100)
		if err != nil || len(got.Addresses) != 0 || got.Invalid != 0 || len(got.Unsupported) != 0 {
			t.Fatalf("comments produced import data: %#v err=%v", got, err)
		}
	}
}

func TestParseProxyInputNodeBudget(t *testing.T) {
	input := "proxies: []\nextra: [" + strings.Repeat("null,", 100001) + "]"
	got, err := ParseProxyInput(input, 100)
	if err == nil || len(got.Addresses) != 0 {
		t.Fatalf("unbounded document accepted: addresses=%d err=%v", len(got.Addresses), err)
	}
}

func FuzzParseProxyInput(f *testing.F) {
	for _, input := range []string{"http://user:password@example.com:80#label", "proxies: []", `{"outbounds":[]}`, "dm1lc3M6Ly9zeW50aGV0aWM=", "proxies: &a [*a]"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got, err := ParseProxyInput(input, 3)
		if err != nil && len(got.Addresses) != 0 {
			t.Fatal("rejected document returned partial addresses")
		}
		if len(got.Addresses) > 3 {
			t.Fatal("endpoint limit exceeded")
		}
		for _, address := range got.Addresses {
			if _, _, err := NormalizeProxy(address); err != nil {
				t.Fatal("import address did not pass proxy validation")
			}
		}
	})
}
