package converter

import (
	"bytes"
	"encoding/json"
	"testing"

	xserial "github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/main/distro/all"
)

// v2go renames every config before it is tested, so every link reaching
// ConvertLink carries a fragment like "#v2go | 🇩🇪 DE | VLESS | 12" —
// spaces, pipes and emoji included. These cases pin that down: the link must
// convert, and the resulting outbound must be something xray will actually load.
func TestConvertLinkWithV2goFragment(t *testing.T) {
	cases := []struct {
		name string
		link string
	}{
		{
			"vless-reality",
			"vless://1cbe9e8a-8e2f-4a1e-9a2f-0e6f9a3b7c11@example.com:443" +
				"?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome" +
				"&pbk=xNfLwSFtT5ZK8Q3iZ6ub1t7z0oUqNVoJ0aQpM2vFhHU&sid=6ba85179e30d4fc2" +
				"&flow=xtls-rprx-vision#v2go | 🇩🇪 DE | VLESS | 12",
		},
		{
			"vless-ws-tls",
			"vless://1cbe9e8a-8e2f-4a1e-9a2f-0e6f9a3b7c11@example.com:443" +
				"?type=ws&security=tls&path=%2Fws&host=example.com&sni=example.com" +
				"#v2go | 🇳🇱 NL | VLESS | 3",
		},
		{
			// base64 userinfo, the shape that actually shows up in the wild
			"ss-base64-userinfo",
			"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#v2go | 🇺🇸 US | SS | 7",
		},
		{
			"trojan-tls",
			"trojan://somepassword@example.com:443?security=tls&sni=example.com&type=tcp" +
				"#v2go | 🇫🇷 FR | TROJAN | 1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outbound, err := ConvertLink(tc.link)
			if err != nil {
				t.Fatalf("ConvertLink: %v", err)
			}

			full := M{
				"log": M{"loglevel": "none"},
				"outbounds": []M{
					outbound,
					{"protocol": "freedom", "tag": "direct"},
				},
			}
			raw, err := json.Marshal(full)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := xserial.LoadJSONConfig(bytes.NewReader(raw)); err != nil {
				t.Fatalf("xray rejected the generated config: %v\n%s", err, raw)
			}
		})
	}
}

func TestConvertLinkRejectsGarbage(t *testing.T) {
	for _, link := range []string{"", "not-a-link", "vless://", "ss://@@@"} {
		if _, err := ConvertLink(link); err == nil {
			t.Errorf("expected error for %q", link)
		}
	}
}

// SIP002 userinfo is percent-encoded per RFC 3986 path rules, where '+' is a
// legal literal character. Decoding the plaintext fallback with
// url.QueryUnescape instead applies form-urlencoded semantics and rewrites
// every '+' into a space, so a password like "my+secret" silently becomes
// "my secret" and the generated config fails authentication downstream with
// no parse error pointing at the cause.
func TestSSPlaintextUserinfoKeepsPlus(t *testing.T) {
	cases := []struct {
		name       string
		link       string
		wantMethod string
		want       string
		loadXray   bool // no real cipher name contains '+', so xray only loads the rest
	}{
		{
			// the shape from the wild: '+' must survive the plaintext path
			name:       "plus in password",
			link:       "ss://aes-256-gcm:my+secret@1.2.3.4:8388#node",
			wantMethod: "aes-256-gcm",
			want:       "my+secret",
			loadXray:   true,
		},
		{
			// percent-encoded '+' decodes to the same literal '+'
			name:       "percent-encoded plus",
			link:       "ss://aes-256-gcm:my%2Bsecret@1.2.3.4:8388#node",
			wantMethod: "aes-256-gcm",
			want:       "my+secret",
			loadXray:   true,
		},
		{
			// '+' in the method portion is a literal too; no real cipher
			// name contains '+', so this case only pins the parse
			name:       "plus in method",
			link:       "ss://2022-blake3-aes+128:secret@1.2.3.4:8388#node",
			wantMethod: "2022-blake3-aes+128",
			want:       "secret",
		},
		{
			// base64 userinfo keeps working (regression guard for the
			// other branch of the same if)
			name:       "base64 userinfo",
			link:       "ss://YWVzLTI1Ni1nY206bXkrc2VjcmV0@1.2.3.4:8388#node",
			wantMethod: "aes-256-gcm",
			want:       "my+secret",
			loadXray:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ob, err := ConvertLink(tc.link)
			if err != nil {
				t.Fatalf("ConvertLink: %v", err)
			}
			servers, ok := ob["settings"].(M)["servers"].([]M)
			if !ok || len(servers) != 1 {
				t.Fatalf("unexpected settings: %#v", ob["settings"])
			}
			if got := servers[0]["method"]; got != tc.wantMethod {
				t.Fatalf("method = %q, want %q", got, tc.wantMethod)
			}
			if got := servers[0]["password"]; got != tc.want {
				t.Fatalf("password = %q, want %q", got, tc.want)
			}

			if tc.loadXray {
				full := M{
					"log": M{"loglevel": "none"},
					"outbounds": []M{
						ob,
						{"protocol": "freedom", "tag": "direct"},
					},
				}
				raw, err := json.Marshal(full)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				if _, err := xserial.LoadJSONConfig(bytes.NewReader(raw)); err != nil {
					t.Fatalf("xray rejected the generated config: %v\n%s", err, raw)
				}
			}
		})
	}
}

// Xray's XHTTP transport builds a request URL from the config's host (falling
// back to the SNI) and ignores the error from http.NewRequest. A value that
// url.Parse rejects therefore crashes the entire process with a nil
// dereference in splithttp/config.go, taking down a whole aggregation run
// rather than failing one config. Such values must never reach the outbound.
func TestXHTTPHostAndSNIAreURLSafe(t *testing.T) {
	const base = "vless://11111111-2222-3333-4444-555555555555@104.16.0.1:443" +
		"?type=xhttp&security=tls"

	unusable := map[string]string{
		"brackets":     base + "&sni=example.com&host=%5Bbad%5D",
		"space":        base + "&sni=example.com&host=ex%20ample.com",
		"newline":      base + "&sni=example.com&host=a%0Ab.com",
		"control char": base + "&sni=example.com&host=a%01b.com",
		"bare bracket": base + "&sni=example.com&host=%5B",
		"bad sni":      base + "&sni=%5Bbad%5D",
	}
	for name, link := range unusable {
		t.Run(name, func(t *testing.T) {
			ob, err := ConvertLink(link)
			if err != nil {
				return // rejecting the config outright is fine too
			}
			for _, got := range urlHostsIn(ob) {
				if !validURLHost(got) {
					t.Fatalf("unusable host %q reached the outbound config", got)
				}
			}
		})
	}

	keep := map[string]string{
		"ipv6 literal": base + "&sni=example.com&host=%5B2001%3Adb8%3A%3A1%5D",
		"normal host":  base + "&sni=example.com&host=example.com",
	}
	for name, link := range keep {
		t.Run(name, func(t *testing.T) {
			ob, err := ConvertLink(link)
			if err != nil {
				t.Fatalf("ConvertLink: %v", err)
			}
			if len(urlHostsIn(ob)) == 0 {
				t.Fatal("valid host was dropped")
			}
		})
	}
}

// urlHostsIn collects the values xray would use as an XHTTP request-URL host.
func urlHostsIn(ob M) []string {
	stream, _ := ob["streamSettings"].(M)
	var out []string
	for _, path := range [][2]string{
		{"xhttpSettings", "host"},
		{"tlsSettings", "serverName"},
		{"realitySettings", "serverName"},
	} {
		if sub, ok := stream[path[0]].(M); ok {
			if v, ok := sub[path[1]].(string); ok && v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}
