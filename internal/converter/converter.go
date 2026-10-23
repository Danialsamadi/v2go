package converter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type M = map[string]any

var protocolPrefixes = []struct {
	prefix string
	name   string
}{
	{"vless://", "vless"},
	{"vmess://", "vmess"},
	{"ss://", "ss"},
	{"trojan://", "trojan"},
	{"hysteria2://", "hysteria2"},
	{"hy2://", "hysteria2"},
}

// validURLHost reports whether h can be used as the host of a URL. Checked by
// parsing rather than by rejecting characters, so bracketed IPv6 literals such
// as [2001:db8::1] remain valid.
func validURLHost(h string) bool {
	u, err := url.Parse("https://" + h + "/")
	return err == nil && u.Host == h
}

func GetProtocol(link string) string {
	link = strings.TrimSpace(link)
	for _, p := range protocolPrefixes {
		if strings.HasPrefix(link, p.prefix) {
			return p.name
		}
	}
	return "unknown"
}

func ConvertLink(link string) (M, error) {
	link = strings.TrimSpace(link)
	switch GetProtocol(link) {
	case "vless":
		return parseVLESS(link)
	case "vmess":
		return parseVMess(link)
	case "ss":
		return parseSS(link)
	case "trojan":
		return parseTrojan(link)
	case "hysteria2":
		return parseHysteria2(link)
	default:
		return nil, fmt.Errorf("unsupported protocol")
	}
}

func parseVLESS(link string) (M, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)

	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}
	uuid := u.User.Username()
	if uuid == "" {
		return nil, fmt.Errorf("missing UUID")
	}

	user := M{
		"id":         uuid,
		"encryption": firstOr(params, "none", "encryption"),
	}
	if flow := first(params, "flow"); flow != "" {
		user["flow"] = flow
	}

	return M{
		"protocol": "vless",
		"tag":      "proxy",
		"settings": M{
			"vnext": []M{{
				"address": u.Hostname(),
				"port":    port,
				"users":   []M{user},
			}},
		},
		"streamSettings": buildStreamSettings(params),
	}, nil
}

func parseVMess(link string) (M, error) {
	raw := link[len("vmess://"):]
	decoded, err := b64DecodeSafe(raw)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var d map[string]any
	if err := json.Unmarshal(decoded, &d); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}

	var port int
	switch v := d["port"].(type) {
	case float64:
		port = int(v)
	case string:
		port, err = strconv.Atoi(v)
		if err != nil || port <= 0 {
			return nil, fmt.Errorf("invalid port: %v", v)
		}
	default:
		return nil, fmt.Errorf("missing/invalid port")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range")
	}

	id, _ := d["id"].(string)
	addr, _ := d["add"].(string)
	if id == "" || addr == "" {
		return nil, fmt.Errorf("missing id or add")
	}

	scy, _ := d["scy"].(string)
	if scy == "" {
		scy, _ = d["security"].(string)
	}
	if scy == "" {
		scy = "auto"
	}

	net_, _ := d["net"].(string)
	if net_ == "" {
		net_ = "tcp"
	}
	tls_, _ := d["tls"].(string)
	if tls_ == "" {
		tls_ = "none"
	}

	params := url.Values{}
	params.Set("type", net_)
	params.Set("security", tls_)

	if v, _ := d["sni"].(string); v != "" {
		params.Set("sni", v)
	}
	if v, _ := d["fp"].(string); v != "" {
		params.Set("fp", v)
	}
	if v, _ := d["alpn"].(string); v != "" {
		params.Set("alpn", v)
	}

	switch net_ {
	case "ws", "websocket", "httpupgrade":
		if v, _ := d["host"].(string); v != "" {
			params.Set("host", v)
		}
		if v, _ := d["path"].(string); v != "" {
			params.Set("path", v)
		}
	case "grpc":
		if v, _ := d["path"].(string); v != "" {
			params.Set("serviceName", v)
		}
		if v, _ := d["host"].(string); v != "" {
			params.Set("authority", v)
		}
		if t, _ := d["type"].(string); t == "multi" {
			params.Set("mode", "multi")
		}
	case "xhttp", "splithttp":
		if v, _ := d["host"].(string); v != "" {
			params.Set("host", v)
		}
		if v, _ := d["path"].(string); v != "" {
			params.Set("path", v)
		}
		if v, _ := d["mode"].(string); v != "" {
			params.Set("mode", v)
		}
	case "tcp", "raw":
		if v, _ := d["type"].(string); v != "" && v != "none" {
			params.Set("headerType", v)
		}
		if v, _ := d["host"].(string); v != "" {
			params.Set("host", v)
		}
	}

	return M{
		"protocol": "vmess",
		"tag":      "proxy",
		"settings": M{
			"vnext": []M{{
				"address": addr,
				"port":    port,
				"users": []M{{
					"id":       id,
					"security": scy,
				}},
			}},
		},
		"streamSettings": buildStreamSettings(params),
	}, nil
}

func parseSS(link string) (M, error) {
	raw := link[len("ss://"):]

	if i := strings.LastIndex(raw, "#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "?"); i >= 0 {
		raw = raw[:i]
	}

	var method, password, host string
	var port int
	var err error

	if i := strings.LastIndex(raw, "@"); i >= 0 {
		userinfoPart := raw[:i]
		serverPart := raw[i+1:]

		var userinfo string
		if b, decErr := b64DecodeSafe(userinfoPart); decErr == nil {
			userinfo = string(b)
		} else {
			// SIP002 encodes the plaintext userinfo as a URI path segment
			// (RFC 3986), where '+' is a literal; QueryUnescape would apply
			// form-urlencoded semantics and rewrite it into a space.
			userinfo, err = url.PathUnescape(userinfoPart)
			if err != nil {
				return nil, fmt.Errorf("invalid userinfo")
			}
		}
		parts := strings.SplitN(userinfo, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid userinfo: no ':'")
		}
		method, password = parts[0], parts[1]
		host, port, err = splitHostPort(serverPart)
	} else {
		b, decErr := b64DecodeSafe(raw)
		if decErr != nil {
			return nil, fmt.Errorf("base64 decode: %w", decErr)
		}
		s := string(b)
		i := strings.LastIndex(s, "@")
		if i < 0 {
			return nil, fmt.Errorf("legacy SS: no '@'")
		}
		mp := s[:i]
		serverPart := s[i+1:]
		parts := strings.SplitN(mp, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("legacy SS: no ':'")
		}
		method, password = parts[0], parts[1]
		host, port, err = splitHostPort(serverPart)
	}
	if err != nil {
		return nil, err
	}

	return M{
		"protocol": "shadowsocks",
		"tag":      "proxy",
		"settings": M{
			"servers": []M{{
				"address":  host,
				"port":     port,
				"method":   method,
				"password": password,
			}},
		},
		"streamSettings": M{"network": "tcp", "security": "none"},
	}, nil
}

func parseTrojan(link string) (M, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}
	password, _ := url.QueryUnescape(u.User.Username())
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}
	if params.Get("security") == "" {
		params.Set("security", "tls")
	}
	return M{
		"protocol": "trojan",
		"tag":      "proxy",
		"settings": M{
			"servers": []M{{
				"address":  u.Hostname(),
				"port":     port,
				"password": password,
			}},
		},
		"streamSettings": buildStreamSettings(params),
	}, nil
}

func parseHysteria2(link string) (M, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}

	auth := ""
	if u.User != nil {
		auth, _ = url.QueryUnescape(u.User.Username())
	}
	if auth == "" {
		return nil, fmt.Errorf("missing auth")
	}

	tlsSettings := M{}
	if sni := first(params, "sni"); sni != "" && validURLHost(sni) {
		tlsSettings["serverName"] = sni
	}
	if fp := first(params, "fp", "fingerprint"); fp != "" {
		tlsSettings["fingerprint"] = fp
	}
	if alpn := first(params, "alpn"); alpn != "" {
		tlsSettings["alpn"] = strings.Split(alpn, ",")
	}
	if pcs := first(params, "pcs"); pcs != "" {
		tlsSettings["pinnedPeerCertSha256"] = pcs
	}
	if vcn := first(params, "vcn"); vcn != "" {
		tlsSettings["verifyPeerCertByName"] = vcn
	}

	hySettings := M{"auth": auth}

	obfs := first(params, "obfs")
	obfsPass := first(params, "obfs-password")
	if obfs != "" && obfsPass != "" {
		hySettings["obfs"] = obfs
		hySettings["obfsPassword"] = obfsPass
	}

	stream := M{
		"network":          "hysteria",
		"security":         "tls",
		"hysteriaSettings": hySettings,
	}
	if len(tlsSettings) > 0 {
		stream["tlsSettings"] = tlsSettings
	}

	return M{
		"protocol": "trojan",
		"tag":      "proxy",
		"settings": M{
			"servers": []M{{
				"address":  u.Hostname(),
				"port":     port,
				"password": auth,
			}},
		},
		"streamSettings": stream,
	}, nil
}

func buildStreamSettings(params url.Values) M {
	network := params.Get("type")
	if network == "" {
		network = "tcp"
	}
	security := params.Get("security")
	if security == "" {
		security = "none"
	}

	stream := M{"network": network, "security": security}

	switch security {
	case "tls":
		tls := M{}
		// An SNI that url.Parse rejects is not a usable server name, and the
		// XHTTP transport will use it as a request-URL host and crash on it.
		if v := params.Get("sni"); v != "" && validURLHost(v) {
			tls["serverName"] = v
		}
		if v := params.Get("fp"); v != "" {
			tls["fingerprint"] = v
		}
		if v := params.Get("alpn"); v != "" {
			tls["alpn"] = strings.Split(v, ",")
		}
		if v := params.Get("pcs"); v != "" {
			tls["pinnedPeerCertSha256"] = v
		}
		if v := params.Get("vcn"); v != "" {
			tls["verifyPeerCertByName"] = v
		}
		if len(tls) > 0 {
			stream["tlsSettings"] = tls
		}
	case "reality":
		r := M{}
		if v := params.Get("sni"); v != "" && validURLHost(v) {
			r["serverName"] = v
		}
		if v := params.Get("fp"); v != "" {
			r["fingerprint"] = v
		}
		if v := params.Get("pbk"); v != "" {
			r["publicKey"] = v
		}
		if v := params.Get("sid"); v != "" {
			r["shortId"] = v
		}
		if v := params.Get("spx"); v != "" {
			r["spiderX"], _ = url.QueryUnescape(v)
		}
		if len(r) > 0 {
			stream["realitySettings"] = r
		}
	}

	switch network {
	case "ws", "websocket":
		ws := M{}
		if v := params.Get("path"); v != "" {
			ws["path"], _ = url.QueryUnescape(v)
		}
		if v := params.Get("host"); v != "" {
			ws["host"] = v
		}
		if len(ws) > 0 {
			stream["wsSettings"] = ws
		}
	case "grpc":
		g := M{}
		if v := params.Get("serviceName"); v != "" {
			g["serviceName"] = v
		}
		if v := params.Get("authority"); v != "" {
			g["authority"] = v
		}
		if params.Get("mode") == "multi" {
			g["multiMode"] = true
		}
		if len(g) > 0 {
			stream["grpcSettings"] = g
		}
	case "httpupgrade":
		h := M{}
		if v := params.Get("path"); v != "" {
			h["path"], _ = url.QueryUnescape(v)
		}
		if v := params.Get("host"); v != "" {
			h["host"] = v
		}
		if len(h) > 0 {
			stream["httpupgradeSettings"] = h
		}
	case "xhttp", "splithttp":
		x := M{}
		if v := params.Get("path"); v != "" {
			x["path"], _ = url.QueryUnescape(v)
		}
		// Xray builds the XHTTP request URL from this host and ignores the
		// error from http.NewRequest, so a host that url.Parse rejects takes
		// the whole process down with a nil dereference rather than failing
		// this one config. Drop it instead; xray then falls back to the SNI or
		// the destination address.
		if v := params.Get("host"); v != "" && validURLHost(v) {
			x["host"] = v
		}
		if v := params.Get("mode"); v != "" {
			x["mode"] = v
		}
		if len(x) > 0 {
			stream["xhttpSettings"] = x
		}
	case "tcp", "raw":
		if params.Get("headerType") == "http" {
			hosts := strings.Split(params.Get("host"), ",")
			stream["tcpSettings"] = M{
				"header": M{
					"type": "http",
					"request": M{
						"headers": M{"Host": hosts},
					},
				},
			}
		}
	}

	return stream
}

func b64DecodeSafe(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	padLen := (4 - len(s)%4) % 4
	padded := s + strings.Repeat("=", padLen)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(padded); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func parsePort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("missing port")
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port: %s", s)
	}
	return p, nil
}

func splitHostPort(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 || end+1 >= len(s) || s[end+1] != ':' {
			return "", 0, fmt.Errorf("invalid IPv6: %s", s)
		}
		host := s[1:end]
		port, err := strconv.Atoi(s[end+2:])
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port")
		}
		return host, port, nil
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("missing port")
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port")
	}
	return s[:i], port, nil
}

func first(p url.Values, keys ...string) string {
	for _, k := range keys {
		if v := p.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func firstOr(p url.Values, def string, keys ...string) string {
	if v := first(p, keys...); v != "" {
		return v
	}
	return def
}
