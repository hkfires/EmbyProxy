package proxy

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/storage"
)

func cloneHeader(in http.Header) http.Header {
	out := http.Header{}
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

// These headers commonly carry client addresses or proxy-derived routing metadata.
var clientIPHeaderNames = []string{
	"Forwarded",
	"Forwarded-For",
	"X-Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-For-Original",
	"X-Forwarded-For-Proxy-Protocol",
	"X-Forwarded-IP",
	"X-Forwarded-Client-IP",
	"X-Original-Forwarded-For",
	"X-Forward-For",
	"X-Real-IP",
	"X-Envoy-External-Address",
	"Client-IP",
	"ClientIP",
	"Client-Real-IP",
	"Real-IP",
	"Real-Client-IP",
	"X-Client-IP",
	"X-Client-Real-IP",
	"X-Cluster-Client-IP",
	"X-Originating-IP",
	"X-Original-IP",
	"X-Original-Remote-Addr",
	"X-Real-Client-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"Proxy-Client-IP",
	"WL-Proxy-Client-IP",
	"X-ProxyUser-IP",
	"X-Appengine-User-IP",
	"Remote-Addr",
	"Remote-Host",
	"HTTP-Client-IP",
	"HTTP-X-Forwarded-For",
	"HTTP-X-Forwarded",
	"HTTP-X-Real-IP",
	"HTTP-X-Cluster-Client-IP",
	"HTTP-Forwarded-For",
	"HTTP-Forwarded",
	"HTTP_CLIENT_IP",
	"HTTP_X_FORWARDED_FOR",
	"HTTP_X_FORWARDED",
	"HTTP_X_REAL_IP",
	"HTTP_X_CLUSTER_CLIENT_IP",
	"HTTP_FORWARDED_FOR",
	"HTTP_FORWARDED",
	"REMOTE_ADDR",
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Forwarded-Port",
}

var cdnMetadataHeaderNames = []string{
	"CDN-Loop",
	"Via",
	"True-Client-IP",
	"Ali-Cdn-Real-IP",
	"Ali-Real-Client-IP",
	"X-Forward-Port",
	"X-Forwarded-SSL",
	"X-Cache",
	"X-Cache-Hits",
	"X-Served-By",
	"X-Timer",
	"X-Varnish",
}

var cdnMetadataHeaderPrefixes = []string{
	"cf-",
	"cloudfront-",
	"x-amz-cf-",
	"x-edge-",
	"fastly-",
	"x-fastly-",
	"x-azure-",
	"x-fd-",
	"akamai-",
	"x-vercel-",
	"fly-",
}

func stripProxyMetadataHeaders(h http.Header) {
headerLoop:
	for key := range h {
		for _, name := range clientIPHeaderNames {
			if strings.EqualFold(key, name) {
				delete(h, key)
				continue headerLoop
			}
		}
		for _, name := range cdnMetadataHeaderNames {
			if strings.EqualFold(key, name) {
				delete(h, key)
				continue headerLoop
			}
		}
		lower := strings.ToLower(key)
		for _, prefix := range cdnMetadataHeaderPrefixes {
			if !strings.HasPrefix(lower, prefix) {
				continue
			}
			delete(h, key)
			break
		}
	}
}

func deleteHeaders(h http.Header, keys ...string) {
	for _, key := range keys {
		h.Del(key)
	}
}

var embyAuthorizationClientRE = regexp.MustCompile(`(?i)\bClient\s*=\s*("[^"]*"|[^,\s]+)`)

func extractClientFromAuth(auth string) string {
	matches := embyAuthorizationClientRE.FindStringSubmatch(strings.TrimSpace(auth))
	if len(matches) < 2 {
		return ""
	}
	val := strings.TrimSpace(matches[1])
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
		val = strings.ReplaceAll(val, `\"`, `"`)
		val = strings.ReplaceAll(val, `\\`, `\`)
	}
	return strings.TrimSpace(val)
}

func hasClientHeader(h http.Header) bool {
	if h == nil {
		return false
	}
	for key, values := range h {
		nk := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(key))
		if nk == "xembyclient" || nk == "xmediabrowserclient" {
			for _, v := range values {
				if strings.TrimSpace(v) != "" {
					return true
				}
			}
		}
	}
	return false
}

func fillMissingClientFromAuth(h http.Header) {
	if hasClientHeader(h) {
		return
	}
	for _, key := range []string{"X-Emby-Authorization", "X-MediaBrowser-Authorization", "Authorization", "X-Authorization"} {
		for _, authVal := range h.Values(key) {
			if client := extractClientFromAuth(authVal); client != "" {
				h.Set("X-Emby-Client", client)
				return
			}
		}
	}
}

func fillMissingClientFromQuery(u *url.URL, h http.Header) {
	if u == nil || hasClientHeader(h) {
		return
	}
	fillMissingClientFromAuth(h)
	if hasClientHeader(h) {
		return
	}
	for key, values := range u.Query() {
		nk := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(key))
		if nk == "client" || nk == "xembyclient" || nk == "xmediabrowserclient" {
			for _, v := range values {
				if strings.TrimSpace(v) != "" {
					h.Set("X-Emby-Client", strings.TrimSpace(v))
					return
				}
			}
		}
	}
}

func setProxyUA(ids *identity.Manager, h http.Header, node storage.Node) {
	if node.Impersonate {
		ua := ids.Snapshot(node.ImpersonateProfile).UserAgent
		if ua == "Yamby/2.0.4.6(Android" {
			ua = "Yamby/2.0.4.6(Android)"
		}
		h.Set("User-Agent", ua)
		return
	}
	ua := strings.TrimSpace(h.Get("User-Agent"))
	if ua == "" {
		h["User-Agent"] = nil
		return
	}
	h.Set("User-Agent", ua)
}

func applyIdentity(ids *identity.Manager, h http.Header, node storage.Node) {
	if node.Impersonate {
		ids.ApplyToHeaders(h, node.ImpersonateProfile, node.Secret)
		return
	}
	fillMissingClientFromAuth(h)
}

func applyIdentityToURL(ids *identity.Manager, u *url.URL, headers http.Header, node storage.Node) {
	if node.Impersonate {
		ids.ApplyToURL(u, headers, node.ImpersonateProfile, node.Secret)
		return
	}
	if u != nil && headers != nil {
		fillMissingClientFromQuery(u, headers)
	}
}

func applyIdentityToResourceURL(ids *identity.Manager, u *url.URL, headers http.Header, node storage.Node) {
	if node.Impersonate {
		ids.ApplyToResourceURL(u, headers, node.ImpersonateProfile, node.Secret)
		return
	}
	if u != nil && headers != nil {
		fillMissingClientFromQuery(u, headers)
	}
}

func applyIdentityToDirectURL(ids *identity.Manager, u *url.URL, headers http.Header, node storage.Node) {
	if node.Impersonate {
		ids.ApplyToDirectURL(u, headers, node.ImpersonateProfile, node.Secret)
		return
	}
	if u != nil && headers != nil {
		fillMissingClientFromQuery(u, headers)
	}
}

func buildCleanProxyHeaders(ids *identity.Manager, raw http.Header, targetURL *url.URL, node storage.Node, env config.ProxyEnv, streaming bool) http.Header {
	h := cloneHeader(raw)
	stripProxyMetadataHeaders(h)
	deleteHeaders(h, "Content-Length")
	if !streaming {
		deleteHeaders(h, "Origin", "Referer", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User")
	}
	h.Set("Host", targetURL.Host)
	setProxyUA(ids, h, node)
	applyIdentity(ids, h, node)
	if !node.Impersonate && targetURL != nil {
		fillMissingClientFromQuery(targetURL, h)
	}
	if rg := raw.Get("Range"); rg != "" {
		h.Set("Range", rg)
	}
	if ifRange := raw.Get("If-Range"); ifRange != "" {
		h.Set("If-Range", ifRange)
	}
	if isEmosNode(node, targetURL, env) {
		applyEmosHeaders(h, env)
	}
	return h
}

func buildDirectOutboundHeaders(ids *identity.Manager, raw http.Header, targetURL *url.URL, env config.ProxyEnv, node storage.Node, mode string) http.Header {
	h := cloneHeader(raw)
	adapter := directAdapter(targetURL)
	stripProxyMetadataHeaders(h)
	deleteHeaders(h,
		"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port",
		"Forwarded", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Content-Length", "Origin", "Referer",
	)
	h.Set("Host", targetURL.Host)
	setProxyUA(ids, h, node)
	applyIdentity(ids, h, node)
	if !node.Impersonate && targetURL != nil {
		fillMissingClientFromQuery(targetURL, h)
	}
	if rg := raw.Get("Range"); rg != "" {
		h.Set("Range", rg)
	}
	if ifRange := raw.Get("If-Range"); ifRange != "" {
		h.Set("If-Range", ifRange)
	}
	if adapter.Referer != "" && (!adapter.KeepReferer || h.Get("Referer") == "") {
		h.Set("Referer", adapter.Referer)
	}
	if !adapter.KeepOrigin {
		h.Del("Origin")
	} else if adapter.Referer != "" {
		if ref, err := url.Parse(adapter.Referer); err == nil {
			h.Set("Origin", ref.Scheme+"://"+ref.Host)
		}
	}
	if mode == "retry-no-origin" {
		h.Del("Origin")
		h.Del("Referer")
	}
	if mode == "retry-browserish" {
		if h.Get("Referer") == "" && adapter.KeepReferer && adapter.Referer != "" {
			h.Set("Referer", adapter.Referer)
		}
	}
	if isEmosNode(node, targetURL, env) {
		applyEmosHeaders(h, env)
	}
	return h
}

func pickAllowOrigin(reqOrigin, allow string) string {
	allow = strings.TrimSpace(allow)
	if reqOrigin == "" {
		return "*"
	}
	if allow == "" {
		return reqOrigin
	}
	if allow == "*" {
		return "*"
	}
	for _, item := range strings.Split(allow, ",") {
		if strings.TrimSpace(item) == reqOrigin {
			return reqOrigin
		}
	}
	return "null"
}

func addCORSHeaders(headers http.Header, reqOrigin string, env config.ProxyEnv) {
	ao := pickAllowOrigin(reqOrigin, env.CORSAllowOrigin)
	headers.Set("Access-Control-Allow-Origin", ao)
	if ao != "*" {
		headers.Set("Vary", "Origin")
	}
}

func sendCORSPreflight(w http.ResponseWriter, reqOrigin string, env config.ProxyEnv) {
	h := w.Header()
	ao := pickAllowOrigin(reqOrigin, env.CORSAllowOrigin)
	h.Set("Access-Control-Allow-Origin", ao)
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")
	h.Set("Access-Control-Max-Age", "86400")
	h.Set("Cache-Control", "no-store")
	if ao != "*" {
		h.Set("Vary", "Origin")
	}
	w.WriteHeader(http.StatusOK)
}

func rewriteSetCookieHeaders(headers http.Header, prefix string) {
	cookies := headers.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	headers.Del("Set-Cookie")
	for _, cookie := range cookies {
		cookie = setCookieDomainRE.ReplaceAllString(cookie, "")
		if prefix != "" {
			if setCookiePathPresentRE.MatchString(cookie) {
				cookie = setCookiePathRE.ReplaceAllString(cookie, "; Path="+prefix)
			} else {
				cookie += "; Path=" + prefix
			}
		}
		headers.Add("Set-Cookie", cookie)
	}
}

func copyResponseHeaders(dst http.Header, src http.Header, bodyDecoded bool) {
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "transfer-encoding" {
			continue
		}
		if bodyDecoded && isDecodedBodyHeader(lower) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func fillContentLengthFromContentRange(headers http.Header) {
	if headers == nil || strings.TrimSpace(headers.Get("Content-Length")) != "" {
		return
	}
	m := contentRangeBytesRE.FindStringSubmatch(strings.TrimSpace(headers.Get("Content-Range")))
	if len(m) != 4 {
		return
	}
	start, errStart := strconv.ParseInt(m[1], 10, 64)
	end, errEnd := strconv.ParseInt(m[2], 10, 64)
	if errStart != nil || errEnd != nil || start < 0 || end < start {
		return
	}
	headers.Set("Content-Length", strconv.FormatInt(end-start+1, 10))
}

func isDecodedBodyHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-encoding", "content-length", "content-md5":
		return true
	default:
		return false
	}
}
