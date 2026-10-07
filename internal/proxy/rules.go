package proxy

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

var (
	nodeNameRE             = regexp.MustCompile(`(?i)^[a-z0-9_-]{1,32}$`)
	staticExtRE            = regexp.MustCompile(`(?i)\.(jpg|jpeg|gif|png|svg|ico|webp|js|css|woff2?|ttf|otf|map|webmanifest|srt|ass|vtt|sub)$`)
	embyImagesRE           = regexp.MustCompile(`(?i)(/Images/|/Icons/|/Branding/|/emby/covers/)`)
	streamingRE            = regexp.MustCompile(`(?i)\.(mp4|m4v|m4s|m4a|ogv|webm|mkv|mov|avi|wmv|flv|ts|m3u8|mpd)$`)
	capyClientRE           = regexp.MustCompile(`(?i)(capy\s*player|capyplayer|卡皮巴拉)`)
	embyPathRE             = regexp.MustCompile(`(?i)^/emby(/|$)`)
	embyPrefixRE           = regexp.MustCompile(`(?i)^/emby`)
	embySlashPrefixRE      = regexp.MustCompile(`(?i)^/emby/`)
	strmStreamPathRE       = regexp.MustCompile(`(?i)(?:^|/)(?:emby/)?videos/[^/]+/(?:stream|original)\.strm$`)
	authAPIRE              = regexp.MustCompile(`(?i)/users/authenticate(byname)?`)
	bearerOrTokenRE        = regexp.MustCompile(`(?i)^(Bearer|Token)\s+`)
	strmExtRE              = regexp.MustCompile(`(?i)\.strm$`)
	httpURLRE              = regexp.MustCompile(`(?i)^https?://`)
	defaultPort80RE        = regexp.MustCompile(`(?i):80$`)
	defaultPort443RE       = regexp.MustCompile(`(?i):443$`)
	acceptRangesBytesRE    = regexp.MustCompile(`(?i)bytes`)
	rangeStartRE           = regexp.MustCompile(`(?i)^\s*bytes\s*=\s*(\d+)-`)
	contentRangeBytesRE    = regexp.MustCompile(`(?i)^\s*bytes\s+(\d+)-(\d+)\s*/\s*(\d+|\*)\s*$`)
	m3u8PathRE             = regexp.MustCompile(`(?i)\.m3u8($|\?)`)
	lineBreakRE            = regexp.MustCompile(`\r?\n`)
	bodyURLRE              = regexp.MustCompile(`https?://[^\s"'<>\\]+`)
	playbackMediaExtRE     = regexp.MustCompile(`(?i)\.(m3u8|mpd|mkv|mp4|ts|m4s)$`)
	embyItemImagesRE       = regexp.MustCompile(`(?i)/emby/items/.+/images/`)
	additionalPartsPathRE  = regexp.MustCompile(`(?i)(?:^|/)(?:emby/)?videos/.+/additionalparts(?:/|$)`)
	setCookieDomainRE      = regexp.MustCompile(`(?i);\s*domain=[^;]+`)
	setCookiePathPresentRE = regexp.MustCompile(`(?i);\s*path=`)
	setCookiePathRE        = regexp.MustCompile(`(?i);\s*path=[^;]+`)
)

var panKeywords = []string{
	"aliyundrive", "alipan", "quark", "baidupcs", "pan.baidu.com",
	"115.com", "123684.com", "uc.cn", "drive.google.com",
	"googleusercontent.com", "1drv.ms", "onedrive.live.com", "sharepoint.com",
}

type directRule struct {
	Name        string
	Keywords    []string
	ForceProxy  bool
	Referer     string
	KeepOrigin  bool
	KeepReferer bool
}

var directRules = []directRule{
	{Name: "tianyi", Keywords: []string{"cloud.189.cn", "189.cn", "ctyun", "e.189.cn", "ctyunxs.cn"}, Referer: "https://cloud.189.cn/"},
	{Name: "115", Keywords: []string{"115.com", "anxia.com", "115cdn"}},
	{Name: "pikpak", Keywords: []string{"mypikpak.com", "pikpak"}},
	{Name: "aliyun", Keywords: []string{"aliyundrive", "alipan"}},
	{Name: "quark", Keywords: []string{"quark", "uc.cn"}},
	{Name: "baidu", Keywords: []string{"pan.baidu.com", "baidupcs"}},
	{Name: "google-drive", Keywords: []string{"drive.google.com", "googleusercontent.com", "googledrive", "gvt1.com"}},
	{Name: "onedrive", Keywords: []string{"onedrive.live.com", "1drv.ms", "sharepoint.com", "sharepoint-df.com"}},
	{Name: "generic-pan", Keywords: []string{"123684.com"}},
}

func directAdapter(u *url.URL) directRule {
	if u == nil {
		return directRule{Name: "generic"}
	}
	hay := strings.ToLower(u.Host + u.Path + "?" + u.RawQuery)
	for _, rule := range directRules {
		for _, keyword := range rule.Keywords {
			if strings.Contains(hay, strings.ToLower(keyword)) {
				return rule
			}
		}
	}
	if isPanURL(u) {
		return directRule{Name: "generic-pan"}
	}
	return directRule{Name: "generic"}
}

func isPanURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, keyword := range panKeywords {
		key := strings.ToLower(keyword)
		if host == key || strings.HasSuffix(host, "."+key) || (!strings.Contains(key, ".") && strings.Contains(host, key)) {
			return true
		}
	}
	return false
}

func isEmosNode(node storage.Node, targetURL *url.URL, env config.ProxyEnv) bool {
	if !env.EmosCompat {
		return false
	}
	if strings.Contains(strings.ToLower(node.Tag), "emos") {
		return true
	}
	host := ""
	if targetURL != nil {
		host = strings.ToLower(targetURL.Hostname())
	}
	if host == "" {
		return false
	}
	for _, item := range strings.Split(env.EmosMatchHosts, ",") {
		if strings.TrimSpace(strings.ToLower(item)) == host {
			return true
		}
	}
	return false
}

func isCapyClient(r *http.Request) bool {
	if r == nil {
		return false
	}
	values := []string{
		r.Header.Get("User-Agent"),
		r.Header.Get("X-Emby-Client"),
		r.Header.Get("X-MediaBrowser-Client"),
		r.Header.Get("X-Emby-Authorization"),
		r.Header.Get("X-MediaBrowser-Authorization"),
		r.Header.Get("Authorization"),
	}
	if r.URL != nil {
		q := r.URL.Query()
		values = append(values,
			q.Get("X-Emby-Client"),
			q.Get("X-MediaBrowser-Client"),
			q.Get("X-Emby-Authorization"),
			q.Get("X-MediaBrowser-Authorization"),
			q.Get("Authorization"),
		)
	}
	for _, value := range values {
		if capyClientRE.MatchString(value) {
			return true
		}
	}
	return false
}

func applyEmosHeaders(headers mapHeader, env config.ProxyEnv) {
	if strings.TrimSpace(env.EmosProxyID) != "" {
		headers.Set("EMOS-PROXY-ID", strings.TrimSpace(env.EmosProxyID))
	}
	if strings.TrimSpace(env.EmosProxyName) != "" {
		headers.Set("EMOS-PROXY-NAME", strings.TrimSpace(env.EmosProxyName))
	}
}

type mapHeader interface {
	Set(string, string)
}

func isPlaybackPath(path string) bool {
	p := normalizedEmbyAPIPath(path)
	return strings.Contains(p, "/smartstrm") || strings.Contains(p, "/videos/") || strings.Contains(p, "/playback/") || strings.Contains(p, "/playbackinfo") || strings.Contains(p, "/sessions/playing") ||
		(strings.Contains(p, "/items/") && (strings.Contains(p, "/download") || strings.Contains(p, "/stream") || strings.Contains(p, "/file"))) ||
		strings.Contains(p, "/audio/") || strings.Contains(p, "/hls/") || strings.Contains(p, "/hls1/") || strings.Contains(p, "/dash/") ||
		streamingRE.MatchString(p) || playbackMediaExtRE.MatchString(p)
}

func normalizedEmbyAPIPath(path string) string {
	return strings.ToLower(stripOptionalEmbyPrefix(path))
}

func stripOptionalEmbyPrefix(path string) string {
	p := ensureLeadingSlash(path)
	if strings.EqualFold(p, "/emby") {
		return "/"
	}
	if len(p) >= len("/emby/") && strings.EqualFold(p[:len("/emby/")], "/emby/") {
		return p[len("/emby"):]
	}
	return p
}

func isSessionsPlayingProgressPath(path string) bool {
	return strings.Contains(normalizedEmbyAPIPath(path), "/sessions/playing/progress")
}

func isSessionsPlayingLifecyclePath(path string) bool {
	p := strings.TrimSuffix(normalizedEmbyAPIPath(path), "/")
	switch p {
	case "/sessions/playing", "/sessions/playing/progress", "/sessions/playing/stopped":
		return true
	default:
		return false
	}
}

func isImagePath(path string) bool {
	return embyItemImagesRE.MatchString(path) || embyImagesRE.MatchString(path)
}

func isSmartStrmPath(path string) bool {
	return strings.Contains(normalizedEmbyAPIPath(path), "/smartstrm")
}

func isAdditionalPartsPath(path string) bool {
	return additionalPartsPathRE.MatchString(path)
}

func routePrefix(name, key string) string {
	prefix := "/" + url.PathEscape(name)
	if key != "" {
		prefix += "/" + url.PathEscape(key)
	}
	return prefix
}

func sameHost(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	ha := strings.ToLower(ua.Hostname())
	hb := strings.ToLower(ub.Hostname())
	if ha != hb {
		return false
	}
	return portOf(ua) == portOf(ub)
}

func portOf(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
