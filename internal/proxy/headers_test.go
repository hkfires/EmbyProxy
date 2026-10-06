package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/storage"
)

func TestSendCORSPreflightMatchesArchivedPolicy(t *testing.T) {
	rec := httptest.NewRecorder()

	sendCORSPreflight(rec, "https://player.example", config.ProxyEnv{})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	headers := rec.Result().Header
	if got := headers.Get("Access-Control-Allow-Origin"); got != "https://player.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want reflected origin", got)
	}
	if got := headers.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want empty", got)
	}
	if got := headers.Get("Access-Control-Allow-Private-Network"); got != "" {
		t.Fatalf("Access-Control-Allow-Private-Network = %q, want empty", got)
	}
	if got := headers.Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want Origin", got)
	}
}

func TestOutboundHeaderBuildersMapClientIdentityHeaders(t *testing.T) {
	targetURL, err := url.Parse("https://upstream.example/emby/Items")
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewManager(nil)
	node := storage.Node{Impersonate: true, ImpersonateProfile: identity.DefaultProfile}
	buildDirect := func(raw http.Header) http.Header {
		return buildDirectOutboundHeaders(ids, raw, targetURL, config.ProxyEnv{}, node, "normal")
	}

	for _, tt := range []struct {
		name  string
		build func(http.Header) http.Header
	}{
		{
			name: "clean proxy",
			build: func(raw http.Header) http.Header {
				return buildCleanProxyHeaders(ids, raw, targetURL, node, config.ProxyEnv{}, false)
			},
		},
		{
			name:  "direct",
			build: buildDirect,
		},
		{
			name: "websocket",
			build: func(raw http.Header) http.Header {
				return buildWebSocketHeaders(ids, raw, targetURL, node)
			},
		},
	} {
		t.Run(tt.name+" without identity headers", func(t *testing.T) {
			assertNoIdentityHeaders(t, tt.build(http.Header{"User-Agent": {"Client/1.0"}}))
		})
	}

	for _, raw := range []http.Header{{}, {"User-Agent": {"Client/1.0"}}} {
		if got := buildDirect(raw).Get("User-Agent"); got != "Yamby/2.1.0.11(Android" {
			t.Fatalf("User-Agent = %q, want impersonated user agent", got)
		}
	}
}

func TestOutboundHeaderBuildersStripProxyMetadataHeaders(t *testing.T) {
	targetURL, err := url.Parse("https://upstream.example/emby/Items")
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewManager(nil)
	node := storage.Node{}
	raw := http.Header{}
	wantAbsent := append([]string{}, cdnMetadataHeaderNames...)
	for _, key := range cdnMetadataHeaderNames {
		raw.Set(key, "proxy-metadata")
	}
	for _, key := range []string{
		"CF-Ray",
		"CF-Visitor",
		"CF-Warp-Tag-Id",
		"Fastly-Client-IP",
		"Fastly-FF",
		"CloudFront-Viewer-Country",
		"CloudFront-Viewer-Address",
		"X-Amz-Cf-Id",
		"X-Edge-Request-Id",
		"X-Fastly-Request-ID",
		"X-Azure-ClientIP",
		"X-Azure-SocketIP",
		"X-Azure-Ref",
		"X-Azure-RequestChain",
		"X-Azure-FDID",
		"X-Azure-Region",
		"X-FD-HealthProbe",
		"Akamai-Client-IP",
		"Akamai-Origin-Hop",
		"X-Vercel-Id",
		"Fly-Client-IP",
	} {
		raw.Set(key, "proxy-prefix-metadata")
		wantAbsent = append(wantAbsent, key)
	}
	raw["cf-worker"] = []string{"lowercase-proxy-metadata"}
	raw["cdn-loop"] = []string{"lowercase-proxy-metadata"}
	wantAbsent = append(wantAbsent, "cf-worker", "cdn-loop")
	raw.Set("User-Agent", "Client/1.0")
	raw.Set("X-Request-Id", "keep-me")

	tests := []struct {
		name  string
		build func(http.Header) http.Header
	}{
		{
			name: "clean proxy",
			build: func(raw http.Header) http.Header {
				return buildCleanProxyHeaders(ids, raw, targetURL, node, config.ProxyEnv{}, false)
			},
		},
		{
			name: "direct",
			build: func(raw http.Header) http.Header {
				return buildDirectOutboundHeaders(ids, raw, targetURL, config.ProxyEnv{}, node, "normal")
			},
		},
		{
			name: "websocket",
			build: func(raw http.Header) http.Header {
				return buildWebSocketHeaders(ids, raw, targetURL, node)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := tt.build(raw)
			assertHeaderKeysAbsent(t, headers, wantAbsent...)
			if got := headers.Get("X-Request-Id"); got != "keep-me" {
				t.Fatalf("X-Request-Id = %q, want keep-me", got)
			}
		})
	}
}

func TestOutboundHeaderBuildersPreserveClientCompressionAndHopByHopHeaders(t *testing.T) {
	targetURL, err := url.Parse("https://upstream.example/emby/Items")
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewManager(nil)
	node := storage.Node{Impersonate: true, ImpersonateProfile: identity.DefaultProfile}
	raw := http.Header{
		"Accept-Encoding":  {"gzip, br"},
		"Connection":       {"Keep-Alive"},
		"Keep-Alive":       {"timeout=5"},
		"Proxy-Connection": {"keep-alive"},
		"Te":               {"trailers"},
		"User-Agent":       {"Original/1.0"},
	}
	tests := []struct {
		name  string
		build func(http.Header) http.Header
	}{
		{
			name: "clean proxy",
			build: func(raw http.Header) http.Header {
				return buildCleanProxyHeaders(ids, raw, targetURL, node, config.ProxyEnv{}, false)
			},
		},
		{
			name: "direct",
			build: func(raw http.Header) http.Header {
				return buildDirectOutboundHeaders(ids, raw, targetURL, config.ProxyEnv{}, node, "normal")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := tt.build(raw)
			for key, want := range map[string]string{
				"Accept-Encoding":  "gzip, br",
				"Connection":       "Keep-Alive",
				"Keep-Alive":       "timeout=5",
				"Proxy-Connection": "keep-alive",
				"Te":               "trailers",
			} {
				if got := headers.Get(key); got != want {
					t.Fatalf("%s = %q, want passthrough %q", key, got, want)
				}
			}
		})
	}
}

func TestOutboundHeaderBuildersNormalizeHillsHeadersAndKeepOrdinaryHeaders(t *testing.T) {
	targetURL, err := url.Parse("https://upstream.example/emby/Items")
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewManager(nil)
	node := storage.Node{Impersonate: true, ImpersonateProfile: "hills_windows"}
	raw := http.Header{
		"Accept":                  {"application/json"},
		"Accept-Encoding":         {"gzip, br"},
		"Authorization":           {`Emby Token="source-token", Client="Original", Device="SOURCE-PC", DeviceId="source-device", Version="0.0.0-test"`},
		"Range":                   {"bytes=0-"},
		"User-Agent":              {"Original/0.0.0-test"},
		"X-Emby-Client":           {"Original"},
		"X-Emby-Client-Version":   {"0.0.0-test"},
		"X-Emby-Device-Id":        {"source-device"},
		"X-Emby-Device-Name":      {"SOURCE-PC"},
		"X-MediaBrowser-Client":   {"Original"},
		"X-MediaBrowser-DeviceId": {"source-media-device"},
	}
	tests := []struct {
		name  string
		build func(http.Header) http.Header
	}{
		{
			name: "clean proxy",
			build: func(raw http.Header) http.Header {
				return buildCleanProxyHeaders(ids, raw, targetURL, node, config.ProxyEnv{}, true)
			},
		},
		{
			name: "direct",
			build: func(raw http.Header) http.Header {
				return buildDirectOutboundHeaders(ids, raw, targetURL, config.ProxyEnv{}, node, "normal")
			},
		},
		{
			name: "websocket",
			build: func(raw http.Header) http.Header {
				return buildWebSocketHeaders(ids, raw, targetURL, node)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := tt.build(raw)
			snap := ids.Snapshot("hills_windows")
			if got := headers.Get("User-Agent"); got != snap.UserAgent {
				t.Fatalf("User-Agent = %q, want %q", got, snap.UserAgent)
			}
			if got := headers.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="Hills Windows"`) || !strings.Contains(got, `DeviceId="`+snap.DeviceID+`"`) {
				t.Fatalf("X-Emby-Authorization = %q, want Hills identity", got)
			}
			if got := headers.Get("X-Emby-Token"); got != "source-token" {
				t.Fatalf("X-Emby-Token = %q, want source-token", got)
			}
			if got := headers.Get("Accept"); got != "application/json" {
				t.Fatalf("Accept = %q, want application/json", got)
			}
			if got := headers.Get("Accept-Encoding"); got != "gzip, br" {
				t.Fatalf("Accept-Encoding = %q, want gzip, br", got)
			}
			if tt.name != "websocket" {
				if got := headers.Get("Range"); got != "bytes=0-" {
					t.Fatalf("Range = %q, want bytes=0-", got)
				}
			}
			assertHeaderKeysAbsent(t, headers,
				"Authorization", "X-Authorization",
				"X-Emby-Client", "X-MediaBrowser-Client",
			)
		})
	}
}

func TestWebSocketHandshakeAddsHillsIdentityQuery(t *testing.T) {
	base, err := url.Parse("wss://upstream.example/emby")
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewManager(nil)
	node := storage.Node{Impersonate: true, ImpersonateProfile: "hills_windows"}
	targetURL := resolveTargetURL(base, "/Sessions/123/WebSocket", "x_emby_device_id=source-device&X-Emby-Language=en-us&tag=v1")
	outboundHeaders := http.Header{
		"Authorization": {`Emby Token="source-token", Client="Original", Device="SOURCE-PC", DeviceId="source-device", Version="0.0.0-test"`},
		"User-Agent":    {"Original/0.0.0-test"},
	}

	applyIdentityToURL(ids, targetURL, outboundHeaders, node)
	headers := buildWebSocketHeaders(ids, outboundHeaders, targetURL, node)

	snap := ids.Snapshot("hills_windows")
	query := targetURL.Query()
	if got := query.Get("X-Emby-Language"); got != "zh-cn" {
		t.Fatalf("X-Emby-Language = %q, want zh-cn", got)
	}
	if got := query.Get("X-Emby-Token"); got != "source-token" {
		t.Fatalf("X-Emby-Token = %q, want source-token", got)
	}
	if got := query.Get("tag"); got != "v1" {
		t.Fatalf("tag = %q, want v1", got)
	}
	if got := query.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="Hills Windows"`) || !strings.Contains(got, `DeviceId="`+snap.DeviceID+`"`) {
		t.Fatalf("X-Emby-Authorization = %q, want Hills identity", got)
	}
	if query.Has("x_emby_device_id") {
		t.Fatalf("x_emby_device_id query was not removed")
	}
	if got := headers.Get("Connection"); got != "Upgrade" {
		t.Fatalf("Connection = %q, want Upgrade", got)
	}
	if got := headers.Get("Upgrade"); got != "websocket" {
		t.Fatalf("Upgrade = %q, want websocket", got)
	}
	if got := headers.Get("X-Emby-Token"); got != "source-token" {
		t.Fatalf("X-Emby-Token = %q, want source-token", got)
	}
}

func assertHeaderKeysAbsent(t *testing.T, headers http.Header, absentKeys ...string) {
	t.Helper()
	for _, absentKey := range absentKeys {
		for key, values := range headers {
			if strings.EqualFold(key, absentKey) {
				t.Fatalf("%s was forwarded as %q", key, values)
			}
		}
	}
}

func assertNoIdentityHeaders(t *testing.T, headers http.Header, except ...string) {
	t.Helper()
	skip := map[string]bool{}
	for _, key := range except {
		skip[http.CanonicalHeaderKey(key)] = true
	}
	for _, key := range []string{"Authorization", "X-Emby-Authorization", "X-Emby-Client", "X-Emby-Client-Version", "X-Emby-Device-Name", "X-Emby-Device-Id"} {
		if skip[http.CanonicalHeaderKey(key)] {
			continue
		}
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s = %q, want empty", key, got)
		}
	}
}
