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
		t.Run(tt.name+" with full impersonation identity headers", func(t *testing.T) {
			headers := tt.build(http.Header{"User-Agent": {"Client/1.0"}})
			if got := headers.Get("X-Emby-Client"); got != "Yamby" {
				t.Fatalf("X-Emby-Client = %q, want Yamby", got)
			}
			if got := headers.Get("X-Emby-Client-Version"); got != "2.0.4.6" {
				t.Fatalf("X-Emby-Client-Version = %q, want 2.0.4.6", got)
			}
			if got := headers.Get("X-Emby-Device-Name"); got != "Android" {
				t.Fatalf("X-Emby-Device-Name = %q, want Android", got)
			}
			if got := headers.Get("X-Emby-Device-Id"); got == "" {
				t.Fatalf("X-Emby-Device-Id is empty")
			}
			if got := headers.Get("X-Emby-Authorization"); !strings.Contains(got, "Client=Yamby") || !strings.Contains(got, "DeviceId="+headers.Get("X-Emby-Device-Id")) {
				t.Fatalf("X-Emby-Authorization = %q, want Yamby identity", got)
			}
			if got := headers.Get("User-Agent"); got != "Yamby/2.0.4.6(Android)" {
				t.Fatalf("User-Agent = %q, want Yamby UA", got)
			}
		})
	}

	for _, raw := range []http.Header{{}, {"User-Agent": {"Client/1.0"}}} {
		if got := buildDirect(raw).Get("User-Agent"); got != "Yamby/2.0.4.6(Android)" {
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
			wantDeviceID := identity.DeriveDeviceID(node.Secret, "hills_windows", "source-device", identity.GetProfile("hills_windows"))
			if got := headers.Get("User-Agent"); got != snap.UserAgent {
				t.Fatalf("User-Agent = %q, want %q", got, snap.UserAgent)
			}
			if got := headers.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="Hills Windows"`) || !strings.Contains(got, `DeviceId="`+wantDeviceID+`"`) {
				t.Fatalf("X-Emby-Authorization = %q, want Hills identity with derived device id", got)
			}
			if got := headers.Get("X-Emby-Client"); got != "Hills Windows" {
				t.Fatalf("X-Emby-Client = %q, want Hills Windows", got)
			}
			if got := headers.Get("X-Emby-Device-Id"); got != wantDeviceID {
				t.Fatalf("X-Emby-Device-Id = %q, want derived device id %q", got, wantDeviceID)
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
				"X-MediaBrowser-Client",
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
	wantDeviceID := identity.DeriveDeviceID(node.Secret, "hills_windows", "source-device", identity.GetProfile("hills_windows"))
	if got := query.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="Hills Windows"`) || !strings.Contains(got, `DeviceId="`+wantDeviceID+`"`) {
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

func TestUnimpersonatedUserAgentBehavior(t *testing.T) {
	ids := identity.NewManager(nil)
	node := storage.Node{Impersonate: false}
	targetURL, _ := url.Parse("https://upstream.example/emby/Items")

	// 1. 关伪装有 UA：出站保持原 UA，不是 Go-http-client，不是 Profile UA
	rawWithUA := http.Header{"User-Agent": {"Lenna/1.0"}}
	h1 := buildCleanProxyHeaders(ids, rawWithUA, targetURL, node, config.ProxyEnv{}, false)
	if got := h1.Get("User-Agent"); got != "Lenna/1.0" {
		t.Fatalf("User-Agent = %q, want Lenna/1.0", got)
	}

	// 2. 关伪装无 UA：保留 key 为 nil，避免 Go 补默认 UA
	rawNoUA := http.Header{}
	h2 := buildCleanProxyHeaders(ids, rawNoUA, targetURL, node, config.ProxyEnv{}, false)
	vals, ok := h2["User-Agent"]
	if !ok {
		t.Fatalf("expected User-Agent key to be present to suppress Go-http-client")
	}
	if len(vals) != 0 {
		t.Fatalf("expected User-Agent slice to be nil/empty, got %v", vals)
	}
}

func TestUnimpersonatedMissingClientFallback(t *testing.T) {
	ids := identity.NewManager(nil)
	node := storage.Node{Impersonate: false}

	// 1. 原有 X-Emby-Client 保留，不被改写
	u1, _ := url.Parse("https://upstream.example/emby/Items?client=other")
	h1 := http.Header{
		"X-Emby-Client": {"OriginalClient"},
	}
	out1 := buildCleanProxyHeaders(ids, h1, u1, node, config.ProxyEnv{}, false)
	if got := out1.Get("X-Emby-Client"); got != "OriginalClient" {
		t.Fatalf("X-Emby-Client = %q, want OriginalClient", got)
	}
	assertNoIdentityHeaders(t, out1, "X-Emby-Client")

	// 2. 无 Client，从 Authorization Client= 补缺
	u2, _ := url.Parse("https://upstream.example/emby/Items")
	h2 := http.Header{
		"X-Emby-Authorization": {`Emby Client="FromAuth", Device="Dev", DeviceId="id", Version="1.0"`},
	}
	out2 := buildCleanProxyHeaders(ids, h2, u2, node, config.ProxyEnv{}, false)
	if got := out2.Get("X-Emby-Client"); got != "FromAuth" {
		t.Fatalf("X-Emby-Client = %q, want FromAuth", got)
	}

	// 3. 无 Client，从 query client 补缺
	u3, _ := url.Parse("https://upstream.example/emby/Items?client=FromQuery")
	h3 := http.Header{}
	out3 := buildCleanProxyHeaders(ids, h3, u3, node, config.ProxyEnv{}, false)
	if got := out3.Get("X-Emby-Client"); got != "FromQuery" {
		t.Fatalf("X-Emby-Client = %q, want FromQuery", got)
	}

	// 4. 两者都无，禁止兜底
	u4, _ := url.Parse("https://upstream.example/emby/Items")
	h4 := http.Header{}
	out4 := buildCleanProxyHeaders(ids, h4, u4, node, config.ProxyEnv{}, false)
	if got := out4.Get("X-Emby-Client"); got != "" {
		t.Fatalf("X-Emby-Client = %q, want empty (no fallback)", got)
	}
}

func TestVidhubImpersonatedIdentityOutbound(t *testing.T) {
	ids := identity.NewManager(nil)
	node := storage.Node{
		Impersonate:        true,
		ImpersonateProfile: "yamby",
		Secret:             "test-node-secret",
	}

	targetURL, _ := url.Parse("https://upstream.example/emby/Items?client=vidhub&version=1.0.0&tag=v1")
	rawHeaders := http.Header{
		"User-Agent":       {"Vidhub/1.0.0(iOS)"},
		"X-Emby-Device-Id": {"vidhub-device-uuid-1"},
		"X-Emby-Token":     {"vidhub-token-123"},
	}

	applyIdentityToURL(ids, targetURL, rawHeaders, node)

	// query 中必须删除了 client 和 version，但保留其他 query
	if targetURL.Query().Has("client") {
		t.Fatalf("query still has client: %s", targetURL.RawQuery)
	}
	if targetURL.Query().Has("version") {
		t.Fatalf("query still has version: %s", targetURL.RawQuery)
	}
	if targetURL.Query().Get("tag") != "v1" {
		t.Fatalf("tag query = %q, want v1", targetURL.Query().Get("tag"))
	}

	outbound := buildCleanProxyHeaders(ids, rawHeaders, targetURL, node, config.ProxyEnv{}, false)

	// 验证五元组
	if got := outbound.Get("X-Emby-Client"); got != "Yamby" {
		t.Fatalf("X-Emby-Client = %q, want Yamby", got)
	}
	if got := outbound.Get("X-Emby-Client-Version"); got != "2.0.4.6" {
		t.Fatalf("X-Emby-Client-Version = %q, want 2.0.4.6", got)
	}
	if got := outbound.Get("X-Emby-Device-Name"); got != "Android" {
		t.Fatalf("X-Emby-Device-Name = %q, want Android", got)
	}
	derivedID := identity.DeriveDeviceID(node.Secret, "yamby", "vidhub-device-uuid-1", identity.GetProfile("yamby"))
	if got := outbound.Get("X-Emby-Device-Id"); got != derivedID {
		t.Fatalf("X-Emby-Device-Id = %q, want derived %q", got, derivedID)
	}
	// UA 必须带闭合括号
	if got := outbound.Get("User-Agent"); got != "Yamby/2.0.4.6(Android)" {
		t.Fatalf("User-Agent = %q, want Yamby/2.0.4.6(Android)", got)
	}
	// Authorization
	wantAuth := "Emby Client=Yamby,Device=Android,DeviceId=" + derivedID + ",Version=2.0.4.6"
	if got := outbound.Get("X-Emby-Authorization"); got != wantAuth {
		t.Fatalf("X-Emby-Authorization = %q, want %q", got, wantAuth)
	}
	// Token 只出站 X-Emby-Token
	if got := outbound.Get("X-Emby-Token"); got != "vidhub-token-123" {
		t.Fatalf("X-Emby-Token = %q, want vidhub-token-123", got)
	}
	if strings.Contains(outbound.Get("X-Emby-Authorization"), "vidhub-token-123") {
		t.Fatalf("Authorization must not contain token")
	}
}

func TestImpersonatedDeviceIDDerivationAndTokenAlias(t *testing.T) {
	ids := identity.NewManager(nil)
	node := storage.Node{
		Impersonate:        true,
		ImpersonateProfile: "yamby",
		Secret:             "secret-1",
	}

	targetURL, _ := url.Parse("https://upstream.example/emby/Items")

	// 1. 两个不同入站 DeviceId -> 产生不同出站 ID
	hA := http.Header{"X-Emby-Device-Id": {"dev-A"}, "X-Emby-Token": {"tok-A"}}
	outA1 := buildCleanProxyHeaders(ids, hA, targetURL, node, config.ProxyEnv{}, false)

	hB := http.Header{"X-Emby-Device-Id": {"dev-B"}, "X-Emby-Token": {"tok-B"}}
	outB := buildCleanProxyHeaders(ids, hB, targetURL, node, config.ProxyEnv{}, false)

	if outA1.Get("X-Emby-Device-Id") == outB.Get("X-Emby-Device-Id") {
		t.Fatalf("different inbound device IDs should yield different outbound IDs: %q", outA1.Get("X-Emby-Device-Id"))
	}

	// 2. 同一入站 DeviceId 多次请求 -> 同一出站 ID
	outA2 := buildCleanProxyHeaders(ids, hA, targetURL, node, config.ProxyEnv{}, false)
	if outA1.Get("X-Emby-Device-Id") != outA2.Get("X-Emby-Device-Id") {
		t.Fatalf("same inbound device ID must yield identical outbound ID")
	}

	// 3. 先发带 DeviceId+Token 的 API，后续只带 Token 的播放直链 -> 复用出站 ID
	directURL, _ := url.Parse("https://upstream.example/emby/Videos/123/stream.mp4?api_key=tok-A")
	directHeaders := http.Header{}
	applyIdentityToDirectURL(ids, directURL, directHeaders, node)

	if got := directHeaders.Get("X-Emby-Device-Id"); got != outA1.Get("X-Emby-Device-Id") {
		t.Fatalf("token alias lookup = %q, want same as API request %q", got, outA1.Get("X-Emby-Device-Id"))
	}

	// 4. 纯 Token 且未命中映射（冷启动直链）-> 回落到 KV 持久 ID，禁止随机
	fallbackURL, _ := url.Parse("https://upstream.example/emby/Videos/999/stream.mp4?api_key=unknown-tok")
	fallbackHeaders := http.Header{}
	applyIdentityToDirectURL(ids, fallbackURL, fallbackHeaders, node)

	snap := ids.Snapshot("yamby")
	if got := fallbackHeaders.Get("X-Emby-Device-Id"); got != snap.DeviceID {
		t.Fatalf("fallback device ID = %q, want profile snapshot ID %q", got, snap.DeviceID)
	}
}
