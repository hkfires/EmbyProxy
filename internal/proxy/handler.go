package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"embyproxy/internal/auth"
	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/requestlog"
	"embyproxy/internal/storage"
)

type Handler struct {
	cfg                       config.Config
	store                     *storage.Store
	ids                       *identity.Manager
	log                       *logging.Logger
	lineBan                   *ttlMap
	progressThrottle          *ttlMap
	playbackDedup             *ttlMap
	imageLimiterMu            sync.Mutex
	imageLimiter              *imageRequestLimiter
	imageCacheMu              sync.Mutex
	imageCache                *imageDiskCache
	activeMu                  sync.Mutex
	activeTarget              map[string]string
	noRedirectClient          *http.Client
	defaultFollowClient       *http.Client
	playbackActionClient      *http.Client
	playbackStreamClient      *http.Client
	playbackStreamProbeClient *http.Client
	imageFollowClient         *http.Client
	rawDirectClient           *http.Client
	rawLinkKeyMu              sync.Mutex
	rawLinkKey                []byte
	targetAttemptTimeout      time.Duration
}

const (
	accessLogFieldUpstreamPool = "upstreamPool"

	upstreamPoolNoRedirect          = "noRedirect"
	upstreamPoolDefaultFollow       = "defaultFollow"
	upstreamPoolPlaybackAction      = "playbackAction"
	upstreamPoolPlaybackStream      = "playbackStream"
	upstreamPoolPlaybackStreamProbe = "playbackStreamProbe"
	upstreamPoolImageFollow         = "imageFollow"
	upstreamPoolRawDirect           = "rawDirect"
	upstreamPoolUndefined           = "undefined"
)

// UpstreamTargetAttemptTimeout limits how long one upstream may take to
// produce a usable response before failover moves to the next target.
const UpstreamTargetAttemptTimeout = 15 * time.Second

var errUpstreamTargetAttemptTimeout = errors.New("upstream target attempt timeout")

type targetAttemptTimerContextKey struct{}

type targetAttemptTimer struct {
	mu      sync.Mutex
	started bool
	timer   *time.Timer
	timeout time.Duration
	cancel  context.CancelCauseFunc
}

func (t *targetAttemptTimer) start() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started {
		return
	}
	t.started = true
	t.timer = time.AfterFunc(t.timeout, func() {
		t.cancel(errUpstreamTargetAttemptTimeout)
	})
}

func (t *targetAttemptTimer) stop() bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	started := t.started
	timer := t.timer
	t.mu.Unlock()
	return !started || timer.Stop()
}

func startTargetAttemptTimer(ctx context.Context) {
	timer, _ := ctx.Value(targetAttemptTimerContextKey{}).(*targetAttemptTimer)
	timer.start()
}

type parsedRoute struct {
	URL      *url.URL
	Segments []string
	Name     string
	Secret   string
	Path     string
	HasKey   bool
}

const (
	rawHostLookupTimeout = 3 * time.Second
	playbackStateTimeout = time.Second
	proxyConnIdleTimeout = 2 * time.Minute
	bodyCopyBufferSize   = 256 * 1024
)

var bodyCopyBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, bodyCopyBufferSize)
	},
}

func New(cfg config.Config, store *storage.Store, ids *identity.Manager, log *logging.Logger) *Handler {
	defaults := storage.DefaultSystemConfig()
	var imageLimiter *imageRequestLimiter
	if defaults.ImageProxyLimitEnabled {
		imageLimiter = newImageRequestLimiter(defaults.ImageProxyMaxConcurrent, time.Duration(defaults.ImageProxyRequestIntervalMS)*time.Millisecond)
	}
	playbackActionTransport := newProxyTransport(false)
	playbackStreamTransport := newProxyTransport(false)
	return &Handler{
		cfg:                       cfg,
		store:                     store,
		ids:                       ids,
		log:                       log,
		lineBan:                   newTTLMap(),
		progressThrottle:          newTTLMap(),
		playbackDedup:             newTTLMap(),
		imageLimiter:              imageLimiter,
		imageCache:                newImageCacheFromSystemConfig(cfg, defaults),
		activeTarget:              map[string]string{},
		noRedirectClient:          newProxyHTTPClient(false),
		defaultFollowClient:       newProxyHTTPClient(true),
		playbackActionClient:      newProxyHTTPClientWithTransport(true, playbackActionTransport),
		playbackStreamClient:      newProxyHTTPClientWithTransport(true, playbackStreamTransport),
		playbackStreamProbeClient: newProxyHTTPClientWithTransport(false, playbackStreamTransport),
		imageFollowClient:         newProxyHTTPClient(true),
		rawDirectClient:           newRawHTTPClient(),
		rawLinkKey:                newRawLinkKey(cfg.AdminToken),
	}
}

func newProxyHTTPClient(follow bool) *http.Client {
	return newProxyHTTPClientWithTransport(follow, newProxyTransport(false))
}

func newProxyHTTPClientWithTransport(follow bool, transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = newProxyTransport(false)
	}
	client := &http.Client{Transport: transport}
	if !follow {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func newRawHTTPClient() *http.Client {
	return &http.Client{Transport: newProxyTransport(true)}
}

func newProxyTransport(protectRaw bool) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialWithIdleTimeout(dialer, proxyConnIdleTimeout),
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: UpstreamTargetAttemptTimeout,
		ExpectContinueTimeout: 5 * time.Second,
	}
	if protectRaw {
		transport.Proxy = nil
		transport.DialContext = dialPublicOnlyWithIdleTimeout(dialer, proxyConnIdleTimeout)
	}
	return transport
}

func dialWithIdleTimeout(dialer *net.Dialer, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &idleTimeoutConn{Conn: conn, timeout: timeout}, nil
	}
}

type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(p)
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(p)
}

func dialPublicOnlyWithIdleTimeout(dialer *net.Dialer, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := resolvePublicDialIPs(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return &idleTimeoutConn{Conn: conn, timeout: timeout}, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no public dial address for %s", host)
	}
}

func resolvePublicDialIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if rawIPBlocked(ip) {
			return nil, fmt.Errorf("blocked private raw host: %s", host)
		}
		return []net.IP{ip}, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, rawHostLookupTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if rawIPBlocked(ip) {
			continue
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("blocked private raw host: %s", host)
	}
	return out, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := withPlaybackLogState(r.Context())
	r = r.WithContext(ctx)
	capture.SetMeta(r, map[string]any{"mode": "proxy", "stage": "route-parse"})
	parsed, status, message := h.parseRequest(r)
	if status != 0 {
		capture.SetMeta(r, map[string]any{"stage": routeStage(status, message)})
		http.Error(w, message, status)
		return
	}
	capture.SetMeta(r, map[string]any{"node": parsed.Name, "stage": "node-lookup"})
	node, err := h.store.GetNode(ctx, "admin", parsed.Name)
	if err != nil {
		h.log.Error("proxy", "node lookup failed", map[string]any{"event": "nodeLookupFailed", "node": parsed.Name, "error": err.Error()})
		http.Error(w, "Node lookup failed", http.StatusInternalServerError)
		return
	}
	if node == nil {
		capture.SetMeta(r, map[string]any{"node": parsed.Name, "stage": "node-not-found"})
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}
	capture.SetMeta(r, map[string]any{"node": parsed.Name, "impersonated": node.Impersonate})
	requestlog.SetRequestURI(ctx, logging.RedactProxyURL(r.URL.RequestURI(), parsed.Name, node.Secret))
	LogRequestStarted(ctx, h.log, r, auth.ClientIP(r, h.trustsProxy(ctx)), parsed.Name)
	parsed.Secret = node.Secret
	strip := 1
	if node.Secret != "" {
		if len(parsed.Segments) < 2 || parsed.Segments[1] != node.Secret {
			capture.SetMeta(r, map[string]any{"node": parsed.Name, "secret": node.Secret, "stage": "invalid-secret"})
			h.log.Warn("proxy", "invalid node secret", map[string]any{"event": "invalidNodeSecret", "node": parsed.Name, "ip": auth.ClientIP(r, h.trustsProxy(ctx))})
			http.Error(w, "Node not found", http.StatusNotFound)
			return
		}
		strip = 2
		parsed.HasKey = true
	}
	parsed.Path = buildRemainingPath(parsed.URL, parsed.Segments, strip)
	capture.SetMeta(r, map[string]any{"node": parsed.Name, "secret": node.Secret, "stage": "route-ready"})
	if parsed.Path == "/" && !strings.HasSuffix(r.URL.Path, "/") {
		capture.SetMeta(r, map[string]any{"node": parsed.Name, "secret": node.Secret, "stage": "trailing-slash-redirect"})
		redirect := *r.URL
		redirect.Path += "/"
		http.Redirect(w, r, redirect.String(), http.StatusMovedPermanently)
		return
	}
	env := h.proxyEnv(ctx)
	if r.Method == http.MethodOptions {
		capture.SetMeta(r, map[string]any{"node": parsed.Name, "secret": node.Secret, "stage": "cors-preflight"})
		sendCORSPreflight(w, r.Header.Get("Origin"), env)
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		h.handleWebSocket(w, r, *node, parsed)
		return
	}
	body, err := h.requestBodyForReplay(w, r)
	if err != nil {
		http.Error(w, "Request body error", http.StatusBadRequest)
		return
	}
	res, err := h.handleNode(ctx, r, *node, parsed, body, env)
	if err != nil {
		h.log.Error("proxy", "request failed", map[string]any{"event": "requestFailed", "node": parsed.Name, "error": err.Error()})
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	h.sendResponse(w, r, res)
}

func (h *Handler) CleanupTTLMaps() {
	h.lineBan.Cleanup()
	h.progressThrottle.Cleanup()
	h.playbackDedup.Cleanup()
	if imageCache := h.ensureImageCache(context.Background()); imageCache != nil {
		imageCache.CleanupExpired()
	}
	if h.store != nil {
		_ = h.store.PrunePlayBuckets(context.Background(), 3)
		_ = h.store.PrunePlaybackStates(context.Background(), 24*time.Hour)
	}
}

func (h *Handler) ResetNodeRoutingState(uid, name string) {
	key := strings.TrimSpace(uid + ":" + strings.ToLower(name))
	if key == ":" {
		return
	}
	h.activeMu.Lock()
	delete(h.activeTarget, key)
	h.activeMu.Unlock()
	h.lineBan.DeletePrefix(key + "|")
}

func (h *Handler) parseRequest(r *http.Request) (parsedRoute, int, string) {
	segments := []string{}
	trimmed := strings.Trim(r.URL.Path, "/")
	if trimmed != "" {
		for _, part := range strings.Split(trimmed, "/") {
			decoded, err := url.PathUnescape(part)
			if err != nil {
				return parsedRoute{}, http.StatusBadRequest, "Bad Request: invalid URL encoding"
			}
			segments = append(segments, decoded)
		}
	}
	name := strings.ToLower(strings.TrimSpace(firstSegment(segments)))
	if name == "" {
		return parsedRoute{}, http.StatusBadRequest, "Missing node name"
	}
	if !nodeNameRE.MatchString(name) {
		return parsedRoute{}, http.StatusNotFound, "Node not found"
	}
	return parsedRoute{URL: r.URL, Segments: segments, Name: name}, 0, ""
}

func (h *Handler) handleNode(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, body []byte, env config.ProxyEnv) (*http.Response, error) {
	targets := storage.SplitTargets(node.Target)
	requestID := requestID(r, h.log)
	nodeName := parsed.Name
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": nodeName, "secret": node.Secret, "stage": "proxy-handle"})
	if len(targets) == 0 {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": nodeName, "secret": node.Secret, "stage": "no-targets"})
		return textResponse(http.StatusInternalServerError, "Invalid node target", nil), nil
	}
	nodeKey := "admin:" + nodeName
	expectedActive, ordered := h.targetOrder(nodeKey, targets)
	var lastRes *http.Response
	var lastErr error
	var lastAttemptMS int64
	tried := 0
	for _, target := range ordered {
		banKey := nodeKey + "|" + target
		if _, banned := h.lineBan.Get(banKey); banned && len(targets) > 1 {
			continue
		}
		tried++
		started := time.Now()
		nodeTry := node
		nodeTry.Target = target
		capture.ClearErrorMeta(r)
		res, err := h.runTargetAttempt(ctx, func(attemptCtx context.Context) (*http.Response, error) {
			return h.handleOneTarget(attemptCtx, r, nodeTry, parsed, body, env)
		})
		if err != nil {
			if ctx.Err() != nil {
				h.closeBody(lastRes)
				return nil, ctx.Err()
			}
			h.lineBan.Set(banKey, 1, time.Minute)
			attemptMS := time.Since(started).Milliseconds()
			capture.AppendErrorAttempt(r, "target-attempt", err, map[string]any{"target": logging.RedactURL(target), "targetAttemptMs": attemptMS})
			h.log.Warn("proxy", "target failed", withAccessLogFields(ctx, map[string]any{"event": "targetFailed", "id": requestID, "node": nodeName, "target": logging.FormatTarget(target), "targetAttemptMs": attemptMS, "error": err.Error()}))
			lastErr = err
			lastAttemptMS = attemptMS
			h.setLastResponse(&lastRes, textResponse(http.StatusBadGateway, "Bad Gateway", nil))
			continue
		}
		status := res.StatusCode
		if status < 500 && status != http.StatusForbidden && status != http.StatusNotFound && status != http.StatusRequestedRangeNotSatisfiable {
			h.closeBody(lastRes)
			lastRes = nil
			capture.ClearErrorMeta(r)
			h.markTargetHealthy(nodeKey, targets, target, expectedActive)
			responseReadyMs := time.Since(started).Milliseconds()
			SetAccessLogField(ctx, "responseReadyMs", responseReadyMs)
			MarkAccessLogResponseBodyStart(ctx, time.Now())
			logFields := responseReadyLogFields(ctx, res, map[string]any{"event": "upstreamReady", "id": requestID, "node": nodeName, "target": logging.FormatTarget(target), "status": status, "responseReadyMs": responseReadyMs})
			h.logResponseReady("proxy", status, logFields)
			setAccessLogTargetFields(ctx, logFields)
			return res, nil
		}
		h.lineBan.Set(banKey, 1, time.Minute)
		attemptMS := time.Since(started).Milliseconds()
		capture.AppendRetryableStatusAttempt(r, "target-attempt", status, attemptMS, logging.RedactURL(target))
		h.log.Warn("proxy", "target returned retryable status", retryableStatusLogFields(res, withAccessLogFields(ctx, map[string]any{"event": "upstreamRetryableStatus", "id": requestID, "node": nodeName, "target": logging.FormatTarget(target), "status": status, "targetAttemptMs": attemptMS})))
		lastErr = nil
		lastAttemptMS = attemptMS
		h.setLastResponse(&lastRes, res)
	}
	if tried == 0 {
		for _, target := range ordered {
			started := time.Now()
			nodeTry := node
			nodeTry.Target = target
			capture.ClearErrorMeta(r)
			res, err := h.runTargetAttempt(ctx, func(attemptCtx context.Context) (*http.Response, error) {
				return h.handleOneTarget(attemptCtx, r, nodeTry, parsed, body, env)
			})
			if err != nil {
				if ctx.Err() != nil {
					h.closeBody(lastRes)
					return nil, ctx.Err()
				}
				attemptMS := time.Since(started).Milliseconds()
				lastErr = err
				lastAttemptMS = attemptMS
				capture.AppendErrorAttempt(r, "target-attempt", err, map[string]any{"target": logging.RedactURL(target), "targetAttemptMs": attemptMS})
				h.setLastResponse(&lastRes, textResponse(http.StatusBadGateway, "Bad Gateway", nil))
				continue
			}
			status := res.StatusCode
			if status < 500 && status != http.StatusForbidden && status != http.StatusNotFound && status != http.StatusRequestedRangeNotSatisfiable {
				h.closeBody(lastRes)
				lastRes = nil
				capture.ClearErrorMeta(r)
				h.markTargetHealthy(nodeKey, targets, target, expectedActive)
				return res, nil
			}
			attemptMS := time.Since(started).Milliseconds()
			lastErr = nil
			lastAttemptMS = attemptMS
			capture.AppendRetryableStatusAttempt(r, "target-attempt", status, attemptMS, logging.RedactURL(target))
			h.setLastResponse(&lastRes, res)
		}
	}
	if lastRes != nil {
		if lastErr != nil {
			capture.SetErrorMeta(r, "target-attempt", lastErr, map[string]any{"meta": map[string]any{"targetAttemptMs": lastAttemptMS}})
		} else if status := lastRes.StatusCode; status >= 500 || status == http.StatusForbidden || status == http.StatusNotFound || status == http.StatusRequestedRangeNotSatisfiable {
			capture.SetRetryableStatusMeta(r, "target-attempt", status, lastAttemptMS)
		}
		return lastRes, nil
	}
	if lastErr != nil {
		capture.SetErrorMeta(r, "target-attempt", lastErr, map[string]any{"meta": map[string]any{"targetAttemptMs": lastAttemptMS}})
		return nil, lastErr
	}
	return textResponse(http.StatusBadGateway, "Bad Gateway", nil), nil
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

func (b *cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel(nil)
	return err
}

func (h *Handler) targetTimeout() time.Duration {
	if h != nil && h.targetAttemptTimeout > 0 {
		return h.targetAttemptTimeout
	}
	return UpstreamTargetAttemptTimeout
}

func (h *Handler) runTargetAttempt(ctx context.Context, fetch func(context.Context) (*http.Response, error)) (*http.Response, error) {
	attemptCtx, cancel := context.WithCancelCause(ctx)
	timer := &targetAttemptTimer{timeout: h.targetTimeout(), cancel: cancel}
	attemptCtx = context.WithValue(attemptCtx, targetAttemptTimerContextKey{}, timer)

	res, err := fetch(attemptCtx)
	if err != nil {
		timer.stop()
		cause := context.Cause(attemptCtx)
		cancel(err)
		if errors.Is(cause, errUpstreamTargetAttemptTimeout) {
			return res, errUpstreamTargetAttemptTimeout
		}
		return res, err
	}
	if !timer.stop() {
		h.closeBody(res)
		cancel(errUpstreamTargetAttemptTimeout)
		return nil, errUpstreamTargetAttemptTimeout
	}
	if res == nil || res.Body == nil {
		cancel(nil)
		return res, nil
	}
	if source := streamResumeSource(res); source != "" && res.Request != nil {
		client := upstreamClientForResponse(res)
		res.Request = res.Request.WithContext(ctx)
		attachUpstreamClient(res, client)
		markStreamResumeCandidate(res, source)
	}
	res.Body = &cancelOnCloseBody{ReadCloser: res.Body, cancel: cancel}
	return res, nil
}

func (h *Handler) handleOneTarget(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, body []byte, env config.ProxyEnv) (*http.Response, error) {
	base, err := url.Parse(node.Target)
	if err != nil {
		return nil, err
	}
	isCapy := isCapyClient(r)
	clientIP := auth.ClientIP(r, h.trustsProxy(ctx))
	reqOrigin := r.Header.Get("Origin")
	forwardPath := parsed.Path
	basePath := strings.TrimRight(base.Path, "/")
	if embyPathRE.MatchString(forwardPath) && embyPathRE.MatchString(basePath) {
		forwardPath = embyPrefixRE.ReplaceAllString(forwardPath, "")
		if forwardPath == "" {
			forwardPath = "/"
		}
	}
	if env.CapyStripEmby == "1" && isCapy && embyPathRE.MatchString(forwardPath) {
		forwardPath = embyPrefixRE.ReplaceAllString(forwardPath, "")
		if forwardPath == "" {
			forwardPath = "/"
		}
	}
	if forwardPath == "/__raw__" || strings.HasPrefix(forwardPath, "/__raw__/") {
		selfPrefix := routePrefix(parsed.Name, node.Secret)
		raw, rawLinkTrusted := h.signedRawURLFromQuery(r, selfPrefix)
		if raw == "" && strings.HasPrefix(forwardPath, "/__raw__/") {
			raw = strings.TrimPrefix(forwardPath, "/__raw__/")
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "raw-bad-url"})
			return textResponse(http.StatusBadRequest, "Bad raw url", nil), nil
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "raw-bad-protocol"})
			return textResponse(http.StatusBadRequest, "Bad Request", nil), nil
		}
		if !h.rawHostAllowedFor(ctx, node, u, env, rawLinkTrusted) {
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "raw-forbidden", "targetUrl": u.String()})
			return localForbiddenResponse("raw", u.String()), nil
		}
		rawRequest := requestWithoutRawLinkSignature(r)
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": parsed.Name, "secret": node.Secret, "stage": "raw-direct", "targetUrl": u.String()})
		return h.handleRawDirect(ctx, rawRequest, raw, env, node, body, rawLinkTrusted)
	}
	targetURL := resolveTargetURL(base, forwardPath, r.URL.RawQuery)
	if h.isSTRM(targetURL.Path) && !strmStreamPathRE.MatchString(targetURL.Path) {
		return h.handleSTRM(ctx, r, node, parsed, targetURL, body, env)
	}
	p := strings.ToLower(targetURL.Path)
	isStreaming := streamingRE.MatchString(forwardPath)
	isStatic := (staticExtRE.MatchString(forwardPath) || embyImagesRE.MatchString(forwardPath)) && r.Method == http.MethodGet
	isAuthAPI := authAPIRE.MatchString(p)
	isPlaybackAPI := isPlaybackPath(p)
	isImageAPI := isImagePath(targetURL.Path)
	isAdditionalPartsAPI := isAdditionalPartsPath(targetURL.Path)
	needCompatOrigin := isAuthAPI || isPlaybackAPI
	shouldProxyMedia := isPlaybackAPI || isImageAPI || isAdditionalPartsAPI
	if shouldProxyMedia {
		return h.handleMediaProxy(ctx, r, node, parsed, targetURL, body, env, isPlaybackAPI, isImageAPI, isAdditionalPartsAPI, reqOrigin, clientIP)
	}
	outboundHeaders := cloneHeader(r.Header)
	if isStatic {
		applyIdentityToResourceURL(h.ids, targetURL, outboundHeaders, node)
	} else {
		applyIdentityToURL(h.ids, targetURL, outboundHeaders, node)
	}
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "proxy-target", "targetUrl": targetURL.String()})
	headers := cloneHeader(outboundHeaders)
	stripProxyMetadataHeaders(headers)
	deleteHeaders(headers, "Content-Length")
	if isCapy && isAuthAPI {
		deleteHeaders(headers, "X-Emby-Token", "X-MediaBrowser-Token", "X-Authorization")
		az := headers.Get("Authorization")
		if bearerOrTokenRE.MatchString(az) {
			headers.Del("Authorization")
		}
		if headers.Get("Content-Type") == "" {
			headers.Set("Content-Type", "application/json;charset=utf-8")
		}
	}
	headers.Set("Host", base.Host)
	applyIdentity(h.ids, headers, node)
	if needCompatOrigin {
		if isPlaybackAPI {
			deleteHeaders(headers, "Origin", "Referer", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User")
			headers.Set("Accept", "*/*")
		} else {
			reqBase := schemeHost(r)
			if headers.Get("Origin") == "" {
				headers.Set("Origin", reqBase)
			}
			if headers.Get("Referer") == "" {
				headers.Set("Referer", reqBase+"/")
			}
			if headers.Get("Accept") == "" {
				headers.Set("Accept", "application/json, text/plain, */*")
			}
			if isAuthAPI && headers.Get("X-Requested-With") == "" {
				headers.Set("X-Requested-With", "XMLHttpRequest")
			}
		}
	}
	setProxyUA(h.ids, headers, node)
	if isPlaybackAPI {
		deleteHeaders(headers, "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Priority")
	}
	if isStatic {
		headers.Del("Range")
	}
	if isEmosNode(node, targetURL, env) {
		applyEmosHeaders(headers, env)
	}
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "proxy-prepared", "targetUrl": targetURL.String(), "outboundHeaders": headers})
	currentHeaders := headers
	if isAuthAPI && r.Method == http.MethodPost {
		if res := h.tryAuthAPI(ctx, r, node, parsed, targetURL, headers, body, env); res != nil {
			return res, nil
		}
	}
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "general-proxy", "targetUrl": targetURL.String(), "outboundHeaders": headers})
	res, err := h.doFetch(ctx, h.noRedirectClient, targetURL, r.Method, headers, body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusForbidden && needCompatOrigin {
		h2 := cloneHeader(headers)
		if isEmosNode(node, targetURL, env) {
			applyEmosHeaders(h2, env)
		}
		reqBase := schemeHost(r)
		h2.Set("Origin", reqBase)
		h2.Set("Referer", reqBase+"/")
		currentHeaders = h2
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "general-retry-compat-origin", "targetUrl": targetURL.String(), "outboundHeaders": h2})
		h.closeBody(res)
		res, err = h.doFetch(ctx, h.noRedirectClient, targetURL, r.Method, h2, body)
		if err != nil {
			return nil, err
		}
	}
	if res.StatusCode == http.StatusForbidden {
		h.closeBody(res)
		res, currentHeaders, err = h.retryGeneral403(ctx, r, node, parsed, targetURL, headers, body, env, base)
		if err != nil {
			return nil, err
		}
	}
	return h.finishGeneralResponse(ctx, r, res, node, parsed, targetURL, base, currentHeaders, env, reqOrigin, isStatic, isImageAPI, isStreaming)
}

func (h *Handler) requestBodyForReplay(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Body == nil {
		return nil, nil
	}
	return capture.DrainAndRemember(r, h.cfg.Defaults.MaxRetryBodyBytes)
}

func (h *Handler) registerPlayback(r *http.Request, in storage.PlaybackInput) {
	if h == nil || h.store == nil {
		return
	}
	if !in.IsPlayback {
		return
	}
	if in.OccurredAt <= 0 {
		in.OccurredAt = time.Now().UnixMilli()
	}
	if r != nil {
		_ = registerPlaybackLog(r.Context(), in)
	}
	h.logPlayback(in)
}

func (h *Handler) finishPlaybackLog(r *http.Request, inboundBytes, outboundBytes int64) {
	if h == nil || h.store == nil || r == nil {
		return
	}
	if in, ok := takePlaybackTrafficLog(r.Context(), inboundBytes, outboundBytes); ok {
		h.logPlayback(in)
	}
}

func (h *Handler) recordPlaybackState(ctx context.Context, in storage.PlaybackInput) {
	if h == nil || h.store == nil {
		return
	}
	if in.OccurredAt <= 0 {
		in.OccurredAt = time.Now().UnixMilli()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), playbackStateTimeout)
	defer cancel()
	if err := h.store.LogPlayback(writeCtx, in); err != nil {
		if h.log != nil {
			h.log.Warn("playback", "playback state write failed", map[string]any{"event": "playbackStateWriteFailed", "error": err.Error()})
		}
		return
	}
}

func (h *Handler) logPlayback(in storage.PlaybackInput) {
	if h == nil || h.store == nil {
		return
	}
	if in.OccurredAt <= 0 {
		in.OccurredAt = time.Now().UnixMilli()
	}
	ok := h.store.LogPlaybackAsync(in)
	if !ok && h.log != nil {
		h.log.Warn("playback", "playback stat queue full", map[string]any{"event": "playbackStatDropped", "stateOnly": in.PlaybackStateOnly})
	}
}

func (h *Handler) sendResponse(w http.ResponseWriter, r *http.Request, res *http.Response) {
	if res == nil {
		http.Error(w, "No response", http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	copyResponseHeaders(w.Header(), res.Header, res.Uncompressed)
	resumePlan, canResume := h.streamResumePlan(r, res)
	if canResume {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", resumePlan.responseLength()))
	}
	w.WriteHeader(res.StatusCode)
	stats := bodyCopyStats{}
	if res.Body != nil && r.Method != http.MethodHead {
		if canResume {
			stats, _ = h.copyResponseBodyWithResume(w, r, res, resumePlan)
		} else {
			stats, _ = h.copyResponseBody(w, r, res)
		}
	}
	h.finishPlaybackLog(r, stats.readBytes, stats.writeBytes)
}

type bodyCopyStats struct {
	readBytes  int64
	writeBytes int64
}

func (h *Handler) copyResponseBody(w http.ResponseWriter, r *http.Request, res *http.Response) (bodyCopyStats, error) {
	started := time.Now()
	reader := &bodyCopyReader{reader: res.Body, started: started}
	writer := &bodyCopyWriter{writer: w}
	buf := getBodyCopyBuffer()
	defer putBodyCopyBuffer(buf)
	copied, err := io.CopyBuffer(writer, reader, buf)
	stats := bodyCopyStats{readBytes: reader.bytes, writeBytes: writer.bytes}
	setBodyCopyFirstReadAccessLogFields(requestContext(r), reader, false)
	if ctxErr := requestContextErr(r); err != nil || ctxErr != nil {
		h.logBodyCopyIssue(r, res, copied, err, ctxErr, time.Since(started), reader, writer)
	}
	return stats, err
}

func getBodyCopyBuffer() []byte {
	return bodyCopyBufferPool.Get().([]byte)
}

func putBodyCopyBuffer(buf []byte) {
	if cap(buf) != bodyCopyBufferSize {
		return
	}
	bodyCopyBufferPool.Put(buf[:bodyCopyBufferSize])
}

type bodyCopyReader struct {
	reader       io.Reader
	started      time.Time
	bytes        int64
	calls        int64
	lastDuration time.Duration
	lastErr      error
	lastAt       time.Time
	firstReadAt  time.Time
	firstReadMs  int64
}

func (r *bodyCopyReader) Read(p []byte) (int, error) {
	started := time.Now()
	n, err := r.reader.Read(p)
	finished := time.Now()
	r.calls++
	r.lastDuration = finished.Sub(started)
	r.lastAt = finished
	if n > 0 {
		if r.bytes == 0 {
			r.firstReadAt = finished
			if !r.started.IsZero() {
				r.firstReadMs = finished.Sub(r.started).Milliseconds()
				if r.firstReadMs < 0 {
					r.firstReadMs = 0
				}
			}
		}
		r.bytes += int64(n)
	}
	if err != nil && err != io.EOF {
		r.lastErr = err
	}
	return n, err
}

type bodyCopyWriter struct {
	writer       io.Writer
	bytes        int64
	calls        int64
	lastDuration time.Duration
	lastErr      error
	lastAt       time.Time
	shortWrite   bool
}

func (w *bodyCopyWriter) Write(p []byte) (int, error) {
	started := time.Now()
	n, err := w.writer.Write(p)
	w.calls++
	w.lastDuration = time.Since(started)
	w.lastAt = time.Now()
	if n > 0 {
		w.bytes += int64(n)
	}
	if err != nil {
		w.lastErr = err
	}
	if err == nil && n != len(p) {
		w.shortWrite = true
	}
	return n, err
}

func requestContextErr(r *http.Request) error {
	if r == nil {
		return nil
	}
	return r.Context().Err()
}

func requestContext(r *http.Request) context.Context {
	if r == nil {
		return nil
	}
	return r.Context()
}

func (h *Handler) logBodyCopyIssue(r *http.Request, res *http.Response, copied int64, copyErr, ctxErr error, elapsed time.Duration, reader *bodyCopyReader, writer *bodyCopyWriter) {
	if h == nil || h.log == nil {
		return
	}
	side := bodyCopyIssueSide(copyErr, ctxErr, reader, writer)
	reason := side
	if ctxErr != nil {
		reason = "client-context-canceled"
	}
	meta := map[string]any{
		"event":        "bodyCopyInterrupted",
		"status":       res.StatusCode,
		"side":         side,
		"reason":       reason,
		"copiedBytes":  copied,
		"readBytes":    reader.bytes,
		"writeBytes":   writer.bytes,
		"readCalls":    reader.calls,
		"writeCalls":   writer.calls,
		"copyMs":       elapsed.Milliseconds(),
		"lastReadMs":   reader.lastDuration.Milliseconds(),
		"lastWriteMs":  writer.lastDuration.Milliseconds(),
		"target":       responseLogTarget(res),
		"contentRange": strings.TrimSpace(res.Header.Get("Content-Range")),
		"contentLen":   strings.TrimSpace(res.Header.Get("Content-Length")),
	}
	setBodyCopyFirstReadLogFields(meta, reader)
	if r != nil {
		meta["id"] = requestID(r, h.log)
		meta["method"] = r.Method
		if uri := responseCopyRequestURI(r); uri != "" {
			meta["uri"] = uri
		}
		if rg := strings.TrimSpace(r.Header.Get("Range")); rg != "" {
			meta["range"] = rg
		}
	}
	var reqCtx context.Context
	if r != nil {
		reqCtx = r.Context()
	}
	if copyErr != nil {
		meta["error"] = copyErr.Error()
		setBodyCopyAccessLogField(reqCtx, "bodyCopyError", copyErr.Error())
	}
	if ctxErr != nil {
		meta["contextErr"] = ctxErr.Error()
		setBodyCopyAccessLogField(reqCtx, "bodyCopyContextErr", ctxErr.Error())
	}
	addStreamResumeLogFields(reqCtx, meta)
	setBodyCopyFirstReadAccessLogFields(reqCtx, reader, true)
	setBodyCopyAccessLogField(reqCtx, "bodyCopySide", side)
	h.log.Warn("proxy", "response body copy interrupted", meta)
}

func responseCopyRequestURI(r *http.Request) string {
	if r == nil {
		return ""
	}
	if uri, ok := requestlog.RequestURI(r.Context()); ok {
		return uri
	}
	return ""
}

func setBodyCopyAccessLogField(ctx context.Context, key string, value any) {
	if ctx == nil {
		return
	}
	SetAccessLogField(ctx, key, value)
}

func setBodyCopyFirstReadLogFields(meta map[string]any, reader *bodyCopyReader) {
	if meta == nil || reader == nil {
		return
	}
	if !reader.firstReadAt.IsZero() {
		meta["firstReadMs"] = reader.firstReadMs
		return
	}
	meta["firstReadStatus"] = "none"
}

func setBodyCopyFirstReadAccessLogFields(ctx context.Context, reader *bodyCopyReader, includeMissing bool) {
	if ctx == nil || reader == nil {
		return
	}
	if !reader.firstReadAt.IsZero() {
		SetAccessLogField(ctx, "firstReadMs", reader.firstReadMs)
		return
	}
	if includeMissing {
		SetAccessLogField(ctx, "firstReadStatus", "none")
	}
}

func bodyCopyIssueSide(copyErr, ctxErr error, reader *bodyCopyReader, writer *bodyCopyWriter) string {
	if writer.lastErr != nil || writer.shortWrite || errors.Is(copyErr, io.ErrShortWrite) {
		return "downstream-write"
	}
	if ctxErr != nil {
		return "context"
	}
	if reader.lastErr != nil {
		return "upstream-read"
	}
	if copyErr != nil {
		return "copy"
	}
	return "context"
}

func (h *Handler) doFetch(ctx context.Context, client *http.Client, target *url.URL, method string, headers http.Header, body []byte) (*http.Response, error) {
	startTargetAttemptTimer(ctx)
	if pool := h.upstreamPoolName(client); pool != "" {
		SetAccessLogField(ctx, accessLogFieldUpstreamPool, pool)
	}
	var reader io.Reader
	if method != http.MethodGet && method != http.MethodHead && body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header = cloneHeader(headers)
	req.Host = target.Host
	res, err := client.Do(req)
	if err != nil {
		return res, err
	}
	attachUpstreamClient(res, client)
	return res, nil
}

func (h *Handler) upstreamPoolName(client *http.Client) string {
	if client == nil {
		return ""
	}
	switch client {
	case h.noRedirectClient:
		return upstreamPoolNoRedirect
	case h.defaultFollowClient:
		return upstreamPoolDefaultFollow
	case h.playbackActionClient:
		return upstreamPoolPlaybackAction
	case h.playbackStreamClient:
		return upstreamPoolPlaybackStream
	case h.playbackStreamProbeClient:
		return upstreamPoolPlaybackStreamProbe
	case h.imageFollowClient:
		return upstreamPoolImageFollow
	case h.rawDirectClient:
		return upstreamPoolRawDirect
	}
	if h.rawDirectClient != nil && sameRoundTripper(client.Transport, h.rawDirectClient.Transport) {
		return upstreamPoolRawDirect
	}
	return upstreamPoolUndefined
}

func sameRoundTripper(a, b http.RoundTripper) bool {
	if a == nil || b == nil {
		return false
	}
	av := reflect.ValueOf(a)
	bv := reflect.ValueOf(b)
	if !av.IsValid() || !bv.IsValid() || av.Type() != bv.Type() || !av.Comparable() {
		return false
	}
	return av.Interface() == bv.Interface()
}

func textResponse(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func bytesResponse(status int, body []byte, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: headers, Body: io.NopCloser(bytes.NewReader(body))}
}

func buildRemainingPath(u *url.URL, segments []string, strip int) string {
	path := "/"
	if len(segments) > strip {
		path += strings.Join(segments[strip:], "/")
	}
	if strings.HasSuffix(u.Path, "/") && path != "/" {
		path += "/"
	}
	return path
}

func resolveTargetURL(base *url.URL, path, rawQuery string) *url.URL {
	u := *base
	basePath := strings.TrimRight(base.Path, "/")
	if basePath == "" {
		u.Path = path
	} else {
		u.Path = basePath + ensureLeadingSlash(path)
	}
	if rawQuery != "" {
		if u.RawQuery == "" {
			u.RawQuery = rawQuery
			return &u
		}
		q := u.Query()
		incoming, _ := url.ParseQuery(rawQuery)
		for key, values := range incoming {
			q.Del(key)
			for _, value := range values {
				q.Add(key, value)
			}
		}
		u.RawQuery = q.Encode()
	}
	return &u
}

func ensureLeadingSlash(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func firstSegment(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	return segments[0]
}

func routeStage(status int, message string) string {
	if status == http.StatusBadRequest && strings.Contains(message, "encoding") {
		return "bad-encoding"
	}
	if status == http.StatusBadRequest {
		return "missing-name"
	}
	return "invalid-name"
}

func schemeHost(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return scheme + "://" + r.Host
}

func requestID(r *http.Request, log *logging.Logger) string {
	if id := r.Context().Value("requestID"); id != nil {
		if s, ok := id.(string); ok && s != "" {
			return s
		}
	}
	return log.NextRequestID("")
}

func (h *Handler) proxyEnv(ctx context.Context) config.ProxyEnv {
	env := h.cfg.ProxyEnv()
	cfg, err := h.store.GetSystemConfig(ctx, h.defaultSystemConfig())
	if err != nil {
		h.log.Warn("proxy", "system config lookup failed", map[string]any{"event": "systemConfigLookupFailed", "error": err.Error()})
		return env
	}
	env.CapyStripEmby = cfg.CapyStripEmby
	env.EmosCompat = cfg.EmosCompat
	env.EmosMatchHosts = cfg.EmosMatchHosts
	env.EmosProxyID = cfg.EmosProxyID
	env.EmosProxyName = cfg.EmosProxyName
	env.CORSAllowOrigin = cfg.CORSAllowOrigin
	env.ExternalAllowHosts = cfg.ExternalAllowHosts
	env.ExternalAllowAny = cfg.ExternalAllowAny
	return env
}

func (h *Handler) trustsProxy(ctx context.Context) bool {
	defaults := h.defaultSystemConfig()
	cfg, err := h.store.GetSystemConfig(ctx, defaults)
	if err != nil {
		h.log.Warn("proxy", "system config lookup failed", map[string]any{"event": "systemConfigLookupFailed", "error": err.Error()})
		return defaults.TrustProxy
	}
	return cfg.TrustProxy
}

func (h *Handler) systemConfig(ctx context.Context) storage.SystemConfig {
	defaults := h.defaultSystemConfig()
	if h.store == nil {
		return defaults
	}
	cfg, err := h.store.GetSystemConfig(ctx, defaults)
	if err != nil {
		if h.log != nil {
			h.log.Warn("proxy", "system config lookup failed", map[string]any{"event": "systemConfigLookupFailed", "error": err.Error()})
		}
		return defaults
	}
	return cfg
}

func (h *Handler) defaultSystemConfig() storage.SystemConfig {
	return storage.DefaultSystemConfig()
}

func (h *Handler) rawHostAllowed(ctx context.Context, node storage.Node, rawURL *url.URL, env config.ProxyEnv) bool {
	return h.rawHostAllowedFor(ctx, node, rawURL, env, false)
}

func (h *Handler) rawHostAllowedFor(ctx context.Context, node storage.Node, rawURL *url.URL, env config.ProxyEnv, bypassExternalAuth bool) bool {
	if rawURL == nil || rawHostBlocked(ctx, rawURL.Hostname()) {
		return false
	}
	if bypassExternalAuth {
		return true
	}
	if env.ExternalAllowAny {
		return true
	}
	allowed := map[string]bool{}
	for _, target := range storage.SplitTargets(node.Target) {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			allowed[strings.ToLower(u.Host)] = true
		}
	}
	for _, item := range strings.Split(env.ExternalAllowHosts, ",") {
		if host := strings.TrimSpace(strings.ToLower(item)); host != "" {
			allowed[host] = true
		}
	}
	return allowed[strings.ToLower(rawURL.Host)]
}

func rawHostBlocked(ctx context.Context, host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return rawIPBlocked(ip)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, rawHostLookupTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
	if err != nil || len(ips) == 0 {
		return true
	}
	for _, ip := range ips {
		if rawIPBlocked(ip) {
			return true
		}
	}
	return false
}

func rawIPBlocked(ip net.IP) bool {
	addr, ok := netIPAddr(ip)
	if !ok || !addr.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range rawBlockedIPPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func netIPAddr(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		addr, ok := netip.AddrFromSlice(v4)
		return addr, ok
	}
	v6 := ip.To16()
	if v6 == nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(v6)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

var rawBlockedIPPrefixes = mustParseRawBlockedIPPrefixes([]string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.31.196.0/24",
	"192.52.193.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"192.175.48.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::/128",
	"::1/128",
	"::ffff:0:0/96",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"2620:4f:8000::/48",
	"3fff::/20",
	"5f00::/16",
	"fc00::/7",
	"fe80::/10",
	"fec0::/10",
	"ff00::/8",
})

func mustParseRawBlockedIPPrefixes(values []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic(err)
		}
		out = append(out, prefix)
	}
	return out
}

func (h *Handler) isSTRM(path string) bool {
	return strmExtRE.MatchString(path)
}

func (h *Handler) getActiveTarget(nodeKey string, targets []string) string {
	h.activeMu.Lock()
	defer h.activeMu.Unlock()
	active := h.activeTarget[nodeKey]
	if active != "" && contains(targets, active) {
		return active
	}
	first := ""
	if len(targets) > 0 {
		first = targets[0]
		h.activeTarget[nodeKey] = first
	}
	return first
}

func (h *Handler) targetOrder(nodeKey string, targets []string) (string, []string) {
	active := h.getActiveTarget(nodeKey, targets)
	idx := indexOf(targets, active)
	if idx < 0 {
		return active, append([]string(nil), targets...)
	}
	out := append([]string{}, targets[idx:]...)
	out = append(out, targets[:idx]...)
	return active, out
}

func (h *Handler) markTargetHealthy(nodeKey string, targets []string, target, expectedActive string) bool {
	h.activeMu.Lock()
	defer h.activeMu.Unlock()
	current := h.activeTarget[nodeKey]
	if current == "" && len(targets) > 0 {
		current = targets[0]
	}
	if expectedActive != "" && current != expectedActive && current != target {
		return false
	}
	if contains(targets, target) {
		h.activeTarget[nodeKey] = target
		return true
	}
	return false
}

func contains(values []string, value string) bool {
	return indexOf(values, value) >= 0
}

func indexOf(values []string, value string) int {
	for i, item := range values {
		if item == value {
			return i
		}
	}
	return -1
}

func (h *Handler) makeDirectCandidates(rawPath, rawQuery string) []string {
	withQuery := func(value string) string {
		if rawQuery == "" {
			return value
		}
		sep := "?"
		if strings.Contains(value, "?") {
			sep = "&"
		}
		return value + sep + rawQuery
	}
	p := strings.TrimSpace(rawPath)
	if httpURLRE.MatchString(p) {
		return []string{withQuery(p)}
	}
	hostPart := strings.Split(strings.Split(strings.Split(p, "/")[0], "?")[0], "#")[0]
	if defaultPort80RE.MatchString(hostPart) {
		return []string{withQuery("http://" + p), withQuery("https://" + p)}
	}
	if defaultPort443RE.MatchString(hostPart) {
		return []string{withQuery("https://" + p), withQuery("http://" + p)}
	}
	return []string{withQuery("https://" + p), withQuery("http://" + p)}
}

func (h *Handler) closeBody(res *http.Response) {
	if res != nil && res.Body != nil {
		_ = res.Body.Close()
	}
}

func (h *Handler) logResponseReady(scope string, status int, fields map[string]any) {
	switch {
	case status >= http.StatusInternalServerError:
		h.log.Error(scope, "response ready", fields)
	case status >= http.StatusBadRequest:
		h.log.Warn(scope, "response ready", fields)
	default:
		h.log.Debug(scope, "response ready", fields)
	}
}

func retryableStatusLogFields(res *http.Response, fields map[string]any) map[string]any {
	if fields == nil {
		fields = map[string]any{}
	}
	if reason := retryableStatusReason(res); reason != "" {
		fields["reason"] = reason
	}
	fields = foldActualTargetLogField(fields, responseLogTarget(res))
	return fields
}

func responseReadyLogFields(ctx context.Context, res *http.Response, fields map[string]any) map[string]any {
	fields = withAccessLogFields(ctx, fields)
	fields = withRedirectLocationLogField(res, fields)
	return foldActualTargetLogField(fields, responseLogTarget(res))
}

func withRedirectLocationLogField(res *http.Response, fields map[string]any) map[string]any {
	if res == nil || !isRedirectStatus(res.StatusCode) {
		return fields
	}
	location := strings.TrimSpace(res.Header.Get("Location"))
	if location == "" {
		return fields
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields["location"] = location
	return fields
}

func responseLogTarget(res *http.Response) string {
	if res == nil || res.Request == nil || res.Request.URL == nil {
		return ""
	}
	return logging.FormatTarget(res.Request.URL.String())
}

func foldActualTargetLogField(fields map[string]any, actualTarget string) map[string]any {
	if actualTarget == "" {
		return fields
	}
	if target, ok := fields["target"]; ok && target != actualTarget {
		fields["nodeTarget"] = target
	}
	fields["target"] = actualTarget
	return fields
}

func setAccessLogTargetFields(ctx context.Context, fields map[string]any) {
	if location, ok := fields["location"]; ok {
		SetAccessLogField(ctx, "location", location)
	}
	nodeTarget, ok := fields["nodeTarget"]
	if !ok {
		return
	}
	if target, ok := fields["target"]; ok {
		SetAccessLogField(ctx, "target", target)
	}
	SetAccessLogField(ctx, "nodeTarget", nodeTarget)
}

func retryableStatusReason(res *http.Response) string {
	if res == nil {
		return ""
	}
	switch res.StatusCode {
	case http.StatusForbidden:
		status := strings.ToLower(res.Status)
		if strings.Contains(status, "forbidden direct host") {
			return "direct-host-not-allowed"
		}
		if strings.Contains(status, "forbidden raw host") {
			return "raw-host-not-allowed"
		}
		return "upstream-forbidden"
	case http.StatusNotFound:
		return "not-found"
	case http.StatusRequestedRangeNotSatisfiable:
		return "range-not-satisfiable"
	default:
		if res.StatusCode >= 500 {
			return "upstream-server-error"
		}
	}
	return ""
}

func (h *Handler) setLastResponse(slot **http.Response, res *http.Response) {
	if slot == nil {
		return
	}
	if *slot != nil && *slot != res {
		h.closeBody(*slot)
	}
	*slot = res
}

func isRetryableProtocolStatus(status int) bool {
	return status == 525 || status == 526 || status == 530
}

var errNoResponse = errors.New("no response")
