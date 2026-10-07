package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"embyproxy/internal/auth"
	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/storage"
)

const proxyRewriteBodyMaxBytes int64 = 10 * 1024 * 1024

var errProxyRewriteBodyTooLarge = errors.New("rewritable upstream response body is too large")

func (h *Handler) handleSTRM(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, sourceURL *url.URL, body []byte, env config.ProxyEnv) (*http.Response, error) {
	headers := cloneHeader(r.Header)
	applyIdentityToResourceURL(h.ids, sourceURL, headers, node)
	stripProxyMetadataHeaders(headers)
	headers.Del("Range")
	headers.Del("If-Range")
	setProxyUA(h.ids, headers, node)
	applyIdentity(h.ids, headers, node)
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "strm-source", "targetUrl": sourceURL.String(), "outboundHeaders": headers})
	res, err := h.doFetch(ctx, h.playbackActionClient, sourceURL, http.MethodGet, headers, nil)
	if err != nil {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "strm-source-failed", "targetUrl": sourceURL.String(), "outboundHeaders": headers})
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return res, nil
	}
	defer res.Body.Close()
	raw, _, err := readProxyRewriteResponseBody(res)
	if err != nil {
		capture.SetErrorMeta(r, "strm-parse-error", err, map[string]any{
			"mode":      "proxy",
			"node":      parsed.Name,
			"secret":    node.Secret,
			"stage":     "strm-parse-error",
			"targetUrl": sourceURL.String(),
			"meta": map[string]any{
				"error":                     err.Error(),
				"strmReadError":             err.Error(),
				"strmSourceStatus":          res.StatusCode,
				"strmSourceContentEncoding": strings.TrimSpace(res.Header.Get("Content-Encoding")),
				"strmSourceContentType":     strings.TrimSpace(res.Header.Get("Content-Type")),
				"strmSourceContentLength":   strings.TrimSpace(res.Header.Get("Content-Length")),
			},
		})
		return textResponse(http.StatusBadGateway, "Bad Gateway", nil), nil
	}
	line := ""
	for _, item := range lineBreakRE.Split(strings.TrimSpace(string(raw)), -1) {
		item = strings.TrimSpace(item)
		if item != "" && !strings.HasPrefix(item, "#") {
			line = item
			break
		}
	}
	if !httpURLRE.MatchString(line) {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "strm-bad-target", "targetUrl": sourceURL.String()})
		return textResponse(http.StatusBadRequest, "Bad STRM", nil), nil
	}
	targetURL, err := url.Parse(line)
	if err != nil || (targetURL.Scheme != "http" && targetURL.Scheme != "https") {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "strm-bad-protocol", "targetUrl": line})
		return textResponse(http.StatusBadRequest, "Bad STRM URL", nil), nil
	}
	capture.SetMeta(r, map[string]any{"mode": "direct", "node": parsed.Name, "secret": node.Secret, "stage": "strm-direct", "targetUrl": targetURL.String()})
	directRes, err := h.handleDirect(ctx, r, targetURL.String(), env, node, body)
	if err != nil {
		return nil, err
	}
	mode := "proxy"
	if directRes.StatusCode >= 300 && directRes.StatusCode < 400 {
		mode = "direct"
	}
	h.registerPlayback(r, storage.PlaybackInput{Node: node, RequestIP: authClientIP(h, r), Headers: r.Header, Status: directRes.StatusCode, RespHeader: directRes.Header, IsPlayback: true, Mode: mode, RequestURL: r.URL.RequestURI(), Method: r.Method, RequestBody: body})
	return directRes, nil
}

func (h *Handler) tryAuthAPI(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, targetURL *url.URL, baseHeaders http.Header, body []byte, env config.ProxyEnv) *http.Response {
	rawAuthURL := cloneURL(targetURL)
	embyAuthURL := cloneURL(targetURL)
	if !embySlashPrefixRE.MatchString(embyAuthURL.Path) {
		embyAuthURL.Path = "/emby" + ensureLeadingSlash(embyAuthURL.Path)
	}
	urls := []*url.URL{embyAuthURL}
	if rawAuthURL.String() != embyAuthURL.String() {
		urls = append(urls, rawAuthURL)
	}
	reqBase := schemeHost(r)
	for _, u := range urls {
		for _, mode := range []string{"with-origin", "no-origin"} {
			hh := cloneHeader(baseHeaders)
			hh.Set("Accept", "application/json, text/plain, */*")
			hh.Set("Content-Type", "application/json;charset=utf-8")
			setProxyUA(h.ids, hh, node)
			applyIdentity(h.ids, hh, node)
			if mode == "with-origin" {
				hh.Set("Origin", reqBase)
				hh.Set("Referer", reqBase+"/")
			} else {
				hh.Del("Origin")
				hh.Del("Referer")
			}
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "auth-" + mode, "targetUrl": u.String(), "outboundHeaders": hh})
			res, err := h.doFetch(ctx, h.noRedirectClient, u, r.Method, hh, body)
			if err != nil {
				continue
			}
			if isAuthSuccess(res) {
				return res
			}
			_ = res.Body.Close()
		}
	}
	_ = env
	return nil
}

func progressThrottleKey(nodeName, clientIP, deviceID, sessionID string, requestURL *url.URL, body []byte) string {
	nodeName = strings.ToLower(strings.TrimSpace(nodeName))
	if nodeName == "" {
		nodeName = "unknown"
	}
	if playSessionID := playSessionIDFromProgress(requestURL, body); playSessionID != "" {
		return nodeName + "|play|" + playSessionID
	}
	return strings.Join([]string{nodeName, strings.TrimSpace(clientIP), strings.TrimSpace(deviceID), strings.TrimSpace(sessionID)}, "|")
}

func playSessionIDFromProgress(requestURL *url.URL, body []byte) string {
	if requestURL != nil {
		for _, name := range []string{"PlaySessionId", "playSessionId", "play_session_id"} {
			if value := strings.TrimSpace(requestURL.Query().Get(name)); value != "" {
				return value
			}
		}
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	for _, name := range []string{"PlaySessionId", "playSessionId", "play_session_id"} {
		if value, ok := payload[name].(string); ok {
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}
	return ""
}

func (h *Handler) handleMediaProxy(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, targetURL *url.URL, body []byte, env config.ProxyEnv, isPlaybackAPI, isImageAPI, isAdditionalPartsAPI bool, reqOrigin, clientIP string) (*http.Response, error) {
	playbackOccurredAt := playbackRequestOccurredAt(r.Context())
	if r.Method == http.MethodPost && isSessionsPlayingLifecyclePath(parsed.Path) {
		h.recordPlaybackState(ctx, storage.PlaybackInput{Node: node, RequestIP: clientIP, Headers: r.Header, IsPlayback: true, Mode: "proxy", RequestURL: r.URL.RequestURI(), Method: r.Method, RequestBody: body, OccurredAt: playbackOccurredAt, PlaybackStateOnly: true})
	}
	outboundHeaders := cloneHeader(r.Header)
	isStreamingMedia := isPlaybackStreamRequest(r, targetURL)
	if isImageAPI || isAdditionalPartsAPI || isStreamingMedia {
		applyIdentityToResourceURL(h.ids, targetURL, outboundHeaders, node)
	} else {
		applyIdentityToURL(h.ids, targetURL, outboundHeaders, node)
	}
	probeDirectExternalRedirect := node.DirectExternal && isPlaybackAPI && !isImageAPI && isStreamingMedia
	hClean := buildCleanProxyHeaders(h.ids, outboundHeaders, targetURL, node, env, isStreamingMedia)
	if targetURL.Query().Get("api_key") == "" {
		if apiKey := r.URL.Query().Get("api_key"); apiKey != "" {
			q := targetURL.Query()
			q.Set("api_key", apiKey)
			targetURL.RawQuery = q.Encode()
		}
	}
	// Image, stream, and smartstrm clients do not send Emby identity headers.
	// Converge after header rewriting and api_key restoration so neither step can put them back.
	if node.Impersonate && h.ids != nil {
		switch {
		case isImageAPI:
			h.ids.NormalizeImpersonatedResource(targetURL, hClean, node.ImpersonateProfile, identity.ResourceImage)
		case isStreamingMedia && isSmartStrmPath(targetURL.Path):
			h.ids.NormalizeImpersonatedResource(targetURL, hClean, node.ImpersonateProfile, identity.ResourceSmartSTRM)
		case isStreamingMedia:
			h.ids.NormalizeImpersonatedResource(targetURL, hClean, node.ImpersonateProfile, identity.ResourceStream)
		}
	}
	stage := "media-proxy"
	if isImageAPI {
		stage = "image-proxy"
	} else if isAdditionalPartsAPI {
		stage = "additionalparts-proxy"
	}
	if isSessionsPlayingProgressPath(targetURL.Path) && r.Method != http.MethodOptions && h.progressThrottle != nil {
		deviceID := r.Header.Get("X-Emby-Device-Id")
		sessionID := targetURL.Query().Get("SessionId")
		if sessionID == "" {
			sessionID = targetURL.Query().Get("sessionId")
		}
		key := progressThrottleKey(parsed.Name, clientIP, deviceID, sessionID, targetURL, body)
		if _, ok := h.progressThrottle.Get(key); ok {
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "progress-throttle", "targetUrl": targetURL.String(), "outboundHeaders": hClean})
			h.registerPlayback(r, storage.PlaybackInput{Node: node, RequestIP: clientIP, Headers: r.Header, Status: http.StatusNoContent, IsPlayback: true, Mode: "proxy", RequestURL: r.URL.RequestURI(), Method: r.Method, RequestBody: body, OccurredAt: playbackOccurredAt})
			return textResponse(http.StatusNoContent, "", http.Header{"Cache-Control": []string{"no-store"}}), nil
		}
		h.progressThrottle.Set(key, 1, time.Duration(h.cfg.Defaults.ProgressThrottleMS)*time.Millisecond)
	}
	cacheKey := ""
	var imageCache *imageDiskCache
	var imageCacheFill *imageCacheFill
	finishImageCacheFill := func() {}
	if isImageAPI {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-preflight", "targetUrl": targetURL.String()})
		imageCache = h.ensureImageCache(ctx)
		cacheKey = imageCacheKey(parsed.Name, targetURL)
		if imageCache == nil {
			SetAccessLogField(ctx, "imageCache", "disabled")
		} else if !imageCacheLookupMethod(r.Method) {
			SetAccessLogField(ctx, "imageCache", "bypass")
			SetAccessLogField(ctx, "imageCacheReason", "method")
		} else if r.Header.Get("Range") != "" {
			SetAccessLogField(ctx, "imageCache", "bypass")
			SetAccessLogField(ctx, "imageCacheReason", "range")
		} else if cached, ok := imageCache.get(r, cacheKey, reqOrigin, env); ok {
			SetAccessLogField(ctx, "imageCache", "hit")
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-cache-hit", "targetUrl": targetURL.String()})
			return cached, nil
		} else {
			fill, leader := imageCache.beginFill(cacheKey)
			if !leader {
				SetAccessLogField(ctx, "imageCache", "wait")
				capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-cache-wait", "targetUrl": targetURL.String()})
				waitStarted := time.Now()
				if err := imageCache.waitFill(ctx, fill); err != nil {
					capture.SetErrorMeta(r, "image-cache-wait", err, map[string]any{"meta": map[string]any{"targetAttemptMs": time.Since(waitStarted).Milliseconds()}})
					return nil, err
				}
				if cached, ok := imageCache.get(r, cacheKey, reqOrigin, env); ok {
					SetAccessLogField(ctx, "imageCache", "hit")
					SetAccessLogField(ctx, "imageCacheCoalesced", true)
					capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-cache-hit", "targetUrl": targetURL.String()})
					return cached, nil
				}
				SetAccessLogField(ctx, "imageCache", "miss")
				SetAccessLogField(ctx, "imageCacheCoalesced", true)
			} else {
				imageCacheFill = fill
				finishImageCacheFill = func() {
					imageCache.finishFill(imageCacheFill)
				}
				SetAccessLogField(ctx, "imageCache", "miss")
			}
		}
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-limit-wait", "targetUrl": targetURL.String()})
		limitStarted := time.Now()
		release, err := h.acquireImageRequestSlot(ctx, parsed.Name)
		if err != nil {
			finishImageCacheFill()
			capture.SetErrorMeta(r, "image-limit-wait", err, map[string]any{"outboundHeaders": hClean, "meta": map[string]any{"targetAttemptMs": time.Since(limitStarted).Milliseconds()}})
			return nil, err
		}
		defer release()
	}
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": stage, "targetUrl": targetURL.String(), "outboundHeaders": hClean})
	var client *http.Client
	switch {
	case probeDirectExternalRedirect:
		client = h.playbackStreamProbeClient
	case isImageAPI:
		client = h.imageFollowClient
	case isStreamingMedia:
		client = h.playbackStreamClient
	case isPlaybackAPI || isAdditionalPartsAPI:
		client = h.playbackActionClient
	default:
		client = h.defaultFollowClient
	}
	fetchStarted := time.Now()
	res, err := h.doFetch(ctx, client, targetURL, r.Method, hClean, body)
	if err != nil {
		finishImageCacheFill()
		capture.SetErrorMeta(r, stage, err, map[string]any{"meta": map[string]any{"targetAttemptMs": time.Since(fetchStarted).Milliseconds()}})
		return nil, err
	}
	if probeDirectExternalRedirect && isRedirectStatus(res.StatusCode) && res.Header.Get("Location") != "" {
		base := targetURL
		if parsedBase, err := url.Parse(node.Target); err == nil && parsedBase.Host != "" {
			base = parsedBase
		}
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "playback-redirect", "targetUrl": targetURL.String(), "outboundHeaders": hClean})
		out, err := h.finishGeneralResponse(ctx, r, res, node, parsed, targetURL, base, hClean, env, reqOrigin, false, false, isStreamingMedia)
		if err != nil {
			finishImageCacheFill()
			return nil, err
		}
		mode := playbackRedirectMode(r, out)
		stage := "playback-redirect"
		playbackTargetURL := targetURL.String()
		if mode == "direct" {
			stage = "playback-direct-302"
			playbackTargetURL = strings.TrimSpace(out.Header.Get("Location"))
		}
		capture.SetMeta(r, map[string]any{"mode": mode, "stage": stage, "targetUrl": playbackTargetURL})
		h.registerPlayback(r, storage.PlaybackInput{Node: node, RequestIP: clientIP, Headers: r.Header, Status: out.StatusCode, RespHeader: out.Header, IsPlayback: true, Mode: mode, RequestURL: r.URL.RequestURI(), Method: r.Method, RequestBody: body, OccurredAt: playbackOccurredAt})
		return out, nil
	}
	if isImageAPI && res.StatusCode == http.StatusForbidden {
		_ = res.Body.Close()
		hImg := cloneHeader(hClean)
		stripProxyMetadataHeaders(hImg)
		deleteHeaders(hImg, "Origin", "Referer", "Range", "If-Range")
		setProxyUA(h.ids, hImg, node)
		hImg.Set("Accept", "image/avif,image/webp,image/apng,image*;q=0.8")
		applyIdentity(h.ids, hImg, node)
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-retry-clean", "targetUrl": targetURL.String(), "outboundHeaders": hImg})
		retryStarted := time.Now()
		res, err = h.doFetch(ctx, h.imageFollowClient, targetURL, r.Method, hImg, nil)
		if err != nil {
			finishImageCacheFill()
			capture.SetErrorMeta(r, "image-retry-clean", err, map[string]any{"meta": map[string]any{"targetAttemptMs": time.Since(retryStarted).Milliseconds()}})
			return nil, err
		}
		if res.StatusCode == http.StatusForbidden {
			_ = res.Body.Close()
			hImg2 := cloneHeader(hImg)
			hImg2.Set("Referer", originOf(targetURL)+"/")
			hImg2.Set("Origin", originOf(targetURL))
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-retry-origin", "targetUrl": targetURL.String(), "outboundHeaders": hImg2})
			retryStarted := time.Now()
			res, err = h.doFetch(ctx, h.imageFollowClient, targetURL, r.Method, hImg2, nil)
			if err != nil {
				finishImageCacheFill()
				capture.SetErrorMeta(r, "image-retry-origin", err, map[string]any{"meta": map[string]any{"targetAttemptMs": time.Since(retryStarted).Milliseconds()}})
				return nil, err
			}
		}
	}
	if isImageAPI && res.StatusCode == http.StatusTooManyRequests {
		h.noteImageRateLimited(parsed.Name, res.Header.Get("Retry-After"))
	}
	headers := cloneHeader(res.Header)
	addCORSHeaders(headers, reqOrigin, env)
	headers.Set("Access-Control-Expose-Headers", "Accept-Ranges, Content-Range, Content-Length, Content-Type")
	if isStreamingMedia {
		fillContentLengthFromContentRange(headers)
		if res.StatusCode == http.StatusPartialContent || res.Header.Get("Content-Range") != "" || acceptRangesBytesRE.MatchString(res.Header.Get("Accept-Ranges")) {
			headers.Set("Accept-Ranges", "bytes")
		} else {
			headers.Del("Accept-Ranges")
		}
		headers.Set("Cache-Control", "no-store, no-transform")
		if m3u8PathRE.MatchString(targetURL.Path) {
			headers.Set("Content-Type", "application/vnd.apple.mpegurl")
		}
	}
	setStreamingRangeAccessLogFields(ctx, r, targetURL, headers, isStreamingMedia)
	if isImageAPI {
		headers.Del("Set-Cookie")
		headers.Del("Vary")
		setImageCacheControl(headers, res.StatusCode, "public, max-age=60, s-maxage=60")
		if imageCache != nil {
			if imageCache.wrapStore(r, cacheKey, res, headers, finishImageCacheFill) {
				finishImageCacheFill = func() {}
			}
		}
		finishImageCacheFill()
	}
	finalRes := res
	if out, ok, err := h.rewriteMediaSourceResponse(ctx, r, res, headers, node, parsed, targetURL, targetURL, hClean); err != nil {
		return nil, err
	} else if ok {
		finalRes = out
	} else {
		res.Header = headers
	}
	h.registerPlayback(r, storage.PlaybackInput{Node: node, RequestIP: clientIP, Headers: r.Header, Status: finalRes.StatusCode, RespHeader: finalRes.Header, IsPlayback: isPlaybackAPI || isStreamingMedia, Mode: "proxy", RequestURL: r.URL.RequestURI(), Method: r.Method, RequestBody: body, OccurredAt: playbackOccurredAt})
	if isStreamingMedia && !isImageAPI {
		markStreamResumeCandidate(finalRes, "playback")
	}
	return finalRes, nil
}

func isPlaybackStreamRequest(r *http.Request, targetURL *url.URL) bool {
	if r == nil || targetURL == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	path := normalizedEmbyAPIPath(targetURL.Path)
	if strings.Contains(path, "/sessions/playing") || strings.Contains(path, "/playbackinfo") || strings.Contains(path, "/additionalparts") {
		return false
	}
	if streamingRE.MatchString(path) || playbackMediaExtRE.MatchString(path) {
		return true
	}
	if strings.Contains(path, "/smartstrm") || strings.Contains(path, "/hls/") || strings.Contains(path, "/hls1/") || strings.Contains(path, "/dash/") {
		return true
	}
	if strings.Contains(path, "/items/") && (strings.Contains(path, "/download") || strings.Contains(path, "/stream") || strings.Contains(path, "/file")) {
		return true
	}
	if strings.Contains(path, "/videos/") {
		return r.Header.Get("Range") != "" || strings.Contains(path, "/stream") || strings.Contains(path, "/original")
	}
	if strings.Contains(path, "/audio/") {
		return r.Header.Get("Range") != "" || strings.Contains(path, "/stream") || strings.Contains(path, "/universal") || strings.Contains(path, "/original")
	}
	return false
}

func setStreamingRangeAccessLogFields(ctx context.Context, r *http.Request, targetURL *url.URL, headers http.Header, isStreamingMedia bool) {
	if !shouldLogStreamingRangeFields(targetURL, isStreamingMedia) {
		return
	}
	if rg := strings.TrimSpace(r.Header.Get("Range")); rg != "" {
		SetAccessLogField(ctx, "range", rg)
	}
	if cr := strings.TrimSpace(headers.Get("Content-Range")); cr != "" {
		SetAccessLogField(ctx, "contentRange", cr)
	}
}

func shouldLogStreamingRangeFields(targetURL *url.URL, isStreamingMedia bool) bool {
	if !isStreamingMedia || targetURL == nil {
		return false
	}
	path := strings.ToLower(targetURL.Path)
	return !strings.Contains(path, "/sessions/playing")
}

func (h *Handler) retryGeneral403(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, targetURL *url.URL, headers http.Header, body []byte, env config.ProxyEnv, base *url.URL) (*http.Response, http.Header, error) {
	h3 := cloneHeader(headers)
	stripProxyMetadataHeaders(h3)
	h3.Set("Host", base.Host)
	setProxyUA(h.ids, h3, node)
	if rg := r.Header.Get("Range"); rg != "" {
		h3.Set("Range", rg)
	}
	deleteHeaders(h3, "Origin", "Referer", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User")
	if isEmosNode(node, targetURL, env) {
		applyEmosHeaders(h3, env)
	}
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "general-retry-clean", "targetUrl": targetURL.String(), "outboundHeaders": h3})
	res, err := h.doFetch(ctx, h.noRedirectClient, targetURL, r.Method, h3, body)
	if err != nil || res.StatusCode != http.StatusForbidden {
		return res, h3, err
	}
	for _, stage := range []string{"general-retry-origin", "general-retry-origin-repeat"} {
		h.closeBody(res)
		h4 := cloneHeader(h3)
		stripProxyMetadataHeaders(h4)
		h4.Set("Host", base.Host)
		setProxyUA(h.ids, h4, node)
		h4.Set("Referer", originOf(base)+"/")
		h4.Set("Origin", originOf(base))
		if rg := r.Header.Get("Range"); rg != "" {
			h4.Set("Range", rg)
		}
		deleteHeaders(h4, "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User")
		if isEmosNode(node, targetURL, env) {
			applyEmosHeaders(h4, env)
		}
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": stage, "targetUrl": targetURL.String(), "outboundHeaders": h4})
		res, err = h.doFetch(ctx, h.noRedirectClient, targetURL, r.Method, h4, body)
		if err != nil || res.StatusCode != http.StatusForbidden {
			return res, h4, err
		}
		h3 = h4
	}
	return res, h3, nil
}

func (h *Handler) finishGeneralResponse(ctx context.Context, r *http.Request, res *http.Response, node storage.Node, parsed parsedRoute, targetURL *url.URL, base *url.URL, currentHeaders http.Header, env config.ProxyEnv, reqOrigin string, isStatic, isImageAPI, isStreaming bool) (*http.Response, error) {
	headers := cloneHeader(res.Header)
	addCORSHeaders(headers, reqOrigin, env)
	selfPrefix := routePrefix(parsed.Name, node.Secret)
	rewriteSetCookieHeaders(headers, selfPrefix)
	if isStatic {
		headers.Set("Access-Control-Allow-Origin", "*")
		headers.Del("Vary")
		headers.Del("Set-Cookie")
		headers.Set("Cache-Control", "public, max-age=31536000, s-maxage=86400")
	} else if isImageAPI {
		headers.Del("Set-Cookie")
		headers.Del("Vary")
		setImageCacheControl(headers, res.StatusCode, "public, max-age=2592000, s-maxage=2592000, immutable")
	} else if isStreaming {
		headers.Set("Cache-Control", "no-store, no-transform")
		fillContentLengthFromContentRange(headers)
	}
	if loc := headers.Get("Location"); loc != "" {
		rewritten, direct, directURL := h.rewriteLocation(r, loc, node, parsed, base, selfPrefix)
		if direct {
			_ = res.Body.Close()
			capture.SetMeta(r, map[string]any{"mode": "direct", "node": parsed.Name, "secret": node.Secret, "stage": "location-direct", "targetUrl": directURL})
			return h.handleDirect(ctx, r, directURL, env, node, nil)
		}
		if rewritten != "" {
			headers.Set("Location", rewritten)
		}
	}
	ct := strings.ToLower(headers.Get("Content-Type"))
	rewriteWithStage := func(stage string, rewrite func([]byte) []byte) (*http.Response, error) {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": stage, "targetUrl": targetURL.String(), "outboundHeaders": currentHeaders})
		out, err := rewriteProxyResponseBody(res, headers, rewrite)
		if err != nil {
			capture.SetErrorMeta(r, stage, err, map[string]any{"meta": map[string]any{
				"error":           err.Error(),
				"errorClass":      "response-rewrite",
				"upstreamStatus":  res.StatusCode,
				"contentEncoding": strings.TrimSpace(headers.Get("Content-Encoding")),
				"contentType":     strings.TrimSpace(headers.Get("Content-Type")),
				"contentLength":   strings.TrimSpace(headers.Get("Content-Length")),
			}})
			return nil, err
		}
		return out, nil
	}
	if res.StatusCode == http.StatusOK && (strings.Contains(ct, "application/vnd.apple.mpegurl") || strings.Contains(ct, "application/x-mpegurl") || strings.Contains(ct, "application/dash+xml")) {
		return rewriteWithStage("manifest-rewrite", func(raw []byte) []byte {
			rewritten := h.rewriteBodyLinks(ctx, string(raw), schemeHost(r)+r.URL.RequestURI(), node, parsed.Name, node.Secret)
			return []byte(rewritten)
		})
	}
	if out, ok, err := h.rewriteMediaSourceResponse(ctx, r, res, headers, node, parsed, targetURL, base, currentHeaders); err != nil {
		return nil, err
	} else if ok {
		return out, nil
	}
	if res.StatusCode == http.StatusOK && strings.Contains(ct, "application/json") && isSystemInfoPath(parsed.Path) {
		return rewriteWithStage("systeminfo-rewrite", func(raw []byte) []byte {
			rewritten, _ := rewriteSystemInfoAddresses(raw, schemeHost(r)+selfPrefix)
			return rewritten
		})
	}
	res.Header = headers
	if isStreaming {
		markStreamResumeCandidate(res, "stream")
	}
	return res, nil
}

func (h *Handler) rewriteMediaSourceResponse(ctx context.Context, r *http.Request, res *http.Response, headers http.Header, node storage.Node, parsed parsedRoute, targetURL, base *url.URL, currentHeaders http.Header) (*http.Response, bool, error) {
	if res == nil || res.StatusCode != http.StatusOK || node.DirectExternal {
		return res, false, nil
	}
	stage := mediaSourceJSONRewriteStage(parsed.Path)
	if stage == "" || !strings.Contains(strings.ToLower(headers.Get("Content-Type")), "application/json") {
		return res, false, nil
	}
	selfPrefix := routePrefix(parsed.Name, node.Secret)
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": stage, "targetUrl": targetURL.String(), "outboundHeaders": currentHeaders})
	origin := schemeHost(r)
	out, err := rewriteProxyResponseBody(res, headers, func(raw []byte) []byte {
		if rewritten, ok := rewriteMediaSourceJSONURLs(raw, origin, selfPrefix, base, false, func(value string) string {
			return h.signedRawLink(origin, selfPrefix, value)
		}); ok {
			return rewritten
		}
		return raw
	})
	if err != nil {
		capture.SetErrorMeta(r, stage, err, map[string]any{"meta": map[string]any{
			"error":           err.Error(),
			"errorClass":      "response-rewrite",
			"upstreamStatus":  res.StatusCode,
			"contentEncoding": strings.TrimSpace(headers.Get("Content-Encoding")),
			"contentType":     strings.TrimSpace(headers.Get("Content-Type")),
			"contentLength":   strings.TrimSpace(headers.Get("Content-Length")),
		}})
		return nil, false, err
	}
	return out, true, nil
}

func readProxyRewriteBody(body io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, proxyRewriteBodyMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > proxyRewriteBodyMaxBytes {
		return nil, errProxyRewriteBodyTooLarge
	}
	return raw, nil
}

func rewriteProxyResponseBody(res *http.Response, headers http.Header, rewrite func([]byte) []byte) (*http.Response, error) {
	defer res.Body.Close()
	raw, encodings, err := readProxyRewriteResponseBody(res)
	if err != nil {
		return nil, err
	}
	body, err := encodeProxyRewriteResponseBody(rewrite(raw), encodings, headers)
	if err != nil {
		return nil, err
	}
	return bytesResponse(res.StatusCode, body, headers), nil
}

func readProxyRewriteResponseBody(res *http.Response) ([]byte, []string, error) {
	if res == nil || res.Body == nil {
		return nil, nil, nil
	}
	if res.Uncompressed {
		raw, err := readProxyRewriteBody(res.Body)
		return raw, nil, err
	}
	encodings := responseContentEncodings(res.Header.Get("Content-Encoding"))
	if len(encodings) == 0 {
		raw, err := readProxyRewriteBody(res.Body)
		return raw, nil, err
	}
	encoded, err := readProxyRewriteBody(res.Body)
	if err != nil {
		return nil, nil, err
	}
	decoded, err := decodeProxyRewriteBody(encoded, encodings)
	return decoded, encodings, err
}

func responseContentEncodings(value string) []string {
	parts := strings.Split(value, ",")
	encodings := make([]string, 0, len(parts))
	for _, part := range parts {
		encoding := strings.ToLower(strings.TrimSpace(part))
		if encoding == "" || encoding == "identity" {
			continue
		}
		encodings = append(encodings, encoding)
	}
	return encodings
}

func decodeProxyRewriteBody(encoded []byte, encodings []string) ([]byte, error) {
	decoded := encoded
	for i := len(encodings) - 1; i >= 0; i-- {
		reader, err := proxyRewriteDecoder(decoded, encodings[i])
		if err != nil {
			return nil, err
		}
		decoded, err = readProxyRewriteBody(reader)
		_ = reader.Close()
		if err != nil {
			return nil, err
		}
	}
	return decoded, nil
}

func encodeProxyRewriteResponseBody(decoded []byte, encodings []string, headers http.Header) ([]byte, error) {
	encoded, err := encodeProxyRewriteBody(decoded, encodings)
	if err != nil {
		return nil, err
	}
	if len(encodings) == 0 {
		headers.Del("Content-Encoding")
	} else {
		headers.Set("Content-Encoding", strings.Join(encodings, ", "))
	}
	headers.Set("Content-Length", fmt.Sprintf("%d", len(encoded)))
	headers.Del("Content-MD5")
	return encoded, nil
}

func encodeProxyRewriteBody(decoded []byte, encodings []string) ([]byte, error) {
	encoded := decoded
	for _, encoding := range encodings {
		var buf bytes.Buffer
		writer, err := proxyRewriteEncoder(&buf, encoding)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(encoded); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		encoded = buf.Bytes()
	}
	return encoded, nil
}

func proxyRewriteDecoder(encoded []byte, encoding string) (io.ReadCloser, error) {
	switch encoding {
	case "br":
		return io.NopCloser(brotli.NewReader(bytes.NewReader(encoded))), nil
	case "zstd":
		reader, err := zstd.NewReader(bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		return zstdReadCloser{Decoder: reader}, nil
	case "gzip", "x-gzip":
		return gzip.NewReader(bytes.NewReader(encoded))
	case "deflate":
		if reader, err := zlib.NewReader(bytes.NewReader(encoded)); err == nil {
			return reader, nil
		}
		return flate.NewReader(bytes.NewReader(encoded)), nil
	default:
		return nil, fmt.Errorf("unsupported content encoding: %s", encoding)
	}
}

func proxyRewriteEncoder(dst io.Writer, encoding string) (io.WriteCloser, error) {
	switch encoding {
	case "br":
		return brotli.NewWriter(dst), nil
	case "zstd":
		return zstd.NewWriter(dst)
	case "gzip", "x-gzip":
		return gzip.NewWriter(dst), nil
	case "deflate":
		return zlib.NewWriter(dst), nil
	default:
		return nil, fmt.Errorf("unsupported content encoding: %s", encoding)
	}
}

type zstdReadCloser struct {
	*zstd.Decoder
}

func (r zstdReadCloser) Close() error {
	r.Decoder.Close()
	return nil
}

func (h *Handler) rewriteLocation(r *http.Request, location string, node storage.Node, parsed parsedRoute, base *url.URL, selfPrefix string) (string, bool, string) {
	origin := schemeHost(r)
	selfPrefixNoSlash := strings.TrimRight(selfPrefix, "/")
	if strings.HasPrefix(location, "/") {
		if location == selfPrefixNoSlash || strings.HasPrefix(location, selfPrefixNoSlash+"/") {
			return "", false, ""
		}
		return origin + selfPrefix + location, false, ""
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", false, ""
	}
	locHost := strings.ToLower(loc.Host)
	baseHost := strings.ToLower(base.Host)
	alreadyPrefixed := loc.Path == selfPrefixNoSlash || strings.HasPrefix(loc.Path, selfPrefixNoSlash+"/")
	if alreadyPrefixed {
		return "", false, ""
	}
	if locHost == baseHost {
		return origin + selfPrefix + loc.Path + queryAndHash(loc), false, ""
	}
	if !node.DirectExternal {
		return "", true, loc.String()
	}
	return loc.String(), false, ""
}

func (h *Handler) rewriteBodyLinks(ctx context.Context, text, requestURL string, currentNode storage.Node, currentName, currentKey string) string {
	if text == "" {
		return text
	}
	reqURL, err := url.Parse(requestURL)
	if err != nil {
		return text
	}
	origin := reqURL.Scheme + "://" + reqURL.Host
	selfPrefix := routePrefix(currentName, currentKey)
	if currentNode.DirectExternal {
		return text
	}
	curHosts := map[string]bool{}
	for _, target := range storage.SplitTargets(currentNode.Target) {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			curHosts[strings.ToLower(u.Host)] = true
		}
	}
	hostMap, _ := h.store.GetHostIndex(ctx, "admin")
	matches := uniqueStrings(bodyURLRE.FindAllString(text, -1))
	if len(matches) == 0 {
		return text
	}
	replacements := map[string]string{}
	for _, full := range matches {
		u, err := url.Parse(full)
		if err != nil {
			continue
		}
		if u.Scheme+"://"+u.Host == origin && (u.Path == selfPrefix || strings.HasPrefix(u.Path, selfPrefix+"/")) {
			continue
		}
		host := strings.ToLower(u.Host)
		if curHosts[host] {
			replacements[full] = origin + selfPrefix + u.Path + queryAndHash(u)
			continue
		}
		if match, ok := hostMap[host]; ok {
			replacements[full] = origin + routePrefix(match.Name, match.Secret) + u.Path + queryAndHash(u)
			continue
		}
		replacements[full] = h.signedRawLink(origin, selfPrefix, full)
	}
	out := text
	for from, to := range replacements {
		out = strings.ReplaceAll(out, from, to)
	}
	return out
}

func mediaSourceJSONRewriteStage(path string) string {
	p := normalizedEmbyAPIPath(path)
	if strings.Contains(p, "/playbackinfo") {
		return "playbackinfo-rewrite"
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) == 4 && parts[0] == "users" && parts[2] == "items" && parts[1] != "" && parts[3] != "" {
		return "mediasource-url-rewrite"
	}
	return ""
}

func rewriteMediaSourceJSONURLs(raw []byte, origin, selfPrefix string, base *url.URL, directExternal bool, rawLink func(string) string) ([]byte, bool) {
	if len(raw) == 0 || directExternal {
		return raw, false
	}
	var payload map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return raw, false
	}
	sources, ok := payload["MediaSources"].([]any)
	if !ok {
		return raw, false
	}
	changed := false
	for _, source := range sources {
		item, ok := source.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"DirectStreamUrl", "TranscodingUrl", "StreamUrl"} {
			if value, ok := item[key].(string); ok {
				if rewritten := rewriteMediaSourceURL(value, origin, selfPrefix, base, rawLink); rewritten != value {
					item[key] = rewritten
					changed = true
				}
			}
		}
	}
	if !changed {
		return raw, false
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return raw, false
	}
	return out, true
}

func rewriteMediaSourceURL(raw, origin, selfPrefix string, base *url.URL, rawLink func(string) string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return raw
	}
	if strings.HasPrefix(value, "/") {
		selfPrefixNoSlash := strings.TrimRight(selfPrefix, "/")
		if value == selfPrefixNoSlash || strings.HasPrefix(value, selfPrefixNoSlash+"/") {
			return raw
		}
		return raw
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return raw
	}
	selfPrefixNoSlash := strings.TrimRight(selfPrefix, "/")
	if u.Scheme+"://"+u.Host == origin && (u.Path == selfPrefixNoSlash || strings.HasPrefix(u.Path, selfPrefixNoSlash+"/")) {
		return u.Path + queryAndHash(u)
	}
	if base != nil && sameHost(value, base.String()) {
		return u.Path + queryAndHash(u)
	}
	if rawLink != nil {
		link := rawLink(value)
		linkURL, err := url.Parse(link)
		if err != nil {
			return link
		}
		rawPath := strings.TrimRight(selfPrefix, "/") + "/__raw__"
		if linkURL.Path == rawPath {
			return "/__raw__" + queryAndHash(linkURL)
		}
		return linkURL.Path + queryAndHash(linkURL)
	}
	return "/__raw__/" + url.QueryEscape(value)
}

func isSystemInfoPath(path string) bool {
	p := strings.ToLower(strings.Trim(path, "/"))
	return p == "system/info" || p == "system/info/public" || p == "emby/system/info" || p == "emby/system/info/public"
}

func rewriteSystemInfoAddresses(raw []byte, publicBase string) ([]byte, bool) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw, false
	}
	changed := false
	for key, value := range payload {
		if !isSystemInfoAddressKey(key) {
			continue
		}
		switch value.(type) {
		case string:
			payload[key] = publicBase
			changed = true
		case []any:
			payload[key] = []any{publicBase}
			changed = true
		}
	}
	if !changed {
		return raw, false
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return raw, false
	}
	return out, true
}

func isSystemInfoAddressKey(key string) bool {
	switch strings.ToLower(key) {
	case "localaddress", "wanaddress", "remoteaddress", "publicaddress", "publicurl", "localaddresses", "wanaddresses", "remoteaddresses":
		return true
	default:
		return false
	}
}

func setImageCacheControl(headers http.Header, status int, cacheValue string) {
	if status == http.StatusNotModified || (status >= 200 && status < 300) {
		headers.Set("Cache-Control", cacheValue)
		return
	}
	headers.Set("Cache-Control", "no-store")
}

func isAuthSuccess(res *http.Response) bool {
	if isRedirectStatus(res.StatusCode) {
		return false
	}
	if !strings.Contains(strings.ToLower(res.Header.Get("Content-Type")), "application/json") {
		return false
	}
	return res.StatusCode == http.StatusOK || res.StatusCode == http.StatusUnauthorized
}

func isRedirectStatus(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func playbackRedirectMode(r *http.Request, res *http.Response) string {
	if res == nil || !isRedirectStatus(res.StatusCode) {
		return "proxy"
	}
	location := strings.TrimSpace(res.Header.Get("Location"))
	if location == "" || (strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//")) {
		return "proxy"
	}
	u, err := url.Parse(location)
	if err != nil || u.Host == "" {
		return "proxy"
	}
	if strings.EqualFold(u.Host, r.Host) {
		return "proxy"
	}
	return "direct"
}

func cloneURL(u *url.URL) *url.URL {
	v := *u
	return &v
}

func originOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func authClientIP(h *Handler, r *http.Request) string {
	return auth.ClientIP(r, h.trustsProxy(r.Context()))
}

func queryAndHash(u *url.URL) string {
	out := ""
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
