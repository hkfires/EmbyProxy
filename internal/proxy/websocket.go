package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"embyproxy/internal/auth"
	"embyproxy/internal/capture"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

const (
	webSocketDialTimeout      = UpstreamTargetAttemptTimeout
	webSocketHandshakeTimeout = UpstreamTargetAttemptTimeout
)

func (h *Handler) handleWebSocket(w http.ResponseWriter, r *http.Request, node storage.Node, parsed parsedRoute) {
	ctx := r.Context()
	requestID := requestID(r, h.log)
	clientIP := auth.ClientIP(r, h.trustsProxy(ctx))
	started := time.Now()
	targets := storage.SplitTargets(node.Target)
	if len(targets) == 0 {
		capture.SetMeta(r, map[string]any{"mode": "ws", "node": parsed.Name, "secret": node.Secret, "stage": "no-targets"})
		h.log.Warn("ws", "node has no targets", map[string]any{"event": "nodeHasNoTargets", "id": requestID, "node": parsed.Name, "ip": clientIP})
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	nodeKey := "admin:" + parsed.Name
	expectedActive, ordered := h.targetOrder(nodeKey, targets)
	var lastErr error
	var lastTarget string
	tried := 0
	for pass := 0; pass < 2; pass++ {
		for _, target := range ordered {
			banKey := nodeKey + "|" + target
			if pass == 0 {
				if _, banned := h.lineBan.Get(banKey); banned && len(targets) > 1 {
					continue
				}
			} else if tried > 0 {
				break
			}
			tried++
			lastTarget = target
			attemptCtx, cancel := context.WithTimeout(ctx, h.targetTimeout())
			succeeded := h.tryWebSocketTarget(attemptCtx, w, r, node, parsed, target, targets, expectedActive, requestID, started)
			cancel()
			if succeeded {
				return
			}
			lastErr = errWebSocketUpgradeFailed
			if ctx.Err() != nil {
				break
			}
			h.lineBan.Set(banKey, 1, time.Minute)
		}
		if tried > 0 {
			break
		}
	}
	if lastErr == nil {
		lastErr = errWebSocketUpgradeFailed
	}
	capture.SetMeta(r, map[string]any{"mode": "ws", "node": parsed.Name, "secret": node.Secret, "stage": "upgrade-failed", "targetUrl": lastTarget, "meta": map[string]any{"error": lastErr.Error()}})
	h.log.Warn("ws", "upgrade failed", map[string]any{"event": "upgradeFailed", "id": requestID, "node": parsed.Name, "target": logging.FormatTarget(lastTarget), "error": lastErr.Error()})
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

func (h *Handler) tryWebSocketTarget(ctx context.Context, w http.ResponseWriter, r *http.Request, node storage.Node, parsed parsedRoute, target string, targets []string, expectedActive, requestID string, started time.Time) bool {
	base, err := url.Parse(target)
	if err != nil {
		h.log.Warn("ws", "target parse failed", map[string]any{"event": "targetParseFailed", "id": requestID, "node": parsed.Name, "target": logging.FormatTarget(target), "error": err.Error()})
		return false
	}
	forwardPath := websocketForwardPath(parsed.Path, base.Path)
	targetURL := resolveTargetURL(base, forwardPath, r.URL.RawQuery)
	outboundHeaders := cloneHeader(r.Header)
	applyIdentityToURL(h.ids, targetURL, outboundHeaders, node)
	headers := buildWebSocketHeaders(h.ids, outboundHeaders, targetURL, node)
	env := h.proxyEnv(ctx)
	if isEmosNode(node, targetURL, env) {
		applyEmosHeaders(headers, env)
	}
	capture.SetMeta(r, map[string]any{"mode": "ws", "node": parsed.Name, "secret": node.Secret, "stage": "upgrade-target", "targetUrl": targetURL.String(), "outboundHeaders": headers})
	res, upstreamConn, upstreamReader, err := h.dialWebSocket(ctx, targetURL, headers)
	if err != nil {
		h.log.Warn("ws", "upstream dial failed", map[string]any{"event": "upstreamDialFailed", "id": requestID, "node": parsed.Name, "target": logging.FormatTarget(target), "error": err.Error()})
		return false
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		_ = upstreamConn.Close()
		h.log.Warn("ws", "upstream rejected upgrade", map[string]any{"event": "upstreamRejectedUpgrade", "id": requestID, "node": parsed.Name, "target": logging.FormatTarget(target), "status": res.StatusCode})
		return false
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstreamConn.Close()
		http.Error(w, "WebSocket hijack not supported", http.StatusInternalServerError)
		return true
	}
	clientConn, clientRW, err := hijacker.Hijack()
	if err != nil {
		_ = upstreamConn.Close()
		h.log.Warn("ws", "client hijack failed", map[string]any{"event": "clientHijackFailed", "id": requestID, "node": parsed.Name, "error": err.Error()})
		return true
	}
	if err := writeWebSocketResponse(clientConn, res); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		h.log.Warn("ws", "write upgrade response failed", map[string]any{"event": "writeUpgradeResponseFailed", "id": requestID, "node": parsed.Name, "error": err.Error()})
		return true
	}
	h.markTargetHealthy("admin:"+parsed.Name, targets, target, expectedActive)
	capture.SetMeta(r, map[string]any{"mode": "ws", "node": parsed.Name, "secret": node.Secret, "stage": "upgraded", "targetUrl": targetURL.String(), "outboundHeaders": headers})
	h.log.Debug("ws", "upgrade completed", map[string]any{"event": "upgradeCompleted", "id": requestID, "node": parsed.Name, "target": logging.FormatTarget(target), "status": 101, "upgradeMs": time.Since(started).Milliseconds()})
	flushBuffered(upstreamConn, clientRW.Reader)
	flushBuffered(clientConn, upstreamReader)
	go copyAndClose(upstreamConn, clientConn)
	go copyAndClose(clientConn, upstreamConn)
	return true
}

func buildWebSocketHeaders(ids *identity.Manager, raw http.Header, targetURL *url.URL, node storage.Node) http.Header {
	headers := cloneHeader(raw)
	stripProxyMetadataHeaders(headers)
	deleteHeaders(headers, "Connection", "Content-Length", "Host")
	headers.Set("Host", targetURL.Host)
	setProxyUA(ids, headers, node)
	applyIdentity(ids, headers, node)
	headers.Set("Connection", "Upgrade")
	headers.Set("Upgrade", "websocket")
	return headers
}

func (h *Handler) dialWebSocket(ctx context.Context, target *url.URL, headers http.Header) (*http.Response, net.Conn, *bufio.Reader, error) {
	conn, err := dialWebSocketConn(ctx, target)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := conn.SetDeadline(webSocketHandshakeDeadline(ctx)); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	reqURL := *target
	if reqURL.Scheme == "ws" {
		reqURL.Scheme = "http"
	} else if reqURL.Scheme == "wss" {
		reqURL.Scheme = "https"
	}
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        &reqURL,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     cloneHeader(headers),
		Host:       target.Host,
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	reader := bufio.NewReader(conn)
	res, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		if res.Body != nil {
			_ = res.Body.Close()
		}
		return nil, nil, nil, err
	}
	return res, conn, reader, nil
}

func dialWebSocketConn(ctx context.Context, target *url.URL) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: webSocketDialTimeout, KeepAlive: 30 * time.Second}
	addr := target.Host
	if !strings.Contains(addr, ":") {
		addr += ":" + defaultWebSocketPort(target.Scheme)
	}
	switch strings.ToLower(target.Scheme) {
	case "https", "wss":
		rawConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		if err := rawConn.SetDeadline(webSocketHandshakeDeadline(ctx)); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		tlsConn := tls.Client(rawConn, &tls.Config{ServerName: target.Hostname()})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		return tlsConn, nil
	case "http", "ws":
		return dialer.DialContext(ctx, "tcp", addr)
	default:
		return nil, fmt.Errorf("unsupported websocket target scheme: %s", target.Scheme)
	}
}

func webSocketHandshakeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(webSocketHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func defaultWebSocketPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https", "wss":
		return "443"
	default:
		return "80"
	}
}

func writeWebSocketResponse(conn net.Conn, res *http.Response) error {
	status := res.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", res.StatusCode, http.StatusText(res.StatusCode))
	}
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 %s\r\n", status); err != nil {
		return err
	}
	for key, values := range res.Header {
		for _, value := range values {
			if _, err := fmt.Fprintf(conn, "%s: %s\r\n", key, value); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(conn, "\r\n")
	return err
}

func flushBuffered(dst io.Writer, reader *bufio.Reader) {
	if reader == nil {
		return
	}
	for reader.Buffered() > 0 {
		n := reader.Buffered()
		_, _ = io.CopyN(dst, reader, int64(n))
	}
}

func copyAndClose(dst net.Conn, src net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
}

func websocketForwardPath(path, basePath string) string {
	forwardPath := path
	if hasPathPrefix(forwardPath, "/emby") && hasPathPrefix(strings.TrimRight(basePath, "/"), "/emby") {
		forwardPath = strings.TrimPrefix(forwardPath, "/emby")
		if forwardPath == "" {
			forwardPath = "/"
		}
	}
	return forwardPath
}

func hasPathPrefix(path, prefix string) bool {
	path = strings.ToLower(path)
	prefix = strings.ToLower(prefix)
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

var errWebSocketUpgradeFailed = errors.New("websocket upgrade failed")
