package admin

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"embyproxy/internal/auth"
	"embyproxy/internal/buildinfo"
	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/localtime"
	"embyproxy/internal/logging"
	"embyproxy/internal/proxy"
	"embyproxy/internal/requestlog"
	"embyproxy/internal/storage"
	"embyproxy/internal/telegram"
	"embyproxy/internal/validators"

	"github.com/tidwall/gjson"
)

//go:embed static/index.html
var indexHTML string

type ResetFunc func(uid, name string)

type ImageCacheManager interface {
	ImageCacheStats(ctx context.Context) (proxy.ImageCacheStats, error)
	ClearImageCache(ctx context.Context) (proxy.ImageCacheStats, error)
}

type trafficCaptureStats struct {
	Enabled bool                       `json:"enabled"`
	File    string                     `json:"file"`
	Bytes   int64                      `json:"bytes"`
	Records int64                      `json:"records"`
	Stages  []trafficCaptureStageStats `json:"stages"`
}

type trafficCaptureStageStats struct {
	Stage   string `json:"stage"`
	Bytes   int64  `json:"bytes"`
	Records int64  `json:"records"`
}

type trafficCaptureScan struct {
	Bytes   int64
	Records int64
	Stages  []trafficCaptureStageStats
}

const trafficCaptureClearWriterBuffer = 256 * 1024
const telegramServerRemarkMaxRunes = 80

type Handler struct {
	cfg        config.Config
	store      *storage.Store
	checker    *auth.Checker
	telegram   *telegram.Service
	log        *logging.Logger
	resetRoute ResetFunc
	imageCache ImageCacheManager
}

func New(cfg config.Config, store *storage.Store, checker *auth.Checker, tg *telegram.Service, log *logging.Logger, reset ResetFunc, imageCaches ...ImageCacheManager) *Handler {
	var imageCache ImageCacheManager
	if len(imageCaches) > 0 {
		imageCache = imageCaches[0]
	}
	return &Handler{
		cfg:        cfg,
		store:      store,
		checker:    checker,
		telegram:   tg,
		log:        log,
		resetRoute: reset,
		imageCache: imageCache,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if r.Method == http.MethodGet && (path == "/admin" || path == "") {
		capture.SetMeta(r, map[string]any{"mode": "admin", "stage": "admin-page"})
		if errText := auth.ValidateAdminToken(h.cfg.AdminToken); errText != "" {
			h.serveAdminTokenError(w, errText)
			return
		}
		h.serveIndex(w, r)
		return
	}
	if strings.HasPrefix(path, "/admin/auth") {
		h.handleAuth(w, r, path)
		return
	}
	capture.SetMeta(r, map[string]any{"mode": "admin", "stage": "admin-auth"})
	if r.Method == http.MethodPost && !validAdminOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": auth.ErrorCrossSiteRequest})
		return
	}
	if h.checker == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "INTERNAL_ERROR"})
		return
	}
	res := h.checker.Check(r)
	if !res.OK {
		writeJSON(w, res.Status, map[string]any{"error": res.Error})
		return
	}
	if r.Method == http.MethodGet && path == "/admin/logs/stream" {
		h.streamLogs(w, r, res)
		return
	}
	if r.Method == http.MethodPost && path == "/admin/api" {
		h.handleAuthorizedAPI(w, r)
		return
	}
	http.NotFound(w, r)
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", time.Time{}, strings.NewReader(indexHTML))
}

func (h *Handler) handleAuth(w http.ResponseWriter, r *http.Request, path string) {
	capture.Suppress(r)
	capture.SetMeta(r, map[string]any{"mode": "admin", "stage": "admin-auth", "adminAction": strings.TrimPrefix(path, "/admin/")})
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodPost && !validAdminOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": auth.ErrorCrossSiteRequest})
		return
	}
	if h.checker == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "INTERNAL_ERROR"})
		return
	}
	switch {
	case r.Method == http.MethodPost && path == "/admin/auth/login":
		var body struct {
			Token string `json:"token"`
			Code  string `json:"code"`
		}
		if !decodeAuthJSON(w, r, &body) {
			return
		}
		session, status, res := h.checker.Login(r, body.Token, body.Code)
		if !res.OK {
			writeJSON(w, res.Status, map[string]any{"ok": false, "error": res.Error, "twoFactor": status})
			return
		}
		auth.SetSessionCookie(w, r, session)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":               true,
			"authenticated":    true,
			"sessionExpiresAt": session.ExpiresAt.UnixMilli(),
			"twoFactor":        status,
		})
	case r.Method == http.MethodPost && path == "/admin/auth/logout":
		h.checker.Logout(r)
		auth.ClearSessionCookie(w, r)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case r.Method == http.MethodGet && path == "/admin/auth/status":
		res := h.checker.Check(r)
		if !res.OK {
			writeJSON(w, res.Status, map[string]any{"ok": false, "authenticated": false, "error": res.Error})
			return
		}
		status, err := h.checker.TwoFactorStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "authenticated": true, "error": auth.ErrorTwoFactorUnavailable})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "authenticated": true, "twoFactor": status})
	case r.Method == http.MethodPost && path == "/admin/auth/2fa/setup":
		res := h.checker.Check(r)
		if !res.OK {
			writeJSON(w, res.Status, map[string]any{"ok": false, "error": res.Error})
			return
		}
		var body struct {
			Token       string `json:"token"`
			CurrentCode string `json:"currentCode"`
		}
		if !decodeAuthJSON(w, r, &body) {
			return
		}
		setup, op := h.checker.BeginTwoFactorSetup(r, res.SessionKey, body.Token, body.CurrentCode, r.Host)
		if !op.OK {
			writeJSON(w, op.Status, map[string]any{"ok": false, "error": op.Error})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "setup": setup})
	case r.Method == http.MethodPost && path == "/admin/auth/2fa/confirm":
		res := h.checker.Check(r)
		if !res.OK {
			writeJSON(w, res.Status, map[string]any{"ok": false, "error": res.Error})
			return
		}
		var body struct {
			SetupID string `json:"setupId"`
			Code    string `json:"code"`
		}
		if !decodeAuthJSON(w, r, &body) {
			return
		}
		session, status, op := h.checker.ConfirmTwoFactorSetup(r, res.SessionKey, body.SetupID, body.Code)
		if !op.OK {
			writeJSON(w, op.Status, map[string]any{"ok": false, "error": op.Error})
			return
		}
		auth.SetSessionCookie(w, r, session)
		h.logSecurityEvent("admin2FAConfigured", "administrator 2FA configured", r)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "twoFactor": status, "sessionExpiresAt": session.ExpiresAt.UnixMilli()})
	case r.Method == http.MethodPost && path == "/admin/auth/2fa/disable":
		res := h.checker.Check(r)
		if !res.OK {
			writeJSON(w, res.Status, map[string]any{"ok": false, "error": res.Error})
			return
		}
		var body struct {
			Token       string `json:"token"`
			CurrentCode string `json:"currentCode"`
		}
		if !decodeAuthJSON(w, r, &body) {
			return
		}
		session, status, op := h.checker.DisableTwoFactor(r, res.SessionKey, body.Token, body.CurrentCode)
		if !op.OK {
			writeJSON(w, op.Status, map[string]any{"ok": false, "error": op.Error})
			return
		}
		auth.SetSessionCookie(w, r, session)
		h.logSecurityEvent("admin2FADisabled", "administrator 2FA disabled", r)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "twoFactor": status, "sessionExpiresAt": session.ExpiresAt.UnixMilli()})
	default:
		http.NotFound(w, r)
	}
}

func decodeAuthJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求 JSON 无效"})
		return false
	}
	return true
}

func validAdminOrigin(r *http.Request) bool {
	if r == nil {
		return false
	}
	fetchSite := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	if fetchSite == "cross-site" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return false
	}
	forwardedProto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(forwardedProto, "https") {
		scheme = "https"
	}
	if !strings.EqualFold(u.Scheme, scheme) {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}

	// Some reverse proxies strip a non-standard external port from Host.
	// Only use the hostname fallback when the browser confirms same-origin.
	if fetchSite != "same-origin" || forwardedProto == "" || u.Port() == "" {
		return false
	}
	requestAuthority, err := url.Parse("//" + strings.TrimSpace(r.Host))
	if err != nil || requestAuthority.Hostname() == "" || requestAuthority.Port() != "" {
		return false
	}
	return strings.EqualFold(u.Hostname(), requestAuthority.Hostname())
}

func (h *Handler) logSecurityEvent(event, message string, r *http.Request) {
	if h == nil || h.log == nil {
		return
	}
	h.log.Info("security", message, map[string]any{"event": event, "ip": h.checker.ClientIP(r)})
}

func (h *Handler) streamLogs(w http.ResponseWriter, r *http.Request, initialAuth auth.Result) {
	capture.Suppress(r)
	requestlog.SuppressAccessLog(r.Context())
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "当前响应不支持日志流"})
		return
	}
	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	header.Set("Connection", "keep-alive")
	header.Set("X-Accel-Buffering", "no")

	ch, cancel := h.log.Subscribe(256)
	defer cancel()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	if _, err := fmt.Fprint(w, ": connected\n\n"); err != nil {
		return
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !h.logStreamAuthorizationValid(r, initialAuth) {
				return
			}
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			if !h.logStreamAuthorizationValid(r, initialAuth) {
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (h *Handler) logStreamAuthorizationValid(r *http.Request, initial auth.Result) bool {
	if h == nil || h.checker == nil || !initial.OK {
		return false
	}
	current := h.checker.Check(r)
	if !current.OK || current.AuthMethod != initial.AuthMethod {
		return false
	}
	if initial.AuthMethod == "session" {
		return initial.SessionKey != "" && current.SessionKey == initial.SessionKey
	}
	return initial.AuthMethod == "token"
}

func (h *Handler) serveAdminTokenError(w http.ResponseWriter, errText string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EmbyProxy 配置错误</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f7f4;color:#18201b;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{width:min(520px,calc(100vw - 32px));border:1px solid #d8ddd5;background:#fff;padding:28px}
h1{margin:0 0 12px;font-size:24px;line-height:1.2}
p{margin:0 0 10px;color:#536052;line-height:1.7}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#9d2f2a}
</style>
</head>
<body>
<main>
<h1>管理 Token 配置无效</h1>
<p>` + errText + `。</p>
<p>请设置安全的 <code>ADMIN_TOKEN</code> 后重启 EmbyProxy。</p>
</main>
</body>
</html>`))
}

func (h *Handler) handleAPI(w http.ResponseWriter, r *http.Request, uid string) {
	body, action, ok := h.decodeAPIRequest(w, r)
	if !ok {
		return
	}
	if uid == "" {
		uid = "admin"
	}
	result, status := h.dispatch(r.Context(), uid, action, body)
	writeJSON(w, status, result)
}

func (h *Handler) handleAuthorizedAPI(w http.ResponseWriter, r *http.Request) {
	body, action, ok := h.decodeAPIRequest(w, r)
	if !ok {
		return
	}
	res, releaseAuthState := h.checker.CheckWithStateGuard(r)
	if !res.OK {
		releaseAuthState()
		writeJSON(w, res.Status, map[string]any{"error": res.Error})
		return
	}
	uid := res.UID
	if uid == "" {
		uid = "admin"
	}
	result, status := func() (map[string]any, int) {
		defer releaseAuthState()
		return h.dispatch(r.Context(), uid, action, body)
	}()
	writeJSON(w, status, result)
}

func (h *Handler) decodeAPIRequest(w http.ResponseWriter, r *http.Request) (map[string]any, string, bool) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求 JSON 无效"})
		return nil, "", false
	}
	capture.RememberParsedBody(r, body)
	action := strings.TrimSpace(asString(body["action"]))
	if action == "logs.list" || action == "logs.clear" {
		capture.Suppress(r)
		requestlog.SuppressAccessLog(ctx)
	}
	if action == "trafficCapture.stats" || action == "trafficCapture.clear" || action == "trafficCapture.clearStage" {
		capture.Suppress(r)
	}
	capture.SetMeta(r, map[string]any{"mode": "admin", "adminAction": action, "stage": "admin-api"})
	return body, action, true
}

func (h *Handler) dispatch(ctx context.Context, uid, action string, body map[string]any) (map[string]any, int) {
	switch action {
	case "list":
		return h.list(ctx, uid), http.StatusOK
	case "save":
		return h.save(ctx, uid, body), http.StatusOK
	case "import":
		return h.importNodes(ctx, uid, body), http.StatusOK
	case "export":
		return h.exportNodes(ctx, uid, body), http.StatusOK
	case "delete":
		name := validators.NormalizeName(body["name"])
		if name == "" {
			return fail("name 不能为空"), http.StatusOK
		}
		if err := h.store.DeleteNode(ctx, uid, name); err != nil {
			return fail(err.Error()), http.StatusInternalServerError
		}
		h.reset(uid, name)
		return ok(), http.StatusOK
	case "batchDelete":
		for _, name := range arrayStrings(body["names"]) {
			nm := validators.NormalizeName(name)
			if nm == "" {
				continue
			}
			_ = h.store.DeleteNode(ctx, uid, nm)
			h.reset(uid, nm)
		}
		return ok(), http.StatusOK
	case "toggleFav":
		name := validators.NormalizeName(body["name"])
		node, err := h.store.GetNode(ctx, uid, name)
		if err != nil {
			return fail(err.Error()), http.StatusInternalServerError
		}
		if node == nil {
			return fail("节点不存在"), http.StatusOK
		}
		node.Fav = !node.Fav
		if err := h.store.SaveNode(ctx, uid, *node); err != nil {
			return fail(err.Error()), http.StatusInternalServerError
		}
		return map[string]any{"ok": true, "fav": node.Fav}, http.StatusOK
	case "saveOrder":
		order := arrayStrings(body["order"])
		if len(order) == 0 {
			order = arrayStrings(body["names"])
		}
		for i, name := range order {
			nm := validators.NormalizeName(name)
			node, _ := h.store.GetNode(ctx, uid, nm)
			if node != nil {
				rank := i + 1
				node.Rank = &rank
				_ = h.store.SaveNode(ctx, uid, *node)
			}
		}
		return ok(), http.StatusOK
	case "batchTag":
		tag := validators.ValidateTag(body["tag"])
		for _, name := range arrayStrings(body["names"]) {
			nm := validators.NormalizeName(name)
			node, _ := h.store.GetNode(ctx, uid, nm)
			if node != nil {
				node.Tag = tag
				_ = h.store.SaveNode(ctx, uid, *node)
			}
		}
		return ok(), http.StatusOK
	case "checkStatus":
		return h.checkStatus(ctx, uid, body), http.StatusOK
	case "compactAll":
		nodes, err := h.store.ListNodes(ctx, uid)
		if err != nil {
			return fail(err.Error()), http.StatusInternalServerError
		}
		count := 0
		for _, node := range nodes {
			if err := h.store.SaveNode(ctx, uid, node); err == nil {
				count++
			}
		}
		return map[string]any{"ok": true, "count": count}, http.StatusOK
	case "tg.get":
		cfg, err := h.store.GetTGConfig(ctx)
		if err != nil {
			return fail(err.Error()), http.StatusInternalServerError
		}
		return map[string]any{"ok": true, "config": cfg, "content": cfg}, http.StatusOK
	case "tg.set":
		return h.tgSet(ctx, body), http.StatusOK
	case "tg.test":
		cfg, err := h.store.GetTGConfig(ctx)
		if err != nil {
			return fail(err.Error()), http.StatusInternalServerError
		}
		if cfg.Token == "" || cfg.Chat == "" {
			return fail("TG 未配置"), http.StatusOK
		}
		text, err := h.telegram.BuildReport(ctx, time.Now().UnixMilli())
		if err != nil {
			return fail(err.Error()), http.StatusInternalServerError
		}
		return map[string]any{"ok": h.telegram.Send(ctx, cfg, text)}, http.StatusOK
	case "config.get":
		cfg, err := h.store.GetSystemConfig(ctx, h.defaultSystemConfig())
		if err != nil {
			return fail(err.Error()), http.StatusInternalServerError
		}
		return map[string]any{"ok": true, "config": cfg, "content": cfg}, http.StatusOK
	case "config.set":
		return h.configSet(ctx, body), http.StatusOK
	case "keepalive.test":
		return h.keepaliveTest(ctx, body)
	case "stats.get":
		days := clamp(intValue(body["days"], 7), 1, 30)
		stats, err := h.store.GetPlayStats(ctx, days)
		if err != nil {
			return fail(err.Error()), http.StatusInternalServerError
		}
		return map[string]any{"ok": true, "stats": stats}, http.StatusOK
	case "logs.list":
		return h.listLogs(body), http.StatusOK
	case "logs.clear":
		return h.clearLogs(), http.StatusOK
	case "imageCache.stats":
		return h.imageCacheStats(ctx), http.StatusOK
	case "imageCache.clear":
		return h.clearImageCache(ctx), http.StatusOK
	case "trafficCapture.stats":
		return h.trafficCaptureStats(ctx), http.StatusOK
	case "trafficCapture.clear":
		return h.clearTrafficCapture(ctx), http.StatusOK
	case "trafficCapture.clearStage":
		return h.clearTrafficCaptureStage(ctx, body), http.StatusOK
	default:
		return fail("未知 action: " + action), http.StatusOK
	}
}

func (h *Handler) imageCacheStats(ctx context.Context) map[string]any {
	if h.imageCache == nil {
		return fail("图片缓存管理器未初始化")
	}
	stats, err := h.imageCache.ImageCacheStats(ctx)
	if err != nil {
		return fail(err.Error())
	}
	return map[string]any{"ok": true, "cache": stats}
}

func (h *Handler) trafficCaptureStats(ctx context.Context) map[string]any {
	if h.store == nil {
		return fail("存储未初始化")
	}
	cfg, err := h.store.GetSystemConfig(ctx, h.defaultSystemConfig())
	if err != nil {
		return fail(err.Error())
	}
	stats, err := h.readTrafficCaptureStats(cfg)
	if err != nil {
		return fail(err.Error())
	}
	return map[string]any{"ok": true, "capture": stats}
}

func (h *Handler) readTrafficCaptureStats(cfg storage.SystemConfig) (trafficCaptureStats, error) {
	stats, path, err := h.trafficCaptureStatsTarget(cfg)
	if err != nil {
		return stats, err
	}
	var scan trafficCaptureScan
	if err := capture.WithFileLock(path, func() error {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			scan = trafficCaptureScan{}
			return nil
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			return errors.New("代理流量记录路径不是文件")
		}
		scan, err = scanTrafficCaptureRecords(path)
		return err
	}); err != nil {
		return stats, err
	}
	stats.Bytes = scan.Bytes
	stats.Records = scan.Records
	stats.Stages = scan.Stages
	return stats, nil
}

func (h *Handler) clearTrafficCapture(ctx context.Context) map[string]any {
	if h.store == nil {
		return fail("存储未初始化")
	}
	cfg, err := h.store.GetSystemConfig(ctx, h.defaultSystemConfig())
	if err != nil {
		return fail(err.Error())
	}
	stats, err := h.clearTrafficCaptureRecords(cfg)
	if err != nil {
		return fail(err.Error())
	}
	return map[string]any{"ok": true, "capture": stats}
}

func (h *Handler) clearTrafficCaptureRecords(cfg storage.SystemConfig) (trafficCaptureStats, error) {
	stats, path, err := h.trafficCaptureStatsTarget(cfg)
	if err != nil {
		return stats, err
	}
	if err := capture.WithFileLock(path, func() error {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			return errors.New("代理流量记录路径不是文件")
		}
		return os.Truncate(path, 0)
	}); err != nil {
		return stats, err
	}
	return stats, nil
}

func (h *Handler) clearTrafficCaptureStage(ctx context.Context, body map[string]any) map[string]any {
	if _, ok := body["stage"]; !ok {
		return fail("stage 不能为空")
	}
	stage := strings.TrimSpace(asString(body["stage"]))
	if h.store == nil {
		return fail("存储未初始化")
	}
	cfg, err := h.store.GetSystemConfig(ctx, h.defaultSystemConfig())
	if err != nil {
		return fail(err.Error())
	}
	stats, err := h.clearTrafficCaptureStageRecords(cfg, stage)
	if err != nil {
		return fail(err.Error())
	}
	return map[string]any{"ok": true, "capture": stats}
}

func (h *Handler) clearTrafficCaptureStageRecords(cfg storage.SystemConfig, stage string) (trafficCaptureStats, error) {
	stats, path, err := h.trafficCaptureStatsTarget(cfg)
	if err != nil {
		return stats, err
	}
	var scan trafficCaptureScan
	if err := capture.WithFileLock(path, func() error {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			scan = trafficCaptureScan{}
			return nil
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			return errors.New("代理流量记录路径不是文件")
		}
		scan, err = filterTrafficCaptureRecordsByStage(path, stage)
		return err
	}); err != nil {
		return stats, err
	}
	stats.Bytes = scan.Bytes
	stats.Records = scan.Records
	stats.Stages = scan.Stages
	return stats, nil
}

func (h *Handler) trafficCaptureStatsTarget(cfg storage.SystemConfig) (trafficCaptureStats, string, error) {
	file, errText := normalizeTrafficCaptureFile(cfg.TrafficCaptureFile, h.defaultSystemConfig().TrafficCaptureFile)
	stats := trafficCaptureStats{Enabled: cfg.TrafficCaptureEnabled, File: file}
	if errText != "" {
		return stats, "", errors.New(errText)
	}
	return stats, h.trafficCaptureFilePath(file), nil
}

func (h *Handler) trafficCaptureFilePath(file string) string {
	file = filepath.FromSlash(file)
	if h == nil || strings.TrimSpace(h.cfg.CWD) == "" {
		return file
	}
	return filepath.Join(h.cfg.CWD, file)
}

func scanTrafficCaptureRecords(path string) (trafficCaptureScan, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return trafficCaptureScan{}, nil
	}
	if err != nil {
		return trafficCaptureScan{}, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	scan := trafficCaptureScan{}
	byStage := map[string]*trafficCaptureStageStats{}
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			scan.Bytes += int64(len(line))
		}
		if len(bytes.TrimSpace(line)) > 0 {
			scan.Records++
			stage := trafficCaptureLineStage(line)
			stats := byStage[stage]
			if stats == nil {
				stats = &trafficCaptureStageStats{Stage: stage}
				byStage[stage] = stats
			}
			stats.Records++
			stats.Bytes += int64(len(line))
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			scan.Stages = sortedTrafficCaptureStageStats(byStage)
			return scan, nil
		}
		return trafficCaptureScan{}, err
	}
}

func trafficCaptureLineStage(line []byte) string {
	result := gjson.GetBytes(line, "stage")
	if !result.Exists() || result.Type != gjson.String {
		return ""
	}
	return strings.TrimSpace(result.String())
}

func sortedTrafficCaptureStageStats(byStage map[string]*trafficCaptureStageStats) []trafficCaptureStageStats {
	stages := make([]trafficCaptureStageStats, 0, len(byStage))
	for _, stats := range byStage {
		stages = append(stages, *stats)
	}
	sort.Slice(stages, func(i, j int) bool {
		if stages[i].Records != stages[j].Records {
			return stages[i].Records > stages[j].Records
		}
		if stages[i].Bytes != stages[j].Bytes {
			return stages[i].Bytes > stages[j].Bytes
		}
		return stages[i].Stage < stages[j].Stage
	})
	return stages
}

func filterTrafficCaptureRecordsByStage(path, stage string) (trafficCaptureScan, error) {
	src, err := os.Open(path)
	if os.IsNotExist(err) {
		return trafficCaptureScan{}, nil
	}
	if err != nil {
		return trafficCaptureScan{}, err
	}
	defer src.Close()

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return trafficCaptureScan{}, err
	}
	tmpName := tmp.Name()
	keepTemp := false
	defer func() {
		if !keepTemp {
			_ = os.Remove(tmpName)
		}
	}()

	reader := bufio.NewReader(src)
	writer := bufio.NewWriterSize(tmp, trafficCaptureClearWriterBuffer)
	scan := trafficCaptureScan{}
	byStage := map[string]*trafficCaptureStageStats{}
	removed := false
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			recordLine := len(bytes.TrimSpace(line)) > 0
			lineStage := ""
			if recordLine {
				lineStage = trafficCaptureLineStage(line)
			}
			if recordLine && lineStage == stage {
				removed = true
			} else if _, err := writer.Write(line); err != nil {
				_ = tmp.Close()
				return trafficCaptureScan{}, err
			} else {
				scan.Bytes += int64(len(line))
				if recordLine {
					scan.Records++
					stats := byStage[lineStage]
					if stats == nil {
						stats = &trafficCaptureStageStats{Stage: lineStage}
						byStage[lineStage] = stats
					}
					stats.Records++
					stats.Bytes += int64(len(line))
				}
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		_ = tmp.Close()
		return trafficCaptureScan{}, readErr
	}
	scan.Stages = sortedTrafficCaptureStageStats(byStage)
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		return trafficCaptureScan{}, err
	}
	if err := tmp.Close(); err != nil {
		return trafficCaptureScan{}, err
	}
	if !removed {
		return scan, nil
	}
	if err := src.Close(); err != nil {
		return trafficCaptureScan{}, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return trafficCaptureScan{}, err
	}
	keepTemp = true
	return scan, nil
}

func (h *Handler) clearImageCache(ctx context.Context) map[string]any {
	if h.imageCache == nil {
		return fail("图片缓存管理器未初始化")
	}
	stats, err := h.imageCache.ClearImageCache(ctx)
	if err != nil {
		return fail(err.Error())
	}
	return map[string]any{"ok": true, "cache": stats}
}

func (h *Handler) clearLogs() map[string]any {
	if h.log == nil {
		return h.listLogs(nil)
	}
	if err := h.log.Clear(); err != nil {
		return fail(err.Error())
	}
	return h.listLogs(map[string]any{"limit": h.log.BufferCapacity(), "page": 1})
}

func (h *Handler) listLogs(body map[string]any) map[string]any {
	if h.log == nil {
		return map[string]any{"ok": true, "logs": []logging.LogEntry{}, "capacity": 0, "hasOlder": false, "oldestId": uint64(0), "newestId": uint64(0), "streamId": uint64(0), "page": 1, "totalPages": 1, "totalEntries": 0}
	}
	limit := clamp(intValue(body["limit"], h.log.BufferCapacity()), 1, h.log.BufferCapacity())
	pageNumber := intValue(body["page"], 0)
	level := strings.ToLower(strings.TrimSpace(asString(body["level"])))
	filter := logging.LogFilter{Query: strings.ToLower(strings.TrimSpace(asString(body["query"])))}
	if level != "" && level != "all" {
		filter.Levels = map[string]bool{level: true}
	}
	page := logging.LogPage{}
	if pageNumber > 0 {
		page = h.log.PageNumber(limit, pageNumber, filter)
	} else {
		page = h.log.Page(limit, uint64Value(body["before"]), filter)
	}
	if page.Page <= 0 {
		page.Page = 1
	}
	if page.TotalPages <= 0 {
		page.TotalPages = 1
	}
	oldestID := uint64(0)
	newestID := uint64(0)
	if len(page.Entries) > 0 {
		oldestID = page.Entries[0].ID
		newestID = page.Entries[len(page.Entries)-1].ID
	}
	streamID := h.log.NewestID()
	return map[string]any{
		"ok":           true,
		"logs":         page.Entries,
		"capacity":     h.log.BufferCapacity(),
		"hasOlder":     page.HasOlder,
		"oldestId":     oldestID,
		"newestId":     newestID,
		"streamId":     streamID,
		"history":      page.History,
		"page":         page.Page,
		"totalPages":   page.TotalPages,
		"totalEntries": page.TotalEntries,
	}
}

func (h *Handler) list(ctx context.Context, uid string) map[string]any {
	nodes, err := h.store.ListNodes(ctx, uid)
	if err != nil {
		return fail(err.Error())
	}
	states, err := h.store.GetAllKeepaliveStates(ctx)
	if err == nil {
		lastMap := map[string]int64{}
		for _, st := range states {
			lastMap[strings.ToLower(st.Node)] = st.LastPlayTS
		}
		for i := range nodes {
			nodes[i].LastPlayAt = lastMap[uid+":"+strings.ToLower(nodes[i].Name)]
		}
	}
	return map[string]any{"ok": true, "nodes": nodes, "uid": uid, "build": buildinfo.Current()}
}

func (h *Handler) save(ctx context.Context, uid string, body map[string]any) map[string]any {
	raw := mapFromAny(body["node"])
	if raw == nil {
		raw = body
	}
	validated := validators.ValidateNodeInput(raw)
	if validated.Error != "" {
		return fail(validated.Error)
	}
	node := validated.Node
	oldNameRaw := strings.ToLower(strings.TrimSpace(asString(raw["oldName"])))
	oldName := ""
	if validators.NameRE.MatchString(oldNameRaw) {
		oldName = oldNameRaw
	}
	kv := h.store.KV()
	prevName := node.Name
	if oldName != "" {
		prevName = oldName
	}
	prevPacked, prevOK, err := kv.Get(ctx, "u:"+uid+":node:"+prevName)
	if err != nil {
		return fail(err.Error())
	}
	if oldName != "" && !prevOK {
		return fail("原节点不存在（可能已删除或列表过期），请刷新后重试")
	}
	existsNew := false
	if _, ok, err := kv.Get(ctx, "u:"+uid+":node:"+node.Name); err != nil {
		return fail(err.Error())
	} else {
		existsNew = ok
	}
	if oldName == "" && existsNew {
		return fail("请求路径重复:该节点已存在")
	}
	if oldName != "" && oldName != node.Name && existsNew {
		return fail("请求路径重复:该节点已存在")
	}
	if prevOK {
		if prevNode, ok := storage.UnpackNode(prevName, prevPacked); ok {
			if _, hasFav := raw["fav"]; !hasFav {
				node.Fav = prevNode.Fav
			}
			if _, hasRank := raw["rank"]; !hasRank {
				node.Rank = prevNode.Rank
			}
		}
	}
	if err := h.store.SaveNode(ctx, uid, node); err != nil {
		return fail(err.Error())
	}
	h.reset(uid, node.Name)
	if oldName != "" && oldName != node.Name {
		_ = h.store.DeleteNode(ctx, uid, oldName)
		h.reset(uid, oldName)
	}
	return map[string]any{"ok": true, "node": node}
}

func (h *Handler) importNodes(ctx context.Context, uid string, body map[string]any) map[string]any {
	items := arrayMaps(body["nodes"])
	if len(items) == 0 {
		if one := mapFromAny(body["node"]); one != nil {
			items = []map[string]any{one}
		} else {
			items = []map[string]any{body}
		}
	}
	results := []map[string]any{}
	for _, item := range items {
		validated := validators.ValidateNodeInput(item)
		if validated.Error != "" {
			results = append(results, map[string]any{"ok": false, "name": item["name"], "error": validated.Error})
			continue
		}
		if err := h.store.SaveNode(ctx, uid, validated.Node); err != nil {
			results = append(results, map[string]any{"ok": false, "name": validated.Node.Name, "error": err.Error()})
			continue
		}
		h.reset(uid, validated.Node.Name)
		results = append(results, map[string]any{"ok": true, "name": validated.Node.Name})
	}
	return map[string]any{"ok": true, "results": results}
}

func (h *Handler) exportNodes(ctx context.Context, uid string, body map[string]any) map[string]any {
	nodes, err := h.store.ListNodes(ctx, uid)
	if err != nil {
		return fail(err.Error())
	}
	wanted := map[string]bool{}
	for _, name := range arrayStrings(body["names"]) {
		if nm := validators.NormalizeName(name); nm != "" && validators.NameRE.MatchString(nm) {
			wanted[nm] = true
		}
	}
	exported := []map[string]any{}
	for _, node := range nodes {
		if len(wanted) > 0 && !wanted[node.Name] {
			continue
		}
		exported = append(exported, exportNode(node))
	}
	return map[string]any{"ok": true, "nodes": exported, "count": len(exported), "uid": uid, "exportedAt": localtime.RFC3339(time.Now())}
}

func (h *Handler) checkStatus(ctx context.Context, uid string, body map[string]any) map[string]any {
	names := arrayStrings(body["names"])
	if len(names) == 0 {
		if one := validators.NormalizeName(body["name"]); one != "" {
			names = []string{one}
		}
	}
	if len(names) == 0 {
		nodes, err := h.store.ListNodes(ctx, uid)
		if err != nil {
			return fail(err.Error())
		}
		for _, node := range nodes {
			names = append(names, node.Name)
		}
	}
	client := &http.Client{}
	results := []map[string]any{}
	for _, name := range names {
		nm := validators.NormalizeName(name)
		node, err := h.store.GetNode(ctx, uid, nm)
		if err != nil {
			results = append(results, map[string]any{"name": nm, "target": nm, "status": 0, "error": err.Error()})
			continue
		}
		if node == nil {
			results = append(results, map[string]any{"name": nm, "target": nm, "status": 0, "error": "节点不存在"})
			continue
		}
		proxyPath := "/" + urlPathEscape(nm)
		if node.Secret != "" {
			proxyPath += "/" + urlPathEscape(node.Secret)
		}
		checked := fmt.Sprintf("http://127.0.0.1:%d%s/emby/System/Info/Public", h.cfg.Port, proxyPath)
		started := time.Now()
		checkCtx, cancel := context.WithTimeout(ctx, statusCheckTimeout(len(storage.SplitTargets(node.Target))))
		req, _ := http.NewRequestWithContext(checkCtx, http.MethodGet, checked, nil)
		req.Header.Set("User-Agent", statusCheckUserAgent(*node))
		res, err := client.Do(req)
		ms := time.Since(started).Milliseconds()
		if err != nil {
			cancel()
			results = append(results, map[string]any{"name": nm, "target": checked, "checked": checked, "status": 0, "error": errorText(err), "ms": ms})
			continue
		}
		_ = res.Body.Close()
		cancel()
		results = append(results, map[string]any{"name": nm, "target": checked, "checked": checked, "status": res.StatusCode, "ms": ms})
	}
	return map[string]any{"ok": true, "results": results}
}

func statusCheckTimeout(targetCount int) time.Duration {
	if targetCount < 1 {
		targetCount = 1
	}
	return time.Duration(targetCount) * proxy.UpstreamTargetAttemptTimeout
}

func statusCheckUserAgent(node storage.Node) string {
	if node.Impersonate {
		return identity.GetProfile(node.ImpersonateProfile).UserAgent
	}
	return "emby-check/1.0"
}

func (h *Handler) tgSet(ctx context.Context, body map[string]any) map[string]any {
	cfgMap := mapFromAny(body["config"])
	if cfgMap == nil {
		cfgMap = mapFromAny(body["content"])
	}
	if cfgMap == nil {
		cfgMap = map[string]any{}
	}
	reportTime := strings.TrimSpace(asString(cfgMap["reportTime"]))
	reportTime = strings.NewReplacer("﹕", ":", "∶", ":").Replace(reportTime)
	if reportTime != "" {
		m := regexp.MustCompile(`^(\d{1,2}):(\d{1,2})(?::(\d{1,2})(?:\.\d+)?)?$`).FindStringSubmatch(reportTime)
		if len(m) == 0 {
			return fail("日报推送时间格式不合法（HH:mm）")
		}
		hh := clamp(intString(m[1]), 0, 23)
		mm := clamp(intString(m[2]), 0, 59)
		reportTime = fmt.Sprintf("%02d:%02d", hh, mm)
	}
	if reportTime == "" {
		reportTime = "00:00"
	}
	serverRemark := strings.TrimSpace(asString(cfgMap["serverRemark"]))
	if strings.ContainsAny(serverRemark, "\r\n") {
		return fail("服务器备注不能包含换行")
	}
	if len([]rune(serverRemark)) > telegramServerRemarkMaxRunes {
		return fail(fmt.Sprintf("服务器备注不能超过 %d 个字符", telegramServerRemarkMaxRunes))
	}
	cfg := storage.TGConfig{
		Enabled:       validators.ToBool(cfgMap["enabled"]),
		Token:         strings.TrimSpace(asString(cfgMap["token"])),
		Chat:          strings.TrimSpace(asString(cfgMap["chat"])),
		ServerRemark:  serverRemark,
		ReportEnabled: boolValue(cfgMap, "reportEnabled", validators.ToBool(cfgMap["enabled"])),
		ReportTime:    reportTime,
	}
	if err := h.store.SaveTGConfig(ctx, cfg); err != nil {
		return fail(err.Error())
	}
	return ok()
}

func (h *Handler) configSet(ctx context.Context, body map[string]any) map[string]any {
	cfgMap := mapFromAny(body["config"])
	if cfgMap == nil {
		cfgMap = mapFromAny(body["content"])
	}
	if cfgMap == nil {
		cfgMap = map[string]any{}
	}
	defaults := h.defaultSystemConfig()
	current, err := h.store.GetSystemConfig(ctx, defaults)
	if err != nil {
		return fail(err.Error())
	}
	logLevelInput := current.LogLevel
	if _, ok := cfgMap["logLevel"]; ok {
		logLevelInput = asString(cfgMap["logLevel"])
	}
	logLevel, errText := normalizeLogLevel(logLevelInput, defaults.LogLevel)
	if errText != "" {
		return fail(errText)
	}
	hostsInput := current.ExternalAllowHosts
	if _, ok := cfgMap["externalAllowHosts"]; ok {
		hostsInput = asString(cfgMap["externalAllowHosts"])
	}
	hosts, errText := normalizeExternalAllowHosts(hostsInput)
	if errText != "" {
		return fail(errText)
	}
	corsAllowOriginInput := current.CORSAllowOrigin
	if _, ok := cfgMap["corsAllowOrigin"]; ok {
		corsAllowOriginInput = asString(cfgMap["corsAllowOrigin"])
	}
	corsAllowOrigin, errText := normalizeCORSAllowOrigin(corsAllowOriginInput)
	if errText != "" {
		return fail(errText)
	}
	trafficCaptureFileInput := current.TrafficCaptureFile
	if _, ok := cfgMap["trafficCaptureFile"]; ok {
		trafficCaptureFileInput = asString(cfgMap["trafficCaptureFile"])
	}
	trafficCaptureFile, errText := normalizeTrafficCaptureFile(trafficCaptureFileInput, defaults.TrafficCaptureFile)
	if errText != "" {
		return fail(errText)
	}
	emosMatchHostsInput := current.EmosMatchHosts
	if _, ok := cfgMap["emosMatchHosts"]; ok {
		emosMatchHostsInput = asString(cfgMap["emosMatchHosts"])
	}
	emosMatchHosts, errText := normalizeEmosMatchHosts(emosMatchHostsInput)
	if errText != "" {
		return fail(errText)
	}
	emosProxyIDInput := current.EmosProxyID
	if _, ok := cfgMap["emosProxyId"]; ok {
		emosProxyIDInput = asString(cfgMap["emosProxyId"])
	}
	emosProxyID, errText := normalizeShortText(emosProxyIDInput, "EMOS Proxy ID", 128)
	if errText != "" {
		return fail(errText)
	}
	emosProxyNameInput := current.EmosProxyName
	if _, ok := cfgMap["emosProxyName"]; ok {
		emosProxyNameInput = asString(cfgMap["emosProxyName"])
	}
	emosProxyName, errText := normalizeShortText(emosProxyNameInput, "EMOS Proxy Name", 128)
	if errText != "" {
		return fail(errText)
	}
	logAccess := current.LogAccess
	if _, ok := cfgMap["logAccess"]; ok {
		logAccess = validators.ToBool(cfgMap["logAccess"])
	}
	imageProxyLimitEnabled := current.ImageProxyLimitEnabled
	if _, ok := cfgMap["imageProxyLimitEnabled"]; ok {
		imageProxyLimitEnabled = validators.ToBool(cfgMap["imageProxyLimitEnabled"])
	}
	imageCacheEnabled := current.ImageCacheEnabled
	if _, ok := cfgMap["imageCacheEnabled"]; ok {
		imageCacheEnabled = validators.ToBool(cfgMap["imageCacheEnabled"])
	}
	cfg := storage.SystemConfig{
		LogLevel:                    logLevel,
		LogAccess:                   logAccess,
		CapyStripEmby:               normalizeBinaryFlag(cfgMap["capyStripEmby"], current.CapyStripEmby),
		EmosCompat:                  boolValue(cfgMap, "emosCompat", current.EmosCompat),
		EmosMatchHosts:              emosMatchHosts,
		EmosProxyID:                 emosProxyID,
		EmosProxyName:               emosProxyName,
		CORSAllowOrigin:             corsAllowOrigin,
		ExternalAllowHosts:          hosts,
		ExternalAllowAny:            boolValue(cfgMap, "externalAllowAny", current.ExternalAllowAny),
		TrustProxy:                  boolValue(cfgMap, "trustProxy", current.TrustProxy),
		ImageProxyLimitEnabled:      imageProxyLimitEnabled,
		ImageProxyMaxConcurrent:     clamp(intValue(cfgMap["imageProxyMaxConcurrent"], current.ImageProxyMaxConcurrent), 1, 32),
		ImageProxyRequestIntervalMS: clamp(intValue(cfgMap["imageProxyRequestIntervalMs"], current.ImageProxyRequestIntervalMS), 0, 5000),
		ImageCacheEnabled:           imageCacheEnabled,
		ImageCacheTTLDays:           clamp(intValue(cfgMap["imageCacheTtlDays"], current.ImageCacheTTLDays), 1, 365),
		TrafficCaptureEnabled:       boolValue(cfgMap, "trafficCaptureEnabled", current.TrafficCaptureEnabled),
		TrafficCaptureFile:          trafficCaptureFile,
		TrafficCaptureBodyMax:       current.TrafficCaptureBodyMax,
		TrafficCaptureTextTypes:     current.TrafficCaptureTextTypes,
	}
	if err := h.store.SaveSystemConfig(ctx, cfg); err != nil {
		return fail(err.Error())
	}
	h.log.Configure(cfg.LogLevel, cfg.LogAccess)
	return ok()
}

func (h *Handler) defaultSystemConfig() storage.SystemConfig {
	return storage.DefaultSystemConfig()
}

func (h *Handler) keepaliveTest(ctx context.Context, body map[string]any) (map[string]any, int) {
	cfg, err := h.store.GetTGConfig(ctx)
	if err != nil {
		return fail(err.Error()), http.StatusInternalServerError
	}
	if !cfg.Enabled || cfg.Token == "" || cfg.Chat == "" {
		return fail("请先在TG设置中启用并配置 Token/Chat ID"), http.StatusBadRequest
	}
	name := asString(body["displayName"])
	if strings.TrimSpace(name) == "" {
		name = asString(body["name"])
	}
	if strings.TrimSpace(name) == "" {
		name = "未命名节点"
	}
	renewDays := maxInt(0, intValue(body["renewDays"], 0))
	remindBeforeDays := maxInt(0, intValue(body["remindBeforeDays"], 0))
	keepaliveAt := strings.TrimSpace(asString(body["keepaliveAt"]))
	if !regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)$`).MatchString(keepaliveAt) {
		keepaliveAt = "00:00"
	}
	text := strings.Join([]string{
		"保号测试通知",
		"节点:" + name,
		fmt.Sprintf("保号周期:%d天", renewDays),
		fmt.Sprintf("提前提醒:%d天", remindBeforeDays),
		"提醒时间:北京时间 " + keepaliveAt,
	}, "\n")
	return map[string]any{"ok": h.telegram.Send(ctx, cfg, text)}, http.StatusOK
}

func (h *Handler) reset(uid, name string) {
	if h.resetRoute != nil {
		h.resetRoute(uid, validators.NormalizeName(name))
	}
}

func exportNode(node storage.Node) map[string]any {
	out := map[string]any{
		"name":                node.Name,
		"target":              node.Target,
		"fav":                 node.Fav,
		"secret":              node.Secret,
		"tag":                 node.Tag,
		"note":                node.Note,
		"displayName":         node.DisplayName,
		"directExternal":      node.DirectExternal,
		"renewDays":           node.RenewDays,
		"remindBeforeDays":    node.RemindBeforeDays,
		"keepaliveAt":         node.KeepaliveAt,
		"keepaliveMaxPerDay":  node.KeepaliveMaxPerDay,
		"keepaliveChangeOnly": node.KeepaliveChangeOnly,
		"impersonate":         node.Impersonate,
		"impersonateProfile":  node.ImpersonateProfile,
	}
	if node.Rank != nil {
		out["rank"] = *node.Rank
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func ok() map[string]any             { return map[string]any{"ok": true} }
func fail(msg string) map[string]any { return map[string]any{"ok": false, "error": msg} }

func normalizeCORSAllowOrigin(value string) (string, string) {
	items := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	})
	if len(items) > 50 {
		return "", "CORS 允许来源数量过多（最多50个）"
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		origin := strings.TrimSpace(item)
		if origin == "" {
			continue
		}
		if len(origin) > 255 {
			return "", "CORS 允许来源包含过长来源"
		}
		if strings.ContainsAny(origin, "\r\n\t") {
			return "", "CORS 允许来源包含非法空白字符"
		}
		if origin == "*" {
			return "*", ""
		}
		if !seen[origin] {
			seen[origin] = true
			out = append(out, origin)
		}
	}
	return strings.Join(out, ","), ""
}

func normalizeExternalAllowHosts(value string) (string, string) {
	items := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	if len(items) > 200 {
		return "", "外部连接白名单数量过多（最多200个）"
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		host := strings.TrimSpace(item)
		if host == "" {
			continue
		}
		if strings.Contains(host, "://") {
			u, err := url.Parse(host)
			if err != nil || u.Host == "" {
				return "", "外部连接白名单包含无效 URL: " + host
			}
			host = u.Host
		}
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			continue
		}
		if len(host) > 255 {
			return "", "外部连接白名单包含过长 host"
		}
		if strings.ContainsAny(host, "/?#") || strings.Contains(host, "@") {
			return "", "外部连接白名单只能填写域名或 host:port"
		}
		if strings.Contains(host, "*") {
			return "", "外部连接白名单不支持通配符"
		}
		u, err := url.Parse("//" + host)
		if err != nil || u.Host == "" {
			return "", "外部连接白名单包含无效 host: " + host
		}
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return strings.Join(out, ","), ""
}

func normalizeLogLevel(value, fallback string) (string, string) {
	level := strings.ToLower(strings.TrimSpace(value))
	if level == "" {
		level = strings.ToLower(strings.TrimSpace(fallback))
	}
	switch level {
	case "silent", "error", "warn", "info", "debug":
		return level, ""
	default:
		return "", "日志等级只能是 silent/error/warn/info/debug"
	}
}

func normalizeBinaryFlag(value any, fallback string) string {
	if value == nil || strings.TrimSpace(asString(value)) == "" {
		if validators.ToBool(fallback) {
			return "1"
		}
		return "0"
	}
	if validators.ToBool(value) {
		return "1"
	}
	return "0"
}

func normalizeEmosMatchHosts(value string) (string, string) {
	items := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	if len(items) > 200 {
		return "", "EMOS 匹配域名数量过多（最多200个）"
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		host := strings.TrimSpace(item)
		if host == "" {
			continue
		}
		if strings.Contains(host, "://") {
			u, err := url.Parse(host)
			if err != nil || u.Host == "" {
				return "", "EMOS 匹配域名包含无效 URL: " + host
			}
			host = u.Host
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if len(host) > 255 {
			return "", "EMOS 匹配域名包含过长 host"
		}
		if strings.ContainsAny(host, "/?#") || strings.Contains(host, "@") {
			return "", "EMOS 匹配域名只能填写域名或 host:port"
		}
		u, err := url.Parse("//" + host)
		if err != nil || u.Host == "" {
			return "", "EMOS 匹配域名包含无效 host: " + host
		}
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return strings.Join(out, ","), ""
}

func normalizeShortText(value, label string, maxLen int) (string, string) {
	text := strings.TrimSpace(value)
	if len(text) > maxLen {
		return "", label + " 过长"
	}
	if strings.ContainsAny(text, "\x00\r\n\t") {
		return "", label + " 包含非法空白字符"
	}
	return text, ""
}

func normalizeTrafficCaptureFile(value, fallback string) (string, string) {
	file := strings.TrimSpace(value)
	if file == "" {
		file = fallback
	}
	if len(file) > 512 {
		return "", "代理流量记录文件路径过长"
	}
	if strings.ContainsAny(file, "\x00\r\n") {
		return "", "代理流量记录文件路径包含非法字符"
	}
	cleaned, ok := cleanTrafficCaptureFile(file)
	if !ok {
		return "", "代理流量记录文件路径必须位于 data 目录内"
	}
	return cleaned, ""
}

func cleanTrafficCaptureFile(file string) (string, bool) {
	normalized := strings.NewReplacer("\\", string(filepath.Separator), "/", string(filepath.Separator)).Replace(strings.TrimSpace(file))
	cleaned := filepath.Clean(normalized)
	if cleaned == "" || cleaned == "." || cleaned == "data" {
		return "", false
	}
	if filepath.IsAbs(cleaned) || filepath.VolumeName(cleaned) != "" {
		return "", false
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", false
	}
	dataPrefix := "data" + string(filepath.Separator)
	if !strings.HasPrefix(cleaned, dataPrefix) {
		return "", false
	}
	return filepath.ToSlash(cleaned), true
}

func mapFromAny(value any) map[string]any {
	m, ok := value.(map[string]any)
	if ok {
		return m
	}
	return nil
}

func arrayMaps(value any) []map[string]any {
	arr, ok := value.([]any)
	if !ok {
		return nil
	}
	out := []map[string]any{}
	for _, item := range arr {
		if m := mapFromAny(item); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func arrayStrings(value any) []string {
	arr, ok := value.([]any)
	if !ok {
		if s := strings.TrimSpace(asString(value)); s != "" {
			return []string{s}
		}
		return nil
	}
	out := []string{}
	for _, item := range arr {
		if s := strings.TrimSpace(asString(item)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func intValue(value any, fallback int) int {
	if value == nil || strings.TrimSpace(asString(value)) == "" {
		return fallback
	}
	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return n
		}
	}
	return fallback
}

func uint64Value(value any) uint64 {
	if value == nil || strings.TrimSpace(asString(value)) == "" {
		return 0
	}
	switch v := value.(type) {
	case uint64:
		return v
	case int:
		if v > 0 {
			return uint64(v)
		}
	case int64:
		if v > 0 {
			return uint64(v)
		}
	case float64:
		if v > 0 {
			return uint64(v)
		}
	case string:
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err == nil {
			return n
		}
	}
	return 0
}

func boolValue(values map[string]any, key string, fallback bool) bool {
	if _, ok := values[key]; !ok {
		return fallback
	}
	return validators.ToBool(values[key])
}

func intString(value string) int {
	n, _ := strconv.Atoi(value)
	return n
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func asString(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func urlPathEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "Client.Timeout") || strings.Contains(strings.ToLower(err.Error()), "deadline") {
		return "timeout"
	}
	return err.Error()
}
