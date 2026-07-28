package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"embyproxy/internal/auth"
	"embyproxy/internal/buildinfo"
	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/proxy"
	"embyproxy/internal/requestlog"
	"embyproxy/internal/storage"
)

func TestServeAdminValidatesTokenConfig(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		wantStatus int
		wantBody   []string
	}{
		{name: "missing admin token", wantStatus: http.StatusInternalServerError, wantBody: []string{auth.AdminTokenNotConfigured}},
		{name: "configured admin token", token: "strong-random-admin-token", wantStatus: http.StatusOK, wantBody: []string{`id="loginWrap"`, `id="appVersion"`}},
		{name: "default admin token", token: "change-me-please", wantStatus: http.StatusInternalServerError, wantBody: []string{auth.AdminTokenDefault}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{AdminToken: tt.token}
			handler := New(cfg, nil, auth.NewChecker(cfg, nil), nil, nil, nil)
			req := httptest.NewRequest(http.MethodGet, "/admin", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			for _, want := range tt.wantBody {
				if !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("body = %q, want to contain %q", rec.Body.String(), want)
				}
			}
		})
	}
}

func TestAdminIndexIncludesTelegramRemark(t *testing.T) {
	if !strings.Contains(indexHTML, `id="tg-serverRemark" maxlength="80"`) {
		t.Fatal("indexHTML missing Telegram server remark input")
	}
}

func TestStatusCheckTimeoutAllowsEveryTargetAttempt(t *testing.T) {
	want := 3 * proxy.UpstreamTargetAttemptTimeout
	if got := statusCheckTimeout(3); got != want {
		t.Fatalf("statusCheckTimeout(3) = %v, want %v", got, want)
	}
	if got := statusCheckTimeout(0); got != proxy.UpstreamTargetAttemptTimeout {
		t.Fatalf("statusCheckTimeout(0) = %v, want one target budget", got)
	}
	if strings.Contains(indexHTML, "msValue > 9999") {
		t.Fatal("indexHTML still reports slow successful checks as timeouts")
	}
}

func TestStatusCheckUserAgentRespectsImpersonation(t *testing.T) {
	tests := []struct {
		name string
		node storage.Node
		want string
	}{
		{
			name: "impersonated profile",
			node: storage.Node{Impersonate: true, ImpersonateProfile: "hills_windows"},
			want: identity.GetProfile("hills_windows").UserAgent,
		},
		{
			name: "passthrough check",
			node: storage.Node{Impersonate: false, ImpersonateProfile: "hills_windows"},
			want: "emby-check/1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statusCheckUserAgent(tt.node); got != tt.want {
				t.Fatalf("statusCheckUserAgent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestListIncludesBuildInfo(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	oldVersion, oldCommit, oldBuiltAt := buildinfo.Version, buildinfo.Commit, buildinfo.BuiltAt
	buildinfo.Version, buildinfo.Commit, buildinfo.BuiltAt = "v-test", "abc1234", "2026-05-31T00:00:00Z"
	defer func() {
		buildinfo.Version, buildinfo.Commit, buildinfo.BuiltAt = oldVersion, oldCommit, oldBuiltAt
	}()

	res := handler.list(ctx, "admin")
	got, ok := res["build"].(buildinfo.Info)
	if !ok {
		t.Fatalf("build info type = %T, want buildinfo.Info", res["build"])
	}
	if got.Version != "v-test" || got.Commit != "abc1234" || got.BuiltAt != "2026-05-31T00:00:00Z" {
		t.Fatalf("build info = %+v", got)
	}
}

func TestAdminIndexIncludesSortableStats(t *testing.T) {
	wants := []string{
		`data-stats-sort="day"`,
		`data-stats-sort="lastActivityAt" aria-sort="descending"`,
		`data-stats-sort="node"`,
		`data-stats-sort="client"`,
		`data-stats-sort="plays"`,
		`data-stats-sort="sessions"`,
		`data-stats-sort="inboundBytes"`,
		`data-stats-sort="outboundBytes"`,
		`let statsSortKey = 'lastActivityAt';`,
	}
	for _, want := range wants {
		if !strings.Contains(indexHTML, want) {
			t.Fatalf("indexHTML missing %q", want)
		}
	}
}

func TestDispatchLogsListReturnsBufferedLogs(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	handler.log.Configure("info", false)
	handler.log.Info("admin", "config saved", map[string]any{"status": "ok"})
	res, status := handler.dispatch(ctx, "admin", "logs.list", map[string]any{"limit": 10})

	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch logs.list status=%d res=%+v", status, res)
	}
	logs, ok := res["logs"].([]logging.LogEntry)
	if !ok {
		t.Fatalf("logs type = %T, want []logging.LogEntry", res["logs"])
	}
	if len(logs) != 1 {
		t.Fatalf("logs len = %d, want 1", len(logs))
	}
	if logs[0].Level != "info" || logs[0].Scope != "admin" || !strings.Contains(logs[0].Line, "config saved") {
		t.Fatalf("log entry = %+v", logs[0])
	}
}

func TestDispatchLogsListSupportsPageNumber(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	for i := 1; i <= 5; i++ {
		handler.log.Info("admin", fmt.Sprintf("line-%d", i), nil)
	}
	res, status := handler.dispatch(ctx, "admin", "logs.list", map[string]any{"limit": 2, "page": 2})

	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch logs.list status=%d res=%+v", status, res)
	}
	logs, ok := res["logs"].([]logging.LogEntry)
	if !ok {
		t.Fatalf("logs type = %T, want []logging.LogEntry", res["logs"])
	}
	if len(logs) != 2 || !strings.Contains(logs[0].Line, "line-2") || !strings.Contains(logs[1].Line, "line-3") {
		t.Fatalf("logs page = %+v", logs)
	}
	if res["page"] != 2 || res["totalPages"] != 3 || res["totalEntries"] != 5 || res["hasOlder"] != true {
		t.Fatalf("pagination metadata = %+v", res)
	}
	if res["streamId"] != uint64(5) {
		t.Fatalf("streamId = %v, want 5", res["streamId"])
	}
}

func TestStreamLogsSendsInitialComment(t *testing.T) {
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.streamLogs(rec, req, auth.Result{OK: true})

	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}
	if got := rec.Body.String(); !strings.Contains(got, ": connected\n\n") {
		t.Fatalf("stream body = %q, want initial connected comment", got)
	}
	if !rec.Flushed {
		t.Fatal("stream response was not flushed")
	}
}

func TestDispatchLogsListFilters(t *testing.T) {
	tests := []struct {
		name             string
		body             map[string]any
		wantMetadata     bool
		wantNewestID     uint64
		wantStreamID     uint64
		wantTotalEntries int
	}{
		{
			name: "level and query",
			body: map[string]any{
				"limit": 10,
				"page":  1,
				"level": "error",
				"query": "req-target",
			},
			wantMetadata:     true,
			wantNewestID:     2,
			wantStreamID:     3,
			wantTotalEntries: 1,
		},
		{
			name: "before cursor",
			body: map[string]any{
				"limit":  10,
				"before": 3,
				"level":  "error",
				"query":  "req-target",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			handler, closeStore := newConfigTestHandler(t)
			defer closeStore()

			handler.log.Info("admin", "node checked", map[string]any{"id": "req-info", "uri": "/System/Info"})
			handler.log.Error("proxy", "upstream failed", map[string]any{"id": "req-target", "uri": "/Videos/1"})
			handler.log.Error("proxy", "other failed", map[string]any{"id": "req-other", "uri": "/Videos/2"})
			res, status := handler.dispatch(ctx, "admin", "logs.list", tt.body)

			if status != http.StatusOK || res["ok"] != true {
				t.Fatalf("dispatch logs.list status=%d res=%+v", status, res)
			}
			logs, ok := res["logs"].([]logging.LogEntry)
			if !ok {
				t.Fatalf("logs type = %T, want []logging.LogEntry", res["logs"])
			}
			if len(logs) != 1 || logs[0].ID != 2 || logs[0].Level != "error" || !strings.Contains(logs[0].Line, "req-target") {
				t.Fatalf("filtered logs = %+v", logs)
			}
			if !tt.wantMetadata {
				return
			}
			if res["totalEntries"] != tt.wantTotalEntries || res["totalPages"] != 1 || res["hasOlder"] != false {
				t.Fatalf("filtered metadata = %+v", res)
			}
			if res["newestId"] != tt.wantNewestID || res["streamId"] != tt.wantStreamID {
				t.Fatalf("filtered newest metadata = %+v", res)
			}
		})
	}
}

func TestDispatchLogsClearRemovesBufferedLogs(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	handler.log.Configure("info", false)
	handler.log.Info("admin", "before clear", nil)
	res, status := handler.dispatch(ctx, "admin", "logs.clear", map[string]any{})

	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch logs.clear status=%d res=%+v", status, res)
	}
	logs, ok := res["logs"].([]logging.LogEntry)
	if !ok {
		t.Fatalf("logs type = %T, want []logging.LogEntry", res["logs"])
	}
	if len(logs) != 0 {
		t.Fatalf("logs len after clear = %d, want 0", len(logs))
	}

	handler.log.Info("admin", "after clear", nil)
	res, status = handler.dispatch(ctx, "admin", "logs.list", map[string]any{"limit": 10})
	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch logs.list status=%d res=%+v", status, res)
	}
	logs = res["logs"].([]logging.LogEntry)
	if len(logs) != 1 || !strings.Contains(logs[0].Line, "after clear") {
		t.Fatalf("logs after new write = %+v", logs)
	}
}

func TestDispatchImageCacheActions(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()
	cache := &fakeImageCacheManager{
		stats: proxy.ImageCacheStats{Enabled: true, Dir: "data/image-cache", Bytes: 2048, Files: 3, Entries: 1},
	}
	handler.imageCache = cache

	res, status := handler.dispatch(ctx, "admin", "imageCache.stats", map[string]any{})
	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch imageCache.stats status=%d res=%+v", status, res)
	}
	stats, ok := res["cache"].(proxy.ImageCacheStats)
	if !ok {
		t.Fatalf("cache stats type = %T, want proxy.ImageCacheStats", res["cache"])
	}
	if stats.Bytes != 2048 || stats.Files != 3 || stats.Entries != 1 {
		t.Fatalf("cache stats = %+v", stats)
	}

	cache.clearStats = proxy.ImageCacheStats{Enabled: true, Dir: "data/image-cache"}
	res, status = handler.dispatch(ctx, "admin", "imageCache.clear", map[string]any{})
	if status != http.StatusOK || res["ok"] != true || !cache.clearCalled {
		t.Fatalf("dispatch imageCache.clear status=%d called=%v res=%+v", status, cache.clearCalled, res)
	}
}

func TestDispatchTrafficCaptureStats(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()
	cwd := t.TempDir()
	handler.cfg.CWD = cwd
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures.jsonl"
	if err := handler.store.SaveSystemConfig(ctx, sys); err != nil {
		t.Fatalf("SaveSystemConfig() error = %v", err)
	}
	path := filepath.Join(cwd, "data", "traffic-captures.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	mediaLine := `{"id":1,"stage":"media-proxy"}`
	imageLine := `{"id":2,"stage":"image-cache-hit"}`
	content := []byte(mediaLine + "\n\n" + imageLine + "\n" + mediaLine)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	res, status := handler.dispatch(ctx, "admin", "trafficCapture.stats", map[string]any{})
	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch trafficCapture.stats status=%d res=%+v", status, res)
	}
	stats, ok := res["capture"].(trafficCaptureStats)
	if !ok {
		t.Fatalf("capture stats type = %T, want trafficCaptureStats", res["capture"])
	}
	if !stats.Enabled || stats.File != "data/traffic-captures.jsonl" || stats.Bytes != int64(len(content)) || stats.Records != 3 {
		t.Fatalf("traffic capture stats = %+v", stats)
	}
	if got := findTrafficCaptureStageStats(t, stats, "media-proxy"); got.Records != 2 || got.Bytes != int64(len(mediaLine+"\n")+len(mediaLine)) {
		t.Fatalf("media-proxy stage stats = %+v", got)
	}
	if got := findTrafficCaptureStageStats(t, stats, "image-cache-hit"); got.Records != 1 || got.Bytes != int64(len(imageLine+"\n")) {
		t.Fatalf("image-cache-hit stage stats = %+v", got)
	}
}

func TestHandleAPISuppressesLogReadActionsAccessLogAndTrafficCapture(t *testing.T) {
	for _, action := range []string{"logs.list", "logs.clear"} {
		t.Run(action, func(t *testing.T) {
			cwd := t.TempDir()
			store, err := storage.New(filepath.Join(cwd, "proxy.db"))
			if err != nil {
				t.Fatalf("storage.New() error = %v", err)
			}
			defer store.Close()
			sys := storage.DefaultSystemConfig()
			sys.TrafficCaptureEnabled = true
			sys.TrafficCaptureFile = "data/traffic-captures.jsonl"
			if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
				t.Fatalf("SaveSystemConfig() error = %v", err)
			}
			handler := New(config.Config{}, nil, nil, nil, logging.New("info", false), nil)
			recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
			ctx := requestlog.WithAccessLogState(context.Background())
			req := httptest.NewRequest(http.MethodPost, "/admin/api", strings.NewReader(fmt.Sprintf(`{"action":"%s"}`, action))).WithContext(ctx)
			rec := httptest.NewRecorder()
			captureSuppressed := false

			recorder.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.handleAPI(w, r, "admin")
				captureSuppressed = capture.Suppressed(r)
			})).ServeHTTP(rec, req)

			if !requestlog.AccessLogSuppressed(ctx) {
				t.Fatalf("%s should suppress its access log entry", action)
			}
			if !captureSuppressed {
				t.Fatalf("%s should suppress its traffic capture record", action)
			}
			if _, err := os.Stat(filepath.Join(cwd, "data", "traffic-captures.jsonl")); !os.IsNotExist(err) {
				t.Fatalf("traffic capture file should not be written, stat err = %v", err)
			}
		})
	}
}

func TestDispatchTrafficCaptureClear(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()
	cwd := t.TempDir()
	handler.cfg.CWD = cwd
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures.jsonl"
	if err := handler.store.SaveSystemConfig(ctx, sys); err != nil {
		t.Fatalf("SaveSystemConfig() error = %v", err)
	}
	path := filepath.Join(cwd, "data", "traffic-captures.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("{\"id\":1}\n{\"id\":2}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	res, status := handler.dispatch(ctx, "admin", "trafficCapture.clear", map[string]any{})
	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch trafficCapture.clear status=%d res=%+v", status, res)
	}
	stats, ok := res["capture"].(trafficCaptureStats)
	if !ok {
		t.Fatalf("capture stats type = %T, want trafficCaptureStats", res["capture"])
	}
	if !stats.Enabled || stats.File != "data/traffic-captures.jsonl" || stats.Bytes != 0 || stats.Records != 0 || len(stats.Stages) != 0 {
		t.Fatalf("traffic capture stats after clear = %+v", stats)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("traffic capture file size after clear = %d, want 0", info.Size())
	}
}

func TestDispatchTrafficCaptureClearStage(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()
	cwd := t.TempDir()
	handler.cfg.CWD = cwd
	sys := storage.DefaultSystemConfig()
	sys.TrafficCaptureEnabled = true
	sys.TrafficCaptureFile = "data/traffic-captures.jsonl"
	if err := handler.store.SaveSystemConfig(ctx, sys); err != nil {
		t.Fatalf("SaveSystemConfig() error = %v", err)
	}
	path := filepath.Join(cwd, "data", "traffic-captures.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	mediaLine := `{"id":1,"stage":"media-proxy"}`
	imageLine := `{"id":2,"stage":"image-cache-hit"}`
	content := []byte(mediaLine + "\n" + imageLine + "\n" + mediaLine + "\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	res, status := handler.dispatch(ctx, "admin", "trafficCapture.clearStage", map[string]any{"stage": "media-proxy"})
	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch trafficCapture.clearStage status=%d res=%+v", status, res)
	}
	stats, ok := res["capture"].(trafficCaptureStats)
	if !ok {
		t.Fatalf("capture stats type = %T, want trafficCaptureStats", res["capture"])
	}
	if stats.Bytes != int64(len(imageLine+"\n")) || stats.Records != 1 || len(stats.Stages) != 1 {
		t.Fatalf("traffic capture stats after stage clear = %+v", stats)
	}
	if got := findTrafficCaptureStageStats(t, stats, "image-cache-hit"); got.Records != 1 || got.Bytes != int64(len(imageLine+"\n")) {
		t.Fatalf("remaining stage stats = %+v", got)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != imageLine+"\n" {
		t.Fatalf("traffic capture file after stage clear = %q", got)
	}
}

func TestHandleAPISuppressesTrafficCaptureAdminActionRecords(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "stats", body: `{"action":"trafficCapture.stats"}`},
		{name: "clear", body: `{"action":"trafficCapture.clear"}`},
		{name: "clear stage", body: `{"action":"trafficCapture.clearStage","stage":"media-proxy"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cwd := t.TempDir()
			store, err := storage.New(filepath.Join(cwd, "proxy.db"))
			if err != nil {
				t.Fatalf("storage.New() error = %v", err)
			}
			defer store.Close()
			sys := storage.DefaultSystemConfig()
			sys.TrafficCaptureEnabled = true
			sys.TrafficCaptureFile = "data/traffic-captures.jsonl"
			if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
				t.Fatalf("SaveSystemConfig() error = %v", err)
			}
			handler := New(config.Config{CWD: cwd}, store, nil, nil, logging.New("info", false), nil)
			recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
			req := httptest.NewRequest(http.MethodPost, "/admin/api", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			captureSuppressed := false

			recorder.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.handleAPI(w, r, "admin")
				captureSuppressed = capture.Suppressed(r)
			})).ServeHTTP(rec, req)

			if !captureSuppressed {
				t.Fatalf("%s should suppress its traffic capture record", tt.name)
			}
			if _, err := os.Stat(filepath.Join(cwd, "data", "traffic-captures.jsonl")); !os.IsNotExist(err) {
				t.Fatalf("traffic capture file should not be written, stat err = %v", err)
			}
		})
	}
}

func findTrafficCaptureStageStats(t *testing.T, stats trafficCaptureStats, stage string) trafficCaptureStageStats {
	t.Helper()
	for _, item := range stats.Stages {
		if item.Stage == stage {
			return item
		}
	}
	t.Fatalf("stage %q not found in %+v", stage, stats.Stages)
	return trafficCaptureStageStats{}
}

func TestNormalizeTrafficCaptureFileRequiresDataDirectory(t *testing.T) {
	got, errText := normalizeTrafficCaptureFile("./data/traffic-captures.jsonl", "")
	if errText != "" {
		t.Fatalf("normalizeTrafficCaptureFile() error = %q", errText)
	}
	if got != "data/traffic-captures.jsonl" {
		t.Fatalf("normalized path = %q, want data/traffic-captures.jsonl", got)
	}

	invalid := []string{
		"../traffic-captures.jsonl",
		"data/../traffic-captures.jsonl",
		filepath.Join(t.TempDir(), "traffic-captures.jsonl"),
		"traffic-captures.jsonl",
	}
	for _, value := range invalid {
		t.Run(value, func(t *testing.T) {
			if got, errText := normalizeTrafficCaptureFile(value, ""); errText == "" {
				t.Fatalf("normalizeTrafficCaptureFile(%q) = %q, want error", value, got)
			}
		})
	}
}

func TestConfigSetImageSettings(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T, context.Context, *Handler)
		payload map[string]any
		want    storage.SystemConfig
	}{
		{
			name: "saves explicit settings",
			payload: map[string]any{
				"imageProxyLimitEnabled":      true,
				"imageProxyMaxConcurrent":     8,
				"imageProxyRequestIntervalMs": 100,
				"imageCacheEnabled":           true,
				"imageCacheTtlDays":           30,
			},
			want: storage.SystemConfig{
				ImageProxyLimitEnabled:      true,
				ImageProxyMaxConcurrent:     8,
				ImageProxyRequestIntervalMS: 100,
				ImageCacheEnabled:           true,
				ImageCacheTTLDays:           30,
			},
		},
		{
			name: "preserves omitted image settings",
			setup: func(t *testing.T, ctx context.Context, handler *Handler) {
				t.Helper()
				saved := storage.DefaultSystemConfig()
				saved.ImageProxyLimitEnabled = true
				saved.ImageProxyMaxConcurrent = 8
				saved.ImageProxyRequestIntervalMS = 100
				saved.ImageCacheEnabled = true
				saved.ImageCacheTTLDays = 30
				if err := handler.store.SaveSystemConfig(ctx, saved); err != nil {
					t.Fatalf("SaveSystemConfig() error = %v", err)
				}
			},
			payload: map[string]any{"logLevel": "debug"},
			want: storage.SystemConfig{
				LogLevel:                    "debug",
				ImageProxyLimitEnabled:      true,
				ImageProxyMaxConcurrent:     8,
				ImageProxyRequestIntervalMS: 100,
				ImageCacheEnabled:           true,
				ImageCacheTTLDays:           30,
			},
		},
		{
			name: "clamps out-of-range settings",
			payload: map[string]any{
				"imageProxyMaxConcurrent":     0,
				"imageProxyRequestIntervalMs": 999999,
				"imageCacheTtlDays":           9999,
			},
			want: storage.SystemConfig{
				ImageProxyMaxConcurrent:     1,
				ImageProxyRequestIntervalMS: 5000,
				ImageCacheTTLDays:           365,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			handler, closeStore := newConfigTestHandler(t)
			defer closeStore()
			if tt.setup != nil {
				tt.setup(t, ctx, handler)
			}

			res := handler.configSet(ctx, map[string]any{"config": tt.payload})
			if res["ok"] != true {
				t.Fatalf("configSet() = %+v", res)
			}
			got, err := handler.store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
			if err != nil {
				t.Fatalf("GetSystemConfig() error = %v", err)
			}
			assertImageConfig(t, got, tt.want)
		})
	}
}

func assertImageConfig(t *testing.T, got, want storage.SystemConfig) {
	t.Helper()
	if want.LogLevel != "" && got.LogLevel != want.LogLevel {
		t.Fatalf("LogLevel = %q, want %q", got.LogLevel, want.LogLevel)
	}
	if got.ImageProxyLimitEnabled != want.ImageProxyLimitEnabled ||
		got.ImageProxyMaxConcurrent != want.ImageProxyMaxConcurrent ||
		got.ImageProxyRequestIntervalMS != want.ImageProxyRequestIntervalMS ||
		got.ImageCacheEnabled != want.ImageCacheEnabled ||
		got.ImageCacheTTLDays != want.ImageCacheTTLDays {
		t.Fatalf("image settings = %+v, want %+v", got, want)
	}
}

func TestTGSetValidatesServerRemark(t *testing.T) {
	tests := []struct {
		name      string
		remark    string
		want      string
		wantError string
	}{
		{name: "trims remark", remark: "  家庭服  ", want: "家庭服"},
		{name: "rejects newline", remark: "家庭服\n备用", wantError: "服务器备注不能包含换行"},
		{name: "rejects long remark", remark: strings.Repeat("服", telegramServerRemarkMaxRunes+1), wantError: "服务器备注不能超过 80 个字符"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			handler, closeStore := newConfigTestHandler(t)
			defer closeStore()

			res := handler.tgSet(ctx, map[string]any{"config": map[string]any{"serverRemark": tt.remark}})
			if tt.wantError != "" {
				if res["ok"] == true || res["error"] != tt.wantError {
					t.Fatalf("tgSet() = %+v, want error %q", res, tt.wantError)
				}
				return
			}
			if res["ok"] != true {
				t.Fatalf("tgSet() = %+v", res)
			}
			cfg, err := handler.store.GetTGConfig(ctx)
			if err != nil {
				t.Fatalf("GetTGConfig() error = %v", err)
			}
			if cfg.ServerRemark != tt.want {
				t.Fatalf("ServerRemark = %q, want %q", cfg.ServerRemark, tt.want)
			}
		})
	}
}

func newConfigTestHandler(t *testing.T) (*Handler, func()) {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatalf("storage.New() error = %v", err)
	}
	handler := New(config.Config{}, store, nil, nil, logging.New("silent", false), nil)
	return handler, func() { _ = store.Close() }
}

type fakeImageCacheManager struct {
	stats       proxy.ImageCacheStats
	clearStats  proxy.ImageCacheStats
	statsErr    error
	clearErr    error
	clearCalled bool
}

func (f *fakeImageCacheManager) ImageCacheStats(ctx context.Context) (proxy.ImageCacheStats, error) {
	return f.stats, f.statsErr
}

func (f *fakeImageCacheManager) ClearImageCache(ctx context.Context) (proxy.ImageCacheStats, error) {
	f.clearCalled = true
	return f.clearStats, f.clearErr
}
