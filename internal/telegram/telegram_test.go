package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"embyproxy/internal/localtime"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func TestSendAddsServerRemark(t *testing.T) {
	tests := []struct {
		name   string
		remark string
		want   string
	}{
		{name: "empty remark", want: "message"},
		{name: "trimmed remark", remark: "  家庭服  ", want: "🏷️ 服务器：家庭服\n\nmessage"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &Service{http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var body struct {
					Text string `json:"text"`
				}
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatalf("decode request body error = %v", err)
				}
				if body.Text != tt.want {
					t.Fatalf("telegram text = %q, want %q", body.Text, tt.want)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}}
			cfg := storage.TGConfig{Token: "token", Chat: "chat", ServerRemark: tt.remark}
			if err := service.Send(context.Background(), cfg, "message"); err != nil {
				t.Fatalf("Send() error = %v", err)
			}
		})
	}
}

func TestSendReportsFailureWithoutToken(t *testing.T) {
	const token = "123456:secret-bot-token"
	tests := []struct {
		name      string
		cfg       storage.TGConfig
		transport roundTripFunc
		want      string
	}{
		{
			name: "missing chat",
			cfg:  storage.TGConfig{Token: token},
			want: "Bot Token 或 Chat ID 未配置",
		},
		{
			name: "telegram description",
			cfg:  storage.TGConfig{Token: token, Chat: "chat"},
			transport: func(req *http.Request) (*http.Response, error) {
				body := `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`
				return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(body))}, nil
			},
			want: "Telegram 返回 400：Bad Request: chat not found",
		},
		{
			name: "status without body",
			cfg:  storage.TGConfig{Token: token, Chat: "chat"},
			transport: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader(""))}, nil
			},
			want: "Telegram 返回 502",
		},
		{
			name: "transport error hides request url",
			cfg:  storage.TGConfig{Token: token, Chat: "chat"},
			transport: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("dial tcp: connection refused")
			},
			want: "连接 Telegram 失败：dial tcp: connection refused",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &Service{http: &http.Client{Transport: tt.transport}}
			err := service.Send(context.Background(), tt.cfg, "message")
			if err == nil {
				t.Fatal("Send() error = nil")
			}
			if err.Error() != tt.want {
				t.Fatalf("Send() error = %q, want %q", err.Error(), tt.want)
			}
			if strings.Contains(err.Error(), "secret-bot-token") {
				t.Fatalf("Send() error leaks the bot token: %q", err.Error())
			}
		})
	}
}

func TestBuildReportText(t *testing.T) {
	tests := []struct {
		name            string
		day             string
		today           summary
		yesterday       summary
		nodeDisplay     map[string]string
		wantContains    []string
		wantNotContains []string
	}{
		{
			name: "normal day",
			day:  "2026-06-08",
			today: summary{
				Plays:          12,
				PlaybackMillis: 19_800_000,
				InboundBytes:   10_000_000_000,
				OutboundBytes:  9_000_000_000,
				Sessions:       8,
				Errors:         1,
				NodeMap:        map[string]int64{"alpha": 8, "beta": 4},
				ClientMap:      map[string]int64{"Infuse/8.0": 6, "Emby Theater": 4, "Unknown": 2},
			},
			yesterday: summary{
				Plays:          7,
				PlaybackMillis: 14_400_000,
				InboundBytes:   5_000_000_000,
				OutboundBytes:  4_000_000_000,
				Sessions:       5,
				NodeMap:        map[string]int64{"alpha": 7},
				ClientMap:      map[string]int64{"Infuse/8.0": 7},
			},
			nodeDisplay: map[string]string{"alpha": "朋友服"},
			wantContains: []string{
				"📊 Emby 播放日报 · 2026-06-08",
				"🕒 统计周期\n   2026-06-07 08:00 至 2026-06-08 08:00\n\n▶ 播放 12 次 · 8 会话 · 2 节点",
				"播放时长 5 小时 30 分",
				"入站 10.00 GB | 出站 9.00 GB",
				"⚠️ 播放出错：1 次",
				"📈 较前一日  播放 +5 · 会话 +3 · 播放出错 +1",
				"播放时长 +1 小时 30 分",
				"入站 +5.00 GB | 出站 +5.00 GB",
				"🏆 节点排行:",
				"1. 朋友服 — 8 次 (66.7%)",
				"2. beta — 4 次 (33.3%)",
				"📱 客户端排行:",
				"1. Infuse/8.0 — 6 次 (50.0%)",
				"2. Emby Theater — 4 次 (33.3%)",
				"3. Unknown — 2 次 (16.7%)",
			},
			wantNotContains: []string{"5xx", "302直链"},
		},
		{
			name:  "empty day with previous activity",
			day:   "2026-06-10",
			today: summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			yesterday: summary{
				Plays:          22,
				PlaybackMillis: 7_200_000,
				Sessions:       18,
				InboundBytes:   10_000_000_000,
				OutboundBytes:  9_230_000_000,
				Errors:         2,
				NodeMap:        map[string]int64{"alpha": 15, "beta": 7},
				ClientMap:      map[string]int64{"Infuse/8.0": 14, "Emby Theater": 8},
			},
			nodeDisplay: map[string]string{"alpha": "朋友服"},
			wantContains: []string{
				"📊 Emby 播放日报 · 2026-06-10",
				"🕒 统计周期\n   2026-06-09 08:00 至 2026-06-10 08:00\n\n📭 本周期无播放",
				"📈 较前一日  播放 -22 · 会话 -18",
				"播放时长 -2 小时 0 分",
				"入站 -10.00 GB | 出站 -9.23 GB",
			},
			wantNotContains: []string{"昨日", "前一日回顾", "22 次 · 18 会话", "播放出错", "节点排行", "客户端排行", "302直链"},
		},
		{
			name: "normal day without errors or yesterday",
			day:  "2026-06-08",
			today: summary{
				Plays:     5,
				Sessions:  3,
				NodeMap:   map[string]int64{"a": 5},
				ClientMap: map[string]int64{"b": 5},
			},
			yesterday: summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			wantContains: []string{
				"📈 较前一日  播放 +5 · 会话 +3",
				"入站 0B | 出站 0B",
			},
			wantNotContains: []string{"5xx", "较昨日"},
		},
		{
			name: "normal day with only error delta",
			day:  "2026-06-08",
			today: summary{
				Plays:         12,
				Sessions:      8,
				InboundBytes:  10_000_000_000,
				OutboundBytes: 9_000_000_000,
				Errors:        2,
				NodeMap:       map[string]int64{"a": 12},
				ClientMap:     map[string]int64{"b": 12},
			},
			yesterday: summary{
				Plays:         12,
				Sessions:      8,
				InboundBytes:  10_000_000_000,
				OutboundBytes: 9_000_000_000,
				NodeMap:       map[string]int64{"a": 12},
				ClientMap:     map[string]int64{"b": 12},
			},
			wantContains: []string{
				"⚠️ 播放出错：2 次",
				"📈 较前一日  播放 0 · 会话 0 · 播放出错 +2",
				"入站 0B | 出站 0B",
			},
			wantNotContains: []string{"5xx", "无变化"},
		},
		{
			name: "duration only current period",
			day:  "2026-06-08",
			today: summary{
				PlaybackMillis: 90_000,
				NodeMap:        map[string]int64{"alpha": 0},
				ClientMap:      map[string]int64{"Infuse/8.0": 0},
			},
			yesterday: summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			wantContains: []string{
				"▶ 播放 0 次 · 0 会话 · 1 节点",
				"播放时长 1 分 30 秒",
				"播放时长 +1 分 30 秒",
			},
			wantNotContains: []string{"本周期无播放", "节点排行", "客户端排行", "0 次 (0.0%)"},
		},
		{
			name:      "empty current period compares previous duration",
			day:       "2026-06-10",
			today:     summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			yesterday: summary{PlaybackMillis: 90_000, NodeMap: map[string]int64{"alpha": 0}, ClientMap: map[string]int64{"Infuse/8.0": 0}},
			wantContains: []string{
				"📭 本周期无播放",
				"播放时长 -1 分 30 秒",
			},
			wantNotContains: []string{"节点排行", "客户端排行", "0 次 (0.0%)"},
		},
		{
			name: "mixed rankings skip duration only entries",
			day:  "2026-06-08",
			today: summary{
				Plays:          1,
				PlaybackMillis: 60_000,
				Sessions:       1,
				NodeMap:        map[string]int64{"new": 1, "continued": 0},
				ClientMap:      map[string]int64{"new-client": 1, "continued-client": 0},
			},
			yesterday:       summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			wantContains:    []string{"new — 1 次 (100.0%)", "new-client — 1 次 (100.0%)"},
			wantNotContains: []string{"continued —", "continued-client —", "0 次 (0.0%)"},
		},
		{
			name:            "empty day without yesterday",
			day:             "2026-06-10",
			today:           summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			yesterday:       summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			wantContains:    []string{"📭 本周期无播放"},
			wantNotContains: []string{"昨日", "上一周期", "较前一日", "无变化"},
		},
		{
			name:            "empty day ignores previous errors only",
			day:             "2026-06-10",
			today:           summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			yesterday:       summary{Errors: 2, NodeMap: map[string]int64{"a": 0}, ClientMap: map[string]int64{"b": 0}},
			wantContains:    []string{"📭 本周期无播放"},
			wantNotContains: []string{"较前一日", "无变化", "播放出错", "节点排行", "客户端排行"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := buildReportText(
				testReportPeriod(tt.day),
				tt.today,
				tt.yesterday,
				tt.nodeDisplay,
			)
			assertContainsAll(t, text, tt.wantContains)
			assertContainsNone(t, text, tt.wantNotContains)
		})
	}

	t.Run("uses configured report window", func(t *testing.T) {
		ctx := context.Background()
		store := newTelegramTestStore(t)

		service := New(store, logging.New("silent", false))
		now := time.Date(2026, 6, 28, 8, 30, 0, 0, localtime.Location()).UnixMilli()
		text, err := service.BuildReport(ctx, "08:00", now)
		if err != nil {
			t.Fatalf("BuildReport() error = %v", err)
		}

		assertContainsAll(t, text, []string{
			"📊 Emby 播放日报 · 2026-06-28",
			"🕒 统计周期\n   2026-06-27 08:00 至 2026-06-28 08:00\n\n",
		})
		assertContainsNone(t, text, []string{"对比周期", "北京时间"})
	})
}

func testReportPeriod(day string) reportPeriod {
	end, err := time.Parse("2006-01-02 15:04", day+" 08:00")
	if err != nil {
		panic(err)
	}
	start := end.AddDate(0, 0, -1)
	return reportPeriod{
		Day:          day,
		CurrentRange: formatReportRange(start, end),
	}
}

func assertContainsAll(t *testing.T, text string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Fatalf("report text missing %q\n%s", want, text)
		}
	}
}

func assertContainsNone(t *testing.T, text string, values []string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(text, value) {
			t.Fatalf("report text should not contain %q\n%s", value, text)
		}
	}
}

func TestCheckAndSendReportSkipsWhenReportDisabled(t *testing.T) {
	ctx := context.Background()
	store := newTelegramTestStore(t)
	if err := store.SaveTGConfig(ctx, storage.TGConfig{
		Enabled:       true,
		ReportEnabled: false,
		Token:         "token",
		Chat:          "chat",
		ReportTime:    "00:00",
	}); err != nil {
		t.Fatalf("SaveTGConfig() error = %v", err)
	}

	calls := 0
	service := New(store, logging.New("silent", false))
	service.http = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	if err := service.CheckAndSendReport(ctx); err != nil {
		t.Fatalf("CheckAndSendReport() error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("telegram calls = %d, want 0", calls)
	}
}

func TestCheckKeepaliveAndNotifyIgnoresReportDisabled(t *testing.T) {
	ctx := context.Background()
	store := newTelegramTestStore(t)
	if err := store.SaveTGConfig(ctx, storage.TGConfig{
		Enabled:       true,
		ReportEnabled: false,
		Token:         "token",
		Chat:          "chat",
	}); err != nil {
		t.Fatalf("SaveTGConfig() error = %v", err)
	}
	if err := store.SaveNode(ctx, "admin", storage.Node{
		Name:             "alpha",
		Target:           "http://example.test",
		DisplayName:      "Alpha",
		RenewDays:        1,
		RemindBeforeDays: 1,
		KeepaliveAt:      "00:00",
	}); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}

	calls := 0
	service := New(store, logging.New("silent", false))
	service.http = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	if err := service.CheckKeepaliveAndNotify(ctx); err != nil {
		t.Fatalf("CheckKeepaliveAndNotify() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("telegram calls = %d, want 1", calls)
	}
}

func newTelegramTestStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestBuildReportIncludesDurationOnlyBuckets(t *testing.T) {
	ctx := context.Background()
	store := newTelegramTestStore(t)
	bucketStart := time.Date(2026, 6, 27, 9, 0, 0, 0, localtime.Location()).UnixMilli()
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO play_buckets (
			bucket_start, node, client, mode, plays, playback_ms, bytes,
			inbound_bytes, outbound_bytes, sessions, errors, updated_at
		) VALUES (?, 'alpha', 'Infuse/8.0', 'direct', 0, 90000, 0, 0, 0, 0, 0, ?)
	`, bucketStart, bucketStart+90_000); err != nil {
		t.Fatalf("insert duration bucket error = %v", err)
	}

	service := New(store, logging.New("silent", false))
	now := time.Date(2026, 6, 28, 8, 30, 0, 0, localtime.Location()).UnixMilli()
	text, err := service.BuildReport(ctx, "08:00", now)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}
	assertContainsAll(t, text, []string{
		"▶ 播放 0 次 · 0 会话 · 1 节点",
		"播放时长 1 分 30 秒",
	})
	assertContainsNone(t, text, []string{"本周期无播放", "节点排行", "客户端排行", "0 次 (0.0%)"})
}

func TestSummarizeIncludesPlaybackMillis(t *testing.T) {
	got := summarize([]storage.PlayStat{
		{Node: "alpha", Client: "Infuse", Plays: 1, PlaybackMillis: 60_000},
		{Node: "beta", Client: "Theater", Plays: 2, PlaybackMillis: 90_000},
	})
	if got.Plays != 3 || got.PlaybackMillis != 150_000 {
		t.Fatalf("summary plays = %d playbackMillis = %d; want 3 and 150000", got.Plays, got.PlaybackMillis)
	}
}

func TestFormatBytesScalesBeyondGB(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value int64
		want  string
	}{
		{name: "zero", value: 0, want: "0B"},
		{name: "negative", value: -1, want: "0B"},
		{name: "bytes", value: 999, want: "999B"},
		{name: "kilobytes", value: 1_500, want: "1.5 KB"},
		{name: "gigabytes", value: 1_500_000_000, want: "1.50 GB"},
		{name: "terabytes", value: 1_500_000_000_000, want: "1.50 TB"},
		{name: "petabytes", value: 1_500_000_000_000_000, want: "1.50 PB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatBytes(tc.value); got != tc.want {
				t.Fatalf("formatBytes() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatSignedBytes(t *testing.T) {
	if got := formatSignedBytes(-1_500_000_000); got != "-1.50 GB" {
		t.Fatalf("formatSignedBytes() = %q", got)
	}
	if got := formatSignedBytes(0); got != "0B" {
		t.Fatalf("formatSignedBytes(0) = %q", got)
	}
}

func TestFormatPlaybackDuration(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value int64
		want  string
	}{
		{name: "zero", want: "0 秒"},
		{name: "negative", value: -1, want: "0 秒"},
		{name: "seconds", value: 59_999, want: "59 秒"},
		{name: "minutes", value: 90_000, want: "1 分 30 秒"},
		{name: "hours", value: 3_600_000, want: "1 小时 0 分"},
		{name: "days", value: 90_000_000, want: "1 天 1 小时"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatPlaybackDuration(tt.value); got != tt.want {
				t.Fatalf("formatPlaybackDuration(%d) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestFormatSignedPlaybackDuration(t *testing.T) {
	for _, tt := range []struct {
		value int64
		want  string
	}{
		{value: 90_000, want: "+1 分 30 秒"},
		{value: -90_000, want: "-1 分 30 秒"},
		{want: "0 秒"},
	} {
		if got := formatSignedPlaybackDuration(tt.value); got != tt.want {
			t.Fatalf("formatSignedPlaybackDuration(%d) = %q, want %q", tt.value, got, tt.want)
		}
	}
}
