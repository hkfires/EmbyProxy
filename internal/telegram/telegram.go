package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"embyproxy/internal/localtime"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

type Service struct {
	store *storage.Store
	log   *logging.Logger
	http  *http.Client
}

func New(store *storage.Store, log *logging.Logger) *Service {
	return &Service{store: store, log: log, http: &http.Client{Timeout: 12 * time.Second}}
}

// Send posts text to the configured chat. Returned errors are user-facing and never contain the bot token.
func (s *Service) Send(ctx context.Context, cfg storage.TGConfig, text string) error {
	token := strings.TrimSpace(cfg.Token)
	chat := strings.TrimSpace(cfg.Chat)
	if token == "" || chat == "" {
		return errors.New("Bot Token 或 Chat ID 未配置")
	}
	if strings.TrimSpace(text) == "" {
		return errors.New("消息内容为空")
	}
	text = withServerRemark(cfg.ServerRemark, text)
	body, _ := json.Marshal(map[string]any{
		"chat_id":                  chat,
		"text":                     text,
		"disable_web_page_preview": true,
	})
	endpoint := "https://api.telegram.org/bot" + token + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		// The request URL embeds the token, so the parse error is not surfaced.
		return errors.New("Bot Token 格式无效")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.http.Do(req)
	if err != nil {
		// *url.Error quotes the request URL, which contains the token; keep only the cause.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("连接 Telegram 失败：%v", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}
	var payload struct {
		Description string `json:"description"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&payload)
	if description := strings.TrimSpace(payload.Description); description != "" {
		return fmt.Errorf("Telegram 返回 %d：%s", res.StatusCode, description)
	}
	return fmt.Errorf("Telegram 返回 %d", res.StatusCode)
}

func withServerRemark(remark, text string) string {
	remark = strings.TrimSpace(remark)
	if remark == "" {
		return text
	}
	return "🏷️ 服务器：" + remark + "\n\n" + text
}

const reportHeaderPrefix = "📊 Emby 播放日报 · "

// BuildReport renders the daily report for the window ending at reportTime (HH:mm, local time) on now's day.
func (s *Service) BuildReport(ctx context.Context, reportTime string, now int64) (string, error) {
	if reportTime == "" {
		reportTime = "00:00"
	}
	var hh, mm int
	_, _ = fmt.Sscanf(reportTime, "%d:%d", &hh, &mm)

	tNow := localtime.FromUnixMilli(now)
	tReportToday := time.Date(tNow.Year(), tNow.Month(), tNow.Day(), hh, mm, 0, 0, localtime.Location())

	endTime := tReportToday.UnixMilli()
	tReportStart := tReportToday.AddDate(0, 0, -1)
	tPreviousStart := tReportToday.AddDate(0, 0, -2)
	startTime := tReportStart.UnixMilli()
	yesterdayEndTime := startTime
	yesterdayStartTime := tPreviousStart.UnixMilli()

	todayStats, _, _, err := s.store.GetRangeStats(ctx, startTime, endTime)
	if err != nil {
		return "", err
	}
	yesterdayStats, _, _, err := s.store.GetRangeStats(ctx, yesterdayStartTime, yesterdayEndTime)
	if err != nil {
		return "", err
	}

	today := summarize(todayStats)
	yesterday := summarize(yesterdayStats)

	nodeDisplay := map[string]string{}
	if nodes, err := s.store.ListNodes(ctx, "admin"); err == nil {
		for _, node := range nodes {
			display := strings.TrimSpace(node.DisplayName)
			if display == "" {
				display = node.Name
			}
			nodeDisplay[strings.ToLower(node.Name)] = display
		}
	}
	period := reportPeriod{
		Day:          tReportToday.Format("2006-01-02"),
		CurrentRange: formatReportRange(tReportStart, tReportToday),
	}
	return buildReportText(period, today, yesterday, nodeDisplay), nil
}

func (s *Service) CheckAndSendReport(ctx context.Context) error {
	cfg, err := s.store.GetTGConfig(ctx)
	if err != nil || !cfg.Enabled || !cfg.ReportEnabled || cfg.Token == "" || cfg.Chat == "" {
		return err
	}
	now := time.Now().UnixMilli()
	day := storage.BeijingDate(now)
	hhmm := storage.BeijingHHMM(now)
	reportTime := cfg.ReportTime
	if reportTime == "" {
		reportTime = "00:00"
	}
	if hhmm < reportTime {
		return nil
	}
	kv := s.store.KV()
	cntKey := "report:cnt:" + day
	cnt := int64Value(mustKVGet(ctx, kv, cntKey))
	if cnt >= 1 {
		return nil
	}
	text, err := s.BuildReport(ctx, cfg.ReportTime, now)
	if err != nil {
		return err
	}
	if err := s.Send(ctx, cfg, text); err != nil {
		s.log.Warn("telegram", "daily report send failed", map[string]any{"event": "dailyReportSendFailed", "day": day, "error": err.Error()})
		return nil
	}
	_ = kv.Put(ctx, cntKey, "1")
	s.log.Debug("telegram", "daily report sent", map[string]any{"event": "dailyReportSent", "day": day, "count": 1})
	return nil
}

type reportPeriod struct {
	Day          string
	CurrentRange string
}

func buildReportText(period reportPeriod, today, yesterday summary, nodeDisplay map[string]string) string {
	if today.Plays == 0 && today.PlaybackMillis == 0 {
		return buildEmptyDayReport(period, today, yesterday)
	}
	lines := []string{
		reportHeaderPrefix + period.Day,
		"",
		"🕒 统计周期",
		"   " + period.CurrentRange,
		"",
		fmt.Sprintf("▶ 播放 %d 次 · %d 会话 · %d 节点", today.Plays, today.Sessions, len(today.NodeMap)),
	}
	lines = append(lines, fmt.Sprintf("   播放时长 %s", formatPlaybackDuration(today.PlaybackMillis)))
	lines = append(lines, fmt.Sprintf("   入站 %s | 出站 %s", formatBytes(today.InboundBytes), formatBytes(today.OutboundBytes)))
	if today.Errors > 0 {
		lines = append(lines, fmt.Sprintf("   ⚠️ 播放出错：%d 次", today.Errors))
	}
	lines = appendComparison(lines, today, yesterday, true)
	if entries := rankEntries(today.NodeMap, today.Plays, nodeDisplay); len(entries) > 0 {
		lines = append(lines, "", "🏆 节点排行:")
		lines = append(lines, entries...)
	}
	if entries := rankEntries(today.ClientMap, today.Plays, nil); len(entries) > 0 {
		lines = append(lines, "", "📱 客户端排行:")
		lines = append(lines, entries...)
	}
	return strings.Join(lines, "\n")
}

func buildEmptyDayReport(period reportPeriod, today, yesterday summary) string {
	lines := []string{
		reportHeaderPrefix + period.Day,
		"",
		"🕒 统计周期",
		"   " + period.CurrentRange,
		"",
		"📭 本周期无播放",
	}
	if hasPlaybackActivity(yesterday) {
		lines = appendComparison(lines, today, yesterday, false)
	}
	return strings.Join(lines, "\n")
}

func hasPlaybackActivity(s summary) bool {
	return s.Plays != 0 || s.PlaybackMillis != 0 || s.Sessions != 0 || s.InboundBytes != 0 || s.OutboundBytes != 0
}

func appendComparison(lines []string, current, previous summary, includeErrors bool) []string {
	lines = append(lines, "")
	if current.Plays == previous.Plays &&
		current.PlaybackMillis == previous.PlaybackMillis &&
		current.Sessions == previous.Sessions &&
		current.InboundBytes == previous.InboundBytes &&
		current.OutboundBytes == previous.OutboundBytes &&
		(!includeErrors || current.Errors == previous.Errors) {
		return append(lines, "📈 较前一日  无变化")
	}
	comparison := fmt.Sprintf("📈 较前一日  播放 %s · 会话 %s",
		formatSignedInt(current.Plays-previous.Plays),
		formatSignedInt(current.Sessions-previous.Sessions))
	if includeErrors && current.Errors != previous.Errors {
		comparison += fmt.Sprintf(" · 播放出错 %s", formatSignedInt(current.Errors-previous.Errors))
	}
	return append(lines,
		comparison,
		fmt.Sprintf("   播放时长 %s", formatSignedPlaybackDuration(current.PlaybackMillis-previous.PlaybackMillis)),
		fmt.Sprintf("   入站 %s | 出站 %s",
			formatSignedBytes(current.InboundBytes-previous.InboundBytes),
			formatSignedBytes(current.OutboundBytes-previous.OutboundBytes)))
}

func formatReportRange(start, end time.Time) string {
	return start.Format("2006-01-02 15:04") + " 至 " + end.Format("2006-01-02 15:04")
}

func (s *Service) CheckKeepaliveAndNotify(ctx context.Context) error {
	cfg, err := s.store.GetTGConfig(ctx)
	if err != nil || !cfg.Enabled || cfg.Token == "" || cfg.Chat == "" {
		return err
	}
	now := time.Now().UnixMilli()
	day := storage.BeijingDate(now)
	hhmm := storage.BeijingHHMM(now)
	nodes, err := s.store.ListNodes(ctx, "admin")
	if err != nil {
		return err
	}
	states, err := s.store.GetAllKeepaliveStates(ctx)
	if err != nil {
		return err
	}
	stateMap := map[string]storage.KeepaliveState{}
	for _, state := range states {
		stateMap[state.Node] = state
	}
	for _, node := range nodes {
		if node.RenewDays <= 0 {
			continue
		}
		state := stateMap["admin:"+node.Name]
		lastPlayTS := state.LastPlayTS
		if lastPlayTS == 0 {
			lastPlayTS = state.AnchorTS
		}
		dueTS := lastPlayTS + int64(node.RenewDays)*86400000
		remindFromTS := dueTS - int64(node.RemindBeforeDays)*86400000
		if now < remindFromTS {
			continue
		}
		keepaliveAt := node.KeepaliveAt
		if keepaliveAt == "" {
			keepaliveAt = "00:00"
		}
		if hhmm < keepaliveAt {
			continue
		}
		maxPerDay := node.KeepaliveMaxPerDay
		if maxPerDay <= 0 {
			maxPerDay = 1
		}
		notifyCount := 0
		if state.NotifyCountDay == day {
			notifyCount = state.NotifyCount
		}
		if notifyCount >= maxPerDay {
			continue
		}
		kv := s.store.KV()
		lastNotifyKey := "keepalive:last:admin:" + node.Name + ":" + day
		lastNotifyTS := int64Value(mustKVGet(ctx, kv, lastNotifyKey))
		if lastNotifyTS > 0 && now-lastNotifyTS < 60*60000 {
			continue
		}
		daysLeft := int((dueTS - now + 86400000 - 1) / 86400000)
		if daysLeft < 0 {
			daysLeft = 0
		}
		lastPlay := "从未"
		if lastPlayTS > 0 {
			lastPlay = localtime.FormatUnixMilli(lastPlayTS, "2006-01-02 15:04")
		}
		display := node.DisplayName
		if display == "" {
			display = node.Name
		}
		lines := []string{
			"保号提醒：" + display,
			"节点：" + node.Name,
			fmt.Sprintf("保号周期：%d 天", node.RenewDays),
			fmt.Sprintf("到期还剩：%d 天", daysLeft),
			"上次播放：" + lastPlay,
		}
		if node.Note != "" {
			lines = append(lines, "备注："+node.Note)
		}
		digestKey := "keepalive:digest:admin:" + node.Name + ":" + day
		digest := storage.FNV1a(strings.Join([]string{node.Name, strconv.Itoa(node.RenewDays), strconv.Itoa(node.RemindBeforeDays), strconv.FormatInt(dueTS, 10), strconv.FormatInt(lastPlayTS, 10)}, "|"))
		prevDigest := mustKVGet(ctx, kv, digestKey)
		if node.KeepaliveChangeOnly && prevDigest == digest {
			continue
		}
		if err := s.Send(ctx, cfg, strings.Join(lines, "\n")); err != nil {
			s.log.Warn("telegram", "keepalive send failed", map[string]any{"event": "keepaliveSendFailed", "node": node.Name, "day": day, "error": err.Error()})
			continue
		}
		_ = kv.Put(ctx, lastNotifyKey, strconv.FormatInt(now, 10))
		_ = kv.Put(ctx, digestKey, digest)
		_ = s.store.UpdateKeepaliveNotify(ctx, "admin", node.Name, day, notifyCount+1, day)
		s.log.Debug("telegram", "keepalive sent", map[string]any{"event": "keepaliveSent", "node": node.Name, "day": day, "count": notifyCount + 1})
	}
	return nil
}

type summary struct {
	Plays          int64
	PlaybackMillis int64
	InboundBytes   int64
	OutboundBytes  int64
	Sessions       int64
	Errors         int64
	NodeMap        map[string]int64
	ClientMap      map[string]int64
}

func summarize(rows []storage.PlayStat) summary {
	out := summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}}
	for _, row := range rows {
		out.Plays += row.Plays
		out.PlaybackMillis += row.PlaybackMillis
		out.InboundBytes += row.InboundBytes
		out.OutboundBytes += row.OutboundBytes
		out.Sessions += row.Sessions
		out.Errors += row.Errors
		out.NodeMap[row.Node] += row.Plays
		out.ClientMap[row.Client] += row.Plays
	}
	return out
}

func rankEntries(values map[string]int64, total int64, display map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	type pair struct {
		Key   string
		Value int64
	}
	pairs := make([]pair, 0, len(values))
	for key, value := range values {
		if value <= 0 {
			continue
		}
		pairs = append(pairs, pair{Key: key, Value: value})
	}
	if len(pairs) == 0 {
		return nil
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Value > pairs[j].Value })
	if len(pairs) > 99 {
		pairs = pairs[:99]
	}
	lines := make([]string, len(pairs))
	for i, p := range pairs {
		name := p.Key
		if display != nil && display[strings.ToLower(p.Key)] != "" {
			name = display[strings.ToLower(p.Key)]
		}
		lines[i] = fmt.Sprintf("   %d. %s — %d 次 (%s)", i+1, name, p.Value, formatPercent(p.Value, total))
	}
	return lines
}

func formatBytes(value int64) string {
	if value <= 0 {
		return "0B"
	}
	units := []struct {
		name   string
		size   float64
		digits int
	}{
		{name: "PB", size: 1e15, digits: 2},
		{name: "TB", size: 1e12, digits: 2},
		{name: "GB", size: 1e9, digits: 2},
		{name: "MB", size: 1e6, digits: 1},
	}
	for _, unit := range units {
		if float64(value) >= unit.size {
			return fmt.Sprintf("%.*f %s", unit.digits, float64(value)/unit.size, unit.name)
		}
	}
	if value >= 1e3 {
		return fmt.Sprintf("%.1f KB", float64(value)/1e3)
	}
	return fmt.Sprintf("%dB", value)
}

func formatSignedBytes(value int64) string {
	if value == 0 {
		return "0B"
	}
	prefix := "+"
	if value < 0 {
		prefix = "-"
		value = -value
	}
	return prefix + formatBytes(value)
}

func formatPlaybackDuration(milliseconds int64) string {
	if milliseconds <= 0 {
		return "0 秒"
	}
	totalSeconds := milliseconds / int64(time.Second/time.Millisecond)
	days := totalSeconds / 86400
	hours := totalSeconds % 86400 / 3600
	minutes := totalSeconds % 3600 / 60
	seconds := totalSeconds % 60
	if days > 0 {
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%d 小时 %d 分", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%d 分 %d 秒", minutes, seconds)
	}
	return fmt.Sprintf("%d 秒", seconds)
}

func formatSignedPlaybackDuration(milliseconds int64) string {
	if milliseconds == 0 {
		return "0 秒"
	}
	prefix := "+"
	if milliseconds < 0 {
		prefix = "-"
		milliseconds = -milliseconds
	}
	return prefix + formatPlaybackDuration(milliseconds)
}

func formatSignedInt(value int64) string {
	if value > 0 {
		return "+" + strconv.FormatInt(value, 10)
	}
	return strconv.FormatInt(value, 10)
}

func formatPercent(part, total int64) string {
	if total <= 0 {
		if part > 0 {
			return "100.0%"
		}
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(part)*100/float64(total))
}

func mustKVGet(ctx context.Context, kv *storage.KV, key string) string {
	value, ok, err := kv.Get(ctx, key)
	if err != nil || !ok {
		return ""
	}
	return value
}

func int64Value(value string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return n
}
