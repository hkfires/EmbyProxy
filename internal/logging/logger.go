package logging

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"embyproxy/internal/localtime"
)

const (
	DefaultBufferCapacity      = 2000
	DefaultHistoryEntriesFile  = 2000
	DefaultHistoryRotatedFiles = 20
	logHistoryBufferSize       = 64 * 1024
	logHistoryFlushInterval    = time.Second
)

var (
	levels = map[string]int{
		"silent": 0,
		"error":  1,
		"warn":   2,
		"info":   3,
		"debug":  4,
	}

	httpURLRE         = regexp.MustCompile(`(?i)^https?://`)
	embeddedHTTPURLRE = regexp.MustCompile(`(?i)https?://[^\s"'<>\\]+`)
	safeLogValueRE    = regexp.MustCompile(`^[A-Za-z0-9_./:@-]+$`)

	metaFieldOrder = map[string]int{
		"event":                10,
		"id":                   20,
		"method":               30,
		"uri":                  40,
		"ip":                   50,
		"node":                 60,
		"nodeTarget":           70,
		"target":               80,
		"upstreamPool":         85,
		"location":             90,
		"range":                100,
		"contentRange":         110,
		"streamResumeFrom":     112,
		"streamResumeAttempts": 114,
		"streamResumeBytes":    116,
		"imageCache":           120,
		"bytes":                130,
		"contentLen":           140,
		"copiedBytes":          150,
		"readBytes":            160,
		"writeBytes":           170,
		"readCalls":            180,
		"writeCalls":           190,
		"responseReadyMs":      200,
		"targetAttemptMs":      210,
		"bodyMs":               220,
		"copyMs":               230,
		"totalMs":              240,
		"firstReadMs":          250,
		"firstReadStatus":      260,
		"lastReadMs":           270,
		"lastWriteMs":          280,
		"upgradeMs":            290,
		"addr":                 300,
		"db":                   310,
		"profile":              320,
		"label":                330,
		"client":               340,
		"version":              350,
		"commit":               360,
		"builtAt":              370,
		"device":               380,
		"deviceId":             390,
		"userAgent":            400,
		"day":                  410,
		"count":                420,
		"reason":               900,
		"side":                 910,
		"contextErr":           920,
		"bodyCopySide":         930,
		"bodyCopyContextErr":   940,
		"bodyCopyError":        950,
		"streamResumeError":    955,
		"error":                960,
	}
)

type Logger struct {
	level     atomic.Int64
	accessLog atomic.Bool
	seq       atomic.Uint64
	// mu keeps buffer and history on the same side of a clear boundary.
	mu      sync.Mutex
	buffer  *logBuffer
	history *logHistory
	subMu   sync.Mutex
	subs    map[chan LogEntry]struct{}
}

type LogEntry struct {
	Type    string `json:"type,omitempty"`
	ID      uint64 `json:"id"`
	Time    string `json:"time"`
	Level   string `json:"level"`
	Scope   string `json:"scope"`
	Message string `json:"message"`
	Line    string `json:"line"`
}

type LogFilter struct {
	Levels map[string]bool
	Query  string
}

type LogPage struct {
	Entries      []LogEntry
	HasOlder     bool
	History      bool
	Page         int
	TotalPages   int
	TotalEntries int
}

type logBuffer struct {
	mu       sync.Mutex
	next     uint64
	start    int
	entries  []LogEntry
	capacity int
}

type logHistory struct {
	mu             sync.Mutex
	path           string
	entriesPerFile int
	maxFiles       int
	entryCount     int
	file           *os.File
	writer         *bufio.Writer
	index          *logBuffer
	closed         bool
	done           chan struct{}
}

func (f LogFilter) empty() bool {
	return len(f.Levels) == 0 && strings.TrimSpace(f.Query) == ""
}

func (f LogFilter) match(e LogEntry) bool {
	if len(f.Levels) > 0 && !f.Levels[strings.ToLower(e.Level)] {
		return false
	}
	query := strings.TrimSpace(strings.ToLower(f.Query))
	if query != "" && !strings.Contains(strings.ToLower(e.Line), query) {
		return false
	}
	return true
}

func New(level string, accessLog bool) *Logger {
	l := &Logger{buffer: newLogBuffer(DefaultBufferCapacity)}
	l.Configure(level, accessLog)
	return l
}

// Configure updates logging behavior for future writes.
func (l *Logger) Configure(level string, accessLog bool) {
	l.level.Store(int64(levels[normalizeLevel(level)]))
	l.accessLog.Store(accessLog)
}

func (l *Logger) NextRequestID(prefix string) string {
	if prefix == "" {
		prefix = "req"
	}
	n := l.seq.Add(1)
	return fmt.Sprintf("%s-%s-%x", prefix, strconv36(time.Now().UnixMilli()), n)
}

func (l *Logger) AccessEnabled() bool {
	return l.accessLog.Load()
}

func (l *Logger) Enabled(level string) bool {
	return int(l.level.Load()) >= levels[normalizeLevel(level)]
}

func (l *Logger) Subscribe(buf int) (<-chan LogEntry, func()) {
	if l == nil {
		ch := make(chan LogEntry)
		close(ch)
		return ch, func() {}
	}
	if buf < 1 {
		buf = 1
	}
	ch := make(chan LogEntry, buf)
	l.subMu.Lock()
	if l.subs == nil {
		l.subs = make(map[chan LogEntry]struct{})
	}
	l.subs[ch] = struct{}{}
	l.subMu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			l.subMu.Lock()
			if _, ok := l.subs[ch]; ok {
				delete(l.subs, ch)
				close(ch)
			}
			l.subMu.Unlock()
		})
	}
	return ch, cancel
}

func (l *Logger) broadcast(entry LogEntry) {
	if l == nil {
		return
	}
	l.subMu.Lock()
	defer l.subMu.Unlock()
	for ch := range l.subs {
		if entry.Type != "" {
			broadcastControlEntry(ch, entry)
			continue
		}
		select {
		case ch <- entry:
		default:
		}
	}
}

func broadcastControlEntry(ch chan LogEntry, entry LogEntry) {
	for {
		select {
		case ch <- entry:
			return
		default:
		}
		// Control events mark stream boundaries, so drop stale buffered log lines
		// instead of losing the boundary or blocking on a slow SSE client.
		select {
		case <-ch:
		default:
		}
	}
}

func (l *Logger) Entries(limit int) []LogEntry {
	if l == nil || l.buffer == nil {
		return nil
	}
	return l.buffer.Entries(limit)
}

// Clear removes buffered and persisted console log entries.
func (l *Logger) Clear() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.history != nil {
		if err := l.history.reset(); err != nil {
			return err
		}
	}
	if l.buffer != nil {
		l.buffer.Clear()
	}
	l.broadcast(LogEntry{Type: "clear"})
	return nil
}

func (l *Logger) BufferCapacity() int {
	if l == nil || l.buffer == nil {
		return 0
	}
	return l.buffer.Capacity()
}

func (l *Logger) NewestID() uint64 {
	if l == nil || l.buffer == nil {
		return 0
	}
	return l.buffer.NewestID()
}

func (l *Logger) EnableHistory(path string, entriesPerFile, maxFiles int) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.history != nil {
		if err := l.history.Close(); err != nil {
			return err
		}
		l.history = nil
	}
	history, err := newLogHistory(path, entriesPerFile, maxFiles)
	if err != nil {
		return err
	}
	l.history = history
	return nil
}

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.history == nil {
		return nil
	}
	return l.history.Close()
}

func (l *Logger) Page(limit int, before uint64, filter LogFilter) LogPage {
	if l == nil {
		return LogPage{}
	}
	if l.buffer != nil {
		entries, hasOlder := l.buffer.EntriesBefore(limit, before, filter)
		if l.history != nil && !filter.empty() {
			historyEntries, historyHasOlder, err := l.history.Page(limit, before, filter)
			if err == nil {
				var truncated bool
				entries, truncated = mergeLogEntriesForPage(limit, historyEntries, entries)
				return LogPage{Entries: entries, HasOlder: hasOlder || historyHasOlder || truncated, History: true}
			}
		}
		if before == 0 || len(entries) > 0 {
			if l.history != nil {
				if len(entries) > 0 && l.history.HasBefore(entries[0].ID) {
					hasOlder = true
				}
				return LogPage{Entries: entries, HasOlder: hasOlder, History: true}
			}
			return LogPage{Entries: entries, HasOlder: hasOlder}
		}
	}
	if l.history != nil {
		entries, hasOlder, err := l.history.Page(limit, before, filter)
		if err == nil {
			return LogPage{Entries: entries, HasOlder: hasOlder, History: true}
		}
	}
	if l.buffer == nil {
		return LogPage{}
	}
	entries, hasOlder := l.buffer.EntriesBefore(limit, before, filter)
	return LogPage{Entries: entries, HasOlder: hasOlder}
}

func mergeLogEntriesForPage(limit int, pages ...[]LogEntry) ([]LogEntry, bool) {
	seen := map[uint64]bool{}
	entries := []LogEntry{}
	for _, page := range pages {
		for _, entry := range page {
			if entry.ID > 0 {
				if seen[entry.ID] {
					continue
				}
				seen[entry.ID] = true
			}
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	if limit <= 0 || limit >= len(entries) {
		return entries, false
	}
	return entries[len(entries)-limit:], true
}

func (l *Logger) PageNumber(limit, page int, filter LogFilter) LogPage {
	if l == nil {
		return LogPage{}
	}
	if l.history != nil {
		entries, totalEntries, totalPages, page, hasOlder, err := l.history.PageNumber(limit, page, filter)
		if err == nil {
			return LogPage{Entries: entries, HasOlder: hasOlder, History: true, Page: page, TotalPages: totalPages, TotalEntries: totalEntries}
		}
	}
	if l.buffer == nil {
		return LogPage{}
	}
	entries, totalEntries, totalPages, page, hasOlder := l.buffer.PageNumber(limit, page, filter)
	return LogPage{Entries: entries, HasOlder: hasOlder, Page: page, TotalPages: totalPages, TotalEntries: totalEntries}
}

func (l *Logger) Debug(scope, msg string, meta map[string]any) { l.write("debug", scope, msg, meta) }
func (l *Logger) Info(scope, msg string, meta map[string]any)  { l.write("info", scope, msg, meta) }
func (l *Logger) Warn(scope, msg string, meta map[string]any)  { l.write("warn", scope, msg, meta) }
func (l *Logger) Error(scope, msg string, meta map[string]any) { l.write("error", scope, msg, meta) }

func (l *Logger) write(level, scope, msg string, meta map[string]any) {
	level = normalizeLevel(level)
	status := promotedMetaValue(meta, "status")
	parts := []string{localtime.RFC3339(time.Now()), "[" + strings.ToUpper(level) + "]"}
	if status != "" {
		parts = append(parts, "["+status+"]")
	}
	parts = append(parts, "["+scope+"]")
	if clean := RedactText(msg); clean != "" && promotedMetaValue(meta, "event") == "" {
		parts = append(parts, clean)
	}
	if formatted := formatMeta(meta); formatted != "" {
		parts = append(parts, formatted)
	}
	line := strings.Join(parts, " ")
	entry := LogEntry{Time: parts[0], Level: level, Scope: scope, Message: RedactText(msg), Line: line}
	l.mu.Lock()
	if l.buffer != nil {
		entry = l.buffer.Append(entry)
	}
	if l.history != nil {
		_ = l.history.Append(entry)
	}
	l.broadcast(entry)
	l.mu.Unlock()
	if !l.Enabled(level) {
		return
	}
	if level == "error" || level == "warn" {
		fmt.Fprintln(os.Stderr, line)
		return
	}
	fmt.Fprintln(os.Stdout, line)
}

func newLogBuffer(capacity int) *logBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &logBuffer{capacity: capacity, entries: make([]LogEntry, 0, capacity)}
}

func (b *logBuffer) Append(entry LogEntry) LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	entry.ID = b.next
	b.appendLocked(entry)
	return entry
}

func (b *logBuffer) AppendWithID(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if entry.ID > b.next {
		b.next = entry.ID
	}
	b.appendLocked(entry)
}

func (b *logBuffer) appendLocked(entry LogEntry) {
	if len(b.entries) < b.capacity {
		b.entries = append(b.entries, entry)
		return
	}
	b.entries[b.start] = entry
	b.start = (b.start + 1) % b.capacity
}

func (b *logBuffer) Entries(limit int) []LogEntry {
	entries, _ := b.EntriesBefore(limit, 0, LogFilter{})
	return entries
}

func (b *logBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clearLocked()
}

func (b *logBuffer) clearLocked() {
	for i := range b.entries {
		b.entries[i] = LogEntry{}
	}
	b.start = 0
	b.entries = b.entries[:0]
}

func (b *logBuffer) snapshot() []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	entries := make([]LogEntry, len(b.entries))
	for i := 0; i < len(b.entries); i++ {
		entries[i] = b.entries[(b.start+i)%b.capacity]
	}
	return entries
}

func (b *logBuffer) EntriesBefore(limit int, before uint64, filter LogFilter) ([]LogEntry, bool) {
	allEntries := b.snapshot()
	total := len(allEntries)
	if limit <= 0 || limit > total {
		limit = total
	}
	all := make([]LogEntry, 0, total)
	for _, entry := range allEntries {
		if (before == 0 || entry.ID < before) && (filter.empty() || filter.match(entry)) {
			all = append(all, entry)
		}
	}
	if limit <= 0 || limit > len(all) {
		limit = len(all)
	}
	hasOlder := len(all) > limit
	if hasOlder {
		all = all[len(all)-limit:]
	}
	return all, hasOlder
}

func (b *logBuffer) PageNumber(limit, page int, filter LogFilter) ([]LogEntry, int, int, int, bool) {
	entries := b.snapshot()
	limit = normalizePageLimit(limit, len(entries))
	if !filter.empty() {
		filtered := make([]LogEntry, 0, len(entries))
		for _, entry := range entries {
			if filter.match(entry) {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}
	total := len(entries)
	totalPages := logPageCount(total, limit)
	page = clampLogPage(page, totalPages)
	start, end := logPageBounds(total, limit, page)
	out := append([]LogEntry(nil), entries[start:end]...)
	return out, total, totalPages, page, start > 0
}

func (b *logBuffer) Capacity() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capacity
}

func (b *logBuffer) NewestID() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) == 0 {
		return 0
	}
	idx := (b.start + len(b.entries) - 1) % b.capacity
	return b.entries[idx].ID
}

func (b *logBuffer) OldestID() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) == 0 {
		return 0
	}
	return b.entries[b.start].ID
}

func newLogHistory(path string, entriesPerFile, maxFiles int) (*logHistory, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("log history path is empty")
	}
	if entriesPerFile < 1 {
		entriesPerFile = DefaultHistoryEntriesFile
	}
	if maxFiles < 1 {
		maxFiles = DefaultHistoryRotatedFiles
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	h := &logHistory{
		path:           path,
		entriesPerFile: entriesPerFile,
		maxFiles:       maxFiles,
		index:          newLogBuffer(entriesPerFile * maxFiles),
		done:           make(chan struct{}),
	}
	if err := h.reset(); err != nil {
		return nil, err
	}
	go h.flushLoop()
	return h, nil
}

func (h *logHistory) reset() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.closeWriterLocked(); err != nil {
		return err
	}
	for _, path := range h.pathsNewestFirst() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	h.entryCount = 0
	if h.index != nil {
		h.index.Clear()
	}
	return nil
}

func (h *logHistory) Append(entry LogEntry) error {
	if h.index != nil {
		// The runtime index is authoritative and independent of JSONL persistence.
		h.index.AppendWithID(entry)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	if h.entryCount >= h.entriesPerFile {
		if err := h.rotateLocked(); err != nil {
			return err
		}
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := h.ensureWriterLocked(); err != nil {
		return err
	}
	if _, err := h.writer.Write(b); err != nil {
		return err
	}
	if err := h.writer.WriteByte('\n'); err != nil {
		return err
	}
	h.entryCount++
	return nil
}

func (h *logHistory) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	close(h.done)
	return h.closeWriterLocked()
}

func (h *logHistory) flushLoop() {
	ticker := time.NewTicker(logHistoryFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.mu.Lock()
			if h.closed {
				h.mu.Unlock()
				return
			}
			_ = h.flushWriterLocked()
			h.mu.Unlock()
		case <-h.done:
			return
		}
	}
}

func (h *logHistory) ensureWriterLocked() error {
	if h.writer != nil && h.file != nil {
		return nil
	}
	f, err := os.OpenFile(h.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	h.file = f
	h.writer = bufio.NewWriterSize(f, logHistoryBufferSize)
	return nil
}

func (h *logHistory) flushWriterLocked() error {
	if h.writer == nil {
		return nil
	}
	if err := h.writer.Flush(); err != nil {
		return err
	}
	return nil
}

func (h *logHistory) closeWriterLocked() error {
	var firstErr error
	if h.writer != nil {
		if err := h.writer.Flush(); err != nil {
			firstErr = err
		}
		h.writer = nil
	}
	if h.file != nil {
		if err := h.file.Close(); firstErr == nil && err != nil {
			firstErr = err
		}
		h.file = nil
	}
	return firstErr
}

func (h *logHistory) HasBefore(id uint64) bool {
	if h == nil || id == 0 {
		return false
	}
	if h.index == nil {
		return false
	}
	oldestID := h.index.OldestID()
	return oldestID > 0 && oldestID < id
}

func (h *logHistory) Page(limit int, before uint64, filter LogFilter) ([]LogEntry, bool, error) {
	if h == nil || h.index == nil {
		return nil, false, nil
	}
	if limit <= 0 {
		limit = h.entriesPerFile
	}
	entries, hasOlder := h.index.EntriesBefore(limit, before, filter)
	return entries, hasOlder, nil
}

func (h *logHistory) PageNumber(limit, page int, filter LogFilter) ([]LogEntry, int, int, int, bool, error) {
	if h == nil || h.index == nil {
		return nil, 0, 1, 1, false, nil
	}
	limit = normalizePageLimit(limit, h.entriesPerFile)
	entries, total, totalPages, page, hasOlder := h.index.PageNumber(limit, page, filter)
	return entries, total, totalPages, page, hasOlder, nil
}

func (h *logHistory) rotateLocked() error {
	if err := h.closeWriterLocked(); err != nil {
		return err
	}
	if h.maxFiles <= 1 {
		if err := os.Remove(h.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		h.entryCount = 0
		return nil
	}
	oldest := rotatedLogPath(h.path, h.maxFiles-1)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		return err
	}
	for i := h.maxFiles - 2; i >= 1; i-- {
		from := rotatedLogPath(h.path, i)
		to := rotatedLogPath(h.path, i+1)
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(h.path, rotatedLogPath(h.path, 1)); err != nil && !os.IsNotExist(err) {
		return err
	}
	h.entryCount = 0
	return nil
}

func (h *logHistory) pathsNewestFirst() []string {
	paths := []string{h.path}
	for i := 1; i < h.maxFiles; i++ {
		paths = append(paths, rotatedLogPath(h.path, i))
	}
	return paths
}

func rotatedLogPath(path string, index int) string {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	return base + "." + strconv.Itoa(index) + ext
}

func normalizePageLimit(limit, fallback int) int {
	if limit > 0 {
		return limit
	}
	if fallback > 0 {
		return fallback
	}
	return 1
}

func logPageCount(total, limit int) int {
	if total <= 0 {
		return 1
	}
	if limit <= 0 {
		return 1
	}
	return (total + limit - 1) / limit
}

func clampLogPage(page, totalPages int) int {
	if totalPages < 1 {
		totalPages = 1
	}
	if page < 1 {
		return 1
	}
	if page > totalPages {
		return totalPages
	}
	return page
}

func logPageBounds(total, limit, page int) (int, int) {
	if total <= 0 {
		return 0, 0
	}
	end := total - (page-1)*limit
	if end < 0 {
		end = 0
	}
	if end > total {
		end = total
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	return start, end
}

func RedactURL(raw string) string {
	value := cleanString(raw, 512)
	if value == "" {
		return ""
	}
	hasOrigin := httpURLRE.MatchString(value)
	u, err := url.Parse(value)
	if err == nil {
		if !hasOrigin {
			u, err = url.Parse("http://local" + ensureLeadingSlash(value))
		}
		if err == nil {
			out := u.EscapedPath()
			if out == "" {
				out = "/"
			}
			if hasOrigin {
				return u.Scheme + "://" + u.Host + out
			}
			return out
		}
	}
	idx := strings.IndexByte(value, '#')
	if idx >= 0 {
		value = value[:idx]
	}
	q := strings.IndexByte(value, '?')
	if q < 0 {
		return value
	}
	return value[:q]
}

func RedactText(raw string) string {
	value := cleanString(raw, 512)
	if value == "" {
		return ""
	}
	return embeddedHTTPURLRE.ReplaceAllStringFunc(value, RedactURL)
}

func RedactProxyURL(raw, nodeName, secret string) string {
	redacted := RedactURL(raw)
	node := strings.ToLower(strings.TrimSpace(nodeName))
	secret = strings.TrimSpace(secret)
	if node == "" || secret == "" || redacted == "" {
		return redacted
	}
	variants := []string{secret, url.PathEscape(secret)}
	for _, v := range variants {
		marker := "/" + node + "/" + v
		if strings.HasPrefix(strings.ToLower(redacted), strings.ToLower(marker)) {
			return "/" + node + "/<secret>" + redacted[len(marker):]
		}
	}
	return redacted
}

func FormatTarget(target string) string {
	u, err := url.Parse(target)
	if err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return RedactURL(target)
}

func ensureLeadingSlash(value string) string {
	if strings.HasPrefix(value, "/") {
		return value
	}
	return "/" + value
}

func cleanString(value string, maxLen int) string {
	replacer := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ")
	s := strings.TrimSpace(replacer.Replace(value))
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func formatMeta(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	keys := make([]string, 0, len(meta))
	for key, value := range meta {
		if key == "status" {
			continue
		}
		if value != nil && fmt.Sprint(value) != "" {
			keys = append(keys, key)
		}
	}
	sortMetaKeys(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+formatValue(meta[key]))
	}
	return strings.Join(parts, " ")
}

func sortMetaKeys(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		left, leftOK := metaFieldOrder[keys[i]]
		right, rightOK := metaFieldOrder[keys[j]]
		if leftOK || rightOK {
			if !leftOK {
				return false
			}
			if !rightOK {
				return true
			}
			if left != right {
				return left < right
			}
		}
		return keys[i] < keys[j]
	})
}

func promotedMetaValue(meta map[string]any, key string) string {
	if len(meta) == 0 {
		return ""
	}
	value, ok := meta[key]
	if !ok || value == nil || fmt.Sprint(value) == "" {
		return ""
	}
	return formatValue(value)
}

func formatValue(value any) string {
	s := RedactText(fmt.Sprint(value))
	if s == "" {
		return ""
	}
	if safeLogValueRE.MatchString(s) {
		return s
	}
	return fmt.Sprintf("%q", s)
}

func normalizeLevel(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if _, ok := levels[v]; ok {
		return v
	}
	return "info"
}

func strconv36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%36]
		n /= 36
	}
	return string(b[i:])
}
