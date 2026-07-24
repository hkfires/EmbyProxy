package logging

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRedactTextStripsEmbeddedURLQueries(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "regular URL",
			input: `Get "https://emby.example/emby/Items/1?X-Emby-Token=secret-token&fields=ShareLevel&api_key=secret-key": context canceled`,
			want:  `Get "https://emby.example/emby/Items/1": context canceled`,
		},
		{
			name:  "parentheses in path",
			input: `Get "https://cdn.example/video/Devote%20100%20Days%20(2025)%5Btmdb=306641%5D/S01E03.mkv?auth_key=secret-auth-key": net/http: TLS handshake timeout`,
			want:  `Get "https://cdn.example/video/Devote%20100%20Days%20(2025)%5Btmdb=306641%5D/S01E03.mkv": net/http: TLS handshake timeout`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactText(tt.input)
			if got != tt.want {
				t.Fatalf("RedactText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactURLStripsQueries(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "absolute signed URL",
			input: "https://cdn.example/video.mkv?sign=secret-sign&signature=secret-signature&design=poster",
			want:  "https://cdn.example/video.mkv",
		},
		{
			name:  "relative Emby URL",
			input: "/node/secret/emby/Sessions/Playing/Progress?UserId=user-secret&X-Emby-Token=token&reqformat=json",
			want:  "/node/secret/emby/Sessions/Playing/Progress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactURL(tt.input); got != tt.want {
				t.Fatalf("RedactURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatValueStripsEmbeddedURLQueryInErrorMeta(t *testing.T) {
	got := formatValue(`Get "https://emby.example/emby/Items/1?X-Emby-Token=secret-token&fields=ShareLevel": context canceled`)

	for _, blocked := range []string{"?", "secret-token", "X-Emby-Token", "fields=ShareLevel"} {
		if strings.Contains(got, blocked) {
			t.Fatalf("formatValue() kept query content %q in %q", blocked, got)
		}
	}
	if !strings.Contains(got, "https://emby.example/emby/Items/1") {
		t.Fatalf("formatValue() = %q, want URL path", got)
	}
}

func TestLoggerEntriesReturnQuerylessConsoleLines(t *testing.T) {
	log := New("debug", true)
	log.Info("proxy", "target headers received", map[string]any{
		"target": "https://emby.example/Items?api_key=secret-key&Fields=Name",
		"status": 200,
	})

	entries := log.Entries(10)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	got := entries[0]
	if got.ID != 1 || got.Level != "info" || got.Scope != "proxy" {
		t.Fatalf("entry metadata = %+v", got)
	}
	for _, blocked := range []string{"?", "secret-key", "api_key", "Fields=Name"} {
		if strings.Contains(got.Line, blocked) {
			t.Fatalf("entry line kept query content %q: %q", blocked, got.Line)
		}
	}
	for _, want := range []string{"INFO", "[200]", "[proxy]", "target=https://emby.example/Items"} {
		if !strings.Contains(got.Line, want) {
			t.Fatalf("entry line = %q, want to contain %q", got.Line, want)
		}
	}
}

func TestLoggerStoresEntriesBelowConfiguredLevel(t *testing.T) {
	log := New("silent", true)
	log.Debug("test", "debug line", nil)
	log.Info("test", "info line", nil)
	log.Warn("test", "warn line", nil)
	log.Error("test", "error line", nil)

	if got := messages(log.Entries(10)); got != "debug line,info line,warn line,error line" {
		t.Fatalf("entries = %q, want all levels", got)
	}
}

func TestLoggerSubscribeReceivesStoredEntries(t *testing.T) {
	log := New("silent", true)
	ch, cancel := log.Subscribe(1)
	defer cancel()

	log.Info("test", "streamed line", nil)

	select {
	case entry := <-ch:
		if entry.ID != 1 || entry.Level != "info" || entry.Message != "streamed line" {
			t.Fatalf("streamed entry = %+v", entry)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for streamed log entry")
	}
}

func TestLoggerSubscribeReceivesClearBeforeNextEntry(t *testing.T) {
	log := New("silent", true)
	ch, cancel := log.Subscribe(4)
	defer cancel()

	log.Info("test", "before clear", nil)
	first := <-ch
	if first.ID != 1 || first.Type != "" {
		t.Fatalf("first event = %+v", first)
	}
	if err := log.Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	log.Info("test", "after clear", nil)

	clearEvent := <-ch
	if clearEvent.Type != "clear" {
		t.Fatalf("clear event = %+v", clearEvent)
	}
	next := <-ch
	if next.ID != 2 || next.Message != "after clear" {
		t.Fatalf("next event = %+v, want monotonic id after clear", next)
	}
}

func TestLoggerSubscribeReceivesClearWhenBufferFull(t *testing.T) {
	log := New("silent", true)
	ch, cancel := log.Subscribe(1)
	defer cancel()

	log.Info("test", "stale line", nil)
	if err := log.Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	select {
	case event := <-ch:
		if event.Type != "clear" {
			t.Fatalf("event = %+v, want clear event", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for clear event")
	}
}

func TestFormatMetaUsesSemanticFieldOrder(t *testing.T) {
	got := formatMeta(map[string]any{
		"bodyCopyError":   "broken pipe",
		"target":          "https://cdn.example",
		"upstreamPool":    "playbackStream",
		"event":           "requestFinished",
		"totalMs":         24,
		"range":           "bytes=1024-",
		"nodeTarget":      "https://upstream.example",
		"uri":             "/node/<secret>/emby/videos/1/original.mkv",
		"method":          "GET",
		"id":              "req-1",
		"ip":              "127.0.0.1",
		"contentRange":    "bytes 1024-2047/4096",
		"bytes":           1024,
		"responseReadyMs": 8,
		"bodyMs":          16,
	})

	wantOrder := []string{
		"event=requestFinished",
		"id=req-1",
		"method=GET",
		"uri=",
		"ip=127.0.0.1",
		"nodeTarget=https://upstream.example",
		"target=https://cdn.example",
		"upstreamPool=playbackStream",
		"range=\"bytes=1024-\"",
		"contentRange=\"bytes 1024-2047/4096\"",
		" bytes=1024 ",
		"responseReadyMs=8",
		"bodyMs=16",
		"totalMs=24",
		"bodyCopyError=\"broken pipe\"",
	}
	assertLineOrder(t, got, wantOrder)
}

func TestLoggerLineSuppressesMessageWhenEventIsPresent(t *testing.T) {
	log := New("debug", true)
	log.Info("access", "request finished", map[string]any{"event": "requestFinished", "id": "req-1"})

	entries := log.Entries(10)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if strings.Contains(entries[0].Line, "request finished") {
		t.Fatalf("line kept message despite event field: %q", entries[0].Line)
	}
	if !strings.Contains(entries[0].Line, "event=requestFinished id=req-1") {
		t.Fatalf("line = %q, want event and id fields", entries[0].Line)
	}
	if entries[0].Message != "request finished" {
		t.Fatalf("message = %q, want preserved message", entries[0].Message)
	}
}

func TestLoggerEntriesHonorsLimit(t *testing.T) {
	log := New("debug", true)
	log.Info("test", "one", nil)
	log.Warn("test", "two", nil)
	log.Error("test", "three", nil)

	entries := log.Entries(2)
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	if entries[0].Message != "two" || entries[1].Message != "three" {
		t.Fatalf("entries = %+v, want last two messages", entries)
	}
}

func TestLoggerHistoryPagination(t *testing.T) {
	tests := []struct {
		name       string
		maxFiles   int
		wantOldest string
	}{
		{name: "history pages older entries", maxFiles: 3, wantOldest: "line-1"},
		{name: "latest page uses memory buffer when history rotated away", maxFiles: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := New("debug", true)
			if err := log.EnableHistory(filepath.Join(t.TempDir(), "console-logs.jsonl"), 2, tt.maxFiles); err != nil {
				t.Fatalf("EnableHistory() error = %v", err)
			}
			t.Cleanup(func() { _ = log.Close() })
			for i := 1; i <= 5; i++ {
				log.Info("test", fmt.Sprintf("line-%d", i), nil)
			}

			latest := log.Page(2, 0, LogFilter{})
			if !latest.History || !latest.HasOlder {
				t.Fatalf("latest page metadata = %+v", latest)
			}
			if messages(latest.Entries) != "line-4,line-5" {
				t.Fatalf("latest messages = %q", messages(latest.Entries))
			}

			older := log.Page(2, latest.Entries[0].ID, LogFilter{})
			if messages(older.Entries) != "line-2,line-3" {
				t.Fatalf("older messages = %q", messages(older.Entries))
			}
			if tt.wantOldest == "" {
				return
			}
			if !older.HasOlder {
				t.Fatalf("older page metadata = %+v", older)
			}

			oldest := log.Page(2, older.Entries[0].ID, LogFilter{})
			if oldest.HasOlder {
				t.Fatalf("oldest page metadata = %+v", oldest)
			}
			if messages(oldest.Entries) != tt.wantOldest {
				t.Fatalf("oldest messages = %q", messages(oldest.Entries))
			}
		})
	}
}

func TestLoggerHistoryPaginationFiltersAcrossHistoryAndBuffer(t *testing.T) {
	tests := []struct {
		name      string
		maxFiles  int
		query     string
		wantLines string
		wantOlder bool
	}{
		{
			name:      "match only in rotated history",
			maxFiles:  3,
			query:     "line-1",
			wantLines: "line-1",
		},
		{
			name:      "match only in memory after history rotation",
			maxFiles:  1,
			query:     "line-4",
			wantLines: "line-4",
		},
		{
			name:      "full page across history and memory",
			maxFiles:  3,
			query:     "line-",
			wantLines: "line-4,line-5",
			wantOlder: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := New("debug", true)
			if err := log.EnableHistory(filepath.Join(t.TempDir(), "console-logs.jsonl"), 2, tt.maxFiles); err != nil {
				t.Fatalf("EnableHistory() error = %v", err)
			}
			t.Cleanup(func() { _ = log.Close() })
			for i := 1; i <= 5; i++ {
				log.Info("test", fmt.Sprintf("line-%d", i), nil)
			}

			page := log.Page(2, 0, LogFilter{Query: tt.query})
			if !page.History || page.HasOlder != tt.wantOlder {
				t.Fatalf("page metadata = %+v", page)
			}
			if got := messages(page.Entries); got != tt.wantLines {
				t.Fatalf("page entries = %q, want %q", got, tt.wantLines)
			}
		})
	}
}

func TestLoggerHistoryPageNumber(t *testing.T) {
	log := New("debug", true)
	if err := log.EnableHistory(filepath.Join(t.TempDir(), "console-logs.jsonl"), 2, 3); err != nil {
		t.Fatalf("EnableHistory() error = %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i := 1; i <= 5; i++ {
		log.Info("test", fmt.Sprintf("line-%d", i), nil)
	}

	tests := []struct {
		page      int
		wantPage  int
		wantLines string
		wantOlder bool
	}{
		{page: 1, wantPage: 1, wantLines: "line-4,line-5", wantOlder: true},
		{page: 2, wantPage: 2, wantLines: "line-2,line-3", wantOlder: true},
		{page: 3, wantPage: 3, wantLines: "line-1"},
		{page: 99, wantPage: 3, wantLines: "line-1"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("page-%d", tt.page), func(t *testing.T) {
			page := log.PageNumber(2, tt.page, LogFilter{})
			if page.Page != tt.wantPage || page.TotalPages != 3 || page.TotalEntries != 5 || page.HasOlder != tt.wantOlder {
				t.Fatalf("page metadata = %+v", page)
			}
			if got := messages(page.Entries); got != tt.wantLines {
				t.Fatalf("page entries = %q, want %q", got, tt.wantLines)
			}
		})
	}
}

func TestLoggerHistoryPageNumberUsesMemoryIndex(t *testing.T) {
	log := New("debug", true)
	historyPath := filepath.Join(t.TempDir(), "console-logs.jsonl")
	if err := log.EnableHistory(historyPath, 2, 3); err != nil {
		t.Fatalf("EnableHistory() error = %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i := 1; i <= 7; i++ {
		log.Info("test", fmt.Sprintf("line-%d", i), nil)
	}

	if got := log.history.index.Capacity(); got != 6 {
		t.Fatalf("history index capacity = %d, want 6", got)
	}
	page := log.PageNumber(2, 1, LogFilter{})
	if page.TotalEntries != 6 || page.TotalPages != 3 || !page.HasOlder {
		t.Fatalf("page metadata = %+v", page)
	}
	if got := messages(page.Entries); got != "line-6,line-7" {
		t.Fatalf("page entries = %q, want latest retained entries", got)
	}

	if err := log.history.Close(); err != nil {
		t.Fatalf("history Close() error = %v", err)
	}
	for _, path := range log.history.pathsNewestFirst() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatalf("Remove(%q) error = %v", path, err)
		}
	}

	page = log.PageNumber(2, 2, LogFilter{})
	if page.TotalEntries != 6 || page.Page != 2 || messages(page.Entries) != "line-4,line-5" {
		t.Fatalf("page after deleting history files = %+v", page)
	}
}

func TestLoggerHistoryPageNumberDoesNotWaitForHistoryWriteLock(t *testing.T) {
	log := New("debug", true)
	if err := log.EnableHistory(filepath.Join(t.TempDir(), "console-logs.jsonl"), 2, 3); err != nil {
		t.Fatalf("EnableHistory() error = %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	log.Info("test", "line", nil)

	locked := make(chan struct{})
	release := make(chan struct{})
	go func() {
		log.history.mu.Lock()
		close(locked)
		<-release
		log.history.mu.Unlock()
	}()
	<-locked

	pageDone := make(chan LogPage, 1)
	go func() {
		pageDone <- log.PageNumber(2, 1, LogFilter{})
	}()
	select {
	case page := <-pageDone:
		if messages(page.Entries) != "line" {
			t.Fatalf("page entries = %q, want line", messages(page.Entries))
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("PageNumber() waited for the history write lock")
	}
	close(release)
}

type failingLogWriter struct{}

func (failingLogWriter) Write([]byte) (int, error) {
	return 0, os.ErrPermission
}

func TestLoggerHistoryIndexKeepsEntriesWhenPersistenceFails(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "console-logs.jsonl")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	log := New("debug", true)
	log.history = &logHistory{
		path:           file.Name(),
		entriesPerFile: 2,
		maxFiles:       3,
		file:           file,
		writer:         bufio.NewWriterSize(failingLogWriter{}, 1),
		index:          newLogBuffer(6),
		done:           make(chan struct{}),
	}
	t.Cleanup(func() { _ = os.Remove(file.Name()) })
	t.Cleanup(func() { _ = log.Close() })

	log.Info("test", "line", nil)
	page := log.PageNumber(2, 1, LogFilter{})
	if !page.History || messages(page.Entries) != "line" {
		t.Fatalf("page after persistence failure = %+v", page)
	}
}

func TestLoggerHistoryIndexSurvivesPersistenceRecoveryAndRotation(t *testing.T) {
	log := New("debug", true)
	historyPath := filepath.Join(t.TempDir(), "console-logs.jsonl")
	if err := log.EnableHistory(historyPath, 2, 3); err != nil {
		t.Fatalf("EnableHistory() error = %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i := 1; i <= 6; i++ {
		log.Info("test", fmt.Sprintf("line-%d", i), nil)
	}

	history := log.history
	history.mu.Lock()
	closeErr := history.closeWriterLocked()
	history.mu.Unlock()
	if closeErr != nil {
		t.Fatalf("closeWriterLocked() error = %v", closeErr)
	}
	file, err := os.OpenFile(historyPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	failingWriter := bufio.NewWriterSize(failingLogWriter{}, 16)
	if err := failingWriter.WriteByte('x'); err != nil {
		t.Fatalf("failing writer setup error = %v", err)
	}
	history.mu.Lock()
	history.file = file
	history.writer = failingWriter
	history.mu.Unlock()

	log.Info("test", "line-7", nil)
	history.mu.Lock()
	entryCountAfterFailure := history.entryCount
	history.mu.Unlock()
	if entryCountAfterFailure != 2 {
		t.Fatalf("entry count after persistence failure = %d, want 2", entryCountAfterFailure)
	}
	for i := 8; i <= 10; i++ {
		log.Info("test", fmt.Sprintf("line-%d", i), nil)
	}
	page := log.PageNumber(10, 1, LogFilter{})
	if page.TotalEntries != 6 || messages(page.Entries) != "line-5,line-6,line-7,line-8,line-9,line-10" {
		t.Fatalf("page after persistence recovery = %+v", page)
	}
}

func TestLogFilterMatch(t *testing.T) {
	entry := LogEntry{
		Level: "error",
		Line:  "2026-06-16T12:00:00+08:00 [ERROR] [proxy] event=requestFinished id=req-42 uri=/Videos/1",
	}
	tests := []struct {
		name   string
		filter LogFilter
		want   bool
	}{
		{name: "empty filter", want: true},
		{name: "level matches", filter: LogFilter{Levels: map[string]bool{"error": true}}, want: true},
		{name: "level mismatch", filter: LogFilter{Levels: map[string]bool{"warn": true}}},
		{name: "query matches line", filter: LogFilter{Query: "req-42"}, want: true},
		{name: "query is case insensitive", filter: LogFilter{Query: "videos/1"}, want: true},
		{name: "query mismatch", filter: LogFilter{Query: "req-99"}},
		{name: "level and query match", filter: LogFilter{Levels: map[string]bool{"error": true}, Query: "requestfinished"}, want: true},
		{name: "level match but query mismatch", filter: LogFilter{Levels: map[string]bool{"error": true}, Query: "not-found"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.match(entry); got != tt.want {
				t.Fatalf("match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoggerPageNumberFiltersEntries(t *testing.T) {
	tests := []struct {
		name        string
		withHistory bool
	}{
		{name: "buffer"},
		{name: "history", withHistory: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := New("debug", true)
			if tt.withHistory {
				if err := log.EnableHistory(filepath.Join(t.TempDir(), "console-logs.jsonl"), 2, 3); err != nil {
					t.Fatalf("EnableHistory() error = %v", err)
				}
				t.Cleanup(func() { _ = log.Close() })
			}
			log.Info("proxy", "alpha path", map[string]any{"id": "req-alpha", "uri": "/Items/1"})
			log.Warn("proxy", "beta path", map[string]any{"id": "req-beta", "uri": "/Videos/2"})
			log.Error("proxy", "gamma failure", map[string]any{"id": "req-gamma", "uri": "/Videos/3"})
			log.Info("proxy", "delta path", map[string]any{"id": "req-delta", "uri": "/Users/1"})
			log.Error("proxy", "epsilon failure", map[string]any{"id": "req-epsilon", "uri": "/Videos/5"})

			cases := []struct {
				name         string
				limit        int
				page         int
				filter       LogFilter
				wantPage     int
				wantTotal    int
				wantPages    int
				wantOlder    bool
				wantMessages string
			}{
				{
					name:         "empty filter matches original pagination",
					limit:        2,
					page:         1,
					wantPage:     1,
					wantTotal:    5,
					wantPages:    3,
					wantOlder:    true,
					wantMessages: "delta path,epsilon failure",
				},
				{
					name:         "level filter latest page",
					limit:        1,
					page:         1,
					filter:       LogFilter{Levels: map[string]bool{"error": true}},
					wantPage:     1,
					wantTotal:    2,
					wantPages:    2,
					wantOlder:    true,
					wantMessages: "epsilon failure",
				},
				{
					name:         "level filter older page",
					limit:        1,
					page:         2,
					filter:       LogFilter{Levels: map[string]bool{"error": true}},
					wantPage:     2,
					wantTotal:    2,
					wantPages:    2,
					wantMessages: "gamma failure",
				},
				{
					name:         "query searches full line",
					limit:        2,
					page:         1,
					filter:       LogFilter{Query: "req-beta"},
					wantPage:     1,
					wantTotal:    1,
					wantPages:    1,
					wantMessages: "beta path",
				},
				{
					name:         "level and query combine",
					limit:        2,
					page:         1,
					filter:       LogFilter{Levels: map[string]bool{"info": true}, Query: "/users/1"},
					wantPage:     1,
					wantTotal:    1,
					wantPages:    1,
					wantMessages: "delta path",
				},
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					page := log.PageNumber(tc.limit, tc.page, tc.filter)
					if page.Page != tc.wantPage || page.TotalEntries != tc.wantTotal || page.TotalPages != tc.wantPages || page.HasOlder != tc.wantOlder {
						t.Fatalf("page metadata = %+v", page)
					}
					if got := messages(page.Entries); got != tc.wantMessages {
						t.Fatalf("page entries = %q, want %q", got, tc.wantMessages)
					}
				})
			}
		})
	}
}

func TestLoggerEnableHistoryClosesPreviousHistory(t *testing.T) {
	log := New("debug", true)
	historyPath := filepath.Join(t.TempDir(), "console-logs.jsonl")
	t.Cleanup(func() { _ = log.Close() })
	if err := log.EnableHistory(historyPath, 10, 2); err != nil {
		t.Fatalf("EnableHistory() error = %v", err)
	}
	log.Info("test", "before", nil)

	if err := log.EnableHistory(historyPath, 10, 2); err != nil {
		t.Fatalf("second EnableHistory() error = %v", err)
	}
	log.Info("test", "after", nil)
}

func TestLoggerClearRemovesBufferedAndHistoryEntries(t *testing.T) {
	log := New("debug", true)
	if err := log.EnableHistory(filepath.Join(t.TempDir(), "console-logs.jsonl"), 2, 3); err != nil {
		t.Fatalf("EnableHistory() error = %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i := 1; i <= 3; i++ {
		log.Info("test", fmt.Sprintf("before-%d", i), nil)
	}
	if page := log.Page(10, 0, LogFilter{}); messages(page.Entries) != "before-1,before-2,before-3" {
		t.Fatalf("entries before clear = %q", messages(page.Entries))
	}

	if err := log.Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	cleared := log.Page(10, 0, LogFilter{})
	if len(cleared.Entries) != 0 || cleared.HasOlder != false || !cleared.History {
		t.Fatalf("page after clear = %+v", cleared)
	}
	if got := log.NewestID(); got != 0 {
		t.Fatalf("NewestID() after clear = %d, want 0", got)
	}
	log.Info("test", "after", nil)
	latest := log.Page(10, 0, LogFilter{})
	if messages(latest.Entries) != "after" {
		t.Fatalf("entries after clear = %q", messages(latest.Entries))
	}
	if latest.Entries[0].ID != 4 {
		t.Fatalf("first entry ID after clear = %d, want 4", latest.Entries[0].ID)
	}
	if got := log.NewestID(); got != 4 {
		t.Fatalf("NewestID() after new entry = %d, want 4", got)
	}
}

func messages(entries []LogEntry) string {
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry.Message)
	}
	return strings.Join(values, ",")
}

func assertLineOrder(t *testing.T, line string, fragments []string) {
	t.Helper()
	last := -1
	for _, fragment := range fragments {
		idx := strings.Index(line, fragment)
		if idx < 0 {
			t.Fatalf("line = %q, want fragment %q", line, fragment)
		}
		if idx <= last {
			t.Fatalf("line = %q, fragment %q appeared out of order", line, fragment)
		}
		last = idx
	}
}
