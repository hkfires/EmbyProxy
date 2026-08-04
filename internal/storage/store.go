package storage

import (
	"container/list"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db                *sql.DB
	mu                sync.RWMutex
	nodeCache         map[string]cacheEntry[*Node]
	negativeNodeMu    sync.Mutex
	negativeNodeCache map[string]*list.Element
	negativeNodeOrder *list.List
	nodeListCache     map[string]cacheEntry[[]Node]
	hostIndexCache    map[string]cacheEntry[map[string]HostMatch]
	sysConfigCache    systemConfigCacheEntry
	sysConfigGen      uint64
	nodeCacheGen      uint64
	playbackMu        sync.RWMutex
	playbackClosed    bool
	playbackQueue     chan PlaybackInput
	playbackWG        sync.WaitGroup
	playbackDropped   uint64
}

type KV struct {
	store *Store
}

type cacheEntry[T any] struct {
	value T
	exp   time.Time
}

type systemConfigCacheEntry struct {
	value SystemConfig
	ok    bool
	exp   time.Time
}

const (
	systemConfigCacheTTL      = 5 * time.Second
	nodeCacheTTL              = 10 * time.Second
	negativeNodeCacheCapacity = 4096
)

type negativeNodeCacheEntry struct {
	key string
	exp time.Time
}

type ListResult struct {
	Keys         []string
	ListComplete bool
	Cursor       int
}

func New(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &Store{
		db:                db,
		nodeCache:         map[string]cacheEntry[*Node]{},
		negativeNodeCache: map[string]*list.Element{},
		negativeNodeOrder: list.New(),
		nodeListCache:     map[string]cacheEntry[[]Node]{},
		hostIndexCache:    map[string]cacheEntry[map[string]HostMatch]{},
	}
	if err := store.InitSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	store.startPlaybackAsyncLogger()
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.closePlaybackAsyncLogger()
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) KV() *KV {
	return &KV{store: s}
}

func (s *Store) InitSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS proxy_kv (
			k TEXT PRIMARY KEY,
			v TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS keepalive_state (
			node TEXT PRIMARY KEY,
			anchor_ts INTEGER NOT NULL,
			last_play_ts INTEGER DEFAULT 0,
			last_notify_day TEXT,
			notify_count_day TEXT,
			notify_count INTEGER DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS play_sessions (
			k TEXT PRIMARY KEY,
			day TEXT NOT NULL,
			last_ts INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS play_events (
			k TEXT PRIMARY KEY,
			day TEXT NOT NULL,
			last_ts INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS playback_states (
			k TEXT PRIMARY KEY,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			mode TEXT NOT NULL,
			item_key TEXT NOT NULL,
			last_event_ts INTEGER NOT NULL,
			last_position_ticks INTEGER NOT NULL DEFAULT 0,
			has_position INTEGER NOT NULL DEFAULT 0,
			is_paused INTEGER NOT NULL DEFAULT 0,
			closed INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_playback_states_updated_at ON playback_states(updated_at);
		CREATE TABLE IF NOT EXISTS play_stats (
			day TEXT NOT NULL,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			plays INTEGER DEFAULT 0,
			playback_ms INTEGER DEFAULT 0,
			bytes INTEGER DEFAULT 0,
			inbound_bytes INTEGER DEFAULT 0,
			outbound_bytes INTEGER DEFAULT 0,
			sessions INTEGER DEFAULT 0,
			errors INTEGER DEFAULT 0,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(day, node, client)
		);
		CREATE TABLE IF NOT EXISTS play_buckets (
			bucket_start INTEGER NOT NULL,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			mode TEXT NOT NULL,
			plays INTEGER DEFAULT 0,
			playback_ms INTEGER DEFAULT 0,
			bytes INTEGER DEFAULT 0,
			inbound_bytes INTEGER DEFAULT 0,
			outbound_bytes INTEGER DEFAULT 0,
			sessions INTEGER DEFAULT 0,
			errors INTEGER DEFAULT 0,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(bucket_start, node, client, mode)
		);
	`)
	if err != nil {
		return err
	}
	return s.ensurePlaybackStatColumns(ctx)
}

func (s *Store) ensurePlaybackStatColumns(ctx context.Context) error {
	for table, columns := range map[string][]string{
		"play_stats": {
			"playback_ms INTEGER DEFAULT 0",
			"inbound_bytes INTEGER DEFAULT 0",
			"outbound_bytes INTEGER DEFAULT 0",
		},
		"play_buckets": {
			"playback_ms INTEGER DEFAULT 0",
		},
		"playback_states": {
			"closed INTEGER DEFAULT 0",
		},
	} {
		cols, err := s.tableColumns(ctx, table)
		if err != nil {
			return err
		}
		for _, column := range columns {
			name := strings.Fields(column)[0]
			if cols[name] {
				continue
			}
			if _, err := s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) tableColumns(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

func (kv *KV) Get(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := kv.store.db.QueryRowContext(ctx, `SELECT v FROM proxy_kv WHERE k = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (kv *KV) GetJSON(ctx context.Context, key string, dst any) (bool, error) {
	value, ok, err := kv.Get(ctx, key)
	if err != nil || !ok {
		return ok, err
	}
	if err := json.Unmarshal([]byte(value), dst); err != nil {
		return false, nil
	}
	return true, nil
}

func (kv *KV) Put(ctx context.Context, key string, value any) error {
	var raw string
	switch v := value.(type) {
	case string:
		raw = v
	case []byte:
		raw = string(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		raw = string(b)
	}
	_, err := kv.store.db.ExecContext(ctx, `
		INSERT INTO proxy_kv (k, v, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at
	`, key, raw, time.Now().UnixMilli())
	return err
}

func (kv *KV) Delete(ctx context.Context, key string) error {
	_, err := kv.store.db.ExecContext(ctx, `DELETE FROM proxy_kv WHERE k = ?`, key)
	return err
}

func (kv *KV) List(ctx context.Context, prefix string, cursor, limit int) (ListResult, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	if cursor < 0 {
		cursor = 0
	}
	rows, err := kv.store.db.QueryContext(ctx, `SELECT k FROM proxy_kv WHERE k LIKE ? ORDER BY k LIMIT ? OFFSET ?`, prefix+"%", limit+1, cursor)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()
	keys := make([]string, 0, limit+1)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return ListResult{}, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, err
	}
	complete := len(keys) <= limit
	if !complete {
		keys = keys[:limit]
	}
	return ListResult{Keys: keys, ListComplete: complete, Cursor: cursor + limit}, nil
}

func (s *Store) GetNode(ctx context.Context, uid, name string) (*Node, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	cacheKey := uid + ":" + name
	if node, ok := s.getNodeCache(cacheKey); ok {
		return node, nil
	}
	if s.getNegativeNodeCache(cacheKey) {
		return nil, nil
	}
	nodeCacheGen := s.nodeCacheGeneration()
	packed, ok, err := s.KV().Get(ctx, "u:"+uid+":node:"+name)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.setNegativeNodeCacheIfGeneration(cacheKey, nodeCacheTTL, nodeCacheGen)
		return nil, nil
	}
	node, valid := UnpackNode(name, packed)
	if !valid {
		s.setNegativeNodeCacheIfGeneration(cacheKey, nodeCacheTTL, nodeCacheGen)
		return nil, nil
	}
	s.setNodeCacheIfGeneration(cacheKey, &node, nodeCacheTTL, nodeCacheGen)
	return &node, nil
}

// CleanupNodeCache removes expired positive and negative node cache entries.
func (s *Store) CleanupNodeCache() {
	if s == nil {
		return
	}
	now := time.Now()
	s.mu.Lock()
	for key, entry := range s.nodeCache {
		if now.After(entry.exp) {
			delete(s.nodeCache, key)
		}
	}
	s.mu.Unlock()

	s.negativeNodeMu.Lock()
	defer s.negativeNodeMu.Unlock()
	for key, element := range s.negativeNodeCache {
		entry, ok := element.Value.(negativeNodeCacheEntry)
		if !ok || now.After(entry.exp) {
			delete(s.negativeNodeCache, key)
			s.negativeNodeOrder.Remove(element)
		}
	}
}

func (s *Store) ListNodes(ctx context.Context, uid string) ([]Node, error) {
	cacheKey := "list:" + uid
	if nodes, ok := s.getListCache(cacheKey); ok {
		return cloneNodes(nodes), nil
	}
	prefix := "u:" + uid + ":node:"
	cursor := 0
	nodes := []Node{}
	for {
		res, err := s.KV().List(ctx, prefix, cursor, 1000)
		if err != nil {
			return nil, err
		}
		for _, key := range res.Keys {
			name := strings.TrimPrefix(key, prefix)
			packed, ok, err := s.KV().Get(ctx, key)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if node, valid := UnpackNode(name, packed); valid {
				nodes = append(nodes, node)
			}
		}
		if res.ListComplete {
			break
		}
		cursor = res.Cursor
	}
	SortNodes(nodes)
	s.setListCache(cacheKey, cloneNodes(nodes), 3*time.Minute)
	return nodes, nil
}

func (s *Store) SaveNode(ctx context.Context, uid string, node Node) error {
	node.Name = strings.ToLower(strings.TrimSpace(node.Name))
	packed, err := PackNode(node)
	if err != nil {
		return err
	}
	if err := s.KV().Put(ctx, "u:"+uid+":node:"+node.Name, packed); err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO keepalive_state (node, anchor_ts) VALUES (?, ?)
		ON CONFLICT(node) DO NOTHING
	`, uid+":"+node.Name, now); err != nil {
		return err
	}
	s.InvalidateNodeCache(uid, node.Name)
	return nil
}

func (s *Store) DeleteNode(ctx context.Context, uid, name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if err := s.KV().Delete(ctx, "u:"+uid+":node:"+name); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM keepalive_state WHERE node = ?`, uid+":"+name); err != nil {
		return err
	}
	s.InvalidateNodeCache(uid, name)
	return nil
}

func (s *Store) InvalidateNodeCache(uid, name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	key := uid + ":" + name
	s.mu.Lock()
	s.nodeCacheGen++
	delete(s.nodeCache, key)
	delete(s.nodeListCache, "list:"+uid)
	delete(s.hostIndexCache, "hostidx:"+uid)
	s.mu.Unlock()

	s.negativeNodeMu.Lock()
	defer s.negativeNodeMu.Unlock()
	if element, ok := s.negativeNodeCache[key]; ok {
		delete(s.negativeNodeCache, key)
		s.negativeNodeOrder.Remove(element)
	}
}

func (s *Store) GetHostIndex(ctx context.Context, uid string) (map[string]HostMatch, error) {
	cacheKey := "hostidx:" + uid
	if hit, ok := s.getHostIndexCache(cacheKey); ok {
		return cloneHostIndex(hit), nil
	}
	nodes, err := s.ListNodes(ctx, uid)
	if err != nil {
		return nil, err
	}
	out := map[string]HostMatch{}
	for _, node := range nodes {
		for _, target := range SplitTargets(node.Target) {
			u, err := url.Parse(target)
			if err == nil && u.Host != "" {
				out[strings.ToLower(u.Host)] = HostMatch{Name: node.Name, Secret: node.Secret}
			}
		}
	}
	s.setHostIndexCache(cacheKey, cloneHostIndex(out), 3*time.Minute)
	return out, nil
}

func (s *Store) GetTGConfig(ctx context.Context) (TGConfig, error) {
	var cfg TGConfig
	value, ok, err := s.KV().Get(ctx, "tg:config")
	if err != nil || !ok {
		return TGConfig{Enabled: false}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &raw); err != nil {
		return TGConfig{Enabled: false}, nil
	}
	if err := json.Unmarshal([]byte(value), &cfg); err != nil {
		return TGConfig{Enabled: false}, nil
	}
	if _, ok := raw["reportEnabled"]; !ok && cfg.Enabled {
		cfg.ReportEnabled = true
	}
	return cfg, nil
}

func (s *Store) SaveTGConfig(ctx context.Context, cfg TGConfig) error {
	return s.KV().Put(ctx, "tg:config", cfg)
}

func (s *Store) GetSystemConfig(ctx context.Context, fallback SystemConfig) (SystemConfig, error) {
	s.mu.RLock()
	entry := s.sysConfigCache
	gen := s.sysConfigGen
	s.mu.RUnlock()
	if !entry.exp.IsZero() && time.Now().Before(entry.exp) {
		if entry.ok {
			return entry.value, nil
		}
		return fallback, nil
	}

	cfg := fallback
	ok, err := s.KV().GetJSON(ctx, "system:config", &cfg)
	if err != nil || !ok {
		if err == nil {
			s.setSystemConfigCacheIfGen(gen, SystemConfig{}, false, systemConfigCacheTTL)
		}
		return fallback, err
	}
	s.setSystemConfigCacheIfGen(gen, cfg, true, systemConfigCacheTTL)
	return cfg, nil
}

func (s *Store) SaveSystemConfig(ctx context.Context, cfg SystemConfig) error {
	if err := s.KV().Put(ctx, "system:config", cfg); err != nil {
		s.invalidateSystemConfigCache()
		return err
	}
	s.setSystemConfigCache(cfg, true, systemConfigCacheTTL)
	return nil
}

func (s *Store) setSystemConfigCache(value SystemConfig, ok bool, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sysConfigGen++
	s.sysConfigCache = systemConfigCacheEntry{value: value, ok: ok, exp: time.Now().Add(ttl)}
}

func (s *Store) setSystemConfigCacheIfGen(gen uint64, value SystemConfig, ok bool, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sysConfigGen != gen {
		return
	}
	s.sysConfigCache = systemConfigCacheEntry{value: value, ok: ok, exp: time.Now().Add(ttl)}
}

func (s *Store) invalidateSystemConfigCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sysConfigGen++
	s.sysConfigCache = systemConfigCacheEntry{}
}

func (s *Store) getNodeCache(key string) (*Node, bool) {
	s.mu.RLock()
	entry, ok := s.nodeCache[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(entry.exp) {
		if ok {
			s.mu.Lock()
			delete(s.nodeCache, key)
			s.mu.Unlock()
		}
		return nil, false
	}
	if entry.value == nil {
		return nil, true
	}
	node := *entry.value
	return &node, true
}

func (s *Store) nodeCacheGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodeCacheGen
}

func (s *Store) setNodeCacheIfGeneration(key string, value *Node, ttl time.Duration, generation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodeCacheGen != generation {
		return false
	}
	if value == nil {
		s.nodeCache[key] = cacheEntry[*Node]{value: nil, exp: time.Now().Add(ttl)}
		return true
	}
	node := *value
	s.nodeCache[key] = cacheEntry[*Node]{value: &node, exp: time.Now().Add(ttl)}
	return true
}

func (s *Store) getNegativeNodeCache(key string) bool {
	now := time.Now()
	s.negativeNodeMu.Lock()
	defer s.negativeNodeMu.Unlock()
	element, ok := s.negativeNodeCache[key]
	if !ok {
		return false
	}
	entry, valid := element.Value.(negativeNodeCacheEntry)
	if !valid || now.After(entry.exp) {
		delete(s.negativeNodeCache, key)
		s.negativeNodeOrder.Remove(element)
		return false
	}
	s.negativeNodeOrder.MoveToFront(element)
	return true
}

func (s *Store) setNegativeNodeCache(key string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	now := time.Now()
	s.negativeNodeMu.Lock()
	defer s.negativeNodeMu.Unlock()
	if element, ok := s.negativeNodeCache[key]; ok {
		element.Value = negativeNodeCacheEntry{key: key, exp: now.Add(ttl)}
		s.negativeNodeOrder.MoveToFront(element)
		return
	}
	element := s.negativeNodeOrder.PushFront(negativeNodeCacheEntry{key: key, exp: now.Add(ttl)})
	s.negativeNodeCache[key] = element
	for len(s.negativeNodeCache) > negativeNodeCacheCapacity {
		oldest := s.negativeNodeOrder.Back()
		if oldest == nil {
			break
		}
		entry, _ := oldest.Value.(negativeNodeCacheEntry)
		delete(s.negativeNodeCache, entry.key)
		s.negativeNodeOrder.Remove(oldest)
	}
}

func (s *Store) setNegativeNodeCacheIfGeneration(key string, ttl time.Duration, generation uint64) bool {
	if ttl <= 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.nodeCacheGen != generation {
		return false
	}
	s.setNegativeNodeCache(key, ttl)
	return true
}

func (s *Store) getListCache(key string) ([]Node, bool) {
	s.mu.RLock()
	entry, ok := s.nodeListCache[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(entry.exp) {
		if ok {
			s.mu.Lock()
			delete(s.nodeListCache, key)
			s.mu.Unlock()
		}
		return nil, false
	}
	return cloneNodes(entry.value), true
}

func (s *Store) setListCache(key string, value []Node, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeListCache[key] = cacheEntry[[]Node]{value: cloneNodes(value), exp: time.Now().Add(ttl)}
}

func (s *Store) getHostIndexCache(key string) (map[string]HostMatch, bool) {
	s.mu.RLock()
	entry, ok := s.hostIndexCache[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(entry.exp) {
		if ok {
			s.mu.Lock()
			delete(s.hostIndexCache, key)
			s.mu.Unlock()
		}
		return nil, false
	}
	return cloneHostIndex(entry.value), true
}

func (s *Store) setHostIndexCache(key string, value map[string]HostMatch, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostIndexCache[key] = cacheEntry[map[string]HostMatch]{value: cloneHostIndex(value), exp: time.Now().Add(ttl)}
}

func cloneNodes(nodes []Node) []Node {
	out := make([]Node, len(nodes))
	copy(out, nodes)
	return out
}

func cloneHostIndex(in map[string]HostMatch) map[string]HostMatch {
	out := make(map[string]HostMatch, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

func mustJSON(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(b)
}
