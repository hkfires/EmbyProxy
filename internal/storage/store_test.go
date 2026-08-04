package storage

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
)

func TestAdmin2FAConfigCRUDAndCorruption(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, configured, err := store.GetAdmin2FAConfig(ctx); err != nil || configured {
		t.Fatalf("initial config = configured %v, err %v", configured, err)
	}
	want := Admin2FAConfig{Version: 1, Salt: "salt", Nonce: "nonce", Ciphertext: "cipher", EnrolledAt: 1234, LastUsedStep: 42}
	if err := store.SaveAdmin2FAConfig(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, configured, err := store.GetAdmin2FAConfig(ctx)
	if err != nil || !configured || got != want {
		t.Fatalf("stored config = %+v, configured %v, err %v", got, configured, err)
	}
	if err := store.KV().Put(ctx, admin2FAConfigKey, "{broken"); err != nil {
		t.Fatal(err)
	}
	if _, configured, err := store.GetAdmin2FAConfig(ctx); err == nil || !configured {
		t.Fatalf("corrupt config = configured %v, err %v", configured, err)
	}
	if err := store.DeleteAdmin2FAConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if _, configured, err := store.GetAdmin2FAConfig(ctx); err != nil || configured {
		t.Fatalf("deleted config = configured %v, err %v", configured, err)
	}
}

func TestDefaultSystemConfigDoesNotTrustProxyHeaders(t *testing.T) {
	if DefaultSystemConfig().TrustProxy {
		t.Fatal("TrustProxy default should be false")
	}
}

func TestGetNodeCachesMissingNodesWithinBound(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	for i := 0; i < negativeNodeCacheCapacity+100; i++ {
		name := "missing-" + strconv.Itoa(i)
		if node, err := store.GetNode(ctx, "admin", name); err != nil || node != nil {
			t.Fatalf("GetNode(%q) = node %v, err %v; want nil, nil", name, node, err)
		}
	}

	store.negativeNodeMu.Lock()
	defer store.negativeNodeMu.Unlock()
	if got := len(store.negativeNodeCache); got > negativeNodeCacheCapacity {
		t.Fatalf("negative node cache size = %d, want <= %d", got, negativeNodeCacheCapacity)
	}
	if got := len(store.negativeNodeCache); got == 0 {
		t.Fatal("negative node cache is empty after missing lookups")
	}
}

func TestNegativeNodeCacheHitKeepsOriginalExpiration(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	key := "admin:first-missing"
	store.setNegativeNodeCache(key, nodeCacheTTL)
	store.setNegativeNodeCache("admin:second-missing", nodeCacheTTL)

	store.negativeNodeMu.Lock()
	element := store.negativeNodeCache[key]
	originalEntry := element.Value.(negativeNodeCacheEntry)
	store.negativeNodeMu.Unlock()

	if !store.getNegativeNodeCache(key) {
		t.Fatal("negative node cache lookup should hit")
	}

	store.negativeNodeMu.Lock()
	defer store.negativeNodeMu.Unlock()
	currentEntry := element.Value.(negativeNodeCacheEntry)
	if !currentEntry.exp.Equal(originalEntry.exp) {
		t.Fatalf("negative node cache expiration changed from %v to %v", originalEntry.exp, currentEntry.exp)
	}
	if store.negativeNodeOrder.Front() != element {
		t.Fatal("negative node cache hit should move the entry to the front")
	}
}

func TestSaveNodeInvalidatesMissingNodeCache(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if node, err := store.GetNode(ctx, "admin", "new-node"); err != nil || node != nil {
		t.Fatalf("initial GetNode() = node %v, err %v; want nil, nil", node, err)
	}
	if err := store.SaveNode(ctx, "admin", Node{Name: "new-node", Target: "https://upstream.example"}); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}
	node, err := store.GetNode(ctx, "admin", "new-node")
	if err != nil {
		t.Fatalf("GetNode() after SaveNode() error = %v", err)
	}
	if node == nil {
		t.Fatal("GetNode() after SaveNode() returned nil")
	}
}

func TestNodeCacheGenerationSkipsStaleLookupResult(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	key := "admin:race-node"
	generation := store.nodeCacheGeneration()
	store.InvalidateNodeCache("admin", "race-node")
	if store.setNegativeNodeCacheIfGeneration(key, nodeCacheTTL, generation) {
		t.Fatal("stale lookup result should not be cached after invalidation")
	}
	if store.getNegativeNodeCache(key) {
		t.Fatal("stale negative cache entry should not be visible")
	}
}

func TestSystemConfigBackfillsImageDefaults(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	fallback := DefaultSystemConfig()
	if err := store.KV().Put(ctx, "system:config", map[string]any{"logLevel": "debug"}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	got, err := store.GetSystemConfig(ctx, fallback)
	if err != nil {
		t.Fatalf("GetSystemConfig() error = %v", err)
	}
	if got.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want debug", got.LogLevel)
	}
	if got.ImageProxyLimitEnabled != fallback.ImageProxyLimitEnabled || got.ImageProxyMaxConcurrent != fallback.ImageProxyMaxConcurrent || got.ImageProxyRequestIntervalMS != fallback.ImageProxyRequestIntervalMS || got.ImageCacheEnabled != fallback.ImageCacheEnabled || got.ImageCacheTTLDays != fallback.ImageCacheTTLDays {
		t.Fatalf("image settings = %+v, want defaults %+v", got, fallback)
	}
}

func TestSystemConfigCacheRefreshesOnSave(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	fallback := DefaultSystemConfig()
	first, err := store.GetSystemConfig(ctx, fallback)
	if err != nil {
		t.Fatalf("GetSystemConfig() error = %v", err)
	}
	if first.LogLevel != fallback.LogLevel {
		t.Fatalf("LogLevel = %q; want fallback %q", first.LogLevel, fallback.LogLevel)
	}

	next := fallback
	next.LogLevel = "debug"
	next.TrustProxy = !fallback.TrustProxy
	if err := store.SaveSystemConfig(ctx, next); err != nil {
		t.Fatalf("SaveSystemConfig() error = %v", err)
	}

	got, err := store.GetSystemConfig(ctx, fallback)
	if err != nil {
		t.Fatalf("GetSystemConfig() after save error = %v", err)
	}
	if got.LogLevel != next.LogLevel || got.TrustProxy != next.TrustProxy {
		t.Fatalf("GetSystemConfig() = %+v; want saved %+v", got, next)
	}
}

func TestTGConfigBackfillsReportEnabledForLegacyEnabledConfig(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.KV().Put(ctx, "tg:config", map[string]any{
		"enabled": true,
		"token":   "token",
		"chat":    "chat",
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := store.GetTGConfig(ctx)
	if err != nil {
		t.Fatalf("GetTGConfig() error = %v", err)
	}
	if !got.ReportEnabled {
		t.Fatalf("ReportEnabled = false, want true for legacy enabled config")
	}
	if got.ServerRemark != "" {
		t.Fatalf("ServerRemark = %q, want empty for legacy config", got.ServerRemark)
	}
}

func TestTGConfigKeepsExplicitReportDisabled(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.SaveTGConfig(ctx, TGConfig{
		Enabled:       true,
		Token:         "token",
		Chat:          "chat",
		ReportEnabled: false,
	}); err != nil {
		t.Fatalf("SaveTGConfig() error = %v", err)
	}

	got, err := store.GetTGConfig(ctx)
	if err != nil {
		t.Fatalf("GetTGConfig() error = %v", err)
	}
	if got.ReportEnabled {
		t.Fatalf("ReportEnabled = true, want false")
	}
}
