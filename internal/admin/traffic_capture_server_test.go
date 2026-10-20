package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func TestTrafficCaptureUsesDeploymentNameForWriteStatsAndClear(t *testing.T) {
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()
	cwd := t.TempDir()
	handler.cfg = config.Config{CWD: cwd, ServerName: "hk1"}
	cfg := storage.DefaultSystemConfig()
	cfg.TrafficCaptureEnabled = true
	if err := handler.store.SaveSystemConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	log := logging.New("silent", false)
	t.Cleanup(func() { _ = log.Close() })

	for _, server := range []string{"hk1", "de1"} {
		recorder := capture.New(config.Config{CWD: cwd, ServerName: server}, handler.store, log)
		for _, node := range []string{"node-a", "node-b"} {
			recorder.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capture.SetMeta(r, map[string]any{"node": node, "stage": node})
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/"+node+"/", nil))
		}
	}

	file := "data/traffic-captures-hk1.jsonl"
	path := filepath.Join(cwd, filepath.FromSlash(file))
	records, err := capture.ReadJSONL(path)
	if err != nil || len(records) != 2 {
		t.Fatalf("ReadJSONL() records=%d error=%v", len(records), err)
	}
	if records[0].Node != "node-a" || records[1].Node != "node-b" {
		t.Fatalf("expected both nodes in the same deployment file, got %q, %q", records[0].Node, records[1].Node)
	}

	legacyPath := filepath.Join(cwd, "data", "traffic-captures.jsonl")
	legacy := []byte("{\"stage\":\"legacy\"}\n")
	if err := os.WriteFile(legacyPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	stats, err := handler.readTrafficCaptureStats(cfg)
	if err != nil || stats.File != file || stats.Records != 2 || stats.Bytes == 0 {
		t.Fatalf("readTrafficCaptureStats() stats=%+v error=%v", stats, err)
	}
	stats, err = handler.clearTrafficCaptureStageRecords(cfg, "node-a")
	if err != nil || stats.File != file || stats.Records != 1 {
		t.Fatalf("clearTrafficCaptureStageRecords() stats=%+v error=%v", stats, err)
	}
	records, err = capture.ReadJSONL(path)
	if err != nil || len(records) != 1 || records[0].Node != "node-b" {
		t.Fatalf("records after stage clear=%+v error=%v", records, err)
	}
	stats, err = handler.clearTrafficCaptureRecords(cfg)
	if err != nil || stats.File != file || stats.Records != 0 || stats.Bytes != 0 {
		t.Fatalf("clearTrafficCaptureRecords() stats=%+v error=%v", stats, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("capture size after clear=%d, want 0", info.Size())
	}

	otherRecords, err := capture.ReadJSONL(filepath.Join(cwd, "data", "traffic-captures-de1.jsonl"))
	if err != nil || len(otherRecords) != 2 {
		t.Fatalf("other deployment records=%d error=%v", len(otherRecords), err)
	}
	content, err := os.ReadFile(legacyPath)
	if err != nil || string(content) != string(legacy) {
		t.Fatalf("legacy file changed: content=%q error=%v", content, err)
	}
}
