package capture

import (
	"path/filepath"
	"strings"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

func TestFileWithServerName(t *testing.T) {
	for _, tt := range []struct {
		name, file, server, want string
	}{
		{name: "deployment", file: "data/traffic-captures.jsonl", server: "hk1", want: "data/traffic-captures-hk1.jsonl"},
		{name: "no server", file: "data/custom.jsonl", want: "data/custom.jsonl"},
		{name: "no file", server: "hk1", want: ""},
		{name: "trim whitespace", file: "data/custom.jsonl", server: " hk1 ", want: "data/custom-hk1.jsonl"},
		{name: "unicode", file: "data/custom.jsonl", server: "香港服务器", want: "data/custom-香港服务器.jsonl"},
		{name: "hostname", file: "data/custom.jsonl", server: "host-1.example.com", want: "data/custom-host-1.example.com.jsonl"},
		{name: "no extension", file: "data/nested/capture", server: "de1", want: "data/nested/capture-de1"},
		{name: "unsafe characters", file: "data/custom.jsonl", server: "../../hk1\\:<>|?*\r\n", want: "data/custom-hk1.jsonl"},
		{name: "only unsafe characters", file: "data/custom.jsonl", server: "../\\", want: "data/custom-unknown-server.jsonl"},
		{name: "long name", file: "data/custom.jsonl", server: strings.Repeat("a", 100), want: "data/custom-" + strings.Repeat("a", 64) + ".jsonl"},
		{name: "long unicode name", file: "data/custom.jsonl", server: strings.Repeat("服", 100), want: "data/custom-" + strings.Repeat("服", 21) + ".jsonl"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := FileWithServerName(tt.file, tt.server); got != tt.want {
				t.Fatalf("FileWithServerName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCaptureFilePathUsesDeploymentName(t *testing.T) {
	cwd := t.TempDir()
	recorder := &Recorder{cfg: config.Config{CWD: cwd, ServerName: "hk1"}}
	for _, tt := range []struct {
		file, want string
	}{
		{file: "", want: filepath.Join(cwd, "data", "traffic-captures-hk1.jsonl")},
		{file: "../escape.jsonl", want: filepath.Join(cwd, "data", "traffic-captures-hk1.jsonl")},
		{file: "data/nested/custom.jsonl", want: filepath.Join(cwd, "data", "nested", "custom-hk1.jsonl")},
	} {
		if got := recorder.captureFilePath(storage.SystemConfig{TrafficCaptureFile: tt.file}); got != tt.want {
			t.Fatalf("captureFilePath(%q) = %q, want %q", tt.file, got, tt.want)
		}
	}
}
